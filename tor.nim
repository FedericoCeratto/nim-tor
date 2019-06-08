## Tor helper library
## Copyright Federico Ceratto <federico.ceratto@gmail.com>
## Released under LGPLv3 License, see LICENSE file
##

import net,
  strutils

export Port

when defined(usesodium):
  import libsodium.sodium

type
  TorController* = ref object of RootObj
    sock: Socket
  OnionServiceDesc* = object of RootObj
    dir*, port*: string
  OnionService* = object of RootObj
    private_key*, service_id*: string
  ServiceKind* = enum
    v2, v3, best

proc readline(s: Socket): string =
  result = ""
  while true:
    let char = s.recv(1, timeout=1000)
    result.add char
    if char == "\n":
      stripLineEnd(result)
      return

proc readlineOK(s: Socket): string =
  let line = s.readline()
  if not line.startsWith("250"):
    raise newException(Exception, "Unexpected controller response: " & line)
  return line


proc expectOK(sock: Socket) =
  let line = sock.readline()
  if line != "250 OK":
    raise newException(Exception, "Unexpected controller response: " & line)

when defined(usesodium):
  proc crypto_authenticate(s: Socket, cookiefn: string) =
    let authcookie = readFile cookiefn
    assert authcookie.len == 32
    let cookiestring = authcookie.toHex()
    let clientnonce = randombytes(32)
    assert authcookie.len == clientnonce.len

    s.send("AUTHCHALLENGE SAFECOOKIE " & clientnonce.toHex() & "\n")

    let line = s.readline()
    if not line.startsWith("250 AUTHCHALLENGE SERVERHASH="):
      raise newException(Exception, "Unexpected controller response: " & line)

    let serverhash = line.split("SERVERHASH=")[1].split(' ')[0].parseHexStr()
    assert serverhash.len == authcookie.len
    let servernonce = line.split("SERVERNONCE=")[1].parseHexStr()
    assert servernonce.len == authcookie.len

    # check the server hash
    block:
      const skey = "Tor safe cookie authentication server-to-controller hash"
      let hmac = new_crypto_auth_hmacsha256(skey)
      hmac.update(authcookie)
      hmac.update(clientnonce)
      hmac.update(servernonce)
      if hmac.finalize() != serverhash:
        raise newException(Exception, "Incorrect server HMAC")

    # generate the server hash
    block:
      const ckey = "Tor safe cookie authentication controller-to-server hash"
      let hmac = new_crypto_auth_hmacsha256(ckey)
      #assert s.parseHexStr().len == 96
      #hmac.update(s.parseHexStr())
      hmac.update(authcookie)
      hmac.update(clientnonce)
      hmac.update(servernonce)
      let token = hmac.finalize().toHex()
      s.send("AUTHENTICATE " & token & "\n")
      s.expectOK()

proc connect_to_controller*(ipaddr="127.0.0.1", port=9051.Port): TorController =
  ## Connect to Tor Controller
  new result
  var s = newSocket()
  result.sock = s
  s.connect(ipaddr, port)
  s.send("PROTOCOLINFO 1\n")

  var cookiefn = ""
  while true:
    let line = s.readline()
    if not line.startsWith("250"):
      raise newException(Exception, "Unexpected controller response: " & line)

    if line.startsWith("250-AUTH"):
      if line.contains("COOKIEFILE="):
        cookiefn = line.split("COOKIEFILE=")[1].split('"')[1]

    if line.startsWith("250 OK"):
      break

  if cookiefn != "":
    # cookie auth required
    when defined(usesodium):
      s.crypto_authenticate(cookiefn)
    else:
      raise newException(Exception, "Cookie auth required. Enable libsodium support.")


proc list_onion_services*(c: TorController): seq[OnionServiceDesc] =
  ## Fetch Onion Services
  result = @[]
  c.sock.send("GETCONF HiddenServiceOptions\n")
  var o = OnionServiceDesc()
  while true:
    let line = c.sock.readline()
    if line.startsWith("250"):
      let entry = line[4..^1]
      if entry.startsWith("HiddenServiceDir"):
        o = OnionServiceDesc(dir: entry.split('=')[1])
      else:
        o.port = entry.split('=')[1]
        result.add o

      if line.startsWith("250 "):
        # this was the last line
        return
    else:
      raise newException(Exception, "Unexpected controller response: " & line)

proc create_onion_service*(c: TorController, service_dir: string, public_port, local_port: Port, ignore_duplicate=true) =
  ## Setup Onion Service
  var services = c.list_onion_services()
  let new_o = OnionServiceDesc(dir:service_dir, port:($public_port & " 127.0.0.1:" & $local_port))
  block:
    for o in services:
      if o.dir != new_o.dir or o.port != new_o.port:
        continue
      # The service already exists
      if ignore_duplicate == false:
        raise newException(Exception, "The Onion Service is already configured.")
      else:
        # do nothing
        return

  # Add the new onion
  services.add new_o

  # Build the SETCONF syntax
  var setconf = "SETCONF"
  for o in services:
    setconf.add " HiddenServiceDir=\"$#\" HiddenServicePort=\"$#\"" % [o.dir, o.port]

  c.sock.send(setconf & "\n")
  c.sock.expectOK()

proc list_ephemeral_onion_services*(c: TorController): seq[OnionService] =
  ## List Ephemeral Onion Services
  ## Returns OnionService sequence with service_id and private_key fields set.
  result = @[]
  c.sock.send("GETINFO onions/current\n")
  var line = c.sock.readline()
  if not line.startsWith("250"):
    raise newException(Exception, "Unexpected controller response: " & line)
  if line.startsWith("250-onions/current="):
    # zero or one service
    let chunks = line.split('=', 1)[1]
    if chunks.len > 0:
      result.add OnionService(service_id:chunks)
    c.sock.expectOK()
    return

  if line.startsWith("250+onions/current="):
    # multiple services listed below
    while true:
      line = c.sock.readline()
      if line == ".":
        # end of list
        c.sock.expectOK()
        return

      result.add OnionService(service_id:line)

proc create_ephemeral_onion_service*(c: TorController, port: Port,
    service_kind=ServiceKind.best): OnionService =
  ## Create Ephemeral Onion Service
  ## Returns OnionService with service_id and private_key fields set.
  let k =
    case service_kind
    of best: "BEST"
    of v2: "RSA1024"
    of v3: "ED25519-V3"

  let cmd = "ADD_ONION NEW:"&k&" Port=" & $port & "\n"
  c.sock.send(cmd)
  result = OnionService()
  while true:
    let line = c.sock.readlineOK()
    if line.startsWith("250-ServiceID"):
      result.service_id = line.split('=', maxsplit=1)[1]
    elif line.startsWith("250-PrivateKey"):
      result.private_key = line.split('=', maxsplit=1)[1]
    elif line == "250 OK":
      return

proc remove_ephemeral_onion_service*(c: TorController, service_id:string) =
  ## Remove Ephemeral Onion Service
  c.sock.send("DEL_ONION " & service_id & "\n")
  c.sock.expectOK()


# SOCKS client

type ProxySocket = ref object of RootObj
  inner*: Socket

proc newProxySocket*(ipaddr="127.0.0.1", port=9050.Port): ProxySocket =
  ## Create a new proxied TCP socket
  new result
  result.inner = newSocket()
  result.inner.connect(ipaddr, port)
  result.inner.send("\x05\x01\x00") # connect with no auth
  let resp = result.inner.recv(2, 1000)
  if resp != "\x05\x00":
    raise newException(Exception, "Unexpected proxy response: " & resp.toHex())

proc connect*(s: ProxySocket, address: string, port: Port) =
  ## Connect by FQDN/hostname or IP address
  #echo repr port.uint16.toHex().fromHex()
  var p = "  "
  p[0] = cast[char](port.uint16 shr 8)
  p[1] = cast[char](port)

  s.inner.send("\x05\x01\x00\x03" & address.len.char & address & p)

proc send*(s: ProxySocket; data: string; flags = {SafeDisconn}) =
  ## Sends data to a socket
  s.inner.send(data, flags)

proc recv*(s: ProxySocket; size: int; timeout = -1; flags = {SafeDisconn}): string =
  s.inner.recv(size, timeout, flags)

proc recvLine*(s: ProxySocket; timeout = -1; flags = {SafeDisconn}; maxLength = MaxLineLength): TaintedString =
  s.inner.recvLine(timeout, flags, maxLength)

proc close*(s: ProxySocket) =
  ## Close socket
  s.inner.close()
