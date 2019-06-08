
import unittest

import tor

suite "functional - client":
  test "client":
    let s = newProxySocket()
    s.connect("1.1.1.1", 80.Port)
    s.send("GET / \n")
    discard s.recvLine(timeout=3000)
    discard s.recv(200)
    s.close()

  test "client - onion":
    let s = newProxySocket()
    s.connect("facebookcorewwwi.onion", 80.Port)
    s.send("GET / \n")
    discard s.recvLine(timeout=3000)
    discard s.recv(200)
    s.close()




when defined(usesodium):

  suite "functional - controller":

    test "create and list traditional Onion Services":
      let c = connect_to_controller()
      discard c.list_onion_services()
      c.create_onion_service("/var/lib/tor/blah/",
                             8888.Port, 8888.Port)

    test "create, list, remove Ephemeral Onion Services":
      let c = connect_to_controller()
      check c.list_ephemeral_onion_services().len == 0

      var o = c.create_ephemeral_onion_service(3333.Port, v2)
      check c.list_ephemeral_onion_services().len == 1

      o = c.create_ephemeral_onion_service(3334.Port, best)
      check c.list_ephemeral_onion_services().len == 2

      o = c.create_ephemeral_onion_service(3334.Port, v3)
      check c.list_ephemeral_onion_services().len == 3

      c.remove_ephemeral_onion_service(o.service_id)
      check c.list_ephemeral_onion_services().len == 2
