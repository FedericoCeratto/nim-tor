##
## Ephemeral onion service v3 demo
## Serve a single file over HTTP
##
## Usage:
## nim c -p:. --hints:off -d:usesodium tests/serve_file_demo.nim
## ./serve_file_demo <filename>

import os, strformat, net

import jester
import tor

var fname = ""

router myrouter:
  get "/":
    send_file fname


proc main() =
  const port = 8080.Port
  fname = paramStr(1)
  assert existsFile fname
  let contr = connect_to_controller()
  let os = contr.create_ephemeral_onion_service(port, v3)
  echo fmt"Connect to http://{os.service_id}.onion:{$port}/"
  let settings = newSettings(port=port)
  var jester = initJester(myrouter, settings=settings)
  jester.serve()

when isMainModule:
  main()
