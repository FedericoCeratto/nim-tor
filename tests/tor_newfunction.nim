import tor

proc testfunc(ps: ProxySocket) =

    ps.connect("facebookcorewwwi.onion", 80.Port)
    ps.send("GET / \n")
    discard ps.recvLine(timeout=3000)
    discard ps.recv(200)
    ps.close()

proc main() =

    var ps = newProxySocket()
    testfunc(ps)

when isMainModule:

    main()