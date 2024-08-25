from DopeShell import DopeShellServer

key = b'myverystrongpasswordo32bitlength'

server = DopeShellServer('0.0.0.0', 4444, key)
server.run()
