import ssl, socket
ctx = ssl.create_default_context()
with socket.create_connection(("127.0.0.1", 443)) as sock:
    with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as ssock:
        print(ssock.version())
