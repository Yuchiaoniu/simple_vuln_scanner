import socket

def grab_banner(target_ip, port, timeout=1):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((target_ip, port))

        # 特殊處理 HTTP
        if port in [80, 443]:
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")

        banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip()
    except Exception:
        return None
    finally:
        sock.close()

def grab_banners(target_ip, open_ports):
    results = {}
    for port in open_ports:
        banner = grab_banner(target_ip, port)
        if banner:
            results[port] = banner
    return results
