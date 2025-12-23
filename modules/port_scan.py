import socket
from concurrent.futures import ThreadPoolExecutor

#使用socket管理網路通訊，使用ThreadPoolExecutor管理多執行緒

# -------------------------
# 1.1 決定掃描範圍
# -------------------------
def get_ports_to_scan(ports):
    return sorted(set(ports)) #由小到大排列


# -------------------------
# 1.2 + 1.3: TCP Connect Scan
# -------------------------
def scan_port(target_ip, port, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            return (port, "open")
        else:
            return (port, "closed")
    except Exception:
        return (port, "closed")
    finally:
        sock.close()


# -------------------------
# 1.4: 多執行緒掃描
# -------------------------
def port_scan(target_ip, ports, threads=100):
    ports_to_scan = get_ports_to_scan(ports)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(
            lambda p: scan_port(target_ip, p),
            ports_to_scan
        )

    open_ports = [port for port, status in results if status == "open"]
    
    return open_ports

