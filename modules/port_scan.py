# -------------------------
# 1.1 決定掃描範圍
#使用標準函式庫socket，管理網路通訊，使用ThreadPoolExecutor管理多執行緒
#也就是透過socket這個檔案，對網路進行檔案讀取與儲存的操作
#這遵循了 Unix 的哲學：「一切皆檔案 (Everything is a file)」。
#先用set保證輸入唯一性，避免掃描重複port號，然後用sorted由小到大排列自定義了傳入ports變數的get_ports_to_scan
# -------------------------

import socket
from concurrent.futures import ThreadPoolExecutor

def get_ports_to_scan(ports):
    return sorted(set(ports)) 


# -------------------------
# 1.2 + 1.3: TCP Connect Scan
#使用socket的socket函式傳入
#socket.AF_INET作為IPv4清單表示要連接的IP種類
#和socket.SOCK_STREAM作為網路協定格式表示要連線的網路協定TCP
#接著調用socket內建函式settimeout傳入scan_port的第二個名為timeout且賦值0.5的參數
# 這樣子傳入TCP/IP格式後，就等同表示定義等待掃描目標port號回應的時間
# 最後透過socket的connect_ex函式進行連線，並把結果存放在result變數
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
# 透過多執行緒ThreadPoolExecutor掃描函式傳入定義好的執行緒數目提高掃描效率
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

