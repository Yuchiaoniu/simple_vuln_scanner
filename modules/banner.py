import socket
import ssl

# -------------------------
# import連線所需要使用的socket和ssl
# 建立原始 Socket，如果是 443 Port，進行 SSL/TLS 包裝
# 透過sendall函式送出一個原始HTTP請求，b代表將字串轉換為二進位元組，因為網路只傳輸二進位
# GET / 表示要讀取，HTTP/1.0\r\n\r\n表示使用http最基本的1.0版本，目標伺服器收到/r/n/r/n以後就會開始處理
# recv(1024)表示接收回傳的前1024個位元組
# return banner.decode代表將代表接收到的訊息的banner變數轉回文字，並使用.strip修剪掉前後的空白
# 最後透過grab_banners函式遍歷目標的所有指定port號
# -------------------------
def grab_banner(target_ip, port, timeout=1):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)

        if port == 443:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=target_ip)

        sock.connect((target_ip, port))

        # 特殊處理 HTTP
        if port in [80, 443]:
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")

        banner_raw = sock.recv(1024)
        banner_text = banner_raw.decode(errors="ignore").strip()
        
            
        return banner_text
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
