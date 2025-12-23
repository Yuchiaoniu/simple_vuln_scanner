import requests 
import ssl 
import socket 
# ------------------------- 
# 4.1 發送 GET / 
# ------------------------- 
def fetch_http(target_ip, port=80, use_https=False): 
    scheme = "https" if use_https else "http" 
    url = f"{scheme}://{target_ip}:{port}/" 
    try: 
        resp = requests.get(url, timeout=3) 
        return resp 
    except Exception as e: 
        return None 

# ------------------------- 
# 4.2 檢查 directory listing 
# ------------------------- 
def check_directory_listing(body: str) -> str: 
    if "<title>Index of /</title>" in body or "Index of /" in body: 
        return "可能存在目錄列出漏洞" 
    return "未發現目錄列出" 
# ------------------------- 
# 4.3 檢查敏感 header 
# ------------------------- 
def check_sensitive_headers(headers: dict) -> dict: 
    checks = ["Server", "X-Powered-By", "X-AspNet-Version", 
              "X-Frame-Options", "Content-Security-Policy"] 
    results = {} 
    for h in checks: 
        results[h] = headers.get(h, "缺失") 
    return results 

# ------------------------- 
# 4.4 + 4.5 + 4.6 檢查 HTTPS 與 TLS 
# ------------------------- 
def check_tls(target_ip, port=443): 
    try: 
        ctx = ssl.create_default_context() 
        with socket.create_connection((target_ip, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=target_ip) as ssock: 
                version = ssock.version() 
                if version in ["TLSv1", "TLSv1.1"]:
                    return f"{version} → 弱 TLS" 
                else: 
                    return f"{version} → 安全" 
    except Exception: 
        return "TLS 檢查失敗" 
# ------------------------- 
# 主檢查流程 
# ------------------------- 
def http_basic_check(target_ip, port=80, use_https=False): 
    resp = fetch_http(target_ip, port, use_https) 
    if not resp: 
        return {"error": "HTTP 請求失敗"} 
    body = resp.text 
    headers = resp.headers

    return { 
        "status_code": resp.status_code, 
        "directory_listing": check_directory_listing(body), 
        "sensitive_headers": check_sensitive_headers(headers), 
        "https_usage": "已使用 HTTPS" if use_https or port == 443 else "未使用 HTTPS",
        "tls_check": check_tls(target_ip, 443) if use_https or port == 443 else "未檢查 (非 HTTPS)" 
        }