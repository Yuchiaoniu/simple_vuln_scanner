import requests

# -------------------------
# 敏感檔案與路徑檢查
# -------------------------
def check_sensitive_files(target_ip, port=80, use_https=False):
    scheme = "https" if use_https else "http"
    base_url = f"{scheme}://{target_ip}:{port}/"
    test_paths = ["robots.txt", "admin/", "phpinfo.php", "config/", "backup/"]

    results = []
    for path in test_paths:
        url = base_url + path
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                results.append(f"{path}: Found")
            else:
                results.append(f"{path}: Not Found")
        except Exception:
            results.append(f"{path}: Error")
    return results

# -------------------------
# 錯誤訊息洩漏測試
# -------------------------
def check_error_leak(target_ip, port=80, use_https=False):
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target_ip}:{port}/test'"
    try:
        resp = requests.get(url, timeout=3)
        body = resp.text
        if any(keyword in body for keyword in ["SQL syntax", "Exception", "Traceback"]):
            return "Found"
        return "Not Found"
    except Exception:
        return "Error"

# -------------------------
# 簡單 SQL Injection 測試
# -------------------------
def check_sql_injection(target_ip, port=80, use_https=False):
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target_ip}:{port}/?id=1' OR '1'='1"
    try:
        resp = requests.get(url, timeout=3)
        if "error" in resp.text.lower() or "syntax" in resp.text.lower():
            return "Possible SQL Injection"
        return "Not Found"
    except Exception:
        return "Error"

# -------------------------
# 簡單 XSS 測試
# -------------------------
def check_xss(target_ip, port=80, use_https=False):
    scheme = "https" if use_https else "http"
    payload = "<script>alert(1)</script>"
    url = f"{scheme}://{target_ip}:{port}/?q={payload}"
    try:
        resp = requests.get(url, timeout=3)
        if payload in resp.text:
            return "Possible XSS"
        return "Not Found"
    except Exception:
        return "Error"

# -------------------------
# Cookie 安全性檢查
# -------------------------
def check_cookie_security(target_ip, port=80, use_https=False):
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target_ip}:{port}/"
    try:
        resp = requests.get(url, timeout=3)
        cookies = resp.cookies
        results = []
        for c in cookies:
            if not c.has_nonstandard_attr("HttpOnly"):
                results.append("Missing HttpOnly")
            if use_https and not c.secure:
                results.append("Missing Secure")
        return results if results else ["Cookie Security OK"]
    except Exception:
        return ["Error"]

# -------------------------
# 主測試流程
# -------------------------
def run_tests(target_ip, port=80, use_https=False):
    results = {
        "sensitive_files": check_sensitive_files(target_ip, port, use_https),
        "error_leak": check_error_leak(target_ip, port, use_https),
        "sql_injection": check_sql_injection(target_ip, port, use_https),
        "xss": check_xss(target_ip, port, use_https),
        "cookie_security": check_cookie_security(target_ip, port, use_https)
    }
    return results
