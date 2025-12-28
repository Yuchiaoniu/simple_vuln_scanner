import requests
import json
import socket

from modules import port_scan, banner, version_compare, http_check, web_vuln_test, report

# -------------------------
# 輔助函式
# -------------------------
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]   # 反向 DNS 查詢
    except Exception:
        return "Unknown Hostname"

def detect_os_from_banner(banner_text):
    banner_text = banner_text.lower()
    if "windows" in banner_text or "iis" in banner_text:
        return "Windows (IIS)"
    elif "ubuntu" in banner_text:
        return "Ubuntu/Linux"
    elif "debian" in banner_text:
        return "Debian/Linux"
    elif "centos" in banner_text or "red hat" in banner_text:
        return "CentOS/RedHat Linux"
    else:
        return "Unknown OS"


# -------------------------
# 主程式入口
# -------------------------
if __name__ == "__main__":
    # 可以改成實驗室主機 IP，例如 10.1.72.2 / 192.168.131.1 / 192.168.64.1
    target_ip = "127.0.0.1"
    ports = [22, 80, 443, 3306, 6379]  # ssh, http, https, mysql, redis

    # 第一步：Port Scan
    open_ports = port_scan.port_scan(target_ip, ports)
    print("[+] Open Ports:", open_ports)

    # 第二步：Banner Grabbing
    banners = banner.grab_banners(target_ip, open_ports)
    for port, content in banners.items():
        print(f"--- Port {port} ---")
        print(content)
        print("-" * 20)

    # 第三步：版本比對
    baseline = version_compare.load_baseline("data/known_versions.json")
    verdicts = version_compare.evaluate_banners(banners, baseline)
    for v in verdicts:
        print(f"- {v.get('port')}/tcp {v.get('service')} {v.get('version')} → {v.get('status')}")

    # 第四、五步：HTTP/HTTPS 基本檢查 + Web漏洞測試
    result = None
    vuln_results = None

    if 80 in open_ports:
        print("[+] HTTP Basic Check:")
        result = http_check.http_basic_check(target_ip, 80, use_https=False)
        print(json.dumps(result, indent=4, ensure_ascii=False))

        print("[+] Web Vulnerability Tests:")
        vuln_results = web_vuln_test.run_tests(target_ip, 80)
        print(vuln_results)

        with open("data/web_vuln_results.json", "w", encoding="utf-8") as f:
            json.dump(vuln_results, f, indent=4, ensure_ascii=False)

    if 443 in open_ports:
        print("[+] HTTPS Basic Check:")
        result = http_check.http_basic_check(target_ip, 443, use_https=True)
        print(json.dumps(result, indent=4, ensure_ascii=False))

        print("[+] Web Vulnerability Tests (HTTPS):")
        vuln_results = web_vuln_test.run_tests(target_ip, 443, use_https=True)
        print(vuln_results)

        with open("data/web_vuln_results.json", "w", encoding="utf-8") as f:
            json.dump(vuln_results, f, indent=4, ensure_ascii=False)

    # 第六步：報告輸出
    hostname = get_hostname(target_ip)
    os_guess = detect_os_from_banner(list(banners.values())[0]) if banners else "Unknown OS"

    print("[+] Generating Report...")
    report.generate_report(verdicts, result, vuln_results, hostname=hostname, os_guess=os_guess)

    # 提示：可以用 python -m http.server 80 測試本機 80 port 是否能被掃描