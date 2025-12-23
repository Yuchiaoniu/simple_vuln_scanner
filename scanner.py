import requests
import json
import socket

from modules import port_scan, banner, version_compare, http_check, web_vuln_test, report

# -------------------------
# 主程式入口
# 學校實驗室主機ip 10.1.72.2   192.168.131.1 192.168.64.1
# -------------------------
if __name__ == "__main__":
    target_ip = "10.1.72.2" 
    ports = [22, 80, 443, 3306, 6379]
    #ssh, http, https, mysql, Redis

    open_ports = port_scan.port_scan(target_ip, ports)
    print("[+] Open Ports:", open_ports)

    banners = banner.grab_banners(target_ip, open_ports)
    print("[+] Banners:", banners)

    baseline = version_compare.load_baseline("data/known_versions.json")
    verdicts = version_compare.evaluate_banners(banners, baseline)
    for v in verdicts:
        print(f"- {v.get('port')}/tcp {v.get('service')} {v.get('version')} → {v.get('status')}")

    # 第四階段：HTTP 基本檢查 
    if 80 in open_ports: 
        print("[+] HTTP Basic Check:") 
        result = http_check.http_basic_check(target_ip, 80, use_https=False) 
        print(result) 
        # 第五階段：Web漏洞基礎測試 
        print("[+] Web Vulnerability Tests:") 
        vuln_results = web_vuln_test.run_tests(target_ip, 80) 
        print(vuln_results)

        # 輸出到 JSON 檔案 
        with open("data/web_vuln_results.json", "w", encoding="utf-8") as f: 
            json.dump(vuln_results, f, indent=4, ensure_ascii=False)
    if 443 in open_ports: 
        print("[+] HTTPS Basic Check:") 
        result = http_check.http_basic_check(target_ip, 443, use_https=True) 
        print(result)

        print("[+] Web Vulnerability Tests (HTTPS):") 
        vuln_results = web_vuln_test.run_tests(target_ip, 443, use_https=True) 
        print(vuln_results)
        with open("data/web_vuln_results.json", "w", encoding="utf-8") as f: 
            json.dump(vuln_results, f, indent=4, ensure_ascii=False)


# ...
if 80 in open_ports:
    print("[+] HTTP Basic Check:")
    result = http_check.http_basic_check(target_ip, 80, use_https=False)
    print(result)

    print("[+] Web Vulnerability Tests:")
    vuln_results = web_vuln_test.run_tests(target_ip, 80)
    print(vuln_results)

    # 第六階段：報告輸出
    print("[+] Generating Report...")
    report.generate_report(verdicts, result, vuln_results)


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]   # 反向 DNS 查詢
    except Exception:
        return "Unknown Hostname"
hostname = get_hostname(target_ip)

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

# 假設只看第一個 banner
os_guess = detect_os_from_banner(list(banners.values())[0]) if banners else "Unknown OS"

print("[+] Generating Report...")
report.generate_report(verdicts, result, vuln_results, hostname=hostname, os_guess=os_guess)

#可以使用python -m http.server 80
#測試有沒有辦法成功掃描正在監聽(對外開放)的port