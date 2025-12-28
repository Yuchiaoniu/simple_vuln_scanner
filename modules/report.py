import json

def generate_report(verdicts, result, vuln_results, hostname="Unknown", os_guess="Unknown", 
                    json_path="data/report.json", txt_path="data/report.txt"):

    report = {
        "host_info": {
            "hostname": hostname,
            "os_guess": os_guess
        },
        "open_ports": verdicts,
        "http_checks": result,
        "web_vuln_tests": vuln_results
    }

    # 輸出 JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    # 輸出文字
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("[+] Host Info:\n")
        f.write(f"    Hostname: {hostname}\n")
        f.write(f"    OS Guess: {os_guess}\n\n")

        f.write("[+] Open Ports:\n")
        for v in verdicts:
            f.write(f"    {v['port']}/tcp ({v['service']} {v['version']}) - {v['status']}\n")

        f.write("\n[+] HTTP Checks:\n")
        f.write(f"    Directory Listing: {result['directory_listing']}\n")
        f.write(f"    HTTPS: {result['https_usage']}\n")
        f.write(f"    TLS Version: {result['tls_check']}\n")
        f.write(f"    Sensitive Headers: {', '.join([k for k,v in result['sensitive_headers'].items() if v != '缺失'])}\n")

        f.write("\n[+] Web Vulnerability Tests:\n")
        f.write(f"    Sensitive Files: {', '.join(vuln_results['sensitive_files'])}\n")
        f.write(f"    Error Leak: {vuln_results['error_leak']}\n")
        f.write(f"    SQL Injection: {vuln_results['sql_injection']}\n")
        f.write(f"    XSS: {vuln_results['xss']}\n")
        f.write(f"    Cookie Security: {', '.join(vuln_results['cookie_security'])}\n")
    return report