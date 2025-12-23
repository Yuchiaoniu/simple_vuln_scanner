import json
import re
from typing import Dict, Optional, Tuple, List

# -------------------------
# 3.1 載入 baseline
# -------------------------
def load_baseline(path: str = "data/known_versions.json") -> Dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {k.strip(): str(v).strip() for k, v in data.items()}
    except Exception:
        return {}

# -------------------------
# 3.2 解析 banner → (service, version)
# -------------------------
SERVICE_PATTERNS = [
    ("OpenSSH", re.compile(r"OpenSSH[_-]?(\d+(?:\.\d+){0,2})", re.I)),
    ("Apache",  re.compile(r"Apache/(\d+(?:\.\d+){0,2})", re.I)),
    ("nginx",   re.compile(r"nginx/(\d+(?:\.\d+){0,2})", re.I)),
    ("Postfix", re.compile(r"Postfix\s+(\d+(?:\.\d+){0,2})", re.I)),
    ("vsFTPd",  re.compile(r"vsFTPd\s+(\d+(?:\.\d+){0,2})", re.I)),
    ("SimpleHTTP", re.compile(r"SimpleHTTP/(\d+(?:\.\d+)?)", re.I)),
    ("Python", re.compile(r"Python/(\d+(?:\.\d+)?)", re.I)),
]

def parse_banner(banner: str) -> Tuple[Optional[str], Optional[str]]:
    text = banner.strip()
    for service, pattern in SERVICE_PATTERNS:
        m = pattern.search(text)
        if m:
            raw_version = m.group(1)
            cleaned = re.match(r"(\d+(?:\.\d+){0,2})", raw_version)
            return service, (cleaned.group(1) if cleaned else raw_version)
    return None, None

# -------------------------
# 3.3 版本標準化與比較
# -------------------------
def normalize(ver: str, width: int = 3) -> Tuple[int, int, int]:
    parts = re.findall(r"\d+", ver)
    nums = [int(p) for p in parts[:width]]
    while len(nums) < width:
        nums.append(0)
    return tuple(nums)

def is_outdated(detected: str, baseline: str) -> bool:
    return normalize(detected) < normalize(baseline)

# -------------------------
# 3.4 對多個 banner 做比對並輸出結果
# -------------------------
def evaluate_banners(banners: Dict[int, str], baseline_map: Dict[str, str]) -> List[Dict]:
    results = []
    for port, banner in banners.items():
        service, version = parse_banner(banner)
        if not service or not version:
            results.append({
                "port": port,
                "service": service or "Unknown",
                "version": version or "Unknown",
                "status": "Unknown version (cannot parse)"
            })
            continue

        baseline = baseline_map.get(service)
        if not baseline:
            results.append({
                "port": port,
                "service": service,
                "version": version,
                "status": "No baseline (cannot judge)"
            })
            continue

        status = "Outdated" if is_outdated(version, baseline) else "OK"
        results.append({
            "port": port,
            "service": service,
            "version": version,
            "baseline": baseline,
            "status": status
        })
    return results