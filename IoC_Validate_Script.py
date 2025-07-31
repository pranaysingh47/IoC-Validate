import requests
import pandas as pd
import time
from typing import List, Dict, Any
import datetime
import os
import sys
import re
import base64

# =========== CONFIGURATION ===========
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
ALIENVAULT_API_KEY = "YOUR_ALIENVAULT_API_KEY"

# =========== END CONFIGURATION ===========

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1"

def vt_headers():
    return {"x-apikey": VT_API_KEY}

def abuseipdb_headers():
    return {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

def alienvault_headers():
    return {"X-OTX-API-KEY": ALIENVAULT_API_KEY}

def defang(ioc: str) -> str:
    # Unfang protocols (handles hxxps[:]//, hxxps://, hxxp[:]//, hxxp://, etc.)
    ioc = re.sub(r'^hxxps?\[\:\]//', lambda m: 'https://' if 's' in m.group(0) else 'http://', ioc, flags=re.IGNORECASE)
    ioc = re.sub(r'^hxxps?\[\:\]', lambda m: 'https://' if 's' in m.group(0) else 'http://', ioc, flags=re.IGNORECASE)
    ioc = re.sub(r'^hxxps?\:', lambda m: 'https:' if 's' in m.group(0) else 'http:', ioc, flags=re.IGNORECASE)
    # Dots
    ioc = re.sub(r'(\[\.\]|\(\.\)|\{dot\})', '.', ioc)
    # Colons
    ioc = re.sub(r'\[\:\]', ':', ioc)
    # [at]
    ioc = ioc.replace('[at]', '@')
    # Remove any accidental double slashes after protocol (e.g., http:////bad.domain.com)
    ioc = re.sub(r'^(https?:)//+', r'\1//', ioc, flags=re.IGNORECASE)
    return ioc

def vt_url_id(ioc_url: str) -> str:
    b64 = base64.urlsafe_b64encode(ioc_url.encode()).decode().rstrip("=")
    return b64

def get_vt_data(ioc: str, ioc_type: str) -> Dict[str, Any]:
    if ioc_type == "domain":
        ioc = ioc.replace("http://", "").replace("https://", "").split("/")[0]
        url = f"{VT_BASE_URL}/domains/{ioc}"
        vt_gui_link = f"https://www.virustotal.com/gui/domain/{ioc}"
    elif ioc_type == "url":
        url_id = vt_url_id(ioc)
        url = f"{VT_BASE_URL}/urls/{url_id}"
        vt_gui_link = f"https://www.virustotal.com/gui/url/{url_id}"
    else:
        url = f"{VT_BASE_URL}/{ioc_type}s/{ioc}"
        vt_gui_link = f"https://www.virustotal.com/gui/{ioc_type}/{ioc}"

    resp = requests.get(url, headers=vt_headers())
    if resp.status_code == 200 and 'data' in resp.json():
        data = resp.json()['data']
        attrs = data.get('attributes', {})
        return {
            "VT_community_score": attrs.get("last_analysis_stats", {}),
            "VT_categories": attrs.get("categories", {}),
            "VT_link": vt_gui_link
        }
    return {}

def get_abuseipdb_data(ip: str) -> Dict[str, Any]:
    url = f"{ABUSEIPDB_BASE_URL}/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    resp = requests.get(url, headers=abuseipdb_headers(), params=params)
    if resp.status_code == 200:
        data = resp.json().get("data", {})
        return {
            "AbuseIPDB_hostname": data.get("hostnames", []),
            "AbuseIPDB_country": data.get("countryCode", ""),
            "AbuseIPDB_owner": data.get("isp", ""),
            "AbuseIPDB_isp": data.get("isp", ""),
            "AbuseIPDB_score": data.get("abuseConfidenceScore", ""),
            "AbuseIPDB_link": f"https://www.abuseipdb.com/check/{ip}"
        }
    return {}

def get_otx_data(ioc: str, ioc_type: str) -> Dict[str, Any]:
    if ioc_type == "ip":
        url = f"{ALIENVAULT_BASE_URL}/indicators/IPv4/{ioc}/general"
        link = f"https://otx.alienvault.com/indicator/ip/{ioc}"
    elif ioc_type == "domain":
        url = f"{ALIENVAULT_BASE_URL}/indicators/domain/{ioc}/general"
        link = f"https://otx.alienvault.com/indicator/domain/{ioc}"
    elif ioc_type == "url":
        url = f"{ALIENVAULT_BASE_URL}/indicators/url/{ioc}/general"
        link = f"https://otx.alienvault.com/indicator/url/{ioc}"
    elif ioc_type == "hash":
        url = f"{ALIENVAULT_BASE_URL}/indicators/file/{ioc}/general"
        link = f"https://otx.alienvault.com/indicator/file/{ioc}"
    else:
        return {}
    resp = requests.get(url, headers=alienvault_headers())
    if resp.status_code == 200:
        data = resp.json()
        return {
            "OTX_pulses": data.get("pulse_info", {}).get("pulses", []),
            "OTX_link": link
        }
    return {}

def detect_ioc_type(ioc: str) -> str:
    # Remove URL scheme for type detection
    ioc_no_scheme = re.sub(r'^(http|https)://', '', ioc, flags=re.IGNORECASE)
    # Remove path for domain detection
    ioc_base = ioc_no_scheme.split('/')[0]
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ioc_base):
        return "ip"
    elif re.match(r"^(?:(?:[a-fA-F\d]{32})|(?:[a-fA-F\d]{40})|(?:[a-fA-F\d]{64})|(?:[a-fA-F\d]{128}))$", ioc_base):
        return "hash"
    elif ioc.lower().startswith("http://") or ioc.lower().startswith("https://"):
        return "url"
    elif re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", ioc_base):
        return "domain"
    else:
        return "file"

def correlate_results(vt: dict, abuseipdb: dict, otx: dict, ioc_type: str) -> str:
    malicious = False
    reasons = []
    vt_score = vt.get("VT_community_score", {})
    if vt_score.get("malicious", 0) > 0:
        malicious = True
        reasons.append("VT: malicious detected")
    if abuseipdb and abuseipdb.get("AbuseIPDB_score", 0) and abuseipdb["AbuseIPDB_score"] > 50:
        malicious = True
        reasons.append("AbuseIPDB: high abuse score")
    if otx.get("OTX_pulses"):
        malicious = True
        reasons.append("OTX: pulse(s) detected")
    if malicious:
        return f"Malicious ({', '.join(reasons)})"
    else:
        return "Not Malicious"

def validate_iocs(iocs: List[str]) -> pd.DataFrame:
    results = []
    for orig_ioc in iocs:
        clean_ioc = defang(orig_ioc)
        ioc_type = detect_ioc_type(clean_ioc)
        vt = get_vt_data(clean_ioc, ioc_type)
        abuseipdb = get_abuseipdb_data(clean_ioc) if ioc_type == "ip" else {}
        otx = get_otx_data(clean_ioc, ioc_type)
        verdict = correlate_results(vt, abuseipdb, otx, ioc_type)
        row = {
            "Original_IoC": orig_ioc,
            "Defanged_IoC": clean_ioc,
            "Type": ioc_type,
            "VT_Community_Score": vt.get("VT_community_score"),
            "VT_Categories": vt.get("VT_categories"),
            "VT_Link": vt.get("VT_link"),
            "AbuseIPDB_Hostname": abuseipdb.get("AbuseIPDB_hostname"),
            "AbuseIPDB_Location": abuseipdb.get("AbuseIPDB_country"),
            "AbuseIPDB_Owner": abuseipdb.get("AbuseIPDB_owner"),
            "AbuseIPDB_ISP": abuseipdb.get("AbuseIPDB_isp"),
            "AbuseIPDB_Score": abuseipdb.get("AbuseIPDB_score"),
            "AbuseIPDB_Link": abuseipdb.get("AbuseIPDB_link"),
            "OTX_Pulses": [p.get("name") for p in otx.get("OTX_pulses", [])],
            "OTX_Link": otx.get("OTX_link"),
            "Correlated_Verdict": verdict
        }
        results.append(row)
        time.sleep(1.5)  # avoid rate limiting
    return pd.DataFrame(results)

def get_timestamp_filename(input_path: str) -> str:
    base_dir = os.path.dirname(os.path.abspath(input_path))
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    now = datetime.datetime.now()
    timestamp = now.strftime("%d%m%Y%H%M")
    out_filename = f"{base_name}_IoC_Validate_{timestamp}.xlsx"
    return os.path.join(base_dir, out_filename)

def load_iocs_from_file(input_path: str) -> List[str]:
    ext = os.path.splitext(input_path)[1].lower()
    if ext == ".txt":
        with open(input_path, "r", encoding="utf-8") as f:
            iocs = [line.strip() for line in f if line.strip()]
    elif ext == ".csv":
        df = pd.read_csv(input_path)
        iocs = df.iloc[:,0].dropna().astype(str).tolist()
    else:
        raise ValueError("Unsupported input file type. Only .txt and .csv are supported.")
    return iocs

def main():
    if len(sys.argv) < 2:
        print("Usage: python ioc_validation.py <input_file.txt|input_file.csv>")
        sys.exit(1)
    input_file = sys.argv[1]
    if not os.path.isfile(input_file):
        print(f"File not found: {input_file}")
        sys.exit(1)
    iocs = load_iocs_from_file(input_file)
    df = validate_iocs(iocs)
    out_filename = get_timestamp_filename(input_file)
    df.to_excel(out_filename, index=False)
    print(f"Results exported to {out_filename}")

if __name__ == "__main__":
    main()
