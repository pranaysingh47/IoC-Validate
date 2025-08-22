import requests
import pandas as pd
import re
import time
import datetime
import os
import sys
import concurrent.futures
import base64
import urllib.parse

# --- CONFIGURATION ---

CA_BUNDLE_PATH = None  # Set to your CA bundle path or None

# ---------------------------- API KEYS ----------------------------

VT_API_KEY = "VT_API_KEY"
ABUSEIPDB_API_KEY = "ABUSEIPDB_API_KEY"
ALIENVAULT_API_KEY = "ALIENVAULT_API_KEY"

# --- API Rate Limit Delays (in seconds) ---
VT_DELAY = 15
OTHER_API_DELAY = 0.5

# --- Caches for API results to avoid redundant calls ---
abuse_ip_cache = {}
alienvault_ip_cache = {}

def defang(ioc):
    return ioc.replace("[.]", ".").replace("[:]", ":").replace("hxxp", "http").replace("hxxps", "https").strip()

def refang(ioc):
    ioc = ioc.replace("[.]", ".").replace("[/]", "/").replace("[://]", "://").replace("hxxp", "http").replace("hxxps", "https")
    ioc = re.sub(r"\[([^\]]+)\]", r"\1", ioc)
    return ioc.strip()

def get_vt_info(ioc, indicator_type):
    """
    Enhanced VT lookup: For URLs, use BOTH /urls endpoint and /search endpoint.
    If either returns a malicious verdict, use that.
    For hashes and others, keep as before.
    """
    headers = {"x-apikey": VT_API_KEY}
    vt_results = {
        "score": None,
        "category": None,
        "link": f"https://www.virustotal.com/gui/search/{ioc}",
        "last_analysis_date": None,
        "whois_date": None,
        "a_records": [],
        "md5": None,
        "sha1": None,
        "sha256": None,
        "file_size": None,
        "file_type_description": None,
        "file_names": None,
    }

    # For URLs, try BOTH /urls and /search
    if indicator_type == "URL":
        vt_ioc = refang(ioc)
        best_score = 0
        best_results = vt_results.copy()

        # --- 1. Try /urls endpoint ---
        try:
            encoded_url_for_b64 = urllib.parse.quote_plus(vt_ioc)
            url_id = base64.urlsafe_b64encode(encoded_url_for_b64.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(url, headers=headers, verify=CA_BUNDLE_PATH, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if "data" in data and data["data"]:
                    first_data_entry = data["data"]
                    attributes = first_data_entry.get("attributes", {})
                    temp_results = vt_results.copy()
                    temp_results["link"] = first_data_entry.get("links", {}).get("self", temp_results["link"])
                    temp_results["score"] = attributes.get("last_analysis_stats", {}).get("malicious", 0)
                    temp_results["category"] = (
                        ", ".join(list(set(attributes.get("categories", {}).values())))
                        if isinstance(attributes.get("categories", {}), dict) else
                        ", ".join(list(set(attributes.get("categories", []))))
                        if isinstance(attributes.get("categories", []), list) else None
                    )
                    temp_results["last_analysis_date"] = datetime.datetime.fromtimestamp(
                        attributes.get("last_analysis_date")).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("last_analysis_date") else None
                    temp_results["whois_date"] = datetime.datetime.fromtimestamp(
                        attributes.get("whois_date")).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("whois_date") else None

                    last_final_url_data = attributes.get("last_final_url_data", {})
                    if last_final_url_data:
                        resolved_ip = last_final_url_data.get("resolved_ip")
                        if resolved_ip:
                            temp_results["a_records"] = [resolved_ip]
                    if temp_results["score"] and temp_results["score"] > best_score:
                        best_score = temp_results["score"]
                        best_results = temp_results.copy()
        except Exception:
            pass  # Fail silently, proceed to /search

        # --- 2. Try /search endpoint ---
        try:
            url = f"https://www.virustotal.com/api/v3/search?query={vt_ioc}"
            response = requests.get(url, headers=headers, verify=CA_BUNDLE_PATH, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if "data" in data and data["data"]:
                    first_data_entry = data["data"][0] if isinstance(data["data"], list) else data["data"]
                    attributes = first_data_entry.get("attributes", {})
                    temp_results = vt_results.copy()
                    temp_results["link"] = first_data_entry.get("links", {}).get("self", temp_results["link"])
                    temp_results["score"] = attributes.get("last_analysis_stats", {}).get("malicious", 0)
                    temp_results["category"] = (
                        ", ".join(list(set(attributes.get("categories", {}).values())))
                        if isinstance(attributes.get("categories", {}), dict) else
                        ", ".join(list(set(attributes.get("categories", []))))
                        if isinstance(attributes.get("categories", []), list) else None
                    )
                    temp_results["last_analysis_date"] = datetime.datetime.fromtimestamp(
                        attributes.get("last_analysis_date")).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("last_analysis_date") else None
                    temp_results["whois_date"] = datetime.datetime.fromtimestamp(
                        attributes.get("whois_date")).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("whois_date") else None
                    last_final_url_data = attributes.get("last_final_url_data", {})
                    if last_final_url_data:
                        resolved_ip = last_final_url_data.get("resolved_ip")
                        if resolved_ip:
                            temp_results["a_records"] = [resolved_ip]
                    if temp_results["score"] and temp_results["score"] > best_score:
                        best_score = temp_results["score"]
                        best_results = temp_results.copy()
        except Exception:
            pass  # Fail silently

        return best_results

    # For hashes or other types, use previous logic
    elif indicator_type in ["MD5 Hash", "SHA1 Hash", "SHA256 Hash"]:
        vt_ioc = ioc
        url = f"https://www.virustotal.com/api/v3/files/{vt_ioc}"
    else:
        vt_ioc = ioc
        url = f"https://www.virustotal.com/api/v3/search?query={vt_ioc}"

    try:
        response = requests.get(url, headers=headers, verify=CA_BUNDLE_PATH, timeout=30)
    except requests.exceptions.RequestException as e:
        return vt_results

    if response.status_code == 200:
        try:
            data = response.json()
        except requests.exceptions.JSONDecodeError:
            return vt_results

        if "data" in data and data["data"]:
            first_data_entry = data["data"]
            if isinstance(first_data_entry, list):
                if not first_data_entry:
                    return vt_results
                first_data_entry = first_data_entry[0]
            attributes = first_data_entry.get("attributes", {})
            vt_results["link"] = first_data_entry.get("links", {}).get("self", vt_results["link"])
            vt_results["score"] = attributes.get("last_analysis_stats", {}).get("malicious", 0)
            categories_raw = attributes.get("categories", {})
            if isinstance(categories_raw, dict):
                vt_results["category"] = ", ".join(list(set(categories_raw.values()))) if categories_raw else None
            elif isinstance(categories_raw, list):
                vt_results["category"] = ", ".join(list(set(categories_raw))) if categories_raw else None
            else:
                vt_results["category"] = None
            if indicator_type in ["Domain", "IPv4", "IPv6"]:
                vt_results["last_analysis_date"] = datetime.datetime.fromtimestamp(
                    attributes.get("last_analysis_date")).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("last_analysis_date") else None
                vt_results["whois_date"] = datetime.datetime.fromtimestamp(
                    attributes.get("whois_date")).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("whois_date") else None
                a_records_list = [rec.get("value") for rec in attributes.get("last_dns_records", []) if rec.get("type") == "A" and rec.get("value")]
                vt_results["a_records"] = a_records_list
            elif indicator_type in ["MD5 Hash", "SHA1 Hash", "SHA256 Hash"]:
                vt_results["md5"] = attributes.get("md5")
                vt_results["sha1"] = attributes.get("sha1")
                vt_results["sha256"] = attributes.get("sha256")
                vt_results["file_size"] = attributes.get("size")
                vt_results["file_type_description"] = attributes.get("type_description")
                file_names_list = attributes.get("names", [])
                vt_results["file_names"] = ", ".join(file_names_list) if file_names_list else None
    return vt_results

def get_abuseipdb_info(ip):
    if ip in abuse_ip_cache:
        return abuse_ip_cache[ip]

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    
    print(f"  --- Fetching AbuseIPDB data for {ip} ---")
    try:
        response = requests.get(url, headers=headers, verify=CA_BUNDLE_PATH, timeout=30)
        print(f"  Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"  AbuseIPDB Request Error for {ip}: {e}")
        result = {
            "is_public": None, "link": f"https://www.abuseipdb.com/check/{ip}",
            "abuse_confidence_score": None
        }
        abuse_ip_cache[ip] = result
        return result

    abuse_results = {
        "is_public": None,
        "link": f"https://www.abuseipdb.com/check/{ip}",
        "abuse_confidence_score": None
    }

    if response.status_code == 200:
        try:
            data = response.json().get("data", {})
        except requests.exceptions.JSONDecodeError:
            print(f"  AbuseIPDB Error: Could not decode JSON for {ip}. Response: {response.text[:200]}...")
            abuse_ip_cache[ip] = abuse_results
            return abuse_results
        
        abuse_results["is_public"] = "Public" if data.get("isPublic") else "Local"
        abuse_results["abuse_confidence_score"] = data.get("abuseConfidenceScore")
    else:
        print(f"  AbuseIPDB API Error for {ip}: Status {response.status_code}. Response: {response.text[:200]}...")
    
    abuse_ip_cache[ip] = abuse_results
    return abuse_results

def get_alienvault_info(ioc): # This function expects an IP
    if ioc in alienvault_ip_cache:
        return alienvault_ip_cache[ioc]

    headers = {
        "X-OTX-API-KEY": ALIENVAULT_API_KEY
    }
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
    
    print(f"  --- Fetching AlienVault OTX data for {ioc} ---")
    try:
        response = requests.get(url, headers=headers, verify=CA_BUNDLE_PATH, timeout=30)
        print(f"  Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"  AlienVault OTX Request Error for {ioc}: {e}")
        result = {
            "pulses": None, "link": f"https://otx.alienvault.com/indicator/ip/{ioc}",
            "country": None, "city": None, "asn": None, "reputation_internal": None,
        }
        alienvault_ip_cache[ioc] = result
        return result

    alienvault_results = {
        "pulses": None,
        "link": f"https://otx.alienvault.com/indicator/ip/{ioc}",
        "country": None,
        "city": None,
        "asn": None,
        "reputation_internal": None,
    }

    if response.status_code == 200:
        try:
            data = response.json()
        except requests.exceptions.JSONDecodeError:
            print(f"  AlienVault OTX Error: Could not decode JSON for {ioc}. Response: {response.text[:200]}...")
            alienvault_ip_cache[ioc] = alienvault_results
            return alienvault_results

        pulses = [pulse["name"] for pulse in data.get("pulse_info", {}).get("pulses", [])]
        alienvault_results["pulses"] = ", ".join(pulses) if pulses else None

        alienvault_results["country"] = data.get("country_name")
        alienvault_results["city"] = data.get("city")
        alienvault_results["asn"] = data.get("asn")
        alienvault_results["reputation_internal"] = data.get("reputation") 

    else:
        print(f"  AlienVault OTX API Error for {ioc}: Status {response.status_code}. Response: {response.text[:200]}...")
    
    alienvault_ip_cache[ioc] = alienvault_results
    return alienvault_results

# ---------------------------- MAIN SCRIPT LOGIC ----------------------------
def main():
    print("[*] Starting IoC Analysis Script...")

    if len(sys.argv) < 2:
        print("Usage: python IoC_Validate.py <input_ioc_filename.txt>")
        print("Example: python IoC_Validate.py example_input.txt")
        sys.exit(1)

    input_filename = sys.argv[1] 
    
    # Use current directory instead of hardcoded path
    if not os.path.exists(input_filename):
        print(f"Error: Input file not found at {input_filename}")
        sys.exit(1)

    print(f"[*] Reading IOCs from: {input_filename}")
    try:
        with open(input_filename, "r") as f:
            iocs = [defang(line.strip()) for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)
        
    total_iocs = len(iocs)
    if total_iocs == 0:
        print("[!] No IOCs found in the input file. Exiting.")
        sys.exit(0)

    print(f"[*] Found {total_iocs} IOCs to process.")
    
    results = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        for i, ioc in enumerate(iocs):
            # Improved progress output - overwrite previous line instead of stacking
            if i > 0:
                # Clear the current line
                sys.stdout.write("\r" + " " * 80 + "\r")  # Clear line
                sys.stdout.flush()

            # Remove http(s):// from indicator names to prevent Excel hyperlinks
            display_ioc = ioc.replace("http://", "").replace("https://", "")
            print(f"[+] Processing IOC {i+1}/{total_iocs}: {display_ioc}")

            indicator_type = "Unknown"
            
            if re.match(r"^[a-fA-F0-9]{64}$", ioc):
                indicator_type = "SHA256 Hash"
            elif re.match(r"^[a-fA-F0-9]{40}$", ioc):
                indicator_type = "SHA1 Hash"
            elif re.match(r"^[a-fA-F0-9]{32}$", ioc):
                indicator_type = "MD5 Hash"
            elif re.match(r"^(http|https)://", ioc):
                indicator_type = "URL"
            elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
                indicator_type = "IPv4"
            elif ":" in ioc and re.match(r"^[0-9a-fA-F:]+$", ioc): 
                indicator_type = "IPv6"
            else: 
                indicator_type = "Domain"

            print(f"  Identified as Type: {indicator_type}")

            # --- API Calls with Delays ---
            time.sleep(VT_DELAY) # Delay BEFORE VirusTotal call
            vt_data = get_vt_info(ioc, indicator_type) # Pass indicator_type here

            abuse_data = {} 
            alienvault_data = {} 

            ip_for_main_lookup = None

            # Logic to get IP for main lookup (now more robust for URLs via VT)
            if indicator_type == "IPv4":
                ip_for_main_lookup = ioc
            elif indicator_type == "URL":
                # For URLs, try to use the resolved IP from VT's URL analysis
                if vt_data.get("a_records") and len(vt_data["a_records"]) > 0:
                    ip_for_main_lookup = vt_data["a_records"][0]
                    print(f"  URL {display_ioc} resolved by VT to IP: {ip_for_main_lookup}. Fetching main IP data.")
                else:
                    print(f"  URL {display_ioc} did not resolve to an IP via VT. Skipping AbuseIPDB/AlienVault for main URL.")
            elif indicator_type == "Domain" and vt_data.get("a_records") and len(vt_data["a_records"]) == 1:
                ip_for_main_lookup = vt_data["a_records"][0]
                print(f"  Domain {display_ioc} resolved by VT to single IP {ip_for_main_lookup}. Fetching main IP data.")

            if ip_for_main_lookup:
                abuse_future = None
                alienvault_future = None

                if ip_for_main_lookup not in abuse_ip_cache:
                    time.sleep(OTHER_API_DELAY) 
                    abuse_future = executor.submit(get_abuseipdb_info, ip_for_main_lookup)
                else:
                    abuse_data = abuse_ip_cache[ip_for_main_lookup]

                if ip_for_main_lookup not in alienvault_ip_cache:
                    alienvault_future = executor.submit(get_alienvault_info, ip_for_main_lookup)
                else:
                    alienvault_data = alienvault_ip_cache[ip_for_main_lookup]

                if abuse_future:
                    abuse_data = abuse_future.result()
                if alienvault_future:
                    alienvault_data = alienvault_future.result()
                
            # --- Handle associated IPs for Domains/URLs (for 'Associated IPs Malicious?' column) ---
            # This logic now correctly uses a_records obtained from the more specific VT URL/Domain lookup
            associated_ips = vt_data.get("a_records", [])
            associated_ips_malicious = "No"

            if associated_ips and (indicator_type == "Domain" or indicator_type == "URL"):
                associated_ip_futures = []
                for ip in associated_ips:
                    # Submit concurrent calls for each associated IP if not in cache
                    if ip not in abuse_ip_cache:
                        time.sleep(OTHER_API_DELAY) 
                        associated_ip_futures.append(executor.submit(get_abuseipdb_info, ip))
                    if ip not in alienvault_ip_cache:
                        associated_ip_futures.append(executor.submit(get_alienvault_info, ip))
                
                # Wait for all associated IP futures to complete
                for future in concurrent.futures.as_completed(associated_ip_futures):
                    try:
                        # Just retrieve results to ensure they are processed and cached
                        future.result() 
                    except Exception as exc:
                        print(f"  Generated an exception for associated IP lookup: {exc}")

                # Now, re-evaluate maliciousness for all associated IPs using the (now populated) cache
                for ip in associated_ips:
                    ip_abuse_data = abuse_ip_cache.get(ip, {}) 
                    ip_alienvault_data = alienvault_ip_cache.get(ip, {})
                    
                    ip_is_malicious = False
                    if ip_abuse_data.get("abuse_confidence_score", 0) is not None and ip_abuse_data.get("abuse_confidence_score", 0) > 0: 
                        ip_is_malicious = True
                    if ip_alienvault_data.get("reputation_internal", 0) and ip_alienvault_data["reputation_internal"] > 0:
                        ip_is_malicious = True
                    if ip_alienvault_data.get("pulses"): 
                        ip_is_malicious = True

                    if ip_is_malicious:
                        associated_ips_malicious = "Yes"
                        break 

            # Check for filename-based IOCs against VT file names
            filename_match_found = False
            if indicator_type == "Domain" and vt_data.get("file_names"):
                # Check if the IOC (domain) appears in any of the file names from VT
                file_names = vt_data.get("file_names", "")
                if display_ioc.lower() in file_names.lower():
                    filename_match_found = True
                    print(f"  Filename match found for {display_ioc} in VT file names")
                
            # --- Populate row_data dictionary ---
            row_data = {
                "Indicator": display_ioc,  # Use display_ioc without http(s)://
                "Type": indicator_type,

                "VirusTotal Score": vt_data.get("score"),
                "VirusTotal Category": vt_data.get("category"),
                "VirusTotal Link": vt_data.get("link"),
                "VT Last Analysis Date": vt_data.get("last_analysis_date"),
                "VT Whois Date": vt_data.get("whois_date"),
                
                "Associated IPs Malicious?": associated_ips_malicious,
                "Filename Match Found": "Yes" if filename_match_found else "No",

                "VT MD5": vt_data.get("md5"),
                "VT SHA1": vt_data.get("sha1"),
                "VT SHA256": vt_data.get("sha256"),
                "VT File Size": vt_data.get("file_size"),
                "VT File Type": vt_data.get("file_type_description"),
                "VT File Names": vt_data.get("file_names"),
                
                "AbuseIPDB Local/Public": abuse_data.get("is_public"),
                "AbuseIPDB Link": abuse_data.get("link"),

                "AlienVault Pulses": alienvault_data.get("pulses"),
                "AlienVault Link": alienvault_data.get("link"),
                "AlienVault Country": alienvault_data.get("country"),
                "AlienVault City": alienvault_data.get("city"),
                "AlienVault ASN": alienvault_data.get("asn"),
            }
            results.append(row_data)

            elapsed_time = time.time() - start_time
            processed_count = i + 1
            
            if processed_count > 0:
                avg_time_per_ioc = elapsed_time / processed_count
                remaining_iocs = total_iocs - processed_count
                estimated_remaining_seconds = avg_time_per_ioc * remaining_iocs
                
                minutes, seconds = divmod(int(estimated_remaining_seconds), 60)
                
                # Overwrite the previous progress line instead of creating new lines
                progress_msg = f"  Progress: {processed_count}/{total_iocs} processed. Estimated time remaining: {minutes:02d}m {seconds:02d}s"
                sys.stdout.write(f"\r{progress_msg}")
                sys.stdout.flush() 
        
    print("\n\n[*] All IoCs processed. Generating Excel report...")
    df = pd.DataFrame(results)
    
    # Use current directory instead of hardcoded path
    base_filename_without_ext = os.path.splitext(os.path.basename(input_filename))[0]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S") 
    output_base_filename = f"{base_filename_without_ext}_IoC_Validate_{timestamp}.xlsx"
    output_filename_full_path = output_base_filename

    writer = pd.ExcelWriter(output_filename_full_path, engine='xlsxwriter')
    
    df.to_excel(writer, sheet_name='IOC Report', index=False, header=False, startrow=1)

    workbook = writer.book
    worksheet = writer.sheets['IOC Report']

    header_format = workbook.add_format({
        'bold': True,
        'border': 1, 
        'align': 'center', 
        'valign': 'vcenter', 
        'fg_color': '#D7E4BC' 
    })

    column_names = df.columns.tolist()

    for col_num, value in enumerate(column_names):
        worksheet.write(0, col_num, value, header_format)
        worksheet.set_column(col_num, col_num, 30) 

    worksheet.set_default_row(15)

    writer.close()
    print(f"\n[+] Report saved to {output_filename_full_path}")
    print("[*] Script execution complete.")


if __name__ == "__main__":
    main()

