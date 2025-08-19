import requests
import pandas as pd
import re
import time
import datetime
import os
import sys
import concurrent.futures
import base64 # Import for Base64 encoding
import urllib.parse # Import for URL encoding

# Load environment from config file if it exists
def load_config():
    """Load configuration from config.env file if it exists"""
    config_file = os.path.join(os.path.dirname(__file__), 'config.env')
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value

# Load configuration
load_config()

# Compile regex patterns for better performance
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
URL_PATTERN = re.compile(r"^(http|https)://")
IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
IPV6_PATTERN = re.compile(r"^[0-9a-fA-F:]+$")

# --- CONFIGURATION ---

CA_BUNDLE_PATH = os.getenv("CA_BUNDLE_PATH", True)  # Default to system CA bundle

# ---------------------------- API KEYS ----------------------------

VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "YOUR_ABUSEIPDB_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "YOUR_ALIENVAULT_API_KEY")

# --- API Rate Limit Delays (in seconds) ---
VT_DELAY = float(os.getenv("VT_DELAY", "15"))  # VirusTotal rate limit
OTHER_API_DELAY = float(os.getenv("OTHER_API_DELAY", "0.5"))  # Other APIs rate limit

# Control debug output (can be disabled for performance)
DEBUG_OUTPUT = os.getenv("DEBUG_OUTPUT", "false").lower() == "true"

def debug_print(message):
    """Print debug messages only if debug output is enabled"""
    if DEBUG_OUTPUT:
        print(message)

# Rate limiting tracking
last_vt_call = 0
last_other_call = 0

def wait_for_rate_limit(api_type="other"):
    """Smart rate limiting that only waits when necessary"""
    global last_vt_call, last_other_call
    
    current_time = time.time()
    
    if api_type == "vt":
        time_since_last = current_time - last_vt_call
        if time_since_last < VT_DELAY:
            sleep_time = VT_DELAY - time_since_last
            debug_print(f"  Rate limiting: waiting {sleep_time:.1f}s for VirusTotal...")
            time.sleep(sleep_time)
        last_vt_call = time.time()
    else:
        time_since_last = current_time - last_other_call
        if time_since_last < OTHER_API_DELAY:
            sleep_time = OTHER_API_DELAY - time_since_last
            time.sleep(sleep_time)
        last_other_call = time.time()

# --- Caches for API results to avoid redundant calls ---
abuse_ip_cache = {}
alienvault_ip_cache = {}

# Cache size limits to prevent memory issues
MAX_CACHE_SIZE = 10000

# Control batch processing for large datasets
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))  # Process in batches to manage memory

def validate_api_keys():
    """Validate that API keys are configured"""
    missing_keys = []
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        missing_keys.append("VT_API_KEY")
    if ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY":
        missing_keys.append("ABUSEIPDB_API_KEY") 
    if ALIENVAULT_API_KEY == "YOUR_ALIENVAULT_API_KEY":
        missing_keys.append("ALIENVAULT_API_KEY")
    
    if missing_keys:
        print(f"[!] Warning: The following API keys are not configured: {', '.join(missing_keys)}")
        print("    Set them as environment variables or edit the script directly")
        print("    Example: export VT_API_KEY='your_actual_key'")
        return False
    return True

def manage_cache_size(cache_dict):
    """Remove oldest entries if cache exceeds max size"""
    if len(cache_dict) > MAX_CACHE_SIZE:
        # Remove oldest entries (simple FIFO approach)
        items_to_remove = len(cache_dict) - MAX_CACHE_SIZE + 1000  # Remove extra to avoid frequent cleanup
        for _ in range(items_to_remove):
            cache_dict.pop(next(iter(cache_dict)), None)

# ---------------------------- HELPER FUNCTIONS ----------------------------

def validate_ioc(ioc):
    """Basic validation of IoC format"""
    if not ioc or len(ioc.strip()) == 0:
        return False
    
    # Check for obviously malformed inputs
    if len(ioc) > 2048:  # Reasonable max length
        return False
        
    # Check for potential injection attempts (basic)
    dangerous_chars = ["<", ">", "\"", "'", "&", ";", "|"]
    if any(char in ioc for char in dangerous_chars):
        return False
        
    return True

def defang(ioc):
    ioc = ioc.replace("[.]", ".").replace("[:]", ":").replace("hxxp", "http").replace("hxxps", "https")
    return ioc.strip()

def process_ioc_batch(iocs_batch, start_index, total_iocs, executor, start_time, clear_console=True):
    """Process a batch of IoCs and return results"""
    batch_results = []
    
    for i, ioc in enumerate(iocs_batch):
        current_index = start_index + i
        
        # Clear console for progress display (optional)
        if current_index > 0 and clear_console:
            try:
                num_lines_to_clear_above = 6 
                for _ in range(num_lines_to_clear_above):
                    sys.stdout.write("\033[F\033[K") 
                sys.stdout.flush()
            except:
                pass

        print(f"\n[+] Processing IoC {current_index+1}/{total_iocs}: {ioc}")

        indicator_type = "Unknown"
        
        if SHA256_PATTERN.match(ioc):
            indicator_type = "SHA256 Hash"
        elif SHA1_PATTERN.match(ioc):
            indicator_type = "SHA1 Hash"
        elif MD5_PATTERN.match(ioc):
            indicator_type = "MD5 Hash"
        elif URL_PATTERN.match(ioc):
            indicator_type = "URL"
        elif IPV4_PATTERN.match(ioc):
            indicator_type = "IPv4"
        elif ":" in ioc and IPV6_PATTERN.match(ioc): 
            indicator_type = "IPv6"
        else: 
            indicator_type = "Domain"

        print(f"  Identified as Type: {indicator_type}")

        # --- API Calls with Smart Rate Limiting ---
        wait_for_rate_limit("vt")
        vt_data = get_vt_info(ioc, indicator_type)

        abuse_data = {} 
        alienvault_data = {} 
        ip_for_main_lookup = None

        # Logic to get IP for main lookup
        if indicator_type == "IPv4":
            ip_for_main_lookup = ioc
        elif indicator_type == "URL":
            if vt_data.get("a_records") and len(vt_data["a_records"]) > 0:
                ip_for_main_lookup = vt_data["a_records"][0]
                debug_print(f"  URL {ioc} resolved by VT to IP: {ip_for_main_lookup}. Fetching main IP data.")
            else:
                debug_print(f"  URL {ioc} did not resolve to an IP via VT. Skipping AbuseIPDB/AlienVault for main URL.")
        elif indicator_type == "Domain" and vt_data.get("a_records") and len(vt_data["a_records"]) == 1:
            ip_for_main_lookup = vt_data["a_records"][0]
            debug_print(f"  Domain {ioc} resolved by VT to single IP {ip_for_main_lookup}. Fetching main IP data.")

        if ip_for_main_lookup:
            abuse_future = None
            alienvault_future = None

            if ip_for_main_lookup not in abuse_ip_cache:
                wait_for_rate_limit("other")
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
            
        # --- Handle associated IPs for Domains/URLs ---
        associated_ips = vt_data.get("a_records", [])
        associated_ips_malicious = "No"

        if associated_ips and (indicator_type == "Domain" or indicator_type == "URL"):
            associated_ip_futures = []
            for ip in associated_ips:
                if ip not in abuse_ip_cache:
                    wait_for_rate_limit("other")
                    associated_ip_futures.append(executor.submit(get_abuseipdb_info, ip))
                if ip not in alienvault_ip_cache:
                    associated_ip_futures.append(executor.submit(get_alienvault_info, ip))
            
            # Wait for all associated IP futures to complete
            for future in concurrent.futures.as_completed(associated_ip_futures):
                try:
                    future.result() 
                except Exception as exc:
                    debug_print(f"  Generated an exception for associated IP lookup: {exc}")

            # Re-evaluate maliciousness for all associated IPs
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
            
        # --- Populate row_data dictionary ---
        row_data = {
            "Indicator": ioc,
            "Type": indicator_type,
            "VirusTotal Score": vt_data.get("score"),
            "VirusTotal Category": vt_data.get("category"),
            "VirusTotal Link": vt_data.get("link"),
            "VT Last Analysis Date": vt_data.get("last_analysis_date"),
            "VT Whois Date": vt_data.get("whois_date"),
            "Associated IPs Malicious?": associated_ips_malicious,
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
        batch_results.append(row_data)

        # Update progress
        elapsed_time = time.time() - start_time
        processed_count = current_index + 1
        
        if processed_count > 0:
            avg_time_per_ioc = elapsed_time / processed_count
            remaining_iocs = total_iocs - processed_count
            estimated_remaining_seconds = avg_time_per_ioc * remaining_iocs
            
            minutes, seconds = divmod(int(estimated_remaining_seconds), 60)
            
            sys.stdout.write(f"\r  Progress: {processed_count}/{total_iocs} processed. Estimated time remaining: {minutes:02d}m {seconds:02d}s")
            sys.stdout.flush()
    
    return batch_results

def get_vt_info(ioc, indicator_type): # Added indicator_type as argument
    headers = {"x-apikey": VT_API_KEY}
    
    # Determine the correct VirusTotal endpoint based on indicator type
    if indicator_type == "URL":
        # VirusTotal's /urls endpoint requires the URL to be Base64-encoded (URL-safe)
        # and then URL-encoded to be part of the path.
        # First, ensure the URL is properly URL-encoded before Base64.
        encoded_url_for_b64 = urllib.parse.quote_plus(ioc)
        url_id = base64.urlsafe_b64encode(encoded_url_for_b64.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif indicator_type in ["MD5 Hash", "SHA1 Hash", "SHA256 Hash"]:
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else: # Default to /search for Domains and IPs, or unknown types
        url = f"https://www.virustotal.com/api/v3/search?query={ioc}"

    try:
        response = requests.get(url, headers=headers, verify=CA_BUNDLE_PATH, timeout=30)
    except requests.exceptions.RequestException as e:
        print(f"  VirusTotal Request Error for {ioc}: {e}")
        return {
            "score": None, "category": None, "link": f"https://www.virustotal.com/gui/search/{ioc}",
            "last_analysis_date": None, "whois_date": None, "a_records": [], 
            "md5": None, "sha1": None, "sha256": None, "file_size": None, 
            "file_type_description": None, "file_names": None,
        }

    vt_results = {
        "score": None,
        "category": None,
        "link": f"https://www.virustotal.com/gui/search/{ioc}", # Default link, might be updated below
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

    if response.status_code == 200:
        try:
            data = response.json()
            # print(f"  VT Raw JSON Data: {data}") # Temporarily uncomment for debugging
        except requests.exceptions.JSONDecodeError:
            print(f"  VirusTotal Error: Could not decode JSON for {ioc}. Response: {response.text[:200]}...")
            return vt_results
        
        if "data" in data and data["data"]:
            first_data_entry = data["data"]
            # For /urls and /files, 'data' is usually a single object, not a list.
            # For /search, 'data' is a list. We need to handle both.
            if isinstance(first_data_entry, list):
                if not first_data_entry: # Handle empty list from /search
                    print(f"  VT Data list is empty for {ioc}")
                    return vt_results
                first_data_entry = first_data_entry[0] # Take the first result from search

            attributes = first_data_entry.get("attributes", {})
            
            # Update the link to be more specific if available
            vt_results["link"] = first_data_entry.get("links", {}).get("self", vt_results["link"])

            vt_results["score"] = attributes.get("last_analysis_stats", {}).get("malicious", 0)
            
            categories_raw = attributes.get("categories", {})
            if isinstance(categories_raw, dict):
                 vt_results["category"] = ", ".join(list(set(categories_raw.values()))) if categories_raw else None
            elif isinstance(categories_raw, list):
                 vt_results["category"] = ", ".join(list(set(categories_raw))) if categories_raw else None
            else:
                 vt_results["category"] = None
            
            # Extracting specific fields for domain/URL/IP
            # Note: For URL analysis, 'last_dns_records' is often under 'last_final_url_filescan' or similar,
            # or requires a separate lookup on the resolved domain/IP.
            # We'll try to get A records from 'last_dns_records' if available.
            if indicator_type in ["Domain", "IPv4", "IPv6"]: # These types use /search or /ip_addresses
                vt_results["last_analysis_date"] = datetime.datetime.fromtimestamp(attributes.get("last_analysis_date")).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("last_analysis_date") else None
                vt_results["whois_date"] = datetime.datetime.fromtimestamp(attributes.get("whois_date")).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("whois_date") else None
                a_records_list = [rec.get("value") for rec in attributes.get("last_dns_records", []) if rec.get("type") == "A" and rec.get("value")]
                vt_results["a_records"] = a_records_list
            elif indicator_type == "URL": # For URLs, A records are found differently if at all
                # Attempt to get A records from the final URL's associated IP, if VT provides it
                # This is a common pattern in VT URL analysis results
                last_final_url_data = attributes.get("last_final_url_data", {})
                if last_final_url_data:
                    # If the final URL resolved to an IP, we can use that for A records
                    resolved_ip = last_final_url_data.get("resolved_ip")
                    if resolved_ip:
                        vt_results["a_records"] = [resolved_ip]
                        print(f"  VT URL resolved to IP: {resolved_ip}")
                
                # Also check for 'last_analysis_date' and 'whois_date' if available for URLs
                vt_results["last_analysis_date"] = datetime.datetime.fromtimestamp(attributes.get("last_analysis_date")).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("last_analysis_date") else None
                vt_results["whois_date"] = datetime.datetime.fromtimestamp(attributes.get("whois_date")).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("whois_date") else None
            
            elif indicator_type in ["MD5 Hash", "SHA1 Hash", "SHA256 Hash"]:
                vt_results["md5"] = attributes.get("md5")
                vt_results["sha1"] = attributes.get("sha1")
                vt_results["sha256"] = attributes.get("sha256")
                vt_results["file_size"] = attributes.get("size")
                vt_results["file_type_description"] = attributes.get("type_description")
                
                file_names_list = attributes.get("names", [])
                vt_results["file_names"] = ", ".join(file_names_list) if file_names_list else None
        else:
            print(f"  VT Data not found in 'data' field for {ioc}")
    else:
        print(f"  VirusTotal API Error for {ioc}: Status {response.status_code}. Response: {response.text[:200]}...")
    
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
    manage_cache_size(abuse_ip_cache)
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
    manage_cache_size(alienvault_ip_cache)
    return alienvault_results

# ---------------------------- MAIN SCRIPT LOGIC ----------------------------
def main():
    print("[*] Starting IoC Analysis Script...")
    
    # Validate API keys are configured
    if not validate_api_keys():
        print("[*] Continuing with limited functionality...")

    if len(sys.argv) < 2:
        print("Usage: python IoC_Validate.py <input_ioc_filename>")
        print("Example: python IoC_Validate.py IoCs.txt")
        sys.exit(1)

    input_filename = sys.argv[1] 
    
    # Use current directory if absolute path not provided
    if os.path.isabs(input_filename):
        ioc_file_path = input_filename
    else:
        ioc_file_path = os.path.join(os.getcwd(), input_filename)

    if not os.path.exists(ioc_file_path):
        print(f"Error: Input file not found at {ioc_file_path}")
        sys.exit(1)

    print(f"[*] Reading IOCs from: {ioc_file_path}")
    try:
        with open(ioc_file_path, "r", encoding='utf-8') as f:
            raw_iocs = [line.strip() for line in f if line.strip()]
            
        # Validate and defang IoCs
        iocs = []
        invalid_count = 0
        for raw_ioc in raw_iocs:
            if validate_ioc(raw_ioc):
                iocs.append(defang(raw_ioc))
            else:
                invalid_count += 1
                print(f"[!] Skipping invalid IoC: {raw_ioc[:50]}...")
                
        if invalid_count > 0:
            print(f"[!] Skipped {invalid_count} invalid IoCs")
            
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)
        
    total_iocs = len(iocs)
    if total_iocs == 0:
        print("[!] No IOCs found in the input file. Exiting.")
        sys.exit(0)

    print(f"[*] Found {total_iocs} IOCs to process.")
    
    # Control console output clearing (can be disabled on incompatible systems)
    CLEAR_CONSOLE = os.getenv("CLEAR_CONSOLE", "true").lower() == "true"
    
    results = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        # Process IoCs in batches for better memory management
        for batch_start in range(0, total_iocs, BATCH_SIZE):
            batch_end = min(batch_start + BATCH_SIZE, total_iocs)
            iocs_batch = iocs[batch_start:batch_end]
            
            print(f"\n[*] Processing batch {batch_start//BATCH_SIZE + 1} ({batch_start+1}-{batch_end} of {total_iocs})")
            
            batch_results = process_ioc_batch(iocs_batch, batch_start, total_iocs, executor, start_time, CLEAR_CONSOLE)
            results.extend(batch_results)
            
            # Clean up memory periodically
            if len(results) > BATCH_SIZE * 2:
                # Write partial results and clear memory for very large datasets
                if total_iocs > BATCH_SIZE * 5:  # Only for very large datasets
                    print(f"\n[*] Writing partial results to manage memory...")
                    # TODO: Implement streaming write for extremely large datasets
                    # For now, we keep all results in memory
        
    print("\n\n[*] All IoCs processed. Generating Excel report...")
    df = pd.DataFrame(results)
    
    # Generate output in same directory as input file or current directory
    input_dir = os.path.dirname(ioc_file_path) if os.path.dirname(ioc_file_path) else os.getcwd()
    
    base_filename_without_ext = os.path.splitext(os.path.basename(input_filename))[0]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S") 
    output_base_filename = f"{base_filename_without_ext}_IoC_Validate_{timestamp}.xlsx"
    output_filename_full_path = os.path.join(input_dir, output_base_filename)

    os.makedirs(input_dir, exist_ok=True)

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

