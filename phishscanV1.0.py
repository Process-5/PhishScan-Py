import requests
import re # Search for patterns (such as URLs)
import base64
from mailparser import parse_from_file # Processing mail structure

# API SETTINGS - ENTER YOUR API KEYS IN THIS SECTION
ABUSE_API_KEY = 'YOUR_ABUSEIPDB_API_KEY'#       <--CHANGE THIS
VT_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'#         <--CHANGE THIS

# Checking in AbuseIPDB if the IP is malicious
def check_ip_reputation(ip):
    # Fixed: Check for placeholder string
    if ip == "Not detected" or "YOUR_ABUSEIPDB" in ABUSE_API_KEY: return 0
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': ABUSE_API_KEY}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    try:
        response = requests.get(url, headers=headers, params=params)
        # Fixed: Corrected 'abuseConfidenceScore' spelling
        if response.status_code == 200:
            return response.json()['data']['abuseConfidenceScore']
        return 0
    except: return 0

# Checking VirusTotal if the URL is malicious
def check_url_reputation(url):
    if "YOUR_VIRUSTOTAL" in VT_API_KEY: return 0
    # VT ID encoding for URL
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        res = requests.get(api_url, headers=headers)
        if res.status_code == 200:
               return res.json()['data']['attributes']['last_analysis_stats']['malicious']
        return 0 # Returns 0 if VT has no record or URL is clean
    except: return 0
    return 0

def decode_base64_payload(payload):
    """Decode the content if it's base64 encoded"""
    try:
        return base64.b64decode(payload).decode('utf-8', errors='ignore')
    except:
        return payload

def get_source_ip(mail_obj):
    # Looking for IPs in 'received hops'
    # Fixed: Corrected spelling to 'received'
    if mail_obj.received:
        for hop in reversed(mail_obj.received):
            if hop.get('from'):
                ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', str(hop['from']))
                if ip_match: return ip_match.group(0)

    # Looking for IPs in specific headers
    headers_to_scan = ['X-Sender-IP', 'X-Originating-IP', 'Authentication-Results']
    for header in headers_to_scan:
        val = mail_obj.headers.get(header, "")
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', str(val))
        if ip_match: return ip_match.group(0)

    return "Not detected"

def analyze_phishing(eml_file):
    try:
        # 1. LOAD THE FILE
        # Load and process the .eml file
        mail = parse_from_file(eml_file)

        # 2. EXTRACT HEADERS
        # Extracting sender and subject info
        subject = mail.subject
        sender_raw = mail.from_[0][1] if mail.from_ else "Unknown"
        return_path = mail.headers.get('Return-Path', '').replace('<', '').replace('>', '')

        spoofing_alert = False
        if return_path and (sender_raw.split('@')[-1].lower() != return_path.split('@')[-1].lower()):
               spoofing_alert = True
        
        # Obtaining source server IP
        ip = get_source_ip(mail)
        ip_score = check_ip_reputation(ip)

        print(f"\n[+] SCANNING REPORT: {eml_file}")
        print(f"    --------------------------")
        print(f"    SUBJECT:   {subject}")
        print(f"    SENDER:    {sender_raw}")
        print(f"    RETURN_PATH:    {return_path}")
        print(f"    SPOOFING:  {'[!] ALERT: Domain Mismatch' if spoofing_alert else '[+] OK'}")
        # Fixed: Added missing closing parenthesis in the print below
        print(f"    SOURCE IP: {ip} (AbuseIPDB: {ip_score}/100)")

        # 3. EXTRACT BODY AND SEARCH FOR LINKS
        full_text = ""
        for part in mail.text_plain + mail.text_html:
            # If content seems to be Base64 encoded, try decoding
            if len(part) > 100 and " " not in part:
                full_text += decode_base64_payload(part)
            else:
                full_text += part

        # Regex for detecting http, https and www links
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        links = set(re.findall(url_pattern, full_text))

        # Standardized variable name
        malicious_links_count = 0
        if links:
            print(f"    LINKS DETECTED ({len(links)}):")
            for link in links:
                vt_hits = check_url_reputation(link)
                indicator = "[!]" if vt_hits > 0 else "[+]"
                print(f"    {indicator} {link} (VT Hits: {vt_hits})")
                if vt_hits > 0: malicious_links_count += 1

        # 4. FINAL VERDICT
        print(f"    ----------------------------------------------------")
        if spoofing_alert or ip_score > 50 or malicious_links_count > 0:
            print("     [!!!] FINAL VERDICT: MALICIOUS / HIGH RISK")
        else:
            print("     [+] FINAL VERDICT: CLEAN OR LOW RISK")
        print(f"     ---------------------------------------------------")

    except Exception as e:
        print(f"[!] ERROR: {e}")

# --- EXECUTION BLOCK ---
if __name__ == "__main__":
    print("=== PhishScan Tool - Helping you to determine if it is or is not malicious ===")
    file_to_analyze = input("Enter the path to the .eml file: ")
    analyze_phishing(file_to_analyze)
