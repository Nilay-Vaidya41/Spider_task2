import argparse
import json
import socket
import requests
import whois
import dns.resolver
import os
import subprocess
import csv

# -------- Subdomain Enumeration (crt.sh) --------
def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        subdomains = sorted({entry['name_value'] for entry in data})
        return list(subdomains)
    except:
        return ["Error fetching subdomains"]

# -------- DNS Lookup --------
def get_dns_records(domain):
    records = {}
    try:
        records['A'] = [ip.to_text() for ip in dns.resolver.resolve(domain, 'A')]
    except:
        records['A'] = []
    try:
        records['MX'] = [str(r.exchange) for r in dns.resolver.resolve(domain, 'MX')]
    except:
        records['MX'] = []
    try:
        records['NS'] = [str(r.target) for r in dns.resolver.resolve(domain, 'NS')]
    except:
        records['NS'] = []
    return records

# -------- WHOIS Lookup --------
def get_whois_info(domain):
    try:
        return str(whois.whois(domain))
    except:
        return "WHOIS fetch failed"

# -------- HTTP Header Grabbing --------
def get_http_headers(domain):
    try:
        response = requests.get("http://" + domain, timeout=5)
        return dict(response.headers)
    except:
        return {"Error": "Could not fetch headers"}

# -------- GeoIP Lookup --------
def get_geoip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return res.json()
    except:
        return {"Error": "GeoIP lookup failed"}

# -------- Port Scanning (Nmap) --------
def run_nmap_scan(domain):
    try:
        print("[*] Running Nmap scan...")
        result = subprocess.check_output(
            ['nmap', '-Pn', '-sV', '-T4', domain],
            stderr=subprocess.DEVNULL
        ).decode()
        return result
    except Exception as e:
        return f"Nmap scan failed: {str(e)}"

# -------- Technology Detection (WhatWeb) --------
def detect_technologies(domain):
    try:
        print("[*] Running WhatWeb...")
        result = subprocess.check_output(['whatweb', domain], stderr=subprocess.DEVNULL).decode()
        return result.strip()
    except Exception as e:
        return f"WhatWeb failed: {str(e)}"

# -------- Email Harvesting (theHarvester) --------
def harvest_emails(domain):
    try:
        print("[*] Running theHarvester...")
        result = subprocess.check_output(
            ['theHarvester', '-d', domain, '-b', 'bing'],
            stderr=subprocess.DEVNULL
        ).decode()
        return result.strip()
    except Exception as e:
        return f"theHarvester failed: {str(e)}"

# -------- MAIN --------
def main():
    parser = argparse.ArgumentParser(description="Intermediate Recon Toolkit")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--subdomains", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("--dns", action="store_true", help="Enable DNS record lookup")
    parser.add_argument("--whois", action="store_true", help="Enable WHOIS info fetch")
    parser.add_argument("--headers", action="store_true", help="Enable HTTP header scan")
    parser.add_argument("--geoip", action="store_true", help="Enable GeoIP lookup")
    parser.add_argument("--portscan", action="store_true", help="Enable Nmap port scan")
    parser.add_argument("--tech", action="store_true", help="Enable technology detection (WhatWeb)")
    parser.add_argument("--emails", action="store_true", help="Enable email harvesting (theHarvester)")
    parser.add_argument("--output", choices=["json", "csv"], default="json", help="Output format (json or csv)")
    args = parser.parse_args()

    domain = args.domain
    results = {}

    if args.subdomains:
        results['Subdomains'] = get_subdomains_crtsh(domain)
    if args.dns:
        results['DNS Records'] = get_dns_records(domain)
    if args.whois:
        results['WHOIS Info'] = get_whois_info(domain)
    if args.headers:
        results['HTTP Headers'] = get_http_headers(domain)
    if args.geoip:
        results['GeoIP Info'] = get_geoip_info(domain)
    if args.portscan:
        results['Port Scan'] = run_nmap_scan(domain)
    if args.tech:
        results['Technology Detection'] = detect_technologies(domain)
    if args.emails:
        results['Email Harvesting'] = harvest_emails(domain)

    # Save report
    os.makedirs("reports", exist_ok=True)
    output_path = f"reports/{domain}_report.{args.output}"

    if args.output == "json":
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
    else:
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            for key, val in results.items():
                writer.writerow([key, json.dumps(val)])

    print(f"\n[+] Report saved to {output_path}")

if __name__ == "__main__":
    main()
