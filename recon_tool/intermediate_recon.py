import argparse
import json
import socket
import requests
import whois
import dns.resolver
import os
import subprocess
import time
import csv
from jinja2 import Environment, FileSystemLoader

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
        result = subprocess.check_output(['nmap', '-Pn', '-sV', '-T4', domain],
                                         stderr=subprocess.DEVNULL).decode()
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
        result = subprocess.check_output(['theHarvester', '-d', domain, '-b', 'bing'],
                                         stderr=subprocess.DEVNULL).decode()
        return result.strip()
    except Exception as e:
        return f"theHarvester failed: {str(e)}"

# -------- Screenshot Capture (gowitness) --------
def take_screenshots(domain, subdomains):
    print("[*] Capturing screenshots...")
    os.makedirs("reports/screenshots", exist_ok=True)
    output_paths = []

    for sub in subdomains:
        url = f"http://{sub}"
        filename = f"reports/screenshots/{sub.replace('.', '_')}_{int(time.time())}.png"
        try:
            subprocess.run(["gowitness", "single", "--url", url, "--destination", filename],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            output_paths.append(filename)
        except Exception as e:
            output_paths.append(f"{url} failed: {e}")

    return output_paths

# -------- WAF/CDN Detection (wafw00f) --------
def detect_waf(domain):
    print("[*] Running WAF/CDN detection...")
    try:
        result = subprocess.check_output(["wafw00f", domain], stderr=subprocess.DEVNULL).decode()
        return result.strip()
    except Exception as e:
        return f"WAF detection failed: {str(e)}"

# -------- Vulnerability Scan (Nikto) --------
def run_nikto_scan(domain):
    print("[*] Running Nikto scan...")
    os.makedirs("reports/vuln", exist_ok=True)
    output_file = f"reports/vuln/{domain}_nikto.txt"
    try:
        with open(output_file, "w") as f:
            subprocess.run(["nikto", "-h", domain], stdout=f, stderr=subprocess.DEVNULL)
        return f"Vuln report saved to {output_file}"
    except Exception as e:
        return f"Nikto scan failed: {str(e)}"

# -------- HTML Report Generation --------
def generate_html_report(domain, results):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report_template.html')
    output = template.render(domain=domain, results=results)
    output_path = f"reports/{domain}_report.html"
    with open(output_path, "w") as f:
        f.write(output)
    print(f"[+] HTML report saved to {output_path}")

# -------- MAIN --------
def main():
    parser = argparse.ArgumentParser(description="Level 3 Recon Toolkit")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--subdomains", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("--dns", action="store_true", help="Enable DNS record lookup")
    parser.add_argument("--whois", action="store_true", help="Enable WHOIS info fetch")
    parser.add_argument("--headers", action="store_true", help="Enable HTTP header scan")
    parser.add_argument("--geoip", action="store_true", help="Enable GeoIP lookup")
    parser.add_argument("--portscan", action="store_true", help="Enable Nmap port scan")
    parser.add_argument("--tech", action="store_true", help="Enable technology detection (WhatWeb)")
    parser.add_argument("--emails", action="store_true", help="Enable email harvesting (theHarvester)")
    parser.add_argument("--screenshots", action="store_true", help="Capture screenshots of subdomains")
    parser.add_argument("--waf", action="store_true", help="Detect WAF/CDN")
    parser.add_argument("--vulnscan", action="store_true", help="Run vulnerability scan with Nikto")
    parser.add_argument("--output", choices=["json", "csv"], default="json", help="Output format (json or csv)")
    args = parser.parse_args()

    domain = args.domain
    results = {}

    if args.subdomains:
        subdomains = get_subdomains_crtsh(domain)
        results['Subdomains'] = subdomains
        if args.screenshots:
            results['Screenshots'] = take_screenshots(domain, subdomains)

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
    if args.waf:
        results['WAF/CDN Detection'] = detect_waf(domain)
    if args.vulnscan:
        results['Vulnerability Scan'] = run_nikto_scan(domain)

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

    print(f"[+] Report saved to {output_path}")
    generate_html_report(domain, results)

if __name__ == "__main__":
    main()
