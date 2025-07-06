

import requests
import whois
import dns.resolver
import socket
import json
import sys

def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        subdomains = sorted({entry['name_value'] for entry in data})
        return list(subdomains)
    except:
        return ["Error fetching subdomains"]

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

def get_whois_info(domain):
    try:
        return str(whois.whois(domain))
    except:
        return "WHOIS fetch failed"

def get_http_headers(domain):
    try:
        response = requests.get("http://" + domain, timeout=5)
        return dict(response.headers)
    except:
        return {"Error": "Could not fetch headers"}

def get_robots_txt(domain):
    try:
        res = requests.get(f"http://{domain}/robots.txt", timeout=5)
        return res.text
    except:
        return "robots.txt not found"

def get_sitemap(domain):
    try:
        res = requests.get(f"http://{domain}/sitemap.xml", timeout=5)
        return res.text
    except:
        return "sitemap.xml not found"

def get_geoip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return res.json()
    except:
        return {"Error": "GeoIP lookup failed"}

def save_to_file(domain, data):
    with open(f"basic_{domain}.txt", "w") as f:
        json.dump(data, f, indent=2)
    print(f"\nSaved to basic_{domain}.txt")

def main():
    if len(sys.argv) < 2:
        domain = input("Enter domain name (e.g. example.com): ")
    else:
        domain = sys.argv[1]

    print(f"\n[+] Recon on: {domain}")

    report = {}
    report['Subdomains'] = get_subdomains_crtsh(domain)
    report['DNS Records'] = get_dns_records(domain)
    report['WHOIS Info'] = get_whois_info(domain)
    report['HTTP Headers'] = get_http_headers(domain)
    report['robots.txt'] = get_robots_txt(domain)
    report['sitemap.xml'] = get_sitemap(domain)
    report['GeoIP'] = get_geoip_info(domain)

    for key, val in report.items():
        print(f"\n=== {key} ===")
        if isinstance(val, (list, dict)):
            print(json.dumps(val, indent=2))
        else:
            print(val)

    save_to_file(domain, report)

if __name__ == "__main__":
    main()
