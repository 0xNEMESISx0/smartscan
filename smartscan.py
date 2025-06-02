#!/usr/bin/env python3
import socket
import argparse
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---- IP INFO ----
def get_ipinfo(target):
    try:
        ip = socket.gethostbyname(target)
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            org = data.get('org','')
            print("\n[+] IP Information:")
            print(f"  IP: {data.get('ip','')}")
            print(f"  Country: {data.get('country','')}")
            print(f"  Region: {data.get('region','')}")
            print(f"  City: {data.get('city','')}")
            print(f"  Org: {org}")
            if "asn" in data:
                print(f"  ASN: {data['asn'].get('asn','')} ({data['asn'].get('name','')})")
            if "loc" in data:
                latlng = data["loc"]
                print(f"  Location: {latlng}")
                print(f"  Google Maps: https://www.google.com/maps?q={latlng}")
            # تخمين نوع الاتصال
            if org and any(x in org.lower() for x in ["google", "amazon", "ovh", "digitalocean", "cloud", "azure"]):
                print("  [!] Target seems to be hosted in a public cloud/datacenter.")
            elif org and any(x in org.lower() for x in ["telecom", "vodafone", "etisalat", "isp", "we data"]):
                print("  [!] Target seems to be a home/ISP connection.")
            elif org and any(x in org.lower() for x in ["university", "edu", "college"]):
                print("  [!] Target seems to be an educational institution.")
            elif org and any(x in org.lower() for x in ["gov", "ministry"]):
                print("  [!] Target seems to be a governmental entity.")
        else:
            print("[!] Could not retrieve IP info.")
    except Exception as e:
        print(f"[!] Error getting IP info: {e}")

# ---- USAGE & RISKS ----
def usage_and_risks(port):
    known_ports = {
        21: ("FTP (File Transfer)", "Plaintext, sniffing risk"),
        22: ("SSH (Remote Access)", "Brute-force target"),
        23: ("Telnet (Remote Access)", "Plaintext, very insecure"),
        25: ("SMTP (Email)", "Spam/relay abuse"),
        53: ("DNS (Domain)", "Amplification attack risk"),
        80: ("HTTP (Web)", "Sniffing, MITM, injection"),
        443: ("HTTPS (Web - Encrypted)", "Outdated TLS/cert issues"),
        3306: ("MySQL (DB)", "Exposure, data leak risk"),
        3389: ("RDP (Remote Desktop)", "Brute-force, remote attacks"),
        179: ("BGP (Routing)", "Route hijack risk"),
        8080: ("HTTP-ALT", "Sniffing, MITM, injection"),
        8443: ("HTTPS-ALT", "Outdated TLS/cert issues"),
    }
    usage, risks = known_ports.get(port, ("Unknown", "Unknown"))
    return usage, risks

def recommendations(port):
    recs = {
        21: "Use SFTP/FTPS; restrict access",
        22: "Keys & 2FA; restrict IPs",
        23: "Disable Telnet, use SSH",
        25: "Auth+TLS; restrict relay",
        53: "No public recursion; rate limit",
        80: "Switch to HTTPS",
        443: "Use TLS 1.2+; renew certs",
        3306: "Internal only; strong creds",
        3389: "VPN/NLA; strong passwords",
        179: "Trusted peers only; MD5 auth",
        8080: "Switch to HTTPS; Auth; firewall",
        8443: "Use TLS 1.2+; renew certs"
    }
    return recs.get(port, "Monitor and restrict access")

def local_cve_list(service_name):
    cve_db = {
        "ssh": [
            "CVE-2018-15473 - User enumeration in OpenSSH",
            "CVE-2016-0777 - Info leak via roaming feature",
            "CVE-2023-48795 - Terrapin (SSH protocol downgrade)"
        ],
        "http": [
            "CVE-2021-41773 - Apache HTTP Server path traversal",
            "CVE-2017-5638 - Apache Struts2 remote code exec"
        ],
        "ftp": [
            "CVE-2015-3306 - VSFTPD backdoor",
            "CVE-1999-0519 - Anonymous FTP enabled"
        ],
        "smtp": [
            "CVE-2009-3560 - Exim remote code exec",
            "CVE-2019-15846 - Exim remote command exec"
        ],
        "dns": [
            "CVE-2020-8616 - BIND DoS large TCP responses",
            "CVE-2008-1447 - DNS cache poisoning (Kaminsky)"
        ],
        "https": [
            "CVE-2014-0160 - OpenSSL Heartbleed",
            "CVE-2021-3449 - OpenSSL DoS"
        ],
        "mysql": [
            "CVE-2012-2122 - MySQL auth bypass",
            "CVE-2016-6662 - MySQL remote root code exec"
        ],
        "rdp": [
            "CVE-2019-0708 - BlueKeep (RDP RCE)",
            "CVE-2012-0002 - RDP DoS"
        ],
        "telnet": [
            "CVE-2016-0772 - Telnet info disclosure"
        ],
        "bgp": [
            "CVE-2020-8595 - Quagga BGPd DoS"
        ]
    }
    return cve_db.get(service_name, [])

def online_cve_search(service_name, max_results=3, api_key=None):
    headers = {"User-Agent": "Mozilla/5.0"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service_name}&resultsPerPage={max_results}"
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            cves = []
            for item in data.get("result", {}).get("CVE_Items", []):
                cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "N/A")
                desc = item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "")
                cves.append(f"{cve_id} - {desc[:80]}...")
            return cves if cves else ["No CVEs found."]
        elif resp.status_code == 403:
            search_url = f"https://nvd.nist.gov/vuln/search/results?query={service_name}"
            return [f"[403 Forbidden: Use API Key or search manually]", f"Search: {search_url}"]
        else:
            return [f"[API ERROR] Status: {resp.status_code}"]
    except Exception as e:
        return [f"[Error]: {e}"]

service_lookup = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    443: "https",
    3306: "mysql",
    3389: "rdp",
    179: "bgp",
    8080: "http",
    8443: "https"
}

def scan_tcp(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        s.close()
        if result == 0:
            usage, risks = usage_and_risks(port)
            return {
                "port": port,
                "protocol": "TCP",
                "status": "open",
                "usage": usage,
                "risks": risks,
                "recommendation": recommendations(port)
            }
    except:
        pass
    return None

def scan_udp(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b'\x00', (target, port))
        data, _ = s.recvfrom(1024)
        s.close()
        usage, risks = usage_and_risks(port)
        return {
            "port": port,
            "protocol": "UDP",
            "status": "open (maybe filtered)",
            "usage": usage,
            "risks": risks,
            "recommendation": recommendations(port)
        }
    except:
        pass
    return None

def main():
    print("🚩 Tip: For live CVE search, register for a free API Key at https://nvd.nist.gov/developers/request-an-api-key and run with --cve-mode online --api-key YOUR_KEY\n")
    parser = argparse.ArgumentParser(description="Smart Port Scanner (No Server Info)")
    parser.add_argument("--target", required=True, help="Target IP or domain")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports range (e.g., 20-1000)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--proto", choices=["tcp", "udp", "both"], default="tcp", help="Protocol: tcp, udp, or both")
    parser.add_argument("--cve-mode", choices=["offline", "online"], default="offline", help="CVE search mode")
    parser.add_argument("--api-key", help="NVD API Key (optional)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    
    args = parser.parse_args()
    target = args.target
    start_port, end_port = map(int, args.ports.split("-"))
    open_ports = []

    # Geolocation
    get_ipinfo(target)
    
    # Scan Ports
    print(f"\n[+] Starting scan on {target} | Ports: {start_port}-{end_port} | Threads: {args.threads} | Protocol: {args.proto.upper()}")
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for port in range(start_port, end_port+1):
            if args.proto in ("tcp", "both"):
                futures.append(executor.submit(scan_tcp, target, port))
            if args.proto in ("udp", "both"):
                futures.append(executor.submit(scan_udp, target, port))
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    # Add CVEs
    print(f"\n[+] Adding CVEs ({args.cve_mode})...")
    for r in open_ports:
        service = service_lookup.get(r["port"])
        if service:
            if args.cve_mode == "offline":
                r["cves"] = local_cve_list(service)
            else:
                r["cves"] = online_cve_search(service, api_key=args.api_key)
        else:
            r["cves"] = []

    # فلترة البورتات المهمة فقط
    filtered_ports = [r for r in open_ports if r["usage"] != "Unknown"]

    # عرض النتائج في جدول
    if filtered_ports:
        table = [[
            r["port"],
            r["protocol"],
            r["status"],
            r["usage"],
            r["risks"],
            r["recommendation"],
            "\n".join(r.get("cves", []))
        ] for r in filtered_ports]
        
        headers = ["Port", "Proto", "Status", "Usage", "Risk", "Recommendation", "CVE(s)"]
        print("\n[+] Scan Results (Well-known ports only):")
        print(tabulate(table, headers=headers, tablefmt="grid"))
    else:
        print("\n[-] No important (well-known) open ports found.")

    # Export JSON if needed
    if args.output:
        with open(args.output, "w") as f:
            json.dump(filtered_ports, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")

    print("\n[+] Scan completed.\n")

if __name__ == "__main__":
    main()
