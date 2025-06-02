# SmartScan

> **SmartScan**
> Automated Port Scanner for Pentesters and Sysadmins —
> CVE, Geolocation & Security Recommendations, all in one CLI tool!

---

Overview

**SmartScan** is a fast, flexible port scanner for Linux/Windows/macOS. 
It helps you discover open ports, get security risk assessment, and even find known vulnerabilities (CVEs) for common services.
SmartScan also gives you GeoIP info about your target with a link to Google Maps, plus clear, actionable security recommendations.

---

 Features

- **Fast multi-threaded port scanning** (TCP/UDP)
- **Security risk scoring & recommendations** for each service
- **CVE lookup** for each open port/service (offline + optional online mode)
- **GeoIP information** (Country, City, ISP, Google Maps link)
- **Clean CLI table output** (for reports or presentations)
- **Export results** as JSON

---

Usage

```bash
python3 smartscan.py --target example.com --ports 20-100 --proto both --cve-mode offline


Options:

    --target : Target IP address or domain

    --ports : Ports range (e.g., 1-1024, default: 1-1024)

    --proto : Protocol: tcp, udp, or both (default: tcp)

    --threads : Number of threads (default: 100)

    --cve-mode : CVE lookup: offline (default) or online (NVD API)

    --api-key : NVD API Key (for online CVE lookup, Get API Key)

    -o, --output : Save results as JSON file



python3 smartscan.py --target must.edu.eg --ports 20-200 --proto both --cve-mode online --api-key <YOUR_NVD_API_KEY>


CVE Online Lookup

    For live CVE info, register your free API key at:
    NVD Developer Portal

    Add --cve-mode online --api-key YOUR_KEY to your command.


Contributions

Pull requests and issues are welcome!
Have an idea or feature request? Open an issue or fork and submit a PR


Disclaimer

This tool is for educational and authorized security testing only.
Do NOT scan targets without permission


💻 Author
    0xNEMESISx0
