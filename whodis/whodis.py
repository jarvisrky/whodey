###For research and educational purposes only. Malicious behavior is strictly forbidden. Be a good person and enjoy.

import socket
import ipaddress
from urllib.parse import urlparse
import requests
from loadscreen.py import print_art



 
RDAP_URL = "https://rdap.org"
OSV_URL = "https://api.osv.dev/v1/vulns"
DOH_URL = "https://dns.google/resolve"
TIMEOUT = 10
MAX_CVES = 5            # User can change number of CVES, 5 is max by default




# Common Vulnerable Ports w/functions
RISKY_PORTS = {
    17:    "QOTD - legacy service, can be abused for DDoS amplification",
    21:    "FTP - often allows anonymous login; sends passwords in plain text",
    23:    "Telnet - unencrypted remote shell",
    104:   "DICOM - medical imaging systems",
    161:   "SNMP - can leak device and network info",
    445:   "SMB - Windows file shares; frequent ransomware entry point",
    623:   "Intel AMT / IPMI - out-of-band hardware management",
    1604:  "Citrix - remote application access",
    2375:  "Docker API (no TLS) - can give full control of the host",
    3389:  "RDP - Windows Remote Desktop; common brute-force target",
    5555:  "Android Debug Bridge - remote shell on Android devices",
    5900:  "VNC - remote desktop, sometimes with no password",
    9000:  "Buffalo TeraStation and other NAS web panels",
    10001: "Gas station tank gauge / serial-to-IP controllers",
    16992: "Intel AMT web interface",
    27017: "MongoDB - databases often exposed without authentication",
    30718: "Lantronix device servers - can leak configs/passwords",
    32400: "Plex media server",
}
 
# Response headers that fingerprint specific software
FINGERPRINT_HEADERS = {
    "X-Jenkins": "Jenkins CI server",
    "X-AspNet-Version": "ASP.NET (version disclosed)",
    "X-owa-version": "Microsoft Exchange Outlook Web Access",
    "X-MS-Server-Fqdn": "Microsoft Lync / Skype for Business",
    "Docker-Distribution-Api-Version": "Docker registry",
    "X-Plex-Protocol": "Plex media server",
}
 
 
#Helper function 
def rdap_entity_name(entities, role):
    """Find the name (vCard 'fn') of the first RDAP entity with the given role."""
    for ent in entities or []:
        if role in ent.get("roles", []):
            vcard = ent.get("vcardArray", [None, []])[1]
            for field in vcard:
                if field[0] == "fn":
                    return field[3]
        nested = rdap_entity_name(ent.get("entities"), role)
        if nested:
            return nested
    return None
 
 
def whois_domain(host):
    """RDAP lookup for the registered domain (tries example.com, then sub.example.com, ...).
    Returns (report lines, registered domain)."""
    labels = host.split(".")
    fallback = ".".join(labels[-2:])
    for i in range(len(labels) - 2, -1, -1):
        domain = ".".join(labels[i:])
        try:
            r = requests.get(f"{RDAP_URL}/domain/{domain}", timeout=TIMEOUT)
        except requests.exceptions.RequestException:
            return ["  WHOIS lookup failed (timeout or connection error)."], fallback
        if r.status_code == 200:
            data = r.json()
            events = {e.get("eventAction"): e.get("eventDate", "")[:10]
                      for e in data.get("events", [])}
            nameservers = [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])]
            return [
                f"  Domain:       {domain}",
                f"  Registrar:    {rdap_entity_name(data.get('entities'), 'registrar') or 'N/A'}",
                f"  Registered:   {events.get('registration', 'N/A')}",
                f"  Expires:      {events.get('expiration', 'N/A')}",
                f"  Nameservers:  {', '.join(nameservers) or 'N/A'}",
            ], domain
    return [f"  No WHOIS/RDAP record found for {host}."], fallback
 
     ###Looks up DNS records via DNS-over-HTTPS JSON API.
    ## Returns list of record strings, or None as applicable"""

def dns_records(name, record_type):

    try:
        r = requests.get(DOH_URL, params={"name": name, "type": record_type}, timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        return None
    if r.status_code != 200:
        return None
    records = []
    for answer in r.json().get("Answer", []):
        # TXT data arrives quoted and sometimes split into chunks: "v=spf1 " "include:..."
        records.append(answer.get("data", "").replace('" "', "").strip('"'))
    return records
 

def parse_tags(record):
    """Turn 'v=DMARC1; p=reject; pct=100' into {'v': 'DMARC1', 'p': 'reject', 'pct': '100'}."""
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags
 
 
def email_spoof_check(domain):
    """Check MX, SPF and DMARC for email security."""
    lines = [f"  Domain:       {domain}"]
 
    mx = dns_records(domain, "MX")
    txt = dns_records(domain, "TXT")
    dmarc_txt = dns_records(f"_dmarc.{domain}", "TXT")
    if mx is None or txt is None or dmarc_txt is None:
        return lines + ["  DNS-over-HTTPS lookup failed (timeout or connection error)."]
 
    lines.append(f"  Mail servers: {list_or_none(sorted(m.split()[-1].rstrip('.') for m in mx if m))}")
 
    # SPF: which servers may send mail for this domain, and what happens to the rest
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        spf_rating = "MISSING - no list of allowed senders"
        lines.append("  SPF record:   none")
    else:
        record = spf[0]
        lines.append(f"  SPF record:   {record[:90]}{'...' if len(record) > 90 else ''}")
        if record.endswith("-all"):
            spf_rating = "strict (-all): unlisted senders should be rejected"
        elif record.endswith("~all"):
            spf_rating = "soft (~all): unlisted senders are only marked suspicious"
        else:
            spf_rating = "WEAK (?all / +all / no 'all'): unlisted senders are not blocked"
        if len(spf) > 1:
            spf_rating += "  [multiple SPF records - invalid config]"
    lines.append(f"  SPF verdict:  {spf_rating}")
 
    # DMARC: what rx should do with mail that fails SPF/DKIM checks
    dmarc = [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        policy, pct = None, 100
        lines.append("  DMARC record: none")
    else:
        tags = parse_tags(dmarc[0])
        policy = tags.get("p", "none").lower()
        pct = int(tags.get("pct", "100")) if tags.get("pct", "100").isdigit() else 100
        lines.append(f"  DMARC record: {dmarc[0][:90]}{'...' if len(dmarc[0]) > 90 else ''}")
        lines.append(f"  DMARC policy: p={policy}, subdomains sp={tags.get('sp', policy)}, pct={pct}")
 
    # Overall verdict
    if policy is None:
        verdict = "HIGH - no DMARC, so spoofed mail from this domain is usually delivered"
    elif policy == "none":
        verdict = "HIGH - DMARC is monitor-only (p=none); spoofed mail is still delivered"
    elif policy == "quarantine":
        verdict = ("MEDIUM - spoofed mail goes to spam" +
                   (f", but only {pct}% of failing mail is affected" if pct < 100 else ""))
    elif policy == "reject":
        verdict = ("LOW - spoofed mail should be rejected" +
                   (f" (but pct={pct}, so not all of it)" if pct < 100 else ""))
    else:
        verdict = f"UNKNOWN - unrecognized DMARC policy '{policy}'"
    lines.append(f"  Spoofing risk: {verdict}")
    lines.append("  (DKIM can't be checked without knowing the domain's selector name.)")
    return lines
 
 
def whois_ip(ip):
    """RDAP lookup for who owns the IP address block."""
    try:
        r = requests.get(f"{RDAP_URL}/ip/{ip}", timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        return ["  IP WHOIS lookup failed (timeout or connection error)."]
    if r.status_code != 200:
        return [f"  IP WHOIS lookup returned status code {r.status_code}."]
    data = r.json()
    owner = (rdap_entity_name(data.get("entities"), "registrant")
             or rdap_entity_name(data.get("entities"), "administrative")
             or "N/A")
    return [
        f"  Owner:        {owner}",
        f"  Network name: {data.get('name', 'N/A')}",
        f"  IP range:     {data.get('startAddress', '?')} - {data.get('endAddress', '?')}",
        f"  Country:      {data.get('country', 'N/A')}",
    ]
 
 
def http_check(url):
    """Like 'curl -I': fetch the page and report status, redirects and key headers."""
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True,
                         headers={"User-Agent": "HW4-recon-script"})
        r.close()
    except requests.exceptions.Timeout:
        return ["  HTTP request timed out."]
    except requests.exceptions.RequestException as e:
        return [f"  HTTP request failed ({type(e).__name__})."]
 
    h = r.headers
    lines = [
        f"  Status:       {r.status_code} {r.reason}",
        f"  Final URL:    {r.url}  ({len(r.history)} redirect(s))",
        f"  Server:       {h.get('Server', 'not disclosed')}",
        f"  X-Powered-By: {h.get('X-Powered-By', 'not disclosed')}",
        f"  HSTS header:  {'present' if 'Strict-Transport-Security' in h else 'MISSING'}",
        f"  CSP header:   {'present' if 'Content-Security-Policy' in h else 'MISSING'}",
    ]
    found = [f"{name}: {desc} ({h[name]})" for name, desc in FINGERPRINT_HEADERS.items() if name in h]
    lines.append(f"  Fingerprints: {'; '.join(found) if found else 'none detected'}")
    return lines
 
 
def osv_lookup(cve):
    """Get details for one CVE from OSV.dev."""
    try:
        r = requests.get(f"{OSV_URL}/{cve}", timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        return [f"  {cve}: OSV lookup failed (timeout or connection error)."]
    if r.status_code == 404:
        return [f"  {cve}: not in the OSV database."]
    if r.status_code != 200:
        return [f"  {cve}: OSV returned status code {r.status_code}."]
 
    data = r.json()
    severity = data.get("severity", [])
    vector = severity[0].get("score", "N/A") if severity else "N/A"
    details = " ".join(data.get("details", "No description.").split())
    if len(details) > 150:
        details = details[:150] + "..."
    return [
        f"  {cve}  (published {data.get('published', 'N/A')[:10]})",
        f"    CVSS:    {vector}",
        f"    Details: {details}",
    ]
 
 
def list_or_none(items, limit=10):
    if not items:
        return "None found"
    shown = ", ".join(str(i) for i in items[:limit])
    if len(items) > limit:
        shown += f" ... (+{len(items) - limit} more)"
    return shown
 
 
# CSEC380 Req
 
def get_public_data(api_url, search_term):
    """api_url = Shodan InternetDB base URL, search_term = the URL to investigate."""
    target = search_term.strip()
    if not target:
        return "Error: Please enter a URL."
    if "://" not in target:
        target = "https://" + target
 
    host = urlparse(target).hostname
    if not host or "." not in host:
        return f"Error: '{search_term}' is not a valid URL."
 
    report = [f"Recon report for {target}", "=" * 60]
 
    # 1) DNS lookup (nslookup)
    try:
        ipaddress.ip_address(host)
        ips, aliases, is_ip = [host], [], True
    except ValueError:
        is_ip = False
        try:
            _, aliases, ips = socket.gethostbyname_ex(host)
        except socket.gaierror:
            return f"Error: DNS lookup failed. '{host}' does not resolve to an IP address."
    ip = ips[0]
    try:
        reverse_dns = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        reverse_dns = "None"
 
    report += ["\n[1] DNS lookup",
               f"  Host:         {host}",
               f"  IP(s):        {', '.join(ips)}",
               f"  Aliases:      {', '.join(aliases) or 'None'}",
               f"  Reverse DNS:  {reverse_dns}",
               f"  -> Investigating {ip}"]
 
    # 2) HTTP check (curl)
    report += ["\n[2] HTTP check"] + http_check(target)
 
    # 3) WHOIS for the domain and the IP owner
    domain = None
    if not is_ip:
        whois_lines, domain = whois_domain(host)
        report += ["\n[3a] Domain WHOIS (RDAP)"] + whois_lines
    report += [f"\n[3b] IP owner WHOIS (RDAP) for {ip}"] + whois_ip(ip)
 
    # 3c) Email spoofing check (SPF + DMARC)
    if domain:
        report += ["\n[3c] Email spoofing check (SPF / DMARC)"] + email_spoof_check(domain)
 
    # 4) Shodan InternetDB
    report.append(f"\n[4] Shodan InternetDB for {ip}")
    vulns = []
    try:
        r = requests.get(f"{api_url.rstrip('/')}/{ip}", timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            vulns = sorted(data.get("vulns", []), reverse=True)
            report += [
                f"  Hostnames:    {list_or_none(data.get('hostnames', []))}",
                f"  Open ports:   {list_or_none(data.get('ports', []))}",
                f"  Software:     {list_or_none(data.get('cpes', []))}",
                f"  Tags:         {list_or_none(data.get('tags', []))}",
                f"  Known CVEs:   {len(vulns)}",
            ]
            flagged = [p for p in data.get("ports", []) if p in RISKY_PORTS]
            report.append("\n[4b] Risky exposed services")
            if flagged:
                report += [f"  ! Port {p}: {RISKY_PORTS[p]}" for p in flagged]
            else:
                report.append("  None of the commonly abused ports are open.")
        elif r.status_code == 404:
            report.append("  Shodan has no data on this IP (private, offline, or never scanned).")
        else:
            report.append(f"  Shodan returned status code {r.status_code}.")
    except requests.exceptions.RequestException:
        report.append("  Shodan lookup failed (timeout or connection error).")
 
    # 5) OSV details for the CVEs Shodan found
    if vulns:
        report.append(f"\n[5] OSV details (newest {min(MAX_CVES, len(vulns))} of {len(vulns)} CVEs)")
        for cve in vulns[:MAX_CVES]:
            report += osv_lookup(cve)
    else:
        report += ["\n[5] OSV details", "  No CVEs to look up."]
 
    return "\n".join(report)
 
#leave room for suggested payload or possibly pipe to additional script.


target_url = input("Enter a URL to investigate (e.g. http://scanme.nmap.org): ")

print(get_public_data("https://internetdb.shodan.io", target_url))
 
