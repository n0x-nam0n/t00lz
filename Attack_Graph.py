#!/usr/bin/env python3
"""
attack_graph.py — Autonomous recon pipeline
Shodan → NVD CVE lookup → CVSS risk scoring → prioritized attack graph

Usage:
    python3 attack_graph.py <target-domain> [--shodan-key KEY] [--gh-token TOKEN]
    python3 attack_graph.py iheartmedia.com --shodan-key YOUR_KEY
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
from datetime import datetime, timezone

# ── optional shodan library; fall back to InternetDB (no key needed) ──────────
try:
    import shodan as shodan_lib
    SHODAN_LIB = True
except ImportError:
    SHODAN_LIB = False

# ─────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────────────
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def _get(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "url": url}
    except Exception as e:
        return {"_error": str(e), "url": url}


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — Shodan / InternetDB asset enumeration
# ─────────────────────────────────────────────────────────────────────────────
HIGH_VALUE_PORTS = {22, 23, 25, 53, 80, 443, 445, 1433, 1521, 3306, 3389,
                    5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017}


def shodan_recon_key(domain, api_key):
    """
    Shodan recon using API key.
    Paid plans: search by hostname/org query.
    Free oss plan: resolve domain → IPs via DNS, then api.host() per IP.
    """
    api = shodan_lib.Shodan(api_key)
    assets = []

    # Check plan — oss can't run search queries
    try:
        info = api.info()
        plan = info.get("plan", "oss")
        query_credits = info.get("query_credits", 0)
    except Exception:
        plan, query_credits = "oss", 0

    if plan != "oss" and query_credits > 0:
        # Paid path: search by hostname + org
        queries = [
            f'hostname:"{domain}"',
            f'org:"{domain.split(".")[0]}"',
        ]
        seen_ips = set()
        for q in queries:
            try:
                results = api.search(q, limit=100)
                for r in results.get("matches", []):
                    ip = r.get("ip_str", "")
                    if ip in seen_ips:
                        continue
                    seen_ips.add(ip)
                    assets.append({
                        "ip":       ip,
                        "port":     r.get("port"),
                        "hostname": r.get("hostnames", []),
                        "product":  r.get("product", ""),
                        "version":  r.get("version", ""),
                        "org":      r.get("org", ""),
                        "os":       r.get("os", ""),
                        "vulns":    list(r.get("vulns", {}).keys()),
                        "cpes":     r.get("cpe23", r.get("cpe", [])),
                        "source":   "shodan-search",
                    })
            except Exception as e:
                print(f"  [!] Shodan search failed ({q}): {e}")
        return assets

    # Free oss path: DNS resolve → api.host() per IP (no query credits needed)
    print(f"  oss plan detected — using host lookup (no query credits consumed)")
    dns_url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
    dns_data = _get(dns_url, headers={"Accept": "application/dns-json"})
    ips = [a["data"] for a in dns_data.get("Answer", []) if a.get("type") == 1]

    # Also try subdomains from cert transparency for broader coverage
    ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
    ct_data = _get(ct_url)
    ct_names = list({e.get("name_value", "").replace("*.", "") for e in (ct_data if isinstance(ct_data, list) else [])})[:20]
    for name in ct_names:
        dns_url2 = f"https://cloudflare-dns.com/dns-query?name={name}&type=A"
        sub_data = _get(dns_url2, headers={"Accept": "application/dns-json"})
        for a in sub_data.get("Answer", []):
            if a.get("type") == 1:
                ips.append(a["data"])

    ips = list(dict.fromkeys(ips))   # deduplicate, preserve order
    print(f"  Resolved {len(ips)} IPs to probe")

    for ip in ips:
        try:
            r = api.host(ip)
            for svc in r.get("data", []):
                assets.append({
                    "ip":       ip,
                    "port":     svc.get("port"),
                    "hostname": r.get("hostnames", []),
                    "product":  svc.get("product", ""),
                    "version":  svc.get("version", ""),
                    "org":      r.get("org", ""),
                    "os":       r.get("os", ""),
                    "vulns":    list(r.get("vulns", {}).keys()),
                    "cpes":     svc.get("cpe23", svc.get("cpe", [])),
                    "source":   "shodan-host",
                })
            time.sleep(1.0)
        except shodan_lib.exception.APIError as e:
            msg = str(e)
            if "Access denied" in msg or "403" in msg:
                # oss plan can't do host lookups on CDN-shared IPs; fall through silently
                pass
            elif "No information available" not in msg:
                print(f"  [!] {ip}: {e}")
        except Exception as e:
            print(f"  [!] {ip}: {e}")

    return assets


def internetdb_recon(domain):
    """
    Free Shodan InternetDB — no key needed.
    Resolves the domain to IPs first via DNS-over-HTTPS, then queries
    https://internetdb.shodan.io/<ip> for each.
    """
    assets = []

    # Resolve domain → IPs via DNS-over-HTTPS (Cloudflare)
    dns_url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
    dns_data = _get(dns_url, headers={"Accept": "application/dns-json"})
    ips = [a["data"] for a in dns_data.get("Answer", []) if a.get("type") == 1]

    if not ips:
        print(f"  [!] Could not resolve {domain} via DNS-over-HTTPS")
        return assets

    print(f"  Resolved {domain} → {', '.join(ips)}")

    for ip in ips:
        data = _get(f"https://internetdb.shodan.io/{ip}")
        if "_error" in data or "_http_error" in data:
            continue
        ports = data.get("ports", [])
        cpes  = data.get("cpes", [])
        vulns = data.get("vulns", [])
        for port in ports:
            assets.append({
                "ip":       ip,
                "port":     port,
                "hostname": data.get("hostnames", []),
                "product":  "",
                "version":  "",
                "org":      "",
                "os":       "",
                "vulns":    vulns,
                "cpes":     cpes,
                "source":   "internetdb",
            })
        if not ports:
            assets.append({
                "ip": ip, "port": None,
                "hostname": data.get("hostnames", []),
                "product": "", "version": "", "org": "", "os": "",
                "vulns": vulns, "cpes": cpes, "source": "internetdb",
            })
        time.sleep(0.3)

    return assets


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — NVD CVE lookup
# ─────────────────────────────────────────────────────────────────────────────
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY = 0.7   # NVD rate limit: ~5 req/30s without key


def nvd_lookup_cpe(cpe, nvd_key=None):
    """Query NVD by CPE string; return list of (cve_id, cvss, description)."""
    params = {"cpeName": cpe, "resultsPerPage": 20}
    url = NVD_BASE + "?" + urllib.parse.urlencode(params)
    headers = {}
    if nvd_key:
        headers["apiKey"] = nvd_key
    data = _get(url, headers=headers)
    time.sleep(NVD_DELAY)
    return _parse_nvd(data)


def nvd_lookup_keyword(keyword, nvd_key=None):
    """Fallback: keyword search when no CPE available.
    Only returns CVEs published after 2018 to suppress ancient false positives
    from broad product-name keyword matches (e.g. 'nginx' matching CVE-2009-*)."""
    params = {"keywordSearch": keyword, "resultsPerPage": 10,
              "pubStartDate": "2018-01-01T00:00:00.000", "pubEndDate": "2099-01-01T00:00:00.000"}
    url = NVD_BASE + "?" + urllib.parse.urlencode(params)
    headers = {}
    if nvd_key:
        headers["apiKey"] = nvd_key
    data = _get(url, headers=headers)
    time.sleep(NVD_DELAY)
    return _parse_nvd(data)


def _parse_nvd(data):
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        # Prefer CVSS v3.1, fall back to v3.0, then v2
        metrics = cve.get("metrics", {})
        score, vector, severity = None, "", "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cv = entries[0].get("cvssData", {})
                score    = cv.get("baseScore")
                vector   = cv.get("vectorString", "")
                severity = cv.get("baseSeverity", entries[0].get("baseSeverity", ""))
                break
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:120]
                break
        results.append({
            "cve_id":   cve_id,
            "score":    score,
            "severity": severity,
            "vector":   vector,
            "desc":     desc,
        })
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — GitHub secret scan
# ─────────────────────────────────────────────────────────────────────────────
GH_SEARCH = "https://api.github.com/search/code"

SECRET_QUERIES = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret',
    '"{domain}" token',
    '"{domain}" credential',
]


def github_secret_scan(domain, gh_token=None):
    """Search GitHub public repos for exposed secrets referencing the target."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if gh_token:
        headers["Authorization"] = f"token {gh_token}"

    findings = []
    # Use full domain in quotes for precision — avoids false positives from
    # short org names like "dot" matching unrelated repos
    search_term = domain

    # File extensions that produce noisy false positives
    NOISY_EXTENSIONS = {
        ".ics", ".txt", ".list", ".csv", ".log", ".lock",
        # ".md",  # uncomment to exclude markdown
        ".xml", ".html", ".htm", ".pdf",
    }

    limit = 5 if gh_token else 3
    for tmpl in SECRET_QUERIES[:limit]:
        q = tmpl.replace("{domain}", search_term)
        url = GH_SEARCH + "?" + urllib.parse.urlencode({"q": q, "per_page": 10})
        data = _get(url, headers=headers)
        if "_error" in data or "_http_error" in data:
            break
        for item in data.get("items", []):
            path = item.get("path", "")
            ext  = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if ext in NOISY_EXTENSIONS:
                continue
            findings.append({
                "repo":    item.get("repository", {}).get("full_name", ""),
                "path":    path,
                "url":     item.get("html_url", ""),
                "matched": q,
            })
        time.sleep(1.0)   # GitHub search rate: 10 req/min unauth, 30 auth

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 — Risk scoring + attack graph generation
# ─────────────────────────────────────────────────────────────────────────────
PORT_RISK = {
    22:    ("SSH",           "MEDIUM", "Brute-force / CVE exploitation"),
    23:    ("Telnet",        "HIGH",   "Cleartext credentials"),
    3389:  ("RDP",          "HIGH",   "BlueKeep/DejaBlue — CVE-2019-0708"),
    445:   ("SMB",          "CRITICAL","EternalBlue / anonymous share access"),
    6379:  ("Redis",        "CRITICAL","No-auth default → write SSH keys"),
    9200:  ("Elasticsearch","CRITICAL","Unauthenticated data access"),
    27017: ("MongoDB",      "CRITICAL","No-auth default"),
    2375:  ("Docker API",   "CRITICAL","Unauthenticated container/host takeover"),
    5432:  ("PostgreSQL",   "HIGH",   "Default creds postgres:postgres"),
    3306:  ("MySQL",        "HIGH",   "Default creds root:''"),
    1433:  ("MSSQL",        "HIGH",   "xp_cmdshell if sysadmin"),
    5900:  ("VNC",          "HIGH",   "Often no auth or weak password"),
    8888:  ("Jupyter",      "HIGH",   "Interactive shell, often no auth"),
    5601:  ("Kibana",       "HIGH",   "Often unauthenticated"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def score_asset(asset, cves):
    """
    Assign a composite risk score (0-100) based on:
    - Port inherent risk (40 pts max)
    - Max CVE CVSS score (40 pts max)
    - Shodan-reported vulns present (20 pts max)
    """
    port = asset.get("port")
    port_info = PORT_RISK.get(port, ("", "LOW", ""))
    port_sev = port_info[1]
    port_pts = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5}.get(port_sev, 0)

    max_cvss = max((c["score"] for c in cves if c.get("score")), default=0)
    cvss_pts = min(int((max_cvss / 10) * 40), 40)

    vuln_pts = min(len(asset.get("vulns", [])) * 10, 20)

    total = port_pts + cvss_pts + vuln_pts
    if total >= 80:
        risk = "CRITICAL"
    elif total >= 60:
        risk = "HIGH"
    elif total >= 40:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return total, risk


def build_attack_graph(assets, cve_map, gh_findings, domain):
    nodes = []

    # Deduplicate by (ip, port)
    seen = set()
    for asset in assets:
        key = (asset["ip"], asset.get("port"))
        if key in seen:
            continue
        seen.add(key)

        cves = cve_map.get(asset["ip"], [])
        score, risk = score_asset(asset, cves)
        port = asset.get("port")
        port_meta = PORT_RISK.get(port, ("Unknown", "LOW", ""))

        high_cves = sorted(
            [c for c in cves if c.get("score") and c["score"] >= 7.0],
            key=lambda c: c["score"],
            reverse=True,
        )[:5]

        metasploit_hints = _metasploit_modules(port, high_cves)

        nodes.append({
            "ip":          asset["ip"],
            "port":        port,
            "service":     port_meta[0] or asset.get("product", ""),
            "product":     asset.get("product", ""),
            "version":     asset.get("version", ""),
            "hostname":    asset.get("hostname", []),
            "org":         asset.get("org", ""),
            "source":      asset.get("source", ""),
            "risk_score":  score,
            "risk":        risk,
            "port_note":   port_meta[2],
            "cves":        high_cves,
            "shodan_vulns":asset.get("vulns", []),
            "msf_hints":   metasploit_hints,
        })

    nodes.sort(key=lambda n: (-n["risk_score"], SEVERITY_ORDER.get(n["risk"], 99)))

    return {
        "target":      domain,
        "generated":   datetime.now(timezone.utc).isoformat(),
        "total_assets": len(nodes),
        "github_hits":  gh_findings,
        "nodes":       nodes,
    }


def _metasploit_modules(port, cves):
    hints = []
    MODULE_MAP = {
        22:    ["auxiliary/scanner/ssh/ssh_login", "exploit/multi/ssh/sshexec"],
        3389:  ["exploit/windows/rdp/cve_2019_0708_bluekeep_rce"],
        445:   ["exploit/windows/smb/ms17_010_eternalblue"],
        6379:  ["auxiliary/scanner/redis/redis_login", "exploit/linux/redis/redis_replication_cmd_exec"],
        9200:  ["auxiliary/scanner/elasticsearch/indices_enum"],
        27017: ["auxiliary/scanner/mongodb/mongodb_login"],
        2375:  ["exploit/linux/http/docker_daemon_tcp"],
        5432:  ["auxiliary/scanner/postgres/postgres_login"],
        3306:  ["auxiliary/scanner/mysql/mysql_login"],
        1433:  ["auxiliary/scanner/mssql/mssql_login"],
    }
    if port in MODULE_MAP:
        hints.extend(MODULE_MAP[port])
    # CVE-specific modules
    for cve in cves:
        cve_id = cve.get("cve_id", "")
        CVE_MODULES = {
            "CVE-2019-0708": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            "CVE-2017-0144": "exploit/windows/smb/ms17_010_eternalblue",
            "CVE-2021-21972": "exploit/multi/http/vmware_vcenter_uploadova_rce",
            "CVE-2022-1388":  "exploit/multi/http/f5_bigip_tmui_rce",
            "CVE-2021-26084": "exploit/multi/http/atlassian_confluence_rce_cve_2021_26084",
        }
        if cve_id in CVE_MODULES:
            mod = CVE_MODULES[cve_id]
            if mod not in hints:
                hints.append(mod)
    return hints[:4]


# ─────────────────────────────────────────────────────────────────────────────
# Output rendering
# ─────────────────────────────────────────────────────────────────────────────
COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
}


def c(color, text):
    return f"{COLORS.get(color,'')}{text}{COLORS['RESET']}"


def render_ascii_graph(graph):
    domain   = graph["target"]
    nodes    = graph["nodes"]
    gh_hits  = graph["github_hits"]
    gen_time = graph["generated"]

    print()
    print(c("BOLD", "=" * 72))
    print(c("BOLD", f"  ATTACK GRAPH — {domain}"))
    print(c("DIM",  f"  Generated: {gen_time}   Assets: {graph['total_assets']}"))
    print(c("BOLD", "=" * 72))

    if not nodes:
        print("\n  No assets discovered.\n")
        return

    # Stats bar
    by_risk = {}
    for n in nodes:
        by_risk[n["risk"]] = by_risk.get(n["risk"], 0) + 1
    stats = " | ".join(
        c(r, f"{r}: {by_risk[r]}")
        for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if r in by_risk
    )
    print(f"\n  {stats}\n")

    for idx, node in enumerate(nodes, 1):
        risk   = node["risk"]
        score  = node["risk_score"]
        ip     = node["ip"]
        port   = node.get("port", "?")
        svc    = node.get("service") or "unknown"
        prod   = node.get("product", "")
        ver    = node.get("version", "")
        hosts  = ", ".join(node["hostname"][:2]) if node["hostname"] else ""
        note   = node.get("port_note", "")

        prod_str = f" [{prod} {ver}]".strip("[ ]").strip() if prod else ""
        host_str = f" ({hosts})" if hosts else ""

        print(c("BOLD", f"  [{idx:02d}] {c(risk, f'[{risk}]')} Score:{score}  {ip}:{port}  {svc}{prod_str}{host_str}"))

        if note:
            print(c("DIM", f"       → {note}"))

        # Shodan-reported vulns
        if node["shodan_vulns"]:
            print(c("DIM", f"       Shodan vulns: {', '.join(node['shodan_vulns'][:6])}"))

        # High-CVSS CVEs
        for cve in node["cves"][:3]:
            sev   = cve.get("severity", "")
            cvss  = cve.get("score", "?")
            cid   = cve.get("cve_id", "")
            desc  = cve.get("desc", "")
            print(f"       {c(sev, f'CVE {cid}')} CVSS:{cvss}  {desc[:80]}")

        # MSF hints
        if node["msf_hints"]:
            mods = "  |  ".join(node["msf_hints"][:2])
            print(c("DIM", f"       MSF: {mods}"))

        print()

    # GitHub leaks
    if gh_hits:
        print(c("BOLD", "  ── GitHub Secret Scan ──"))
        for h in gh_hits[:10]:
            print(f"  {c('HIGH', h['repo'])}  {h['path']}")
            print(c("DIM", f"    {h['url']}"))
        print()

    # Top 5 priority targets
    top = [n for n in nodes if n["risk"] in ("CRITICAL", "HIGH")][:5]
    if top:
        print(c("BOLD", "  ── Priority Targets ──"))
        for n in top:
            msf = n["msf_hints"][0] if n["msf_hints"] else "manual"
            print(f"  {c(n['risk'], n['ip'])}:{n['port']}  →  {msf}")
        print()

    print(c("BOLD", "=" * 72))


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Autonomous attack-graph recon pipeline")
    parser.add_argument("target",                  help="Target domain (e.g. iheartmedia.com)")
    parser.add_argument("--shodan-key",            default=os.environ.get("SHODAN_API_KEY"),
                        help="Shodan API key (or set SHODAN_API_KEY env var)")
    parser.add_argument("--gh-token",              default=os.environ.get("GITHUB_TOKEN"),
                        help="GitHub token for higher rate limits")
    parser.add_argument("--nvd-key",               default=os.environ.get("NVD_API_KEY"),
                        help="NVD API key (optional, increases rate limit)")
    parser.add_argument("--cvss-min",  type=float, default=7.0,
                        help="Minimum CVSS score to flag (default 7.0)")
    parser.add_argument("--out",                   default=None,
                        help="Write JSON output to file (default: attack_graph_<domain>.json)")
    parser.add_argument("--no-github", action="store_true",
                        help="Skip GitHub secret scan")
    parser.add_argument("--ips",                   default=None,
                        help="Comma-separated IPs to scan directly (bypass DNS resolution)")
    args = parser.parse_args()

    domain = args.target.lower().strip().lstrip("https://").lstrip("http://").split("/")[0]
    out_file = args.out or f"attack_graph_{domain.replace('.', '_')}.json"

    print(c("BOLD", f"\n[*] Target: {domain}"))

    # Phase 1 — Asset enum
    print(c("BOLD", "\n[1/4] Asset Enumeration"))
    if args.ips:
        print(f"  Manual IPs: {args.ips}")
        manual_ips = [ip.strip() for ip in args.ips.split(",") if ip.strip()]
        assets = []
        for ip in manual_ips:
            data = _get(f"https://internetdb.shodan.io/{ip}")
            if "_error" in data or "_http_error" in data:
                print(f"  {ip}: not in InternetDB ({data})")
                continue
            for port in data.get("ports", []):
                assets.append({
                    "ip": ip, "port": port,
                    "hostname": data.get("hostnames", []),
                    "product": "", "version": "", "org": "", "os": "",
                    "vulns": data.get("vulns", []),
                    "cpes":  data.get("cpes", []),
                    "source": "internetdb-manual",
                })
    elif args.shodan_key and SHODAN_LIB:
        print("  Using Shodan API key")
        assets = shodan_recon_key(domain, args.shodan_key)
    else:
        print("  Using InternetDB (no key required)")
        assets = internetdb_recon(domain)

    print(f"  Found {len(assets)} asset records")

    # Phase 2 — CVE lookup
    print(c("BOLD", "\n[2/4] CVE Lookup (NVD API)"))
    cve_map = {}
    unique_ips = {}
    for a in assets:
        ip = a["ip"]
        if ip not in unique_ips:
            unique_ips[ip] = a

    for ip, asset in unique_ips.items():
        cves = []
        # Try Shodan-reported vulns first (already CVE IDs)
        for cve_id in asset.get("vulns", [])[:5]:
            params = {"cveId": cve_id}
            url = NVD_BASE + "?" + urllib.parse.urlencode(params)
            data = _get(url, headers={"apiKey": args.nvd_key} if args.nvd_key else {})
            cves.extend(_parse_nvd(data))
            time.sleep(NVD_DELAY)

        # Try CPE-based lookup
        for cpe in asset.get("cpes", [])[:3]:
            cves.extend(nvd_lookup_cpe(cpe, args.nvd_key))

        # Fallback: keyword search by product name
        if not cves and asset.get("product"):
            term = asset["product"]
            if asset.get("version"):
                term += " " + asset["version"]
            cves.extend(nvd_lookup_keyword(term, args.nvd_key))

        # Filter by CVSS minimum
        cves = [c for c in cves if c.get("score") is None or c["score"] >= args.cvss_min]
        if cves:
            cve_map[ip] = cves
            print(f"  {ip}: {len(cves)} CVEs ≥ CVSS {args.cvss_min}")

    # Phase 3 — GitHub secret scan
    gh_findings = []
    if not args.no_github:
        print(c("BOLD", "\n[3/4] GitHub Secret Scan"))
        gh_findings = github_secret_scan(domain, args.gh_token)
        print(f"  Found {len(gh_findings)} potential secret references")
    else:
        print(c("BOLD", "\n[3/4] GitHub Secret Scan (skipped)"))

    # Phase 4 — Build and render attack graph
    print(c("BOLD", "\n[4/4] Building Attack Graph"))
    graph = build_attack_graph(assets, cve_map, gh_findings, domain)

    render_ascii_graph(graph)

    # Write JSON
    with open(out_file, "w") as f:
        json.dump(graph, f, indent=2)
    print(f"\n  JSON saved → {out_file}\n")


if __name__ == "__main__":
    main()
