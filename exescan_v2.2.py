#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  Exescan — Port scanner + service detection                    ║
║  with active verification & vulnerability hypotheses           ║
║                                                                ║
║  Author  : SilentGhost.Exe1                                    ║
║  Usage   :                                                     ║
║    python exescan.py 192.168.1.10 --ports 1-1000               ║
║    python exescan.py example.com --ports 22,80 --nuclei        ║
║                                                                ║
║  ⚠  ONLY use on systems you own or are authorized to test.     ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import asyncio

import csv
import ipaddress
import json
import random
import shutil
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime

# ════════════════════════════════════════════════════════════════
#  AUTHOR CREDIT & METADATA
# ════════════════════════════════════════════════════════════════

AUTHOR   = "SilentGhost.Exe1"
VERSION  = "2.1"
TOOLNAME = "Exescan"

# ════════════════════════════════════════════════════════════════
#  THEME — mauve on black
# ════════════════════════════════════════════════════════════════

RESET  = "\033[0m"
MAUVE  = "\033[38;5;135m"   # primary mauve
LIGHT  = "\033[38;5;183m"   # light mauve (accents)
DIM    = "\033[38;5;97m"    # dim mauve (details)
WARN   = "\033[38;5;213m"   # pink-violet (alerts)
OKGRN  = "\033[38;5;147m"   # pale green-violet (OK)

LOGO = rf"""
 ███████╗██╗  ██╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔════╝╚██╗██╔╝██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
 █████╗   ╚███╔╝ █████╗  ███████╗██║     ███████║██╔██╗ ██║
 ██╔══╝   ██╔██╗ ██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
 ███████╗██╔╝ ██╗███████╗███████║╚██████╗██║  ██║██║ ╚████║
 ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
        v2.1  ·  port & vulnerability scanner
             crafted by ꧁༒☬👻 S꙲i꙲l꙲e꙲n꙲t꙲G꙲h꙲o꙲s꙲t꙲.꙲E꙲x꙲e꙲1꙲ 👻☬༒꧂
"""


def banner() -> None:
    if sys.stdout.isatty():
        print(f"{MAUVE}{LOGO}{RESET}")
        print(f"{DIM}{'─' * 62}{RESET}")
        print(f"{LIGHT}  {TOOLNAME} — offensive-defense scanner for authorized labs{RESET}")
        print(f"{DIM}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
        print(f"{DIM}  {'─' * 62}{RESET}\n")
    else:
        print(f"[{TOOLNAME}] starting (non-TTY output, colors disabled)")


def info(msg: str) -> None:
    print(f"{MAUVE}[•]{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{WARN}[!]{RESET} {msg}")


def ok(msg: str) -> None:
    print(f"{OKGRN}[✓]{RESET} {msg}")


# ════════════════════════════════════════════════════════════════
#  SIGNATURE DATABASE — each rule = hypothesis, never confirmation
# ════════════════════════════════════════════════════════════════

@dataclass
class VulnRule:
    ref: str               # identifier (CVE, MS, etc.)
    service_sig: str       # expected signature in banner (lowercase)
    version_range: tuple   # (min_inclusive, max_exclusive)
    description: str
    verify_hint: str       # how to manually confirm


RULES = [
    VulnRule("CVE-2021-41773", "apache/2.4.49", ("2.4.49", "2.4.50"),
             "Path traversal / potential RCE via mod_cgi",
             "Try GET /cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd (non-destructive)"),
    VulnRule("CVE-2021-42013", "apache/2.4.50", ("2.4.50", "2.4.51"),
             "Bypass of the 41773 fix — same path traversal family",
             "Try GET /cgi-bin/%%2e%%2e%%2f etc/passwd"),
    VulnRule("CVE-2017-0144 (MS17-010)", "smb", (),
             "SMB exposed — EternalBlue hypothesis",
             "nmap --script smb-vuln-ms17-010 -p 445 <host>"),
    VulnRule("OpenSSH user enumeration", "openssh_", ("1.0", "7.7"),
             "User enumeration possible",
             "nmap --script ssh-auth-methods or manual svc probe"),
    VulnRule("vsftpd 2.3.4 backdoor", "vsftpd 2.3.4", ("2.3.4", "2.3.5"),
             "Historic backdoor: ':)))' triggers a shell on port 6200",
             "Try nc <host> 6200 in your lab"),
    VulnRule("ProFTPD mod_copy", "proftpd 1.3.5", ("1.3.5", "1.3.6"),
             "Arbitrary file copy via SITE CPFR/CPTO",
             "Verify SITE CPFR with a test account"),
    VulnRule("Redis unauthenticated", "redis", (),
             "Redis probably exposed without AUTH",
             "redis-cli -h <host> ping — if +PONG it's open"),
    VulnRule("MySQL anonymous access", "mysql", (),
             "MySQL exposed — check default accounts",
             "mysql -h <host> -u root -p (lab only)"),
    VulnRule("IIS path traversal", "microsoft-iis", (),
             "IIS exposed — traversal variants depend on version",
             "Try per version: %c0%af, ..%%35%63"),
]

SERVICE_HINTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}

TLS_PORTS = {443, 465, 563, 636, 989, 990, 992, 993, 995, 8883, 8443}


def parse_version(v: str):
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return None


def in_range(version_str: str, rng: tuple) -> bool:
    v = parse_version(version_str)
    if v is None or not rng:
        return False
    lo = parse_version(rng[0]) or ()
    hi = parse_version(rng[1]) or ()
    return lo <= v < hi


# ════════════════════════════════════════════════════════════════
#  TARGET NORMALIZATION — accepts "example.com", "https://example.com",
#  "example.com:8080", plain IPs … no scheme required.
# ════════════════════════════════════════════════════════════════

def normalize_target(raw: str) -> tuple:
    """
    Strips scheme, userinfo, path and port from the input.
    Returns (clean_host, explicit_port_or_None).
    Handles: example.com, https://example.com, example.com:8080,
             http://10.0.0.1:9000/admin, 192.168.1.1
    """
    target = raw.strip()
    # Strip scheme if user pasted one
    for scheme in ("https://", "http://"):
        if target.lower().startswith(scheme):
            target = target[len(scheme):]
    # Strip userinfo (user:pass@host)
    if "@" in target:
        target = target.split("@", 1)[-1]
    # Strip path / query / fragment
    for sep in ("/", "?", "#"):
        idx = target.find(sep)
        if idx != -1:
            target = target[:idx]
    # Strip explicit port (but beware IPv6 like [::1]:80 — lab-level support)
    explicit_port = None
    if target.startswith("[") and "]:" in target:
        host_part, port_part = target[1:].rsplit("]:", 1)
        try:
            explicit_port = int(port_part)
            target = host_part
        except ValueError:
            pass
    elif target.count(":") == 1:
        host_part, port_part = target.rsplit(":", 1)
        if port_part.isdigit():
            explicit_port = int(port_part)
            target = host_part
    target = target.strip()
    if not target:
        sys.exit("[!] Empty target after normalization.")
    return target, explicit_port


def resolve_host(host: str) -> str:
    """Accepts plain IPs or domain names (example.com) — no scheme needed."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            sys.exit(f"[!] Could not resolve {host}")


def reverse_dns(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ════════════════════════════════════════════════════════════════
#  ASYNC TCP SCAN — open / closed / filtered correctly distinguished
# ════════════════════════════════════════════════════════════════

@dataclass
class PortResult:
    port: int
    state: str                  # open | closed | filtered
    banner: str = ""
    tls: bool = False
    tls_fingerprint: str = ""
    http_server: str = ""
    http_title: str = ""
    guessed_service: str = ""
    traversal_suspect: bool = False
    missing_headers: str = ""
    exposed_files: str = ""
    outdated: str = ""
    hypotheses: list = field(default_factory=list)


def extract_http_fields(raw: str) -> tuple:
    server, title = "", ""
    for line in raw.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    lower = raw.lower()
    if "<title>" in lower and "</title>" in lower:
        s = lower.index("<title>") + 7
        e = lower.index("</title>", s)
        title = raw[s:e].strip()[:80]
    return server, title


async def grab_banner(host: str, port: int, timeout: float) -> str:
    """Reads greeting banner, or sends a minimal HEAD request."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
        return ""

    text = ""
    try:
        first = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        text = first.decode("utf-8", errors="replace").strip()
    except Exception:
        pass

    if not text:
        try:
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " +
                         host.encode() + b"\r\nUser-Agent: Exescan/2.1\r\n\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            text = resp.decode("utf-8", errors="replace").strip()
        except Exception:
            pass

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return text


async def probe_port(host: str, port: int, timeout: float, jitter: float) -> PortResult:
    """
    States:
      - connection established        -> open
      - RST (ConnectionRefused)       -> closed
      - timeout / unreachable / ICMP  -> filtered
    Random jitter reduces IDS detection.
    """
    if jitter:
        await asyncio.sleep(random.uniform(0, jitter))

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except ConnectionRefusedError:
        return PortResult(port, "closed")
    except (asyncio.TimeoutError, OSError):
        return PortResult(port, "filtered")

    result = PortResult(port, "open")
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    text = await grab_banner(host, port, timeout)
    result.banner = text[:500]

    if text.upper().startswith(("HTTP/1", "HTTP/2")):
        srv, ttl = extract_http_fields(text)
        result.http_server = srv
        result.http_title = ttl

    if port in TLS_PORTS:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _, w2 = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
            )
            obj = w2.get_extra_info("ssl_object")
            if obj is not None:
                import hashlib
                der = obj.getpeercert(True)
                result.tls = True
                if der:
                    result.tls_fingerprint = (
                        f"sha256:{hashlib.sha256(der).hexdigest()[:16]}…"
                    )
            w2.close()
        except Exception:
            pass

    if result.http_server:
        result.traversal_suspect = await check_traversal(host, port, timeout)
    if result.state == "open" and port in (80, 443, 8080, 8000):
        mh = await check_security_headers(host, port, timeout)
        result.missing_headers = ",".join(mh)
        ef = await check_exposed_files(host, port, timeout)
        result.exposed_files = ",".join(ef)
    result.outdated = check_outdated_banner(result.banner)
    result.guessed_service = guess_service(result)
    result.hypotheses = match_hypotheses(result)
    return result


async def check_traversal(host: str, port: int, timeout: float) -> bool:
    """
    Active, strictly READ-ONLY path traversal check (CVE-2021-41773 style).
    Suspect if 'root:' comes back from /etc/passwd. No writes, no exec.
    """
    payloads = ["/.%2e/.%2e/.%2e/.%2e/etc/passwd",
                "/%2e%2e/%2e%2e/%2e%2e/etc/passwd"]
    for p in payloads:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            req = (f"GET {p} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: Exescan/2.1\r\nConnection: close\r\n\r\n")
            writer.write(req.encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(8192), timeout=timeout)
            body = resp.decode("utf-8", errors="replace")
            writer.close()
            if "root:" in body and "bin/" in body:
                return True
        except Exception:
            continue
    return False


def guess_service(r: PortResult) -> str:
    text = r.banner.lower()
    table = [
        ("openssh", "SSH"), ("dropbear", "SSH"),
        ("ftp", "FTP"), ("220 ", "FTP?"),
        ("smtp", "SMTP"), ("postfix", "SMTP"),
        ("redis", "Redis"), ("mysql", "MySQL"),
        ("http/", "HTTP"), ("<html", "HTTP"),
        ("microsoft-iis", "IIS"), ("nginx", "nginx"),
        ("apache", "Apache"), ("postgres", "PostgreSQL"),
    ]
    for sig, name in table:
        if sig in text:
            return name
    return SERVICE_HINTS.get(r.port, "unknown")


def match_hypotheses(r: PortResult) -> list:
    """Generates HYPOTHESES — never confirmations."""
    out = []
    text = (r.banner + " " + r.http_server).lower()
    for rule in RULES:
        if rule.service_sig.lower() in text:
            version = None
            for tok in (r.banner + " " + r.http_server).replace("/", " ").split():
                if tok and tok[0].isdigit() and "." in tok:
                    version = tok.strip(",;")
                    break
            if in_range(version or "", rule.version_range) or not rule.version_range:
                out.append({
                    "ref": rule.ref,
                    "status": "HYPOTHESIS — active verification required",
                    "description": rule.description,
                    "how_to_verify": rule.verify_hint,
                    "observed": r.banner[:150] or r.http_server,
                })
    if r.traversal_suspect:
        out.append({
            "ref": "Path traversal CONFIRMED (passwd read succeeded)",
            "status": "CONFIRMED (active non-destructive probe)",
            "description": "Server returns /etc/passwd on an encoded traversal "
                           "payload. Real vulnerability.",
            "how_to_verify": "curl --path-as-is 'http://host:%d/.%%2e/.%%2e/etc/passwd'" % r.port,
            "observed": "HTTP response containing root: bin/",
        })
    return out


# ════════════════════════════════════════════════════════════════
#  NUCLEI INTEGRATION — thousands of community templates via subprocess
# ════════════════════════════════════════════════════════════════

def nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def install_hint() -> str:
    return ("Install Nuclei: go install -v github.com/projectdiscovery/"
            "nuclei/v2/cmd/nuclei@latest\n"
            "            or download from https://github.com/"
            "projectdiscovery/nuclei/releases")


def run_nuclei(host: str, ip: str, open_ports: list, severity: str,
               timeout: int) -> list:
    """
    Runs Nuclei against each open HTTP(S) port found by the scan.
    Returns a list of parsed findings. Read-only templates by default.
    """
    if not nuclei_available():
        warn("Nuclei binary not found in PATH.")
        warn(install_hint())
        return []

    targets = []
    for r in open_ports:
        scheme = "https" if (r.port in TLS_PORTS or r.tls) else "http"
        targets.append(f"{scheme}://{host}:{r.port}")

    cmd = [
        "nuclei",
        "-silent",
        "-jsonl",                      # machine-readable output
        "-severity", severity,         # e.g. low,medium,high,critical
        "-timeout", str(timeout),
        "-no-color",
        "-duc",                        # disable update check
    ]
    info(f"Running Nuclei on {len(targets)} target(s) "
         f"(severity >= {severity})…")
    for t in targets:
        info(f"  ↳ {t}")
        cmd += ["-u", t]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout * 60)
            yield_lines = proc.stdout.splitlines()
            cmd.pop(-1)  # remove last -u to append next one cleanly
            for line in yield_lines:
                try:
                    item = json.loads(line)
                    yield item
                except json.JSONDecodeError:
                    continue
        except subprocess.TimeoutExpired:
            warn(f"Nuclei timed out on {t}")
        except FileNotFoundError:
            warn("Nuclei disappeared from PATH mid-run?")
            return []


def collect_nuclei(findings_iter) -> list:
    out = []
    for item in findings_iter:
        out.append({
            "template": item.get("template-id", "?"),
            "name": item.get("info", {}).get("name", "?"),
            "severity": item.get("info", {}).get("severity", "?"),
            "matched_at": item.get("matched-at", "?"),
            "reference": (item.get("info", {}).get("reference") or [""])[0],
        })
    return out


def print_nuclei_findings(findings: list) -> None:
    if not findings:
        info("Nuclei: no matching vulnerabilities found (or not installed).")
        return
    print(f"\n{WARN}{'═' * 62}{RESET}")
    print(f"{WARN}  NUCLEI FINDINGS — real template matches{RESET}")
    print(f"{WARN}{'═' * 62}{RESET}")
    for f in findings:
        sev = f["severity"].upper()
        print(f"{WARN}  [{sev:<8}] {f['name']}{RESET}")
        print(f"{DIM}           template : {f['template']}{RESET}")
        print(f"{DIM}           matched  : {f['matched_at']}{RESET}")
        if f["reference"]:
            print(f"{DIM}           ref      : {f['reference']}{RESET}")
    print()


# ════════════════════════════════════════════════════════════════
#  ORCHESTRATION
# ════════════════════════════════════════════════════════════════

async def scan(host: str, ports: list, timeout: float,
               workers: int, jitter: float) -> list:
    sem = asyncio.Semaphore(workers)
    done = 0
    total = len(ports)

    async def guarded(p):
        nonlocal done
        async with sem:
            res = await probe_port(host, p, timeout, jitter)
            done += 1
            if done % 50 == 0 or done == total:
                info(f"Progress: {done}/{total} ports tested…")
            return res

    return await asyncio.gather(*(guarded(p) for p in ports))


def parse_ports(spec: str) -> list:
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        else:
            if part.isdigit():
                ports.add(int(part))
    return sorted(ports)


def export_csv(results: list, path: str) -> None:
        with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f, quoting=csv.QUOTE_ALL)
                w.writerow(["port", "state", "service", "tls", "banner", "http_server", "http_title", "missing_headers", "exposed_files", "traversal_suspect", "outdated"])
                for r in results:
                        banner_clean = (r.banner or "")[:200].replace("\r", " ").replace("\n", " ").replace(",", ";")
                        w.writerow([r.port, r.state, r.guessed_service, r.tls, banner_clean, r.http_server, r.http_title, r.missing_headers, r.exposed_files, r.traversal_suspect, r.outdated])

def export_json_report(results: list, findings: list, host: str, ip: str,
                       rdns, path: str):
    report = {
        "tool": TOOLNAME,
        "version": VERSION,
        "author": AUTHOR,
        "date": datetime.now().isoformat(),
        "target": host, "ip": ip, "reverse_dns": rdns,
        "port_results": [asdict(r) for r in results],
        "nuclei_findings": findings,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def print_report(results: list, host: str, ip: str, rdns) -> None:
    open_ports = [r for r in results if r.state == "open"]

    print()
    print(f"{MAUVE}{'═' * 62}{RESET}")
    print(f"{LIGHT}  REPORT — {host} ({ip}){RESET}")
    if rdns:
        print(f"{DIM}  Reverse DNS : {rdns}{RESET}")
    print(f"{DIM}  {len(open_ports)} open port(s) out of {len(results)} tested{RESET}")
    print(f"{MAUVE}{'═' * 62}{RESET}\n")

    for r in sorted(open_ports, key=lambda x: x.port):
        tag = f"{MAUVE}[OPEN]{RESET}"
        svc = (f"{LIGHT}{r.guessed_service}{RESET}"
               if r.guessed_service != "unknown" else DIM + "?" + RESET)
        tls = f" {WARN}[TLS]{RESET}" if r.tls else ""
        print(f"{tag} {r.port:>5}/tcp  {svc}{tls}")
        if r.banner:
            first = r.banner.splitlines()[0][:90]
            print(f"        {DIM}Banner : {first}{RESET}")
        if r.http_server:
            print(f"        {DIM}Server : {r.http_server}{RESET}")
        if r.http_title:
            print(f"        {DIM}Title  : {r.http_title}{RESET}")
        for h in r.hypotheses:
            confirmed = h["status"].startswith("CONFIRMED")
            color = WARN if confirmed else DIM
            label = "⛔" if confirmed else "⚠"
            print(f"        {color}{label} {h['ref']} — {h['status']}{RESET}")
            print(f"        {DIM}   {h['description']}{RESET}")
            print(f"        {DIM}   → Verify : {h['how_to_verify']}{RESET}")
        print()

    if not open_ports:
        warn("No open ports found.")
    closed = sum(1 for r in results if r.state == "closed")
    filt = sum(1 for r in results if r.state == "filtered")
    info(f"Summary : {len(open_ports)} open · {closed} closed · {filt} filtered")


def main():
    parser = argparse.ArgumentParser(
        prog=TOOLNAME,
        description=(f"{TOOLNAME} v{VERSION} — port scanner & vulnerability "
                     f"hypothesis engine by {AUTHOR}. Authorized labs only."),
        epilog=f"Example: python exescan.py example.com --ports 1-1024 --nuclei\n"
               f"Author : {AUTHOR}"
    )
    parser.add_argument("target",
                        help="Target — IP or domain, no scheme needed "
                             "(example.com, https://example.com, 192.168.1.10)")
    parser.add_argument("--ports", default="1-1000",
                        help="e.g. 22,80,443 or 1-1024 (default 1-1000)")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--workers", type=int, default=200)
    parser.add_argument("--jitter", type=float, default=0.05,
                        help="Max random delay between probes (anti-IDS)")
    parser.add_argument("--nuclei", action="store_true",
                        help="Chain Nuclei templates on open HTTP(S) ports")
    parser.add_argument("--severity", default="medium,high,critical",
                        help="Nuclei severity filter (default medium,high,critical)")
    parser.add_argument("--json", metavar="FILE", help="Export report as JSON")
    parser.add_argument("--csv", metavar="FILE", help="Export results as CSV")
    parser.add_argument("--no-banner", action="store_true", help="Hide the logo")
    args = parser.parse_args()

    if not args.no_banner:
        banner()

    warn("AUTHORIZED USE ONLY — target your own lab or systems you're cleared for.")

    # Target normalization: example.com, https://example.com, IP:port …
    host, explicit_port = normalize_target(args.target)
    ip = resolve_host(host)
    rdns = reverse_dns(ip)

    ports = parse_ports(args.ports)
    if explicit_port and explicit_port not in ports:
        ports.insert(0, explicit_port)   # honor target like example.com:8080
        ports.sort()

    if not ports:
        sys.exit("[!] No valid ports specified.")

    info(f"Target : {args.target} → normalized '{host}' → resolved {ip}"
         f" · {len(ports)} ports · {args.workers} workers")
    t0 = time.time()
    results = asyncio.run(scan(ip, ports, args.timeout, args.workers, args.jitter))
    info(f"Scan finished in {time.time() - t0:.2f}s")

    print_report(results, args.host if hasattr(args, 'host') else args.target,
                 ip, rdns)

    open_ports = [r for r in results if r.state == "open"]

    # Nuclei chaining
    nuclei_findings = []
    if args.nuclei and open_ports:
        findings_iter = run_nuclei(host, ip, open_ports, args.severity,
                                   int(max(args.timeout, 5)))
        nuclei_findings = collect_nuclei(findings_iter)
        print_nuclei_findings(nuclei_findings)

    if args.json:
        export_json_report(results, nuclei_findings,
                           host, ip, rdns, args.json)
        ok(f"JSON report → {args.json}")
    if args.csv:
        export_csv(results, args.csv)
        ok(f"CSV report → {args.csv}")

    print(f"\n{MAUVE}  — {TOOLNAME} v{VERSION} by {AUTHOR}. Stay in the legal lane. —{RESET}\n")
async def check_security_headers(host, port, timeout):
    # Retourne la liste des headers manquants
    missing = []
    try:
        import ssl, asyncio
        use_tls = port == 443
        # On fait juste une requête HEAD simple, on ne télécharge rien
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ssl.create_default_context() if use_tls else None), timeout)
        writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout)
        writer.close()
        text = data.decode(errors="ignore").lower()
        for h in ["x-frame-options", "content-security-policy", "strict-transport-security", "x-content-type-options"]:
            if h not in text:
                missing.append(h)
    except:
        pass
    return missing

async def check_exposed_files(host, port, timeout):
    # Vérifie juste le status code, on ne télécharge pas le contenu sensible
    found = []
    paths = ["/robots.txt", "/.env", "/.git/HEAD", "/backup.zip", "/.git/config"]
    for p in paths:
        try:
            import asyncio, ssl
            use_tls = port == 443
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ssl.create_default_context() if use_tls else None), timeout)
            writer.write(f"GET {p} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout)
            writer.close()
            if b"200 OK" in data:
                found.append(p)
        except:
            pass
    return found

def check_outdated_banner(banner):
    # Très simple : si le banner contient une vieille version connue
    if not banner:
        return ""
    b = banner.lower()
    if "apache/2.4.49" in b or "apache/2.4.50" in b:
        return "Apache 2.4.49/50 - CVE-2021-41773 possible"
    if "apache/2.2" in b:
        return "Apache 2.2 tres ancien - a verifier"
    if "microsoft-iis/6.0" in b or "microsoft-iis/7.0" in b:
        return "IIS ancien - a verifier"
    return ""


if __name__ == "__main__":
    main()
