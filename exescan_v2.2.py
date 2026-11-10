#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  Exescan — Port scanner + service detection                    ║
║  with active verification & vulnerability hypotheses           ║
║                                                                ║
║  Author  : SilentGhost.Exe1                                    ║
║  Usage   :                                                     ║
║    python exescan.py                                           ║
║    (numbered menu → enter IP)                                  ║
║                                                                ║
║  ⚠  ONLY use on systems you own or are authorized to test.     ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import asyncio
import concurrent.futures
import csv
import ipaddress
import json
import os
import random
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime

# ════════════════════════════════════════════════════════════════
#  AUTHOR CREDIT & METADATA
# ════════════════════════════════════════════════════════════════

AUTHOR   = "SilentGhost.Exe1"
VERSION  = "2.3"
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
        v{VERSION}  ·  TCP/UDP port & vulnerability scanner
             crafted by ꧁༒☬👻 SilentGhost.Exe1 👻☬༒꧂
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
    ref: str
    service_sig: str
    version_range: tuple
    description: str
    verify_hint: str


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
    # UDP common
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
    161: "SNMP", 162: "SNMP-trap", 500: "IKE", 514: "Syslog",
}

TLS_PORTS = {443, 465, 563, 636, 989, 990, 992, 993, 995, 8883, 8443}

# Common top ports (nmap-inspired, TCP)
TOP_PORTS_TCP = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8000, 8888, 9200, 27017
]
TOP_PORTS_UDP = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 623, 1434, 1900, 5353]


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
#  TARGET NORMALIZATION
# ════════════════════════════════════════════════════════════════

def normalize_target(raw: str) -> tuple:
    target = raw.strip()
    for scheme in ("https://", "http://"):
        if target.lower().startswith(scheme):
            target = target[len(scheme):]
    if "@" in target:
        target = target.split("@", 1)[-1]
    for sep in ("/", "?", "#"):
        idx = target.find(sep)
        if idx != -1:
            target = target[:idx]
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
#  RESULTS
# ════════════════════════════════════════════════════════════════

@dataclass
class PortResult:
    port: int
    state: str                  # open | closed | filtered | open|filtered
    protocol: str = "tcp"
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


# ════════════════════════════════════════════════════════════════
#  TCP SCAN
# ════════════════════════════════════════════════════════════════

async def grab_banner(host: str, port: int, timeout: float) -> str:
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
                         host.encode() + b"\r\nUser-Agent: Exescan/2.3\r\n\r\n")
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


async def check_traversal(host: str, port: int, timeout: float) -> bool:
    payloads = ["/.%2e/.%2e/.%2e/.%2e/etc/passwd",
                "/%2e%2e/%2e%2e/%2e%2e/etc/passwd"]
    for p in payloads:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            req = (f"GET {p} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: Exescan/2.3\r\nConnection: close\r\n\r\n")
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


async def check_security_headers(host, port, timeout):
    missing = []
    try:
        use_tls = port == 443
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl.create_default_context() if use_tls else None),
            timeout
        )
        writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout)
        writer.close()
        text = data.decode(errors="ignore").lower()
        for h in ["x-frame-options", "content-security-policy", "strict-transport-security", "x-content-type-options"]:
            if h not in text:
                missing.append(h)
    except Exception:
        pass
    return missing


async def check_exposed_files(host, port, timeout):
    found = []
    paths = ["/robots.txt", "/.env", "/.git/HEAD", "/backup.zip", "/.git/config"]
    for p in paths:
        try:
            use_tls = port == 443
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl.create_default_context() if use_tls else None),
                timeout
            )
            writer.write(f"GET {p} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout)
            writer.close()
            if b"200 OK" in data:
                found.append(p)
        except Exception:
            pass
    return found


def check_outdated_banner(banner):
    if not banner:
        return ""
    b = banner.lower()
    if "apache/2.4.49" in b or "apache/2.4.50" in b:
        return "Apache 2.4.49/50 - CVE-2021-41773 possible"
    if "apache/2.2" in b:
        return "Apache 2.2 very old - verify"
    if "microsoft-iis/6.0" in b or "microsoft-iis/7.0" in b:
        return "Old IIS - verify"
    return ""


async def probe_port_tcp(host: str, port: int, timeout: float, jitter: float) -> PortResult:
    if jitter:
        await asyncio.sleep(random.uniform(0, jitter))

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except ConnectionRefusedError:
        return PortResult(port, "closed", "tcp")
    except (asyncio.TimeoutError, OSError):
        return PortResult(port, "filtered", "tcp")

    result = PortResult(port, "open", "tcp")
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


# ════════════════════════════════════════════════════════════════
#  UDP SCAN (basic, no root required)
# ════════════════════════════════════════════════════════════════

def probe_port_udp_sync(host: str, port: int, timeout: float) -> PortResult:
    """Simple UDP probe. Response = open, timeout = open|filtered."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        # Minimal probe payload (empty or common for some services)
        sock.sendto(b"", (host, port))
        data, _ = sock.recvfrom(1024)
        banner = data.decode("utf-8", errors="replace")[:200] if data else ""
        return PortResult(port, "open", "udp", banner=banner)
    except socket.timeout:
        return PortResult(port, "open|filtered", "udp")
    except OSError:
        return PortResult(port, "filtered", "udp")
    finally:
        sock.close()


async def probe_port_udp(host: str, port: int, timeout: float, jitter: float) -> PortResult:
    if jitter:
        await asyncio.sleep(random.uniform(0, jitter))
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        result = await loop.run_in_executor(pool, probe_port_udp_sync, host, port, timeout)
    result.guessed_service = SERVICE_HINTS.get(port, "unknown")
    return result


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
            "description": "Server returns /etc/passwd on an encoded traversal payload. Real vulnerability.",
            "how_to_verify": f"curl --path-as-is 'http://host:{r.port}/.%%2e/.%%2e/etc/passwd'",
            "observed": "HTTP response containing root: bin/",
        })
    return out


# ════════════════════════════════════════════════════════════════
#  NUCLEI (fixed command construction)
# ════════════════════════════════════════════════════════════════

def nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def install_hint() -> str:
    return ("Install Nuclei: go install -v github.com/projectdiscovery/"
            "nuclei/v2/cmd/nuclei@latest\n"
            "            or download from https://github.com/"
            "projectdiscovery/nuclei/releases")


def run_nuclei(host: str, ip: str, open_ports: list, severity: str, timeout: int):
    if not nuclei_available():
        warn("Nuclei binary not found in PATH.")
        warn(install_hint())
        return

    targets = []
    for r in open_ports:
        if r.protocol != "tcp":
            continue
        scheme = "https" if (r.port in TLS_PORTS or r.tls) else "http"
        targets.append(f"{scheme}://{host}:{r.port}")

    if not targets:
        return

    base_cmd = [
        "nuclei",
        "-silent",
        "-jsonl",
        "-severity", severity,
        "-timeout", str(timeout),
        "-no-color",
        "-duc",
    ]
    info(f"Running Nuclei on {len(targets)} target(s) (severity >= {severity})…")
    for t in targets:
        info(f"  ↳ {t}")
        cmd = base_cmd + ["-u", t]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 60)
            for line in proc.stdout.splitlines():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
        except subprocess.TimeoutExpired:
            warn(f"Nuclei timed out on {t}")
        except FileNotFoundError:
            warn("Nuclei disappeared from PATH mid-run?")
            return


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
#  SCAN ORCHESTRATION
# ════════════════════════════════════════════════════════════════

async def scan(host: str, ports: list, timeout: float, workers: int, jitter: float, protocol: str = "tcp") -> list:
    sem = asyncio.Semaphore(workers)
    done = 0
    total = len(ports)
    probe = probe_port_tcp if protocol == "tcp" else probe_port_udp

    async def guarded(p):
        nonlocal done
        async with sem:
            res = await probe(host, p, timeout, jitter)
            done += 1
            if done % 200 == 0 or done == total:
                info(f"Progress: {done}/{total} {protocol.upper()} ports tested…")
            return res

    return await asyncio.gather(*(guarded(p) for p in ports))


def parse_ports(spec: str) -> list:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        else:
            if part.isdigit():
                ports.add(int(part))
    return sorted(ports)


def get_port_preset(choice: str, protocol: str) -> list:
    if choice == "1":
        return list(range(1, 1001))
    elif choice == "2":
        return TOP_PORTS_TCP if protocol == "tcp" else TOP_PORTS_UDP
    elif choice == "3":
        return list(range(1, 1001)) + (TOP_PORTS_TCP if protocol == "tcp" else TOP_PORTS_UDP)
    elif choice == "4":
        return parse_ports(input("Enter custom ports (e.g. 22,80,443 or 1-1024): ").strip())
    else:
        return list(range(1, 1001))


# ════════════════════════════════════════════════════════════════
#  EXPORT
# ════════════════════════════════════════════════════════════════

def export_csv(results: list, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["port", "protocol", "state", "service", "tls", "banner", "http_server",
                    "http_title", "missing_headers", "exposed_files", "traversal_suspect", "outdated"])
        for r in results:
            banner_clean = (r.banner or "")[:200].replace("\r", " ").replace("\n", " ").replace(",", ";")
            w.writerow([r.port, r.protocol, r.state, r.guessed_service, r.tls, banner_clean,
                        r.http_server, r.http_title, r.missing_headers, r.exposed_files,
                        r.traversal_suspect, r.outdated])


def export_json_report(results: list, findings: list, host: str, ip: str, rdns, path: str, protocol: str):
    report = {
        "tool": TOOLNAME,
        "version": VERSION,
        "author": AUTHOR,
        "date": datetime.now().isoformat(),
        "target": host, "ip": ip, "reverse_dns": rdns,
        "protocol": protocol,
        "port_results": [asdict(r) for r in results],
        "nuclei_findings": findings,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def print_report(results: list, host: str, ip: str, rdns, protocol: str) -> None:
    open_ports = [r for r in results if r.state in ("open", "open|filtered")]
    interesting = [r for r in open_ports if r.state == "open" or r.banner or r.guessed_service not in ("?", "unknown")]

    print()
    print(f"{MAUVE}{'═' * 62}{RESET}")
    print(f"{LIGHT}  REPORT — {host} ({ip})  [{protocol.upper()}]{RESET}")
    if rdns:
        print(f"{DIM}  Reverse DNS : {rdns}{RESET}")
    print(f"{DIM}  {len(open_ports)} open/open|filtered port(s) out of {len(results)} tested{RESET}")
    print(f"{MAUVE}{'═' * 62}{RESET}\n")

    # Only print interesting ports (true open or with banner/service)
    shown = interesting if interesting else open_ports[:10]
    for r in sorted(shown, key=lambda x: x.port):
        tag = f"{MAUVE}[{r.state.upper()}]{RESET}"
        svc = (f"{LIGHT}{r.guessed_service}{RESET}"
               if r.guessed_service not in ("?", "unknown") else DIM + "?" + RESET)
        tls = f" {WARN}[TLS]{RESET}" if r.tls else ""
        print(f"{tag} {r.port:>5}/{r.protocol}  {svc}{tls}")
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

    if len(open_ports) > len(shown):
        info(f"... and {len(open_ports) - len(shown)} more open|filtered ports (UDP timeouts are normal)")

    if not open_ports:
        warn("No open ports found.")
    closed = sum(1 for r in results if r.state == "closed")
    filt = sum(1 for r in results if r.state in ("filtered", "open|filtered"))
    info(f"Summary : {len(open_ports)} open/open|filtered · {closed} closed · {filt} filtered")


# ════════════════════════════════════════════════════════════════
#  HISTORY & ISP
# ════════════════════════════════════════════════════════════════

HISTORY_FILE = os.path.expanduser("~/.exescan_history.json")


def load_history() -> list:
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_history(history: list) -> None:
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except Exception as e:
        warn(f"Could not save history: {e}")


def get_isp_info(ip: str) -> dict:
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {"status": "fail", "query": ip}


def print_isp_table(info: dict) -> None:
    if info.get("status") != "success":
        info_msg = info.get("message", "No data")
        print(f"{DIM}  ISP info unavailable ({info_msg}){RESET}")
        return
    print(f"\n{LIGHT}┌{'─' * 50}┐{RESET}")
    print(f"{LIGHT}│ ISP / Geolocation Info{' ' * 27}│{RESET}")
    print(f"{LIGHT}├{'─' * 50}┤{RESET}")
    rows = [
        ("IP", info.get("query", "?")),
        ("ISP", info.get("isp", "?")),
        ("Org", info.get("org", "?")),
        ("AS", info.get("as", "?")),
        ("Country", info.get("country", "?")),
        ("Region", info.get("regionName", "?")),
        ("City", info.get("city", "?")),
    ]
    for k, v in rows:
        print(f"{LIGHT}│ {k:<10} : {str(v)[:36]:<36} │{RESET}")
    print(f"{LIGHT}└{'─' * 50}┘{RESET}\n")


def view_history():
    history = load_history()
    if not history:
        info("No scan history yet.")
        return
    print(f"\n{LIGHT}Scan History ({len(history)} entries){RESET}")
    print(f"{DIM}{'─' * 62}{RESET}")
    for i, entry in enumerate(history, 1):
        ts = entry.get("date", "?")[:19].replace("T", " ")
        target = entry.get("target", "?")
        ip = entry.get("ip", "?")
        proto = entry.get("protocol", "?").upper()
        opens = entry.get("open_count", 0)
        print(f"  {i:2d}) {ts}  {target:<20} ({ip})  {proto}  {opens} open")
    print(f"{DIM}{'─' * 62}{RESET}")
    print()


def manage_history():
    history = load_history()
    if not history:
        info("No history to manage.")
        return
    view_history()
    print("Manage history:")
    print("  1) Delete one entry (by number)")
    print("  2) Clear all history")
    print("  0) Back")
    choice = input(f"{MAUVE}Choice: {RESET}").strip()
    if choice == "1":
        try:
            num = int(input(f"{MAUVE}Entry number to delete: {RESET}"))
            if 1 <= num <= len(history):
                removed = history.pop(num - 1)
                save_history(history)
                ok(f"Deleted: {removed.get('target', '?')}")
            else:
                warn("Invalid number.")
        except ValueError:
            warn("Not a number.")
    elif choice == "2":
        confirm = input(f"{WARN}Clear ALL history? (yes/N): {RESET}").strip().lower()
        if confirm == "yes":
            save_history([])
            ok("History cleared.")
        else:
            info("Cancelled.")
    # else back


# ════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU (persistent loop)
# ════════════════════════════════════════════════════════════════

def do_scan():
    print(f"\n{LIGHT}New Scan{RESET}")
    print("1) Protocol")
    print("   1) TCP")
    print("   2) UDP")
    proto_choice = input(f"{MAUVE}Select protocol [1]: {RESET}").strip() or "1"
    protocol = "udp" if proto_choice == "2" else "tcp"

    print("\n2) Port range")
    print("   1) First 1000 ports (1-1000)")
    print("   2) Top common ports")
    print("   3) First 1000 + top ports")
    print("   4) Custom ports")
    port_choice = input(f"{MAUVE}Select port range [1]: {RESET}").strip() or "1"

    target = input(f"\n{MAUVE}Enter target IP or domain: {RESET}").strip()
    if not target:
        warn("No target given.")
        return

    print("\n3) Advanced (press Enter for defaults)")
    try:
        timeout = float(input(f"{MAUVE}Timeout seconds [2.0]: {RESET}").strip() or "2.0")
        workers = int(input(f"{MAUVE}Workers [100]: {RESET}").strip() or "100")
    except ValueError:
        timeout, workers = 2.0, 100
    use_nuclei = input(f"{MAUVE}Run Nuclei? (y/N): {RESET}").strip().lower() == "y"

    host, explicit_port = normalize_target(target)
    ip = resolve_host(host)
    rdns = reverse_dns(ip)
    isp = get_isp_info(ip)
    print_isp_table(isp)

    ports = get_port_preset(port_choice, protocol)
    if explicit_port and explicit_port not in ports:
        ports.append(explicit_port)
        ports.sort()

    info(f"Target: {target} → {host} → {ip} · {protocol.upper()} · {len(ports)} ports")
    t0 = time.time()
    try:
        results = asyncio.run(scan(ip, ports, timeout, workers, 0.05, protocol))
    except KeyboardInterrupt:
        warn("Scan interrupted.")
        return
    info(f"Scan finished in {time.time() - t0:.2f}s")

    print_report(results, host, ip, rdns, protocol)

    open_ports = [r for r in results if r.state in ("open", "open|filtered")]
    nuclei_findings = []
    if use_nuclei and open_ports:
        findings_iter = run_nuclei(host, ip, open_ports, "medium,high,critical", max(int(timeout), 5))
        nuclei_findings = collect_nuclei(findings_iter)
        print_nuclei_findings(nuclei_findings)

    # Offer to save to history
    save_q = input(f"\n{MAUVE}Save this scan to history? (Y/n): {RESET}").strip().lower()
    if save_q in ("", "y", "yes"):
        history = load_history()
        entry = {
            "date": datetime.now().isoformat(),
            "target": target,
            "host": host,
            "ip": ip,
            "protocol": protocol,
            "open_count": len(open_ports),
            "ports_scanned": len(ports),
            "isp": isp.get("isp", ""),
            "city": isp.get("city", ""),
            "country": isp.get("country", ""),
        }
        history.insert(0, entry)  # newest first
        # keep last 100
        history = history[:100]
        save_history(history)
        ok("Saved to history.")

    input(f"\n{DIM}Press Enter to return to menu...{RESET}")


def clear_screen():
    """Clear terminal and move cursor to top."""
    print("\033[2J\033[H", end="")
    # fallback
    os.system("cls" if os.name == "nt" else "clear")


def interactive_menu():
    # Ignore Ctrl+C at the top level so menu doesn't die
    def ignore_sigint(signum, frame):
        print(f"\n{WARN}Use the menu option to exit.{RESET}")
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, ignore_sigint)

    # Clear and start at top
    clear_screen()
    banner()
    warn("AUTHORIZED USE ONLY — target your own lab or systems you're cleared for.")

    while True:
        try:
            print(f"\n{LIGHT}Exescan Menu{RESET}")
            print(f"{DIM}{'─' * 40}{RESET}")
            print("  1) New scan")
            print("  2) View history")
            print("  3) Manage history (delete / clear)")
            print("  0) Exit")
            print(f"{DIM}{'─' * 40}{RESET}")
            choice = input(f"{MAUVE}Select option: {RESET}").strip()

            if choice == "1":
                do_scan()
            elif choice == "2":
                view_history()
                input(f"{DIM}Press Enter to continue...{RESET}")
            elif choice == "3":
                manage_history()
                input(f"{DIM}Press Enter to continue...{RESET}")
            elif choice == "0":
                print(f"\n{MAUVE}  — {TOOLNAME} v{VERSION} by {AUTHOR}. Stay in the legal lane. —{RESET}\n")
                sys.exit(0)
            else:
                warn("Invalid choice.")

            # Clear again when returning to menu so it always starts at top
            clear_screen()
            banner()
            warn("AUTHORIZED USE ONLY — target your own lab or systems you're cleared for.")
        except KeyboardInterrupt:
            print()
            continue
        except Exception as e:
            warn(f"Error: {e}")
            input(f"{DIM}Press Enter to continue...{RESET}")


# ════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════

def main():
    interactive_menu()


if __name__ == "__main__":
    main()
