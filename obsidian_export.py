"""
obsidian_export.py — Obsidian vault export module for Syd

Synced from mAIpper-v0.6.py — Phase 1 & 2

Converts Nmap scan data (from Syd's existing XML parser or paste parser)
into structured Obsidian markdown notes and a canvas visualization.

What's new in this sync (v0.6 improvements):
  - Host notes carry YAML frontmatter: ip, hostnames, status, tags, sources
  - Re-runs merge new scan data; operator's 'status' and '## Operator Notes'
    section are always preserved
  - Canvas rebuilt as single pane of glass:
      * Stable deterministic node IDs (hashlib.md5) — manual operator additions survive
      * Campaign Overview text node (stats + key AI findings)
      * Scan note file cards connected to the hosts they discovered
      * Subnet group nodes (/24) containing color-coded host cards
      * Next Steps text node drawn from AI analysis

Syd-specific interface (unchanged — syd.py imports these by name):
  - syd_services_to_scan_data()  — converts Syd's flat services list to scan_data dict
  - build_analysis_prompt()      — builds the LLM user-message prompt
  - export_to_obsidian()         — main entry point called by the Report Builder UI
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import math
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ============================================================
# Constants
# ============================================================

CANVAS_FILENAME = "Assessment Canvas.canvas"

# Obsidian canvas color strings mapped to operator status values.
# Set 'status' in frontmatter inside Obsidian; mAIpper colors the card on next export.
STATUS_COLORS: dict[str, str | None] = {
    "not-started": None,   # default (white)
    "in-progress":  "3",   # yellow
    "done":         "4",   # green
    "exploited":    "1",   # red
    "blocked":      "6",   # purple
}

# Sentinel separating auto-generated content from operator-written content
OPERATOR_NOTES_SENTINEL = "## Operator Notes"
OPERATOR_NOTES_HINT     = "_Add your own findings, observations, and next steps below._"

# Canvas layout constants (pixels)
CARD_W            = 360
CARD_H            = 220
CARD_GAP_X        = 60
CARD_GAP_Y        = 60
GROUP_PAD         = 60
GROUP_LABEL_H     = 40
SCAN_CARD_W       = 360
SCAN_CARD_H       = 160
OVERVIEW_W        = 720
OVERVIEW_H        = 220
NEXT_STEPS_W      = 640
NEXT_STEPS_H      = 420
GROUP_GAP         = 120
ROW_GAP           = 120


# ============================================================
# Basic helpers
# ============================================================

def _safe_filename(s: str) -> str:
    """Strip characters that are illegal in Obsidian / Windows filenames."""
    for ch in '<>:"/\\|?*\n\r\t':
        s = s.replace(ch, "_")
    return s.strip().strip(".")


def _ensure_md(name: str) -> str:
    return name if name.lower().endswith(".md") else f"{name}.md"


def _stable_id(key: str) -> str:
    """Return a deterministic 12-char hex ID derived from *key*."""
    return hashlib.md5(key.encode()).hexdigest()[:12]


_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _is_ipv4(value: str) -> bool:
    return bool(value and _IPV4_RE.match(str(value).strip()))


def _get_subnet_label(ip: str) -> str:
    """Return the /24 network label for an IPv4 address."""
    if not _is_ipv4(ip):
        return "unknown"
    parts = str(ip).split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


# ============================================================
# Frontmatter helpers
# ============================================================

def _fm_encode(v: object) -> str:
    if isinstance(v, list):
        return json.dumps(v, ensure_ascii=False)
    if v is None:
        return "null"
    return str(v)


def write_frontmatter(fm: dict) -> str:
    """Render *fm* as a YAML frontmatter block (including delimiters)."""
    lines = ["---"]
    for k, v in fm.items():
        lines.append(f"{k}: {_fm_encode(v)}")
    lines.append("---")
    return "\n".join(lines) + "\n"


def read_frontmatter(text: str) -> tuple[dict, str]:
    """
    Parse the leading YAML frontmatter from *text*.
    Returns ``(frontmatter_dict, body)`` where *body* is everything after
    the closing ``---``.  Returns ``({}, text)`` if no frontmatter is found.
    """
    if not text.startswith("---\n"):
        return {}, text

    end = text.find("\n---\n", 4)
    if end == -1:
        return {}, text

    fm_text = text[4:end]
    body    = text[end + 5:]

    fm: dict = {}
    for line in fm_text.splitlines():
        if ": " not in line and not line.endswith(":"):
            continue
        key, _, raw = line.partition(": ")
        key = key.strip()
        raw = raw.strip()
        if not key:
            continue
        try:
            fm[key] = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            fm[key] = raw if raw else None

    return fm, body


def extract_operator_notes(body: str) -> str:
    """
    Return operator-written content after OPERATOR_NOTES_SENTINEL.
    Strips the hint line and leading/trailing blank lines.
    """
    idx = body.find(OPERATOR_NOTES_SENTINEL)
    if idx == -1:
        return ""

    after = body[idx + len(OPERATOR_NOTES_SENTINEL):]
    lines = after.splitlines()

    content_lines: list[str] = []
    past_hint = False
    for line in lines:
        if not past_hint and line.strip() in ("", OPERATOR_NOTES_HINT):
            continue
        past_hint = True
        content_lines.append(line)

    while content_lines and not content_lines[-1].strip():
        content_lines.pop()

    return "\n".join(content_lines)


# ============================================================
# Port tags & hints
# ============================================================

def get_tags_from_ports(open_ports: list) -> list[str]:
    """Derive short service tags from an open-ports list for frontmatter."""
    tags: set[str] = set()
    port_nums = {p.get("port", 0) for p in open_ports}
    svc_names = {(p.get("service", {}).get("name", "") or "").lower() for p in open_ports}

    if port_nums & {80, 81, 443, 8000, 8080, 8443} or svc_names & {"http", "https", "http-proxy"}:
        tags.add("web")
    if 445 in port_nums or svc_names & {"microsoft-ds", "smb"}:
        tags.add("smb")
    if port_nums & {88, 464} or any("kerberos" in s for s in svc_names):
        tags.add("kerberos")
    if port_nums & {389, 636, 3268, 3269} or svc_names & {"ldap", "ldaps", "globalcatldap", "globalcatldapssl"}:
        tags.add("ldap")
    if 135 in port_nums or "msrpc" in svc_names:
        tags.add("rpc")
    if port_nums & {1433, 1434} or any("mssql" in s for s in svc_names):
        tags.add("mssql")
    if 3306 in port_nums or "mysql" in svc_names:
        tags.add("mysql")
    if 5432 in port_nums or any("postgres" in s for s in svc_names):
        tags.add("postgres")
    if 22 in port_nums or "ssh" in svc_names:
        tags.add("ssh")
    if 3389 in port_nums or "ms-wbt-server" in svc_names:
        tags.add("rdp")
    if port_nums & {5985, 5986} or any("winrm" in s for s in svc_names):
        tags.add("winrm")
    if 21 in port_nums or "ftp" in svc_names:
        tags.add("ftp")
    if 53 in port_nums or "domain" in svc_names:
        tags.add("dns")
    if port_nums & {161, 162} or "snmp" in svc_names:
        tags.add("snmp")
    if port_nums & {25, 465, 587} or svc_names & {"smtp", "smtps", "submission"}:
        tags.add("smtp")
    if 2049 in port_nums or "nfs" in svc_names:
        tags.add("nfs")
    if 6379 in port_nums or any("redis" in s for s in svc_names):
        tags.add("redis")

    if {"kerberos", "ldap", "smb"} <= tags:
        tags.add("domain-controller")

    return sorted(tags)


def _render_port_hints(port: int, service_name: str, product: str = "", extrainfo: str = "") -> list[str]:
    """Return operator-facing hints for a given port/service."""
    svc   = (service_name or "").lower()
    prod  = (product or "").lower()
    hints: list[str] = []

    if port in (80, 81, 443, 8000, 8080, 8443) or svc in ("http", "https", "http-proxy"):
        hints.append("Web service — consider: whatweb, nikto, gobuster/feroxbuster, curl, manual browsing")
        hints.append("Check: default creds, admin panels, exposed APIs, vhosts, interesting headers")
    if port == 445 or svc in ("microsoft-ds", "smb", "netbios-ssn"):
        hints.append("SMB — consider: netexec smb, smbclient, smbmap, enum4linux-ng")
        hints.append("Check: share access, null sessions, SMB signing, local admin reuse, domain membership")
    if port in (88, 464) or "kerberos" in svc:
        hints.append("Kerberos — consider: kerbrute, GetUserSPNs, AS-REP roast, netexec")
    if port in (389, 636, 3268, 3269) or svc in ("ldap", "ldaps", "globalcatldap"):
        hints.append("LDAP — consider: ldapsearch, netexec ldap, bloodyAD")
        hints.append("Check: anonymous bind, naming contexts, domain structure, password policy")
    if port == 135 or svc == "msrpc":
        hints.append("MSRPC — consider: rpcclient, netexec, enumerate domain clues and services")
    if port == 139 or svc == "netbios-ssn":
        hints.append("NetBIOS — enumerate shares, names, and Windows host information")
    if port in (5985, 5986) or "winrm" in svc:
        hints.append("WinRM — consider: evil-winrm, netexec winrm (useful with creds)")
    if port in (1433, 1434) or "mssql" in svc or "sql server" in prod:
        hints.append("MSSQL — consider: impacket-mssqlclient, netexec mssql, xp_cmdshell if SA access")
    if port == 3306 or "mysql" in svc:
        hints.append("MySQL — test auth paths, enumerate databases, check for UDF injection")
    if port == 5432 or "postgres" in svc:
        hints.append("PostgreSQL — test for weak/default credentials and accessible databases")
    if port == 22 or svc == "ssh":
        hints.append("SSH — consider: ssh-audit, banner grab, key-based auth checks, cautious cred testing")
    if port == 21 or svc == "ftp":
        hints.append("FTP — check: anonymous access, writable dirs, plaintext credential exposure")
    if port in (25, 465, 587) or svc in ("smtp", "smtps", "submission"):
        hints.append("SMTP — consider: smtp-user-enum, swaks, open relay check")
    if port == 53 or svc == "domain":
        hints.append("DNS — consider: dig, dnsrecon, zone transfer testing")
    if port == 3389 or svc == "ms-wbt-server":
        hints.append("RDP — consider: netexec rdp, xfreerdp, NLA / domain clues")
    if port == 2049 or svc == "nfs":
        hints.append("NFS — use: showmount, test accessible exports and weak permissions")
    if port in (161, 162) or svc == "snmp":
        hints.append("SNMP — try: snmpwalk, onesixtyone, test common community strings")
    if port in (5900, 5901, 5902) or svc == "vnc":
        hints.append("VNC — verify auth requirements and assess screenshot / password attack viability")
    if port == 6379 or "redis" in svc:
        hints.append("Redis — verify bind/auth config and whether dangerous commands are exposed remotely")
    if port in (9200, 9300) or "elasticsearch" in svc:
        hints.append("Elasticsearch — check for unauthenticated cluster or index access")
    if port in (2375, 2376) or "docker" in svc:
        hints.append("Docker API — verify remote daemon access and authentication/TLS posture")

    return hints


# ============================================================
# Host/port rendering helpers
# ============================================================

def _choose_display_name(host: dict) -> str:
    hostnames = [h["name"].strip() for h in host.get("hostnames", []) if h.get("name")]
    for hn in hostnames:
        if "." in hn and not _IPV4_RE.match(hn):
            return hn.rstrip(".")
    for hn in hostnames:
        if hn:
            return hn.rstrip(".")
    for addr in host.get("addresses", []):
        if addr.get("addrtype") == "ipv4" and addr.get("addr"):
            return addr["addr"]
    return "unknown-host"


def _primary_ipv4(host: dict) -> Optional[str]:
    for addr in host.get("addresses", []):
        if addr.get("addrtype") == "ipv4" and addr.get("addr"):
            return addr["addr"]
    return None


def _render_service_str(port_info: dict) -> str:
    svc   = port_info.get("service", {})
    parts = [svc.get("name", "")]
    if svc.get("product"):   parts.append(svc["product"])
    if svc.get("version"):   parts.append(svc["version"])
    if svc.get("extrainfo"): parts.append(f"({svc['extrainfo']})")
    return " ".join(p for p in parts if p).strip() or "—"


# ============================================================
# Syd-specific data model conversion (unchanged)
# ============================================================

def syd_services_to_scan_data(
    services: list[dict],
    xml_path: Optional[str] = None,
    scan_name: str = "Nmap Scan",
    nmap_args: str = "",
) -> dict:
    """
    Convert Syd's flat services list (from parse_xml_results or
    parse_services_from_text) into the mAIpper-style scan_data dict.

    Syd service dict keys:
        host, hostname, port, protocol, service, product, version, extra_info

    Output mirrors mAIpper's parse_nmap_xml() return value.
    """
    host_map: dict[str, dict] = {}

    for svc in services:
        ip       = svc.get("host", "unknown")
        hostname = svc.get("hostname", "")

        if ip not in host_map:
            host_map[ip] = {
                "state":      "up",
                "addresses":  [{"addr": ip, "addrtype": "ipv4"}],
                "hostnames":  [{"name": hostname, "type": "user"}] if hostname else [],
                "open_ports": [],
            }
        elif hostname and not host_map[ip]["hostnames"]:
            host_map[ip]["hostnames"] = [{"name": hostname, "type": "user"}]

        host_map[ip]["open_ports"].append({
            "protocol": svc.get("protocol", "tcp"),
            "port":     int(svc.get("port", 0)),
            "service": {
                "name":      svc.get("service", ""),
                "product":   svc.get("product", ""),
                "version":   svc.get("version", ""),
                "extrainfo": svc.get("extra_info", ""),
                "tunnel":    "",
            },
            "scripts": [],
        })

    for hdata in host_map.values():
        hdata["open_ports"].sort(key=lambda p: (p["protocol"], p["port"]))

    return {
        "source_file":  xml_path or scan_name,
        "parsed_at":    dt.datetime.now().isoformat(timespec="seconds"),
        "nmap_args":    nmap_args,
        "nmap_version": "",
        "hosts":        list(host_map.values()),
    }


# ============================================================
# Analysis prompt builder (called directly by syd.py)
# ============================================================

def build_analysis_prompt(scan_data: dict) -> str:
    """
    Build the LLM user-message prompt from scan_data.
    Targets Syd's chat_completion interface (caller sets the system role).
    """
    hosts = scan_data.get("hosts", [])

    lines = [
        f"Nmap args: {scan_data.get('nmap_args', '(unknown)')}",
        f"Hosts scanned: {len(hosts)}",
        "",
        "Host details:",
    ]

    for host in hosts:
        display = _choose_display_name(host)
        ip      = _primary_ipv4(host) or "unknown"
        lines.append(f"\nHost: {display}  (IP: {ip})")

        open_ports = host.get("open_ports", [])
        if not open_ports:
            lines.append("  Open ports: none")
            continue

        for p in open_ports:
            svc   = p.get("service", {})
            parts = [svc.get("name", "unknown")]
            if svc.get("product"):   parts.append(svc["product"])
            if svc.get("version"):   parts.append(svc["version"])
            if svc.get("extrainfo"): parts.append(f"({svc['extrainfo']})")
            lines.append(f"  {p.get('protocol', '')}/{p.get('port', '')}: {' '.join(parts).strip()}")

            for script in p.get("scripts", [])[:3]:
                out = " ".join((script.get("output", "") or "").split())
                if len(out) > 220:
                    out = out[:217] + "..."
                if out:
                    lines.append(f"    script:{script.get('id', '')} -> {out}")

    return f"""You are an experienced penetration tester analyzing Nmap scan results for a client engagement.

Produce practical, operator-focused analysis. Be concise and specific.

Priorities:
- Identify notable exposed services and the realistic attack surface
- Suggest useful enumeration tools for discovered services (netexec, smbclient, ldapsearch, gobuster, etc.)
- Recommend practical next-step commands or techniques
- Highlight likely misconfigurations, risky exposures, or commonly exploitable weaknesses
- Infer technology stacks where reasonable, but clearly separate facts from assumptions
- Do NOT invent vulnerabilities not supported by the scan data

Nmap Scan Summary
=================
{chr(10).join(lines)}

Return your response in markdown using exactly these sections:

## Key Observations
- Brief bullets of the most important findings

## Enumeration Suggestions
- Group by service or host; include relevant tools and follow-up ideas

## Potential Attack Paths
- Realistic next steps or paths suggested by the scan
- Distinguish confirmed findings from assumptions

## Notable Risks or Misconfigurations
- Anything unusually exposed or high-value
"""


# ============================================================
# Host note writing (merge-aware, with frontmatter)
# ============================================================

def _write_host_note(
    hosts_dir: Path,
    host: dict,
    scan_stem: str,
    scan_display: str,
) -> tuple[str, str]:
    """
    Write or merge a host note.

    On first write: creates the note with frontmatter, detailed port sections
    with operator hints, and an empty Operator Notes section.

    On re-export: reads existing frontmatter, preserves 'status' and the
    operator's ## Operator Notes content, rebuilds all auto-generated sections
    with the latest scan data merged in.

    Returns (display_name, host_stem).
    """
    display    = _choose_display_name(host)
    host_stem  = _safe_filename(display)
    host_path  = hosts_dir / _ensure_md(host_stem)
    primary_ip = _primary_ipv4(host)
    open_ports = host.get("open_ports", [])

    # ---- Read existing ----
    existing_fm: dict = {}
    existing_op_notes = ""
    if host_path.exists():
        old_text = host_path.read_text(encoding="utf-8")
        existing_fm, old_body = read_frontmatter(old_text)
        existing_op_notes = extract_operator_notes(old_body)
        logger.debug(f"Merging host note: {host_path.name}")
    else:
        logger.debug(f"Creating host note: {host_path.name}")

    # ---- Merge frontmatter ----
    scan_source = f"{scan_display} - Nmap"
    existing_sources: list = existing_fm.get("sources", [])
    merged_sources = existing_sources if scan_source in existing_sources \
        else existing_sources + [scan_source]

    existing_hostnames: list = existing_fm.get("hostnames", [])
    new_hostnames = [h["name"].strip() for h in host.get("hostnames", []) if h.get("name")]
    merged_hostnames = existing_hostnames + [h for h in new_hostnames if h not in existing_hostnames]

    new_tags = get_tags_from_ports(open_ports)
    merged_tags = sorted(set(existing_fm.get("tags", [])) | set(new_tags))

    fm = {
        "ip":        primary_ip or existing_fm.get("ip"),
        "hostnames": merged_hostnames,
        "status":    existing_fm.get("status", "not-started"),
        "tags":      merged_tags,
        "sources":   merged_sources,
    }

    # ---- Build body ----
    lines: list[str] = [f"**State:** {host.get('state', 'up')}"]
    if primary_ip:
        lines.append(f"**IP:** {primary_ip}")
    lines.append(f"**Open Ports:** {len(open_ports)}")
    lines += ["", "## Open Ports"]

    if open_ports:
        for p in open_ports:
            proto   = p.get("protocol", "tcp")
            port    = p.get("port", 0)
            svc_str = _render_service_str(p)
            lines.append(f"### {proto}/{port} — {svc_str}")
            svc   = p.get("service", {})
            hints = _render_port_hints(
                port,
                svc.get("name", ""),
                svc.get("product", ""),
                svc.get("extrainfo", ""),
            )
            for hint in hints:
                lines.append(f"- {hint}")
            lines.append("")
    else:
        lines += ["_No open ports detected._", ""]

    lines += ["## Scan References"]
    for src in merged_sources:
        src_stem = _safe_filename(src)
        lines.append(f"- [[Scans/{src_stem}|{src}]]")

    # Operator Notes — always last, always preserved
    lines += ["", OPERATOR_NOTES_SENTINEL, OPERATOR_NOTES_HINT]
    if existing_op_notes:
        lines += ["", existing_op_notes]

    body = "\n".join(lines)
    host_path.write_text(write_frontmatter(fm) + "\n" + body, encoding="utf-8")
    return display, host_stem


# ============================================================
# Scan note writing
# ============================================================

def _write_scan_note(
    scan_path: Path,
    scan_display: str,
    scan_data: dict,
    host_entries: list[tuple[str, str, dict]],
    analysis_text: Optional[str],
    model_name: Optional[str],
) -> None:
    """Scan notes are always overwritten — they are fully derived artifacts."""
    lines = [
        f"# {scan_display} — Nmap",
        "",
        f"- **Source:** `{scan_data['source_file']}`",
        f"- **Parsed:** {scan_data['parsed_at']}",
        f"- **Nmap args:** `{scan_data.get('nmap_args', '') or 'unknown'}`",
        "",
        "## Hosts",
        "",
    ]

    for display, host_stem, host in host_entries:
        lines.append(f"### [[Hosts/{host_stem}|{display}]]")
        for p in host.get("open_ports", []):
            lines.append(f"- **{p['protocol']}/{p['port']}** — {_render_service_str(p)}")
        if not host.get("open_ports"):
            lines.append("- No open ports detected")
        lines.append("")

    lines += ["## Analysis", ""]
    if model_name:
        lines.append(f"_Model: {model_name}_\n")
    lines.append(analysis_text or "_No AI analysis generated._")

    scan_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"Wrote scan note: {scan_path.name}")


# ============================================================
# Canvas node / edge constructors
# ============================================================

def _text_node(nid: str, text: str, x: int, y: int, w: int, h: int, color: str | None = None) -> dict:
    n: dict = {"id": nid, "type": "text", "text": text, "x": x, "y": y, "width": w, "height": h}
    if color:
        n["color"] = color
    return n


def _file_node(nid: str, file: str, x: int, y: int, w: int, h: int, color: str | None = None) -> dict:
    n: dict = {"id": nid, "type": "file", "file": file, "x": x, "y": y, "width": w, "height": h}
    if color:
        n["color"] = color
    return n


def _group_node(nid: str, label: str, x: int, y: int, w: int, h: int, color: str | None = None) -> dict:
    n: dict = {"id": nid, "type": "group", "label": label, "x": x, "y": y, "width": w, "height": h}
    if color:
        n["color"] = color
    return n


def _edge(eid: str, from_id: str, to_id: str, label: str = "") -> dict:
    e: dict = {
        "id":       eid,
        "fromNode": from_id,
        "fromSide": "bottom",
        "toNode":   to_id,
        "toSide":   "top",
    }
    if label:
        e["label"] = label
    return e


# ============================================================
# Canvas content helpers
# ============================================================

def _read_host_fm(host_path: Path) -> dict:
    try:
        fm, _ = read_frontmatter(host_path.read_text(encoding="utf-8"))
        return fm
    except Exception:
        return {}


def _build_campaign_overview(
    vault_dir: Path,
    scan_host_map: dict,
    all_analyses: list[tuple[str, str]],
) -> str:
    hosts_dir  = vault_dir / "Hosts"
    host_notes = sorted(hosts_dir.glob("*.md")) if hosts_dir.exists() else []

    total_hosts  = len(host_notes)
    total_scans  = len(scan_host_map)
    status_counts: dict[str, int] = {}
    all_tags: set[str] = set()
    total_ports  = 0

    for hp in host_notes:
        fm = _read_host_fm(hp)
        status = fm.get("status", "not-started")
        status_counts[status] = status_counts.get(status, 0) + 1
        all_tags.update(fm.get("tags", []))
        try:
            _, body = read_frontmatter(hp.read_text(encoding="utf-8"))
            total_ports += sum(
                1 for line in body.splitlines()
                if line.strip().startswith("###") and "—" in line
            )
        except Exception:
            pass

    lines = [
        "# Campaign Overview",
        "",
        f"**Hosts:** {total_hosts}  ·  **Scans:** {total_scans}  ·  **Open Ports:** {total_ports}",
        "",
    ]

    if status_counts:
        parts = [f"{k}: {v}" for k, v in sorted(status_counts.items())]
        lines += [f"**Progress:** {' · '.join(parts)}", ""]

    display_tags = sorted(all_tags - {"rpc"})
    if display_tags:
        lines += [f"**Services seen:** {', '.join(display_tags)}", ""]

    if all_analyses:
        text  = all_analyses[-1][1]
        match = re.search(
            r"##\s+Key Observations(.*?)(?=\n##\s|\Z)", text, re.DOTALL | re.IGNORECASE
        )
        if match:
            bullets = [
                l.strip() for l in match.group(1).splitlines()
                if l.strip().startswith(("-", "*", "•"))
            ][:4]
            if bullets:
                lines += ["**Key Findings:**"] + bullets

    return "\n".join(lines)


def _build_next_steps(all_analyses: list[tuple[str, str]], max_items: int = 14) -> str:
    items: list[str] = []

    for _name, text in all_analyses:
        for section in ("Potential Attack Paths", "Enumeration Suggestions"):
            match = re.search(
                rf"##\s+{re.escape(section)}(.*?)(?=\n##\s|\Z)",
                text, re.DOTALL | re.IGNORECASE,
            )
            if not match:
                continue
            for line in match.group(1).splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                cleaned = re.sub(r"^[-*•\d]+[.)]\s*", "", stripped).strip()
                if cleaned and len(cleaned) > 12 and cleaned not in items:
                    items.append(cleaned)
                if len(items) >= max_items:
                    break
            if len(items) >= max_items:
                break

    if not items:
        return "# Next Steps\n\n_Run an export with AI analysis enabled to populate next steps._"

    return "# Next Steps\n\n" + "\n".join(f"- {item}" for item in items[:max_items])


# ============================================================
# Canvas layout engine
# ============================================================

def _group_dimensions(n_hosts: int, cols: int = 2) -> tuple[int, int]:
    if n_hosts == 0:
        return 300, 200
    actual_cols = min(n_hosts, cols)
    rows    = math.ceil(n_hosts / cols)
    inner_w = actual_cols * CARD_W + (actual_cols - 1) * CARD_GAP_X
    inner_h = rows * CARD_H + (rows - 1) * CARD_GAP_Y
    return GROUP_PAD * 2 + inner_w, GROUP_PAD + GROUP_LABEL_H + inner_h + GROUP_PAD


def build_canvas(
    vault_dir: Path,
    canvas_name: str,
    scan_host_map: dict,
    all_analyses: list[tuple[str, str]],
    canvas_cols: int = 2,
    max_groups_per_row: int = 3,
) -> Path:
    """
    Build (or patch) the Obsidian Canvas file.

    Layout (top → bottom):
      1. Campaign Overview  — aggregated stats and key AI findings
      2. Scan note cards    — one per processed scan
      3. Subnet groups      — /24 groups containing color-coded host cards
      4. Next Steps         — extracted action items from AI analysis

    Nodes the operator added manually (IDs not managed here) are preserved.
    """
    hosts_dir   = vault_dir / "Hosts"
    canvas_path = vault_dir / canvas_name

    existing_canvas: dict = {"nodes": [], "edges": []}
    if canvas_path.exists():
        try:
            existing_canvas = json.loads(canvas_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    managed_ids: set[str] = set()
    our_nodes:   list[dict] = []
    our_edges:   list[dict] = []

    # 1. Campaign Overview
    ov_id = _stable_id("campaign_overview")
    managed_ids.add(ov_id)
    our_nodes.append(_text_node(
        ov_id,
        _build_campaign_overview(vault_dir, scan_host_map, all_analyses),
        -(OVERVIEW_W // 2), -900, OVERVIEW_W, OVERVIEW_H,
    ))

    # 2. Scan cards
    scan_stems    = list(scan_host_map.keys())
    total_scan_w  = len(scan_stems) * SCAN_CARD_W + max(0, len(scan_stems) - 1) * CARD_GAP_X
    scan_row_x0   = -(total_scan_w // 2)
    scan_row_y    = -900 + OVERVIEW_H + 100
    scan_node_ids: dict[str, str] = {}

    for i, scan_stem in enumerate(scan_stems):
        sid = _stable_id(f"scan_{scan_stem}")
        managed_ids.add(sid)
        scan_node_ids[scan_stem] = sid
        sx  = scan_row_x0 + i * (SCAN_CARD_W + CARD_GAP_X)
        rel = f"Scans/{_ensure_md(scan_stem)}"
        our_nodes.append(_file_node(sid, rel, sx, scan_row_y, SCAN_CARD_W, SCAN_CARD_H))

        eid = _stable_id(f"edge_overview_{sid}")
        managed_ids.add(eid)
        our_edges.append(_edge(eid, ov_id, sid))

    # 3. Subnet groups
    subnet_hosts: dict[str, list[tuple[str, Path]]] = {}
    if hosts_dir.exists():
        for hp in sorted(hosts_dir.glob("*.md")):
            fm     = _read_host_fm(hp)
            ip     = fm.get("ip")
            subnet = _get_subnet_label(ip) if ip and _is_ipv4(str(ip)) else "unknown"
            subnet_hosts.setdefault(subnet, []).append((hp.stem, hp))

    subnets = sorted(subnet_hosts.keys())
    gdims   = [_group_dimensions(len(subnet_hosts[s]), canvas_cols) for s in subnets]

    cur_y = scan_row_y + SCAN_CARD_H + ROW_GAP
    group_positions: list[tuple[int, int]] = []

    for row_i in range(math.ceil(len(subnets) / max_groups_per_row) if subnets else 0):
        start = row_i * max_groups_per_row
        end   = min(start + max_groups_per_row, len(subnets))
        row_total_w = sum(gdims[j][0] for j in range(start, end)) + (end - start - 1) * GROUP_GAP
        row_height  = max((gdims[j][1] for j in range(start, end)), default=200)
        x = -(row_total_w // 2)
        for j in range(start, end):
            group_positions.append((x, cur_y))
            x += gdims[j][0] + GROUP_GAP
        cur_y += row_height + ROW_GAP

    host_node_ids: dict[str, str] = {}

    for i, subnet in enumerate(subnets):
        if i >= len(group_positions):
            break
        gx, gy = group_positions[i]
        gw, gh = gdims[i]
        gid = _stable_id(f"subnet_{subnet}")
        managed_ids.add(gid)
        our_nodes.append(_group_node(gid, subnet, gx, gy, gw, gh))

        for j, (host_stem, hp) in enumerate(subnet_hosts[subnet]):
            col = j % canvas_cols
            row = j // canvas_cols
            hx  = gx + GROUP_PAD + col * (CARD_W + CARD_GAP_X)
            hy  = gy + GROUP_PAD + GROUP_LABEL_H + row * (CARD_H + CARD_GAP_Y)
            hid = _stable_id(f"host_{host_stem}")
            managed_ids.add(hid)
            host_node_ids[host_stem] = hid

            fm    = _read_host_fm(hp)
            color = STATUS_COLORS.get(fm.get("status", "not-started"))
            rel   = f"Hosts/{_ensure_md(host_stem)}"
            our_nodes.append(_file_node(hid, rel, hx, hy, CARD_W, CARD_H, color))

    # Scan → host edges
    for scan_stem, host_stems in scan_host_map.items():
        sid = scan_node_ids.get(scan_stem)
        if not sid:
            continue
        for host_stem in host_stems:
            hid = host_node_ids.get(host_stem)
            if not hid:
                continue
            eid = _stable_id(f"edge_{sid}_{hid}")
            managed_ids.add(eid)
            our_edges.append(_edge(eid, sid, hid))

    # 4. Next Steps
    ns_id = _stable_id("next_steps")
    managed_ids.add(ns_id)
    our_nodes.append(_text_node(
        ns_id,
        _build_next_steps(all_analyses),
        -(NEXT_STEPS_W // 2), cur_y + 40,
        NEXT_STEPS_W, NEXT_STEPS_H,
        color="5",
    ))

    # Preserve operator-added nodes; replace our managed ones
    preserved = [n for n in existing_canvas.get("nodes", []) if n.get("id") not in managed_ids]
    canvas_path.write_text(
        json.dumps({"nodes": preserved + our_nodes, "edges": our_edges}, indent=2),
        encoding="utf-8",
    )
    logger.info(
        f"Canvas written: {canvas_path.name} "
        f"({len(preserved) + len(our_nodes)} nodes, {len(our_edges)} edges, "
        f"{len(preserved)} preserved)"
    )
    return canvas_path


# ============================================================
# Main entry point (called by syd.py — signature must not change)
# ============================================================

def export_to_obsidian(
    vault_dir: Path,
    scan_data: dict,
    scan_name: str,
    analysis_text: Optional[str] = None,
    model_name: Optional[str] = None,
    canvas_name: str = CANVAS_FILENAME,
) -> dict:
    """
    Full export pipeline:
      1. Create vault directory structure
      2. Write / merge host notes (frontmatter + Operator Notes preserved)
      3. Write scan note
      4. Rebuild canvas (single pane of glass)

    Returns a result dict consumed by syd.py's Report Builder UI:
      vault_dir, scan_note, canvas, hosts_created, hosts_updated, total_hosts
    """
    logger.info(f"Starting Obsidian export → {vault_dir}")

    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "Hosts").mkdir(exist_ok=True)
    (vault_dir / "Scans").mkdir(exist_ok=True)

    hosts = scan_data.get("hosts", [])

    scan_display = scan_name
    if len(hosts) == 1:
        scan_display = _choose_display_name(hosts[0])

    scan_stem = _safe_filename(f"{scan_display} - Nmap")
    scan_path = vault_dir / "Scans" / _ensure_md(scan_stem)

    host_entries: list[tuple[str, str, dict]] = []
    hosts_created = 0
    hosts_updated = 0

    for host in hosts:
        host_path = vault_dir / "Hosts" / _ensure_md(_safe_filename(_choose_display_name(host)))
        existed   = host_path.exists()
        display, host_stem = _write_host_note(vault_dir / "Hosts", host, scan_stem, scan_display)
        host_entries.append((display, host_stem, host))
        if existed:
            hosts_updated += 1
        else:
            hosts_created += 1

    _write_scan_note(scan_path, scan_display, scan_data, host_entries, analysis_text, model_name)

    scan_host_map = {scan_stem: [stem for _, stem, _ in host_entries]}
    all_analyses  = [(scan_display, analysis_text)] if analysis_text else []

    build_canvas(vault_dir, canvas_name, scan_host_map, all_analyses)

    canvas_path = vault_dir / canvas_name
    result = {
        "vault_dir":     str(vault_dir),
        "scan_note":     str(scan_path),
        "canvas":        str(canvas_path),
        "hosts_created": hosts_created,
        "hosts_updated": hosts_updated,
        "total_hosts":   len(hosts),
    }

    logger.info(
        f"Export complete — {hosts_created} created, {hosts_updated} updated, "
        f"scan note: {scan_path.name}"
    )
    return result
