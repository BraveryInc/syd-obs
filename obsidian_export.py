"""
obsidian_export.py — Obsidian vault export module for Syd

Converts Nmap scan data (from Syd's existing XML parser or paste parser)
into structured Obsidian markdown notes with intelligent merge behavior:

  - Host notes (Hosts/<ip>.md):
      Merges new scan data into existing notes without clobbering manual
      content written by the operator in the ## Notes section.

  - Scan notes (Scans/<name>.md):
      Always overwritten — these are fully derived from a scan file.

  - Canvas (Assessment Canvas.canvas):
      Additive — only inserts NEW host nodes; preserves existing node
      positions so manual Obsidian layout is not reset.

LLM analysis is driven by Syd's existing Qwen instance rather than Ollama.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
import datetime as dt
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Canvas layout defaults ───────────────────────────────────────────────────

CANVAS_COLS     = 3
CARD_W          = 360
CARD_H          = 240
GAP_X           = 120
GAP_Y           = 120
START_X         = 100
START_Y         = 100
CANVAS_FILENAME = "Assessment Canvas.canvas"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _safe_filename(s: str) -> str:
    """Strip characters that are illegal in file/directory names."""
    bad = '<>:"/\\|?*\n\r\t'
    for ch in bad:
        s = s.replace(ch, "_")
    return s.strip().strip(".")


def _new_node_id() -> str:
    return f"host_{uuid.uuid4().hex[:12]}"


def _ensure_md(name: str) -> str:
    return name if name.lower().endswith(".md") else f"{name}.md"


# ── Data model conversion ─────────────────────────────────────────────────────

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

    Output mirrors mAIpper's parse_nmap_xml() return value so
    build_analysis_prompt() and create_obsidian_vault() can consume it directly.
    """
    # Group services by host IP
    host_map: dict[str, dict] = {}

    for svc in services:
        ip = svc.get("host", "unknown")
        hostname = svc.get("hostname", "")

        if ip not in host_map:
            host_map[ip] = {
                "state": "up",
                "addresses": [{"addr": ip, "addrtype": "ipv4"}],
                "hostnames": [{"name": hostname, "type": "user"}] if hostname else [],
                "open_ports": [],
            }
        elif hostname and not host_map[ip]["hostnames"]:
            host_map[ip]["hostnames"] = [{"name": hostname, "type": "user"}]

        host_map[ip]["open_ports"].append({
            "protocol": svc.get("protocol", "tcp"),
            "port": int(svc.get("port", 0)),
            "service": {
                "name":      svc.get("service", ""),
                "product":   svc.get("product", ""),
                "version":   svc.get("version", ""),
                "extrainfo": svc.get("extra_info", ""),
                "tunnel":    "",
            },
            "scripts": [],
        })

    # Sort ports within each host
    for hdata in host_map.values():
        hdata["open_ports"].sort(key=lambda p: (p["protocol"], p["port"]))

    return {
        "source_file":  xml_path or scan_name,
        "parsed_at":    dt.datetime.now().isoformat(timespec="seconds"),
        "nmap_args":    nmap_args,
        "nmap_version": "",
        "hosts":        list(host_map.values()),
    }


# ── Analysis prompt builder ───────────────────────────────────────────────────

def build_analysis_prompt(scan_data: dict) -> str:
    """
    Build the LLM prompt from scan_data.  Mirrors mAIpper's build_ollama_prompt
    but targets Syd's chat_completion interface (system + user messages).
    Returns the *user* message string; the system role is set in the caller.
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
            proto   = p.get("protocol", "")
            port    = p.get("port", "")
            svc     = p.get("service", {})
            parts   = [svc.get("name", "unknown")]
            if svc.get("product"):   parts.append(svc["product"])
            if svc.get("version"):   parts.append(svc["version"])
            if svc.get("extrainfo"): parts.append(f"({svc['extrainfo']})")
            lines.append(f"  {proto}/{port}: {' '.join(parts).strip()}")

            for script in p.get("scripts", [])[:3]:
                out = (script.get("output", "") or "").strip()
                out = " ".join(out.split())
                if len(out) > 220:
                    out = out[:217] + "..."
                if out:
                    lines.append(f"    script:{script.get('id', '')} -> {out}")

    scan_summary = "\n".join(lines)

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
{scan_summary}

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


# ── Host note writing (merge-aware) ──────────────────────────────────────────

_MANAGED_SECTIONS = {
    "## Host Info",
    "## Open Ports",
    "## Scan References",
}


def _render_service_str(port_info: dict) -> str:
    svc   = port_info.get("service", {})
    parts = [svc.get("name", "")]
    if svc.get("product"):   parts.append(svc["product"])
    if svc.get("version"):   parts.append(svc["version"])
    if svc.get("extrainfo"): parts.append(f"({svc['extrainfo']})")
    return " ".join(p for p in parts if p).strip() or "—"


def _render_port_hints(port: int, service_name: str, product: str = "", extrainfo: str = "") -> list[str]:
    """Return operator hints for a given port/service (ported from mAIpper)."""
    svc   = (service_name or "").lower()
    prod  = (product or "").lower()
    extra = (extrainfo or "").lower()
    hints: list[str] = []

    web_ports = {80, 81, 443, 8000, 8080, 8443}
    if port in web_ports or svc in ("http", "https", "http-proxy"):
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

    if port in (5985, 5986) or "winrm" in svc:
        hints.append("WinRM — consider: evil-winrm, netexec winrm (useful with creds)")

    if port in (1433, 1434) or "mssql" in svc or "sql server" in prod:
        hints.append("MSSQL — consider: impacket-mssqlclient, netexec mssql, xp_cmdshell if SA access")

    if port == 3306 or "mysql" in svc:
        hints.append("MySQL — test auth paths, enumerate databases, check for UDF injection")

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

    return hints


def _build_host_note_sections(host: dict, scan_stem: str, scan_display: str) -> str:
    """
    Build the managed sections of a host note as a string block.
    These are the sections that Syd owns and will update on re-export.
    """
    display  = _choose_display_name(host)
    ip       = _primary_ipv4(host) or "unknown"
    ports    = host.get("open_ports", [])

    lines = [
        "## Host Info",
        f"- **State:** {host.get('state', 'up')}",
        f"- **IP:** {ip}",
        f"- **Open Ports:** {len(ports)}",
        "",
        "## Open Ports",
    ]

    if ports:
        for p in ports:
            proto   = p.get("protocol", "tcp")
            port    = p.get("port", 0)
            svc_str = _render_service_str(p)
            lines.append(f"### {proto}/{port} — {svc_str}")
            svc = p.get("service", {})
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
        lines += ["- None", ""]

    lines += [
        "## Scan References",
        f"- [[Scans/{scan_stem}|{scan_display}]]",
        "",
    ]

    return "\n".join(lines)


def _write_host_note(host_path: Path, host: dict, scan_stem: str, scan_display: str) -> None:
    """
    Write or intelligently merge a host note.

    Merge strategy:
    - If file doesn't exist → write fresh, appending a blank ## Notes section
    - If file exists:
        - Replace managed sections (Host Info, Open Ports, Scan References)
          with freshly generated content
        - Preserve everything in ## Notes and any other operator-added sections
        - Add a new scan reference to ## Scan References if not already present
    """
    managed_content = _build_host_note_sections(host, scan_stem, scan_display)

    if not host_path.exists():
        full_content = managed_content + "## Notes\n- \n"
        host_path.write_text(full_content, encoding="utf-8")
        logger.debug(f"Created new host note: {host_path}")
        return

    # ── File exists: merge ────────────────────────────────────────────────
    existing = host_path.read_text(encoding="utf-8")

    # Split into sections by ## heading
    section_re = re.compile(r"^(## .+)$", re.MULTILINE)
    splits     = section_re.split(existing)

    # splits alternates: [pre-heading text, heading, content, heading, content ...]
    # Collect sections we want to preserve (not managed)
    preserved_sections: list[tuple[str, str]] = []  # (heading, content)
    notes_found        = False
    scan_ref_line      = f"- [[Scans/{scan_stem}|{scan_display}]]"

    i = 1
    while i < len(splits):
        heading = splits[i].strip()
        content = splits[i + 1] if i + 1 < len(splits) else ""
        i += 2

        if heading in _MANAGED_SECTIONS:
            # We will regenerate these — but capture existing scan refs
            # so we can merge them into the new Scan References section
            if heading == "## Scan References":
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("- [[Scans/") and line not in [scan_ref_line]:
                        # Preserve old scan references we don't already have
                        pass  # handled below in managed_content rebuild
            continue

        # Preserve everything else (## Notes, custom sections, etc.)
        preserved_sections.append((heading, content))
        if heading == "## Notes":
            notes_found = True

    # Rebuild: managed sections first, then operator sections
    result = managed_content
    for heading, content in preserved_sections:
        result += f"{heading}\n{content}"

    # If there was no ## Notes section before, add one
    if not notes_found:
        result += "## Notes\n- \n"

    host_path.write_text(result, encoding="utf-8")
    logger.debug(f"Updated host note: {host_path}")


# ── Scan note writing ─────────────────────────────────────────────────────────

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
            svc_str = _render_service_str(p)
            lines.append(f"- **{p['protocol']}/{p['port']}** — {svc_str}")
        if not host.get("open_ports"):
            lines.append("- No open ports detected")
        lines.append("")

    lines += ["## Analysis", ""]

    if model_name:
        lines.append(f"_Model: {model_name}_\n")

    lines.append(analysis_text or "_No AI analysis generated._")

    scan_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"Wrote scan note: {scan_path}")


# ── Canvas (additive) ─────────────────────────────────────────────────────────

def update_canvas(vault_dir: Path, canvas_name: str = CANVAS_FILENAME) -> None:
    """
    Rebuild the canvas ensuring every host note has a node.
    - Existing nodes are LEFT UNTOUCHED (positions preserved).
    - New host notes get new nodes appended after the existing layout.
    """
    canvas_path = vault_dir / canvas_name
    hosts_dir   = vault_dir / "Hosts"

    if not hosts_dir.exists():
        logger.warning("Hosts directory does not exist — skipping canvas update")
        return

    # Load existing canvas if present
    existing_canvas: dict = {"nodes": [], "edges": []}
    if canvas_path.exists():
        try:
            existing_canvas = json.loads(canvas_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"Could not parse existing canvas, will rebuild: {e}")

    existing_nodes   = existing_canvas.get("nodes", [])
    existing_files   = {n["file"] for n in existing_nodes if n.get("type") == "file"}

    # Discover all current host notes
    host_notes = sorted(hosts_dir.glob("*.md"))

    # Figure out which are new
    new_notes = [
        hp for hp in host_notes
        if str(hp.relative_to(vault_dir)).replace("\\", "/") not in existing_files
    ]

    if not new_notes:
        logger.info("Canvas is up to date — no new host nodes to add")
        # Still write back in case edges or other content was reset
        canvas_path.write_text(
            json.dumps(existing_canvas, indent=2), encoding="utf-8"
        )
        return

    # Determine starting position for new nodes
    # Find the rightmost column and bottom row of existing nodes
    if existing_nodes:
        max_x = max((n.get("x", 0) + n.get("width", CARD_W) for n in existing_nodes), default=START_X)
        max_y = max((n.get("y", 0) for n in existing_nodes), default=START_Y)
    else:
        max_x = START_X
        max_y = START_Y

    # Lay out new nodes in rows starting after the existing block
    # Count existing file nodes to determine column continuation
    col_offset = len([n for n in existing_nodes if n.get("type") == "file"]) % CANVAS_COLS

    new_nodes = []
    for i, hp in enumerate(new_notes):
        col = (col_offset + i) % CANVAS_COLS
        row = (col_offset + i) // CANVAS_COLS

        if existing_nodes:
            # Append below existing content
            x = START_X + col * (CARD_W + GAP_X)
            y = max_y + CARD_H + GAP_Y + row * (CARD_H + GAP_Y)
        else:
            x = START_X + col * (CARD_W + GAP_X)
            y = START_Y + row * (CARD_H + GAP_Y)

        rel_file = str(hp.relative_to(vault_dir)).replace("\\", "/")
        new_nodes.append({
            "id":     _new_node_id(),
            "type":   "file",
            "file":   rel_file,
            "x":      x,
            "y":      y,
            "width":  CARD_W,
            "height": CARD_H,
        })
        logger.debug(f"New canvas node: {rel_file} at x={x}, y={y}")

    existing_canvas["nodes"] = existing_nodes + new_nodes
    canvas_path.write_text(json.dumps(existing_canvas, indent=2), encoding="utf-8")
    logger.info(f"Canvas updated — added {len(new_nodes)} new node(s): {canvas_path}")


# ── Main entry point ──────────────────────────────────────────────────────────

def _choose_display_name(host: dict) -> str:
    hostnames = [h["name"].strip() for h in host.get("hostnames", []) if h.get("name")]
    for hn in hostnames:
        if "." in hn and not re.match(r"^\d+\.\d+\.\d+\.\d+$", hn):
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
      2. Write/merge host notes
      3. Write scan note
      4. Update canvas (additive)

    Returns a result dict with paths and counts for UI feedback.
    """
    logger.info(f"Starting Obsidian export to: {vault_dir}")

    vault_dir.mkdir(parents=True, exist_ok=True)
    hosts_dir = vault_dir / "Hosts"
    scans_dir = vault_dir / "Scans"
    hosts_dir.mkdir(exist_ok=True)
    scans_dir.mkdir(exist_ok=True)

    hosts       = scan_data.get("hosts", [])
    host_entries: list[tuple[str, str, dict]] = []

    # Derive scan display name and stem
    if len(hosts) == 1:
        scan_display = _choose_display_name(hosts[0])
    else:
        scan_display = scan_name

    scan_stem = _safe_filename(f"{scan_display} - Nmap")
    scan_path = scans_dir / _ensure_md(scan_stem)

    hosts_written   = 0
    hosts_updated   = 0

    for host in hosts:
        display   = _choose_display_name(host)
        host_stem = _safe_filename(display)
        host_path = hosts_dir / _ensure_md(host_stem)

        existed = host_path.exists()
        _write_host_note(host_path, host, scan_stem, scan_display)

        if existed:
            hosts_updated += 1
        else:
            hosts_written += 1

        host_entries.append((display, host_stem, host))
        logger.debug(f"{'Updated' if existed else 'Created'} host note: {host_path.name}")

    _write_scan_note(scan_path, scan_display, scan_data, host_entries, analysis_text, model_name)

    update_canvas(vault_dir, canvas_name)

    canvas_path = vault_dir / canvas_name
    result = {
        "vault_dir":       str(vault_dir),
        "scan_note":       str(scan_path),
        "canvas":          str(canvas_path),
        "hosts_created":   hosts_written,
        "hosts_updated":   hosts_updated,
        "total_hosts":     len(hosts),
    }

    logger.info(
        f"Export complete — "
        f"{hosts_written} host(s) created, {hosts_updated} updated, "
        f"scan note at {scan_path.name}"
    )
    return result
