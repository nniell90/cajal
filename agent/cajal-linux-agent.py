#!/usr/bin/env python3
"""Cajal Linux collector agent.

This agent phones home to Cajal, polls for read-only troubleshooting commands,
executes a restricted command set locally, and returns output.
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

AGENT_VERSION = "1.0.1"
DEFAULT_POLL_INTERVAL_SEC = 1.5
MAX_OUTPUT_LINES = 140
MAX_OUTPUT_LINE_CHARS = 700
HOST_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")
PING_LATENCY_PATTERN = re.compile(r"=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+")
SPEEDTEST_AUTH_REQUIRED_PATTERN = re.compile(
    r"auth(?:entication)?\s+required|login\s+required|no\s+tokens?\s+found|permission\s+denied",
    re.IGNORECASE,
)
SPEEDTEST_BACKEND_CANDIDATES = (
    {"cmd": "speedtest-cli", "args": ["--json"]},
    {"cmd": "speedtest", "args": ["--accept-license", "--accept-gdpr", "--format=json"]},
)
LAST_SPEEDTEST_BACKEND = ""
IP_ROUTE_SRC_PATTERN = re.compile(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b")
IP_ROUTE_DEV_PATTERN = re.compile(r"\bdev\s+([A-Za-z0-9_.:-]+)\b")
IP_ADDR_ROW_PATTERN = re.compile(r"^\d+:\s+([^\s:]+).*?\binet\s+(\d+\.\d+\.\d+\.\d+)/\d+")
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
VIRTUAL_IFACE_PREFIXES = (
    "docker",
    "br-",
    "veth",
    "cni",
    "flannel",
    "virbr",
    "zt",
    "tailscale",
    "tun",
    "tap",
    "wg",
)
PHYSICAL_IFACE_PREFIXES = ("eth", "en", "wl", "ww", "bond", "team")


class ApiError(Exception):
    def __init__(self, status_code, message):
        super().__init__(message)
        self.status_code = int(status_code)


def safe_host(value):
    host = str(value or "").strip()
    if not host:
        return ""
    if not HOST_PATTERN.fullmatch(host):
        return ""
    return host


def is_non_loopback_ipv4(value):
    ip = str(value or "").strip()
    if not ip:
        return False
    try:
        socket.inet_aton(ip)
    except OSError:
        return False
    if ip.startswith("127.") or ip == "0.0.0.0":
        return False
    return True


def detect_primary_local_ipv4():
    candidates = []
    probes = [("8.8.8.8", 53), ("1.1.1.1", 53)]

    for host, port in probes:
        route_ip, route_iface = probe_linux_route_source(host)
        if is_non_loopback_ipv4(route_ip):
            candidates.append((route_ip, route_iface))

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((host, port))
            ip = str(sock.getsockname()[0] or "").strip()
            if is_non_loopback_ipv4(ip):
                candidates.append((ip, ""))
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    candidates.extend(list_linux_global_ipv4_candidates())

    try:
        hostname = socket.gethostname() or ""
        rows = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_DGRAM)
        for row in rows:
            sockaddr = row[4] if len(row) > 4 else ()
            ip = str(sockaddr[0] if sockaddr else "").strip()
            if is_non_loopback_ipv4(ip):
                candidates.append((ip, ""))
    except Exception:
        pass

    best_ip = ""
    best_score = -10_000
    for ip, iface in candidates:
        score = score_local_ipv4_candidate(ip, iface)
        if score > best_score:
            best_score = score
            best_ip = ip
    return best_ip


def is_virtual_iface(name):
    iface = str(name or "").strip().lower()
    if not iface:
        return False
    for prefix in VIRTUAL_IFACE_PREFIXES:
        if iface.startswith(prefix):
            return True
    return False


def score_local_ipv4_candidate(ip, iface=""):
    if not is_non_loopback_ipv4(ip):
        return -10_000
    score = 100
    text = str(ip or "").strip()
    if text.startswith("169.254."):
        score -= 90

    iface_name = str(iface or "").strip().lower()
    if iface_name:
        # De-prioritize container/overlay bridge networks in favor of real NICs.
        if is_virtual_iface(iface_name):
            score -= 80
        else:
            score += 30
        for prefix in PHYSICAL_IFACE_PREFIXES:
            if iface_name.startswith(prefix):
                score += 20
                break
    return score


def probe_linux_route_source(target):
    host = str(target or "").strip()
    if not host:
        return ("", "")
    try:
        completed = subprocess.run(
            ["ip", "-4", "route", "get", host],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
    except Exception:
        return ("", "")
    if completed.returncode != 0:
        return ("", "")
    text = str(completed.stdout or "").strip()
    src_match = IP_ROUTE_SRC_PATTERN.search(text)
    dev_match = IP_ROUTE_DEV_PATTERN.search(text)
    src_ip = str(src_match.group(1) if src_match else "").strip()
    iface = str(dev_match.group(1) if dev_match else "").strip()
    if not is_non_loopback_ipv4(src_ip):
        return ("", "")
    return (src_ip, iface)


def list_linux_global_ipv4_candidates():
    rows = []
    try:
        completed = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
    except Exception:
        return rows
    if completed.returncode != 0:
        return rows
    for raw in str(completed.stdout or "").splitlines():
        match = IP_ADDR_ROW_PATTERN.search(raw.strip())
        if not match:
            continue
        iface = str(match.group(1) or "").strip()
        ip = str(match.group(2) or "").strip()
        if is_non_loopback_ipv4(ip):
            rows.append((ip, iface))
    return rows


def clip_line(value):
    text = str(value or "").replace("\r", "")
    if len(text) > MAX_OUTPUT_LINE_CHARS:
        return text[:MAX_OUTPUT_LINE_CHARS] + "...[truncated]"
    return text


def split_lines(*chunks):
    rows = []
    for chunk in chunks:
        text = str(chunk or "")
        for row in text.splitlines():
            line = clip_line(row.rstrip())
            if line:
                rows.append(line)
    return rows


def clip_lines(lines):
    clean = [clip_line(line) for line in (lines or []) if str(line or "").strip()]
    if not clean:
        return ["(no output)"]
    return clean[-MAX_OUTPUT_LINES:]


def parse_speedtest_json(raw_stdout):
    text = str(raw_stdout or "").strip()
    if not text:
        return (None, None)
    try:
        payload = json.loads(text)
        down_bps = 0.0
        up_bps = 0.0
        # Ookla speedtest JSON: download.bandwidth/upload.bandwidth are bytes/sec.
        if isinstance(payload.get("download"), dict) and isinstance(payload.get("upload"), dict):
            down_bps = float(payload.get("download", {}).get("bandwidth", 0.0)) * 8.0
            up_bps = float(payload.get("upload", {}).get("bandwidth", 0.0)) * 8.0
        # speedtest-cli JSON: download/upload are already bits/sec.
        elif "download" in payload and "upload" in payload:
            down_bps = float(payload.get("download", 0.0))
            up_bps = float(payload.get("upload", 0.0))
        down_mbps = round(down_bps / 1000000.0, 1) if down_bps > 0 else None
        up_mbps = round(up_bps / 1000000.0, 1) if up_bps > 0 else None
        return (down_mbps, up_mbps)
    except Exception:
        return (None, None)


def parse_speedtest_public_ip(raw_stdout):
    text = str(raw_stdout or "").strip()
    if not text:
        return ""
    try:
        payload = json.loads(text)
    except Exception:
        return ""

    candidates = [
        payload.get("interface", {}).get("externalIp") if isinstance(payload.get("interface"), dict) else "",
        payload.get("client", {}).get("ip") if isinstance(payload.get("client"), dict) else "",
        payload.get("interface", {}).get("ip") if isinstance(payload.get("interface"), dict) else "",
    ]
    for candidate in candidates:
        ip = str(candidate or "").strip()
        if not ip:
            continue
        try:
            socket.inet_aton(ip)
            return ip
        except OSError:
            continue
    return ""


def is_public_ipv4(value):
    text = str(value or "").strip()
    if not text:
        return False
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return False
    return parsed.version == 4 and parsed.is_global


def parse_public_ipv4_from_text(raw_text):
    text = str(raw_text or "")
    if not text:
        return ""
    matches = IPV4_PATTERN.findall(text)
    for candidate in reversed(matches):
        if is_public_ipv4(candidate):
            return candidate
    return ""


def parse_ping_latency(stdout):
    match = PING_LATENCY_PATTERN.search(str(stdout or ""))
    if not match:
        return None
    try:
        return round(float(match.group(1)), 1)
    except Exception:
        return None


def run_exec_candidates(candidates, timeout_sec=15):
    last_error = None
    for entry in candidates:
        cmd = str(entry.get("cmd") or "").strip()
        args = [str(arg) for arg in entry.get("args") or []]
        if not cmd:
            continue
        try:
            completed = subprocess.run(
                [cmd] + args,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=False,
            )
            return {
                "ok": completed.returncode == 0,
                "exit_code": int(completed.returncode),
                "cmdline": " ".join([cmd] + args),
                "stdout": completed.stdout or "",
                "stderr": completed.stderr or "",
            }
        except FileNotFoundError:
            last_error = {
                "ok": False,
                "exit_code": 127,
                "cmdline": " ".join([cmd] + args),
                "stdout": "",
                "stderr": f"{cmd}: not found",
            }
            continue
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "exit_code": 124,
                "cmdline": " ".join([cmd] + args),
                "stdout": "",
                "stderr": "command timed out",
            }
        except Exception as exc:
            return {
                "ok": False,
                "exit_code": 1,
                "cmdline": " ".join([cmd] + args),
                "stdout": "",
                "stderr": str(exc),
            }
    if last_error is not None:
        return last_error
    return {
        "ok": False,
        "exit_code": 127,
        "cmdline": "",
        "stdout": "",
        "stderr": "no executable candidate configured",
    }


def format_exec_result(label, result):
    lines = []
    cmdline = str(result.get("cmdline") or "").strip()
    if label:
        lines.append(f"$ {label}")
    if cmdline and cmdline != label:
        lines.append(f"exec: {cmdline}")
    lines.extend(split_lines(result.get("stdout")))
    stderr_rows = split_lines(result.get("stderr"))
    if stderr_rows:
        lines.extend([f"stderr: {row}" for row in stderr_rows])
    if not lines:
        lines = ["(no output)"]
    return clip_lines(lines)


def run_ping(host):
    target = safe_host(host)
    if not target:
        return {"ok": False, "exitCode": 1, "lines": ["Usage: ping [host]"]}
    result = run_exec_candidates(
        [{"cmd": "ping", "args": ["-c", "3", "-W", "1", target]}],
        timeout_sec=12,
    )
    return {
        "ok": bool(result.get("ok")),
        "exitCode": int(result.get("exit_code", 1)),
        "lines": format_exec_result(f"ping {target}", result),
    }


def run_traceroute(host):
    target = safe_host(host)
    if not target:
        return {"ok": False, "exitCode": 1, "lines": ["Usage: traceroute [host]"]}
    result = run_exec_candidates(
        [
            {"cmd": "traceroute", "args": ["-n", "-m", "8", "-w", "1", target]},
            {"cmd": "tracepath", "args": ["-n", "-m", "8", target]},
        ],
        timeout_sec=20,
    )
    return {
        "ok": bool(result.get("ok")),
        "exitCode": int(result.get("exit_code", 1)),
        "lines": format_exec_result(f"traceroute {target}", result),
    }


def run_dns(host):
    target = safe_host(host)
    if not target:
        return {"ok": False, "exitCode": 1, "lines": ["Usage: dns [hostname]"]}
    result = run_exec_candidates(
        [
            {"cmd": "nslookup", "args": [target]},
            {"cmd": "getent", "args": ["hosts", target]},
            {"cmd": "dig", "args": ["+short", target]},
        ],
        timeout_sec=15,
    )
    return {
        "ok": bool(result.get("ok")),
        "exitCode": int(result.get("exit_code", 1)),
        "lines": format_exec_result(f"dns {target}", result),
    }


def run_ipconfig(interface_name=""):
    iface = safe_host(interface_name)
    if interface_name and not iface:
        return {"ok": False, "exitCode": 1, "lines": ["Usage: ipconfig [interface]"]}
    if iface:
        candidates = [
            {"cmd": "ip", "args": ["-brief", "addr", "show", "dev", iface]},
            {"cmd": "ip", "args": ["addr", "show", "dev", iface]},
            {"cmd": "ifconfig", "args": [iface]},
        ]
        label = f"ipconfig {iface}"
    else:
        candidates = [
            {"cmd": "ip", "args": ["-brief", "address"]},
            {"cmd": "ip", "args": ["addr", "show"]},
            {"cmd": "ifconfig", "args": ["-a"]},
        ]
        label = "ipconfig"
    result = run_exec_candidates(candidates, timeout_sec=15)
    return {
        "ok": bool(result.get("ok")),
        "exitCode": int(result.get("exit_code", 1)),
        "lines": format_exec_result(label, result),
    }


def ordered_speedtest_candidates():
    preferred = str(LAST_SPEEDTEST_BACKEND or "").strip().lower()
    installed = []
    missing = []
    preferred_entry = None
    for candidate in SPEEDTEST_BACKEND_CANDIDATES:
        cmd = str(candidate.get("cmd") or "").strip()
        if not cmd:
            continue
        if cmd.lower() == preferred:
            preferred_entry = candidate
            continue
        if shutil.which(cmd):
            installed.append(candidate)
        else:
            missing.append(candidate)
    ordered = []
    if preferred_entry is not None:
        preferred_cmd = str(preferred_entry.get("cmd") or "").strip()
        if preferred_cmd and shutil.which(preferred_cmd):
            ordered.append(preferred_entry)
        else:
            missing.insert(0, preferred_entry)
    ordered.extend(installed)
    ordered.extend(missing)
    return ordered


def run_speedtest(target):
    host = safe_host(target or "8.8.8.8") or "8.8.8.8"
    speed_candidates = ordered_speedtest_candidates()
    speed_result = None
    down_mbps = None
    up_mbps = None
    public_ip = ""
    failure_notes = []
    auth_required = False
    global LAST_SPEEDTEST_BACKEND
    for candidate in speed_candidates:
        result = run_exec_candidates([candidate], timeout_sec=35)
        candidate_down, candidate_up = parse_speedtest_json(result.get("stdout"))
        candidate_public_ip = parse_speedtest_public_ip(result.get("stdout"))
        if candidate_down is not None or candidate_up is not None:
            speed_result = result
            down_mbps = candidate_down
            up_mbps = candidate_up
            public_ip = candidate_public_ip
            LAST_SPEEDTEST_BACKEND = str(candidate.get("cmd") or "").strip().lower()
            break

        exit_code = int(result.get("exit_code", 1))
        stderr_text = str(result.get("stderr") or "").strip()
        if exit_code == 127:
            reason = "not installed"
        else:
            reason = stderr_text.splitlines()[0] if stderr_text else "unknown execution error"
        cmdline = str(result.get("cmdline") or candidate.get("cmd") or "speedtest").strip()
        failure_notes.append(f"{cmdline}: {reason}")
        diag_text = "\n".join(
            [
                str(result.get("stdout") or ""),
                str(result.get("stderr") or ""),
                reason,
            ]
        )
        if SPEEDTEST_AUTH_REQUIRED_PATTERN.search(diag_text):
            auth_required = True
        speed_result = result

    if speed_result is None:
        speed_result = {"ok": False, "exit_code": 1, "cmdline": "", "stdout": "", "stderr": ""}
    ping_result = run_exec_candidates(
        [{"cmd": "ping", "args": ["-c", "3", "-W", "1", host]}],
        timeout_sec=12,
    )
    latency_ms = parse_ping_latency(ping_result.get("stdout"))
    has_data = down_mbps is not None or up_mbps is not None or latency_ms is not None
    lines = [
        f"Speed test snapshot for target {host}",
        f"down={down_mbps if down_mbps is not None else 'n/a'} Mbps up={up_mbps if up_mbps is not None else 'n/a'} Mbps latency={latency_ms if latency_ms is not None else 'n/a'} ms",
    ]
    backend_cmdline = str(speed_result.get("cmdline") or "").strip()
    if backend_cmdline:
        lines.append(f"speedtest backend: {backend_cmdline}")
    if public_ip:
        lines.append(f"public_ip={public_ip}")
    if down_mbps is None and up_mbps is None:
        if auth_required:
            lines.append("Throughput test needs speedtest auth on this host; latency check still ran.")
            lines.append("Install speedtest-cli for non-interactive throughput tests: sudo apt-get install -y speedtest-cli")
        elif failure_notes and all(note.endswith(": not installed") for note in failure_notes):
            lines.append("speedtest CLI unavailable; install speedtest or speedtest-cli on collector host.")
        elif failure_notes:
            lines.append(f"speedtest CLI failed ({failure_notes[0]}); ping latency still attempted.")
        elif not speed_result.get("ok"):
            exit_code = int(speed_result.get("exit_code", 1))
            stderr_text = str(speed_result.get("stderr") or "").strip()
            if exit_code == 127:
                lines.append("speedtest CLI unavailable; install speedtest or speedtest-cli on collector host.")
            else:
                detail = stderr_text.splitlines()[0] if stderr_text else "unknown execution error"
                lines.append(f"speedtest CLI failed ({detail}); ping latency still attempted.")
    if not has_data:
        lines.append("No speedtest data captured.")
    payload = {
        "ok": bool(has_data),
        "exitCode": 0 if has_data else 1,
        "lines": clip_lines(lines),
        "metrics": {
            "speedtest": {
                "target": host,
                "downloadMbps": down_mbps,
                "uploadMbps": up_mbps,
                "latencyMs": latency_ms,
                "publicIp": public_ip,
            }
        },
    }
    return payload


def run_publicip():
    candidates = [
        {"cmd": "curl", "args": ["-4", "-fsSL", "https://api.ipify.org"]},
        {"cmd": "wget", "args": ["-qO-", "https://api.ipify.org"]},
        {"cmd": "curl", "args": ["-4", "-fsSL", "https://ipv4.icanhazip.com"]},
        {"cmd": "wget", "args": ["-qO-", "https://ipv4.icanhazip.com"]},
        {"cmd": "curl", "args": ["-4", "-fsSL", "https://ifconfig.me/ip"]},
        {"cmd": "wget", "args": ["-qO-", "https://ifconfig.me/ip"]},
        {"cmd": "dig", "args": ["+short", "myip.opendns.com", "@resolver1.opendns.com"]},
        {"cmd": "dig", "args": ["+short", "myip.opendns.com", "@208.67.222.222"]},
        {"cmd": "nslookup", "args": ["myip.opendns.com", "resolver1.opendns.com"]},
    ]
    notes = []
    hits = []
    first_seen = {}
    counts = {}
    sources = {}
    for candidate in candidates:
        result = run_exec_candidates([candidate], timeout_sec=12)
        raw = "\n".join(
            [
                str(result.get("stdout") or ""),
                str(result.get("stderr") or ""),
            ]
        )
        ip = parse_public_ipv4_from_text(raw)
        cmdline = str(result.get("cmdline") or candidate.get("cmd") or "publicip").strip()
        if ip:
            hits.append(ip)
            if ip not in first_seen:
                first_seen[ip] = len(hits) - 1
            counts[ip] = int(counts.get(ip, 0)) + 1
            if ip not in sources:
                sources[ip] = []
            if cmdline and cmdline not in sources[ip]:
                sources[ip].append(cmdline)
            continue
        reason = str(result.get("stderr") or "").strip() or str(result.get("stdout") or "").strip() or "no output"
        notes.append(f"{cmdline}: {reason.splitlines()[0] if reason else 'unknown error'}")

    if counts:
        ranked = sorted(
            counts.keys(),
            key=lambda key: (-int(counts.get(key, 0)), int(first_seen.get(key, 0)))
        )
        best_ip = str(ranked[0]).strip()
        best_sources = sources.get(best_ip) or []
        confidence = int(counts.get(best_ip, 1))
        lines = [
            "Collector WAN public IP probe complete.",
            f"public_ip={best_ip}",
            f"confidence={confidence}/{len(hits)}",
        ]
        if best_sources:
            lines.append(f"source={best_sources[0]}")
        return {
            "ok": True,
            "exitCode": 0,
            "lines": clip_lines(lines),
            "metrics": {
                "publicIp": best_ip
            },
        }

    fail_lines = ["Collector WAN public IP probe failed."]
    if notes:
        fail_lines.append(notes[0])
    fail_lines.append("No public IPv4 detected.")
    return {
        "ok": False,
        "exitCode": 1,
        "lines": clip_lines(fail_lines),
        "metrics": {
            "publicIp": ""
        },
    }


def run_doctor():
    checks = [
        {"name": "ping", "candidates": ["ping"], "required": True, "hint": "install iputils-ping"},
        {"name": "traceroute", "candidates": ["traceroute", "tracepath"], "required": True, "hint": "install traceroute or iputils-tracepath"},
        {"name": "dns lookup", "candidates": ["nslookup", "dig", "getent"], "required": True, "hint": "install dnsutils or bind9-dnsutils"},
        {"name": "speedtest", "candidates": ["speedtest", "speedtest-cli"], "required": False, "hint": "install speedtest or speedtest-cli"},
    ]
    lines = ["Collector capability check:"]
    ok = True
    for row in checks:
        chosen = ""
        for cmd in row["candidates"]:
            if shutil.which(cmd):
                chosen = cmd
                break
        if chosen:
            lines.append(f"[PASS] {row['name']}: {chosen}")
            continue
        if row["required"]:
            ok = False
            lines.append(f"[FAIL] {row['name']}: missing ({row['hint']})")
        else:
            lines.append(f"[WARN] {row['name']}: missing ({row['hint']}); throughput tests may show n/a")
    return {
        "ok": ok,
        "exitCode": 0 if ok else 1,
        "lines": clip_lines(lines),
    }


def safe_update_url(value):
    raw = str(value or "").strip()
    if not raw or len(raw) > 2048:
        return ""
    if any(ch in raw for ch in (" ", "\n", "\r", "\t", '"', "'")):
        return ""
    try:
        parsed = urllib.parse.urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return ""
    except Exception:
        return ""
    return raw


def run_update(package_url, target_version=""):
    url = safe_update_url(package_url)
    version = str(target_version or "").strip()[:64]
    if not url:
        return {
            "ok": False,
            "exitCode": 1,
            "lines": ["Usage: update <http(s)://cajal-host/api/agent/linux/download?format=deb> [targetVersion]"],
        }

    download_with_curl = shutil.which("curl")
    download_with_wget = shutil.which("wget")
    dpkg_path = shutil.which("dpkg")
    sh_path = shutil.which("sh") or "/bin/sh"
    if not dpkg_path:
        return {
            "ok": False,
            "exitCode": 1,
            "lines": ["dpkg not found on collector host; cannot install update package."],
        }
    if not (download_with_curl or download_with_wget):
        return {
            "ok": False,
            "exitCode": 1,
            "lines": ["Neither curl nor wget is installed; cannot download update package."],
        }

    ts = int(time.time())
    deb_path = f"/tmp/cajal-agent-update-{ts}.deb"
    log_path = f"/tmp/cajal-agent-update-{ts}.log"
    quoted_url = shlex.quote(url)
    quoted_deb = shlex.quote(deb_path)
    quoted_dpkg = shlex.quote(dpkg_path)

    if download_with_curl:
        downloader_cmd = f"{shlex.quote(download_with_curl)} -fsSL {quoted_url} -o {quoted_deb}"
    else:
        downloader_cmd = f"{shlex.quote(download_with_wget)} -qO {quoted_deb} {quoted_url}"

    script = (
        "set -eu\n"
        f"{downloader_cmd}\n"
        f"{quoted_dpkg} -i {quoted_deb} || (command -v apt-get >/dev/null 2>&1 && apt-get -f install -y)\n"
        "command -v systemctl >/dev/null 2>&1 && systemctl restart cajal-agent || true\n"
    )

    log_handle = None
    try:
        log_handle = open(log_path, "a", encoding="utf-8")  # pylint: disable=consider-using-with
        subprocess.Popen(  # pylint: disable=consider-using-with
            [sh_path, "-lc", script],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
        lines = [
            "Collector agent update started in background.",
            f"download={url}",
            f"targetVersion={version or 'unknown'}",
            f"log={log_path}",
            "Re-run `status` in ~60 seconds to verify new agent version.",
        ]
        return {
            "ok": True,
            "exitCode": 0,
            "lines": clip_lines(lines),
        }
    except Exception as exc:
        return {
            "ok": False,
            "exitCode": 1,
            "lines": clip_lines([f"Failed to start update job: {exc}", f"log={log_path}"]),
        }
    finally:
        if log_handle and not log_handle.closed:
            log_handle.close()


def execute_remote_command(command_text):
    raw = str(command_text or "").strip()
    if not raw:
        return {"ok": False, "exitCode": 1, "lines": ["No command provided"]}
    try:
        tokens = shlex.split(raw)
    except Exception:
        return {"ok": False, "exitCode": 1, "lines": ["Failed to parse command text"]}
    if not tokens:
        return {"ok": False, "exitCode": 1, "lines": ["No command provided"]}

    command = str(tokens[0]).lower()
    args = tokens[1:]
    if command == "ping":
        return run_ping(args[0] if args else "")
    if command in ("traceroute", "tracert", "trace"):
        return run_traceroute(args[0] if args else "")
    if command in ("dns", "resolve", "nslookup"):
        if command == "dns" and args and str(args[0]).lower() == "resolve":
            host = args[1] if len(args) > 1 else ""
        else:
            host = args[0] if args else ""
        return run_dns(host)
    if command == "ipconfig":
        return run_ipconfig(args[0] if args else "")
    if command == "speedtest":
        return run_speedtest(args[0] if args else "8.8.8.8")
    if command in ("publicip", "public-ip", "wanip"):
        return run_publicip()
    if command == "update":
        package_url = args[0] if args else ""
        target_version = args[1] if len(args) > 1 else ""
        return run_update(package_url, target_version)
    if command in ("doctor", "deps", "capabilities"):
        return run_doctor()

    return {
        "ok": False,
        "exitCode": 1,
        "lines": [f"Unsupported agent command: {command}"],
    }


def read_json_body(response):
    raw = response.read()
    text = raw.decode("utf-8", errors="replace")
    if not text.strip():
        return {}
    try:
        return json.loads(text)
    except Exception:
        return {"raw": text}


def post_json(url, payload, timeout_sec=20, ssl_context=None):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec, context=ssl_context) as response:
            status = int(response.getcode() or 200)
            body = read_json_body(response)
            if status >= 400:
                raise ApiError(status, str(body.get("error") or f"HTTP {status}"))
            return body
    except urllib.error.HTTPError as exc:
        try:
            body = read_json_body(exc)
            detail = str(body.get("error") or body or "")
        except Exception:
            detail = ""
        raise ApiError(exc.code, detail or f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ApiError(0, f"Network error: {exc.reason}") from exc


def parse_args():
    parser = argparse.ArgumentParser(description="Cajal Linux collector agent")
    parser.add_argument("--server", required=True, help="Cajal server base URL, e.g. http://10.0.0.5:4000")
    parser.add_argument("--site", required=True, help="Collector site id")
    parser.add_argument("--password", default="", help="Collector agent password")
    parser.add_argument(
        "--password-env",
        default="CAJAL_AGENT_PASSWORD",
        help="Read password from this environment variable when --password is not set",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL_SEC,
        help="Fallback poll interval in seconds",
    )
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    return parser.parse_args()


def main():
    args = parse_args()
    server = str(args.server or "").strip().rstrip("/")
    site_id = str(args.site or "").strip()
    password = str(args.password or "").strip() or str(os.environ.get(args.password_env or "", "")).strip()
    if not server:
        print("server is required", file=sys.stderr)
        return 1
    if not site_id:
        print("site is required", file=sys.stderr)
        return 1
    if not password:
        print("password is required (--password or --password-env)", file=sys.stderr)
        return 1

    ssl_context = None
    if args.insecure:
        ssl_context = ssl._create_unverified_context()  # pylint: disable=protected-access

    register_url = f"{server}/api/agent/register"
    poll_url = f"{server}/api/agent/poll"
    result_url = f"{server}/api/agent/result"

    token = ""
    fallback_poll = max(0.5, float(args.poll_interval or DEFAULT_POLL_INTERVAL_SEC))
    hostname = socket.gethostname() or "unknown-host"
    install_id = str(os.environ.get("CAJAL_AGENT_INSTALL_ID", "") or "").strip()[:128]
    installed_at = str(os.environ.get("CAJAL_AGENT_INSTALLED_AT", "") or "").strip()

    while True:
        if not token:
            try:
                local_ip = detect_primary_local_ipv4()
                agent_payload = {
                    "hostname": hostname,
                    "localIp": local_ip,
                    "platform": platform.platform(),
                    "version": AGENT_VERSION,
                }
                if install_id:
                    agent_payload["installId"] = install_id
                if installed_at:
                    agent_payload["installedAt"] = installed_at
                response = post_json(
                    register_url,
                    {
                        "siteId": site_id,
                        "password": password,
                        "agent": agent_payload,
                    },
                    timeout_sec=20,
                    ssl_context=ssl_context,
                )
                token = str(response.get("token") or "").strip()
                if not token:
                    raise ApiError(500, "No token returned by Cajal")
                print(f"[agent] registered site={site_id} host={hostname} localIp={local_ip or 'unknown'}")
            except ApiError as exc:
                print(f"[agent] register failed ({exc.status_code}): {exc}", file=sys.stderr)
                time.sleep(5)
                continue
            except Exception as exc:
                print(f"[agent] register unexpected error: {exc}", file=sys.stderr)
                time.sleep(5)
                continue

        poll_sleep = fallback_poll
        try:
            poll_response = post_json(poll_url, {"token": token}, timeout_sec=30, ssl_context=ssl_context)
            poll_ms = float(poll_response.get("pollIntervalMs") or 0.0)
            if poll_ms > 0:
                poll_sleep = max(0.4, poll_ms / 1000.0)
            command = poll_response.get("command")
            if command and isinstance(command, dict):
                command_id = str(command.get("id") or "").strip()
                command_text = str(command.get("command") or "").strip()
                if command_id and command_text:
                    result = execute_remote_command(command_text)
                    payload = {
                        "token": token,
                        "commandId": command_id,
                        "ok": bool(result.get("ok")),
                        "exitCode": int(result.get("exitCode", 1)),
                        "lines": clip_lines(result.get("lines") or []),
                    }
                    metrics = result.get("metrics")
                    if isinstance(metrics, dict):
                        payload["metrics"] = metrics
                    try:
                        post_json(result_url, payload, timeout_sec=30, ssl_context=ssl_context)
                    except ApiError as exc:
                        if exc.status_code == 401:
                            print("[agent] session expired while posting result; re-registering")
                            token = ""
                        else:
                            print(f"[agent] result post failed ({exc.status_code}): {exc}", file=sys.stderr)
                    except Exception as exc:
                        print(f"[agent] result post error: {exc}", file=sys.stderr)
        except ApiError as exc:
            if exc.status_code == 401:
                print("[agent] session rejected; re-registering")
                token = ""
            else:
                print(f"[agent] poll failed ({exc.status_code}): {exc}", file=sys.stderr)
        except Exception as exc:
            print(f"[agent] poll error: {exc}", file=sys.stderr)

        time.sleep(poll_sleep)


if __name__ == "__main__":
    sys.exit(main())
