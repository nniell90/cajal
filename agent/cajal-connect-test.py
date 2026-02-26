#!/usr/bin/env python3
"""Cajal collector connectivity diagnostics CLI.

Runs local connectivity checks and a real collector agent register/poll cycle.
"""

import argparse
import json
import os
import platform
import re
import shutil
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_ENV_FILE = "/etc/cajal-agent/agent.env"
DEFAULT_PASSWORD_ENV = "CAJAL_AGENT_PASSWORD"
SERVER_PATTERN = re.compile(r"^https?://.+", re.IGNORECASE)
DIAG_VERSION = "1.0.0"


class ApiError(Exception):
    def __init__(self, status_code, message):
        super().__init__(message)
        self.status_code = int(status_code)


def parse_env_file(path):
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                values[key] = value
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return values


def normalize_insecure(value):
    text = str(value or "").strip().lower()
    return text in ("1", "true", "yes", "on")


def add_result(results, status, check, message, detail=""):
    results.append(
        {
            "status": str(status),
            "check": str(check),
            "message": str(message),
            "detail": str(detail or ""),
        }
    )


def post_json(url, payload, timeout_sec=10, ssl_context=None):
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
            raw = response.read().decode("utf-8", errors="replace")
            body = {}
            if raw.strip():
                try:
                    body = json.loads(raw)
                except Exception:
                    body = {"raw": raw}
            if status >= 400:
                raise ApiError(status, str(body.get("error") or f"HTTP {status}"))
            return body
    except urllib.error.HTTPError as exc:
        raw = ""
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        detail = ""
        if raw.strip():
            try:
                detail = str(json.loads(raw).get("error") or "")
            except Exception:
                detail = raw.strip()
        raise ApiError(exc.code, detail or f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise ApiError(0, f"Network error: {reason}") from exc


def get_json(url, timeout_sec=10, ssl_context=None):
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec, context=ssl_context) as response:
            status = int(response.getcode() or 200)
            raw = response.read().decode("utf-8", errors="replace")
            body = {}
            if raw.strip():
                try:
                    body = json.loads(raw)
                except Exception:
                    body = {"raw": raw}
            if status >= 400:
                raise ApiError(status, str(body.get("error") or f"HTTP {status}"))
            return body
    except urllib.error.HTTPError as exc:
        raw = ""
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        detail = ""
        if raw.strip():
            try:
                detail = str(json.loads(raw).get("error") or "")
            except Exception:
                detail = raw.strip()
        raise ApiError(exc.code, detail or f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise ApiError(0, f"Network error: {reason}") from exc


def parse_args():
    parser = argparse.ArgumentParser(description="Cajal collector connectivity diagnostics")
    parser.add_argument("--env-file", default=DEFAULT_ENV_FILE, help="Path to cajal agent env file")
    parser.add_argument("--server", default="", help="Cajal base URL override, e.g. http://10.0.0.5:4000")
    parser.add_argument("--site", default="", help="Collector site id override")
    parser.add_argument("--password", default="", help="Collector password override")
    parser.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV, help="Env var used if --password is empty")
    parser.add_argument("--timeout", type=float, default=6.0, help="Timeout seconds for each network check")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--skip-register", action="store_true", help="Skip register/poll API checks")
    parser.add_argument("--strict-tools", action="store_true", help="Treat missing local troubleshooting tools as failures")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    return parser.parse_args()


def build_config(args):
    existing = parse_env_file(args.env_file)
    server = str(args.server or existing.get("CAJAL_AGENT_SERVER") or existing.get("CAJAL_AGENT_SERVER_URL") or "").strip().rstrip("/")
    site = str(args.site or existing.get("CAJAL_AGENT_SITE") or existing.get("CAJAL_AGENT_SITE_ID") or "").strip()
    password = str(args.password or existing.get("CAJAL_AGENT_PASSWORD") or "").strip()
    if not password and args.password_env:
        password = str(os.environ.get(args.password_env, "")).strip()
    insecure = bool(args.insecure or normalize_insecure(existing.get("CAJAL_AGENT_INSECURE", "0")))
    install_id = str(existing.get("CAJAL_AGENT_INSTALL_ID") or "").strip()
    installed_at = str(existing.get("CAJAL_AGENT_INSTALLED_AT") or "").strip()
    return {
        "server": server,
        "site": site,
        "password": password,
        "insecure": insecure,
        "install_id": install_id,
        "installed_at": installed_at,
        "envFile": args.env_file,
    }


def summarize_server(server):
    if not SERVER_PATTERN.match(server or ""):
        return (None, None, "Server URL must start with http:// or https://")
    parsed = urllib.parse.urlparse(server)
    scheme = (parsed.scheme or "").lower()
    host = parsed.hostname or ""
    if scheme not in ("http", "https") or not host:
        return (None, None, "Server URL must include host and use http:// or https://")
    port = parsed.port or (443 if scheme == "https" else 80)
    return (parsed, port, "")


def detect_local_tool(candidates):
    for cmd in candidates:
        path = shutil.which(str(cmd or "").strip())
        if path:
            return (str(cmd), str(path))
    return ("", "")


def run_local_tool_checks(results, strict=False):
    checks = [
        {
            "check": "tools.ping",
            "label": "ping",
            "candidates": ["ping"],
            "required": True,
            "hint": "install iputils-ping",
        },
        {
            "check": "tools.traceroute",
            "label": "traceroute",
            "candidates": ["traceroute", "tracepath"],
            "required": False,
            "hint": "install traceroute or iputils-tracepath",
        },
        {
            "check": "tools.dns",
            "label": "dns lookup",
            "candidates": ["nslookup", "dig", "getent"],
            "required": False,
            "hint": "install dnsutils or bind9-dnsutils",
        },
        {
            "check": "tools.speedtest",
            "label": "speedtest",
            "candidates": ["speedtest", "speedtest-cli"],
            "required": False,
            "hint": "install speedtest or speedtest-cli (WAN throughput otherwise shows n/a)",
        },
    ]
    for row in checks:
        command, path = detect_local_tool(row.get("candidates", []))
        if command:
            add_result(results, "pass", row["check"], f"{row['label']} available", f"{command} -> {path}")
            continue
        is_required = bool(row.get("required"))
        status = "fail" if (is_required or strict) else "warn"
        add_result(results, status, row["check"], f"{row['label']} command not found", str(row.get("hint") or ""))


def print_text_report(config, results, elapsed_ms):
    print("Cajal Connect Test")
    print(f"server: {config.get('server') or '(not set)'}")
    print(f"site: {config.get('site') or '(not set)'}")
    print(f"password: {'set' if config.get('password') else 'not set'}")
    print(f"insecure TLS: {bool(config.get('insecure'))}")
    print("")
    for row in results:
        status = str(row.get("status", "info")).upper()
        check = str(row.get("check", "check"))
        message = str(row.get("message", ""))
        detail = str(row.get("detail", "")).strip()
        print(f"[{status}] {check}: {message}")
        if detail:
            print(f"        {detail}")
    print("")
    fail_count = sum(1 for r in results if r.get("status") == "fail")
    warn_count = sum(1 for r in results if r.get("status") == "warn")
    pass_count = sum(1 for r in results if r.get("status") == "pass")
    print(f"summary: {pass_count} pass, {warn_count} warn, {fail_count} fail ({elapsed_ms:.0f} ms)")
    if fail_count:
        print("next steps:")
        print("  - verify server URL/site id/password in /etc/cajal-agent/agent.env")
        print("  - run: sudo cajal-agent-setup")
        print("  - run: sudo systemctl status cajal-agent --no-pager")
        print("  - run: sudo journalctl -u cajal-agent -n 120 --no-pager")


def main():
    args = parse_args()
    started = time.perf_counter()
    config = build_config(args)
    results = []
    ssl_context = None
    if config.get("insecure"):
        ssl_context = ssl._create_unverified_context()  # pylint: disable=protected-access

    run_local_tool_checks(results, strict=bool(args.strict_tools))

    parsed, port, parse_error = summarize_server(config.get("server", ""))
    if parse_error:
        add_result(results, "fail", "config.server", parse_error)
    else:
        add_result(results, "pass", "config.server", "Server URL looks valid", f"{parsed.scheme}://{parsed.netloc}")

    if config.get("site"):
        add_result(results, "pass", "config.site", "Site id is set", config.get("site"))
    else:
        add_result(results, "fail", "config.site", "Collector site id is not set")

    if config.get("password"):
        add_result(results, "pass", "config.password", "Collector password is set")
    else:
        add_result(results, "fail", "config.password", "Collector password is not set")

    if parsed:
        try:
            dns_started = time.perf_counter()
            records = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
            addresses = sorted({row[4][0] for row in records if row and len(row) >= 5 and row[4]})
            dns_ms = (time.perf_counter() - dns_started) * 1000.0
            preview = ", ".join(addresses[:4]) if addresses else "no records"
            add_result(results, "pass", "dns.resolve", f"Resolved {parsed.hostname}", f"{preview} ({dns_ms:.1f} ms)")
        except Exception as exc:
            add_result(results, "fail", "dns.resolve", f"Failed to resolve {parsed.hostname}", str(exc))

        try:
            tcp_started = time.perf_counter()
            with socket.create_connection((parsed.hostname, port), timeout=max(0.2, args.timeout)):
                pass
            tcp_ms = (time.perf_counter() - tcp_started) * 1000.0
            add_result(results, "pass", "tcp.connect", f"Connected to {parsed.hostname}:{port}", f"{tcp_ms:.1f} ms")
        except Exception as exc:
            add_result(results, "fail", "tcp.connect", f"Failed to connect to {parsed.hostname}:{port}", str(exc))

        health_url = urllib.parse.urljoin(config["server"] + "/", "api/health")
        try:
            health_started = time.perf_counter()
            health_body = get_json(health_url, timeout_sec=max(0.4, args.timeout), ssl_context=ssl_context)
            health_ms = (time.perf_counter() - health_started) * 1000.0
            ok = bool(health_body.get("ok"))
            status = "pass" if ok else "warn"
            message = "Health endpoint reachable" if ok else "Health endpoint reachable but returned ok=false"
            add_result(results, status, "api.health", message, f"{health_ms:.1f} ms")
        except ApiError as exc:
            add_result(results, "fail", "api.health", f"Health check failed ({exc.status_code})", str(exc))
        except Exception as exc:
            add_result(results, "fail", "api.health", "Health check failed", str(exc))

    can_register = (
        not args.skip_register
        and parsed is not None
        and bool(config.get("site"))
        and bool(config.get("password"))
    )
    if not can_register and not args.skip_register:
        add_result(results, "warn", "api.agent.register", "Skipped register check", "Fix config failures above first")

    if can_register:
        register_url = urllib.parse.urljoin(config["server"] + "/", "api/agent/register")
        payload = {
            "siteId": config["site"],
            "password": config["password"],
            "agent": {
                "hostname": socket.gethostname() or "unknown-host",
                "platform": platform.platform(),
                "version": f"connect-test-{DIAG_VERSION}",
                "installId": str(config.get("install_id") or ""),
                "installedAt": str(config.get("installed_at") or ""),
            },
        }
        token = ""
        try:
            reg_started = time.perf_counter()
            reg_body = post_json(register_url, payload, timeout_sec=max(0.4, args.timeout), ssl_context=ssl_context)
            reg_ms = (time.perf_counter() - reg_started) * 1000.0
            token = str(reg_body.get("token") or "").strip()
            if not token:
                add_result(results, "fail", "api.agent.register", "Register returned no token")
            else:
                add_result(results, "pass", "api.agent.register", "Agent register accepted", f"{reg_ms:.1f} ms")
        except ApiError as exc:
            message = f"Register failed ({exc.status_code})"
            hint = str(exc)
            if exc.status_code == 401:
                hint = f"{hint}. Password mismatch."
            elif exc.status_code == 404:
                hint = f"{hint}. Site id not found."
            elif exc.status_code == 409:
                hint = f"{hint}. Collector role/password may be missing, or a newer install is already locked."
            elif exc.status_code == 0:
                hint = f"{hint}. Cannot reach Cajal server."
            add_result(results, "fail", "api.agent.register", message, hint)
        except Exception as exc:
            add_result(results, "fail", "api.agent.register", "Register failed", str(exc))

        if token:
            poll_url = urllib.parse.urljoin(config["server"] + "/", "api/agent/poll")
            try:
                poll_started = time.perf_counter()
                post_json(poll_url, {"token": token}, timeout_sec=max(0.4, args.timeout), ssl_context=ssl_context)
                poll_ms = (time.perf_counter() - poll_started) * 1000.0
                add_result(results, "pass", "api.agent.poll", "Poll succeeded with returned token", f"{poll_ms:.1f} ms")
            except ApiError as exc:
                add_result(results, "fail", "api.agent.poll", f"Poll failed ({exc.status_code})", str(exc))
            except Exception as exc:
                add_result(results, "fail", "api.agent.poll", "Poll failed", str(exc))

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    fail_count = sum(1 for r in results if r.get("status") == "fail")
    if args.json:
        payload = {
            "ok": fail_count == 0,
            "elapsedMs": round(elapsed_ms, 1),
            "config": {
                "server": config.get("server"),
                "site": config.get("site"),
                "passwordSet": bool(config.get("password")),
                "insecure": bool(config.get("insecure")),
                "envFile": config.get("envFile"),
            },
            "results": results,
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        print_text_report(config, results, elapsed_ms)
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
