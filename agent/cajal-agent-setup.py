#!/usr/bin/env python3
"""Cajal Linux agent local setup wizard.

Collects server URL, collector site id, and agent password, then writes:
  /etc/cajal-agent/agent.env

Setup now supports:
- Collector discovery (`/api/agent/collectors`) so users can pick collector by name
- Live verification (`/api/agent/register` + `/api/agent/poll`) before saving config
"""

import argparse
import datetime
import getpass
import json
import os
import re
import shutil
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


DEFAULT_ENV_FILE = "/etc/cajal-agent/agent.env"
DEFAULT_POLL_INTERVAL = "1.5"
DEFAULT_TIMEOUT_SEC = 8.0
SERVER_PATTERN = re.compile(r"^https?://.+", re.IGNORECASE)


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


def shell_quote(value):
    text = str(value or "")
    return "'" + text.replace("'", "'\"'\"'") + "'"


def normalize_insecure(value):
    text = str(value or "").strip().lower()
    if text in ("1", "true", "yes", "on"):
        return "1"
    return "0"


def normalize_server(value):
    return str(value or "").strip().rstrip("/")


def validate_config(config):
    server = normalize_server(config.get("server"))
    site = str(config.get("site") or "").strip()
    password = str(config.get("password") or "")
    poll_interval = str(config.get("poll_interval") or DEFAULT_POLL_INTERVAL).strip()
    errors = []

    if not server:
        errors.append("Cajal server URL is required.")
    elif not SERVER_PATTERN.match(server):
        errors.append("Cajal server URL must start with http:// or https://")

    if not site:
        errors.append("Collector site id is required.")

    if len(password) < 8:
        errors.append("Agent password must be at least 8 characters.")
    elif len(password) > 256:
        errors.append("Agent password must be 256 characters or less.")

    try:
        poll = float(poll_interval)
        if poll < 0.4 or poll > 120:
            errors.append("Poll interval must be between 0.4 and 120 seconds.")
    except Exception:
        errors.append("Poll interval must be a number.")

    return errors


def render_env_content(config):
    lines = [
        f"CAJAL_AGENT_SERVER={shell_quote(normalize_server(config['server']))}",
        f"CAJAL_AGENT_SITE={shell_quote(config['site'])}",
        f"CAJAL_AGENT_PASSWORD={shell_quote(config['password'])}",
        f"CAJAL_AGENT_POLL_INTERVAL={shell_quote(config['poll_interval'])}",
        f"CAJAL_AGENT_INSECURE={config['insecure']}",
        f"CAJAL_AGENT_INSTALL_ID={shell_quote(config.get('install_id', ''))}",
        f"CAJAL_AGENT_INSTALLED_AT={shell_quote(config.get('installed_at', ''))}",
        "",
    ]
    return "\n".join(lines)


def generate_install_identity():
    return {
        "install_id": str(uuid.uuid4()),
        "installed_at": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def write_env_file(path, content):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, 0o600)


def prompt_text(label, default=""):
    if default:
        return input(f"{label} [{default}]: ").strip() or default
    return input(f"{label}: ").strip()


def read_json_response(response):
    raw = response.read().decode("utf-8", errors="replace")
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


def request_json(url, method="GET", payload=None, timeout_sec=DEFAULT_TIMEOUT_SEC, ssl_context=None):
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=max(0.4, float(timeout_sec or DEFAULT_TIMEOUT_SEC)), context=ssl_context) as res:
            status = int(res.getcode() or 200)
            data = read_json_response(res)
            if status >= 400:
                raise ApiError(status, str(data.get("error") or f"HTTP {status}"))
            return data
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            payload = read_json_response(exc)
            detail = str(payload.get("error") or payload or "")
        except Exception:
            detail = ""
        raise ApiError(exc.code, detail or f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise ApiError(0, f"Network error: {reason}") from exc


def build_ssl_context(insecure=False):
    if insecure:
        return ssl._create_unverified_context()  # pylint: disable=protected-access
    return None


def detect_local_tool(candidates):
    for cmd in candidates:
        path = shutil.which(str(cmd or "").strip())
        if path:
            return (str(cmd), str(path))
    return ("", "")


def local_tool_checks(strict_speedtest=False):
    rows = []
    checks = [
        {
            "name": "ping",
            "candidates": ["ping"],
            "required": True,
            "hint": "install iputils-ping",
        },
        {
            "name": "traceroute",
            "candidates": ["traceroute", "tracepath"],
            "required": True,
            "hint": "install traceroute or iputils-tracepath",
        },
        {
            "name": "dns lookup",
            "candidates": ["nslookup", "dig", "getent"],
            "required": True,
            "hint": "install dnsutils or bind9-dnsutils",
        },
        {
            "name": "speedtest",
            "candidates": ["speedtest", "speedtest-cli"],
            "required": bool(strict_speedtest),
            "hint": "install speedtest or speedtest-cli",
        },
    ]
    has_fail = False
    for row in checks:
        command, path = detect_local_tool(row.get("candidates", []))
        if command:
            rows.append({"status": "pass", "name": row["name"], "detail": f"{command} -> {path}"})
            continue
        status = "fail" if row.get("required") else "warn"
        if status == "fail":
            has_fail = True
        detail = str(row.get("hint") or "")
        if row.get("name") == "speedtest":
            detail = f"{detail}; WAN throughput tests may show n/a until installed"
        rows.append({"status": status, "name": row["name"], "detail": detail})
    return (rows, has_fail)


def print_local_tool_report(rows):
    print("Local tool check:", file=sys.stderr)
    for row in rows:
        status = str(row.get("status") or "info").upper()
        name = str(row.get("name") or "tool")
        detail = str(row.get("detail") or "").strip()
        if detail:
            print(f"  [{status}] {name}: {detail}", file=sys.stderr)
        else:
            print(f"  [{status}] {name}", file=sys.stderr)


def resolve_site_id(raw_site, collectors):
    value = str(raw_site or "").strip()
    if not value:
        return ""
    if value.isdigit():
        idx = int(value, 10) - 1
        if 0 <= idx < len(collectors):
            return str(collectors[idx].get("id") or "").strip()

    for row in collectors:
        site_id = str(row.get("id") or "").strip()
        if site_id == value:
            return site_id

    value_lower = value.lower()
    for row in collectors:
        name = str(row.get("name") or "").strip().lower()
        site_id = str(row.get("id") or "").strip()
        if name and name == value_lower:
            return site_id

    match = re.match(r"^(.*)\[(.+)\]$", value)
    if match:
        candidate = str(match.group(2) or "").strip()
        if candidate:
            return candidate
    return value


def fetch_collectors(server, insecure=False, timeout_sec=DEFAULT_TIMEOUT_SEC):
    base = normalize_server(server)
    if not base or not SERVER_PATTERN.match(base):
        return []
    endpoint = urllib.parse.urljoin(base + "/", "api/agent/collectors")
    payload = request_json(
        endpoint,
        method="GET",
        timeout_sec=timeout_sec,
        ssl_context=build_ssl_context(insecure=insecure),
    )
    rows = payload.get("collectors")
    if not isinstance(rows, list):
        return []
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        site_id = str(row.get("id") or "").strip()
        if not site_id:
            continue
        out.append(
            {
                "id": site_id,
                "name": str(row.get("name") or site_id).strip() or site_id,
                "agentPasswordSet": bool(row.get("agentPasswordSet")),
            }
        )
    return out


def verify_registration(config, timeout_sec=DEFAULT_TIMEOUT_SEC):
    server = normalize_server(config.get("server"))
    site = str(config.get("site") or "").strip()
    password = str(config.get("password") or "")
    insecure = normalize_insecure(config.get("insecure")) == "1"
    ssl_context = build_ssl_context(insecure=insecure)

    register_url = urllib.parse.urljoin(server + "/", "api/agent/register")
    poll_url = urllib.parse.urljoin(server + "/", "api/agent/poll")
    hostname = socket.gethostname() or "setup-host"
    payload = {
        "siteId": site,
        "password": password,
        "agent": {
            "hostname": hostname,
            "platform": "setup-verify",
            "version": "setup-verify-1.0.0",
            "installId": str(config.get("install_id") or "").strip(),
            "installedAt": str(config.get("installed_at") or "").strip(),
        },
    }
    try:
        reg = request_json(
            register_url,
            method="POST",
            payload=payload,
            timeout_sec=timeout_sec,
            ssl_context=ssl_context,
        )
        token = str(reg.get("token") or "").strip()
        if not token:
            return (False, "Register endpoint returned no token.")
        request_json(
            poll_url,
            method="POST",
            payload={"token": token},
            timeout_sec=timeout_sec,
            ssl_context=ssl_context,
        )
        return (True, "Collector register/poll verified.")
    except ApiError as exc:
        detail = str(exc)
        if exc.status_code == 401:
            detail = f"{detail} (password mismatch)"
        elif exc.status_code == 404:
            detail = f"{detail} (site id not found)"
        elif exc.status_code == 409:
            detail = f"{detail} (collector role/password missing, or newer install already locked)"
        elif exc.status_code == 0:
            detail = f"{detail} (cannot reach Cajal server)"
        return (False, f"Verification failed ({exc.status_code}): {detail}")
    except Exception as exc:
        return (False, f"Verification failed: {exc}")


def collect_cli(initial, timeout_sec=DEFAULT_TIMEOUT_SEC):
    if not sys.stdin.isatty():
        return None
    print("Cajal Agent Setup", file=sys.stderr)
    print("Enter collector connection values.", file=sys.stderr)

    server = normalize_server(prompt_text("Cajal server URL", initial.get("server", "")))
    insecure = normalize_insecure(prompt_text("Allow insecure TLS (0 or 1)", initial.get("insecure", "0")))

    collectors = []
    if server and SERVER_PATTERN.match(server):
        try:
            collectors = fetch_collectors(server, insecure=insecure == "1", timeout_sec=timeout_sec)
        except Exception as exc:
            print(f"Could not load collector list: {exc}", file=sys.stderr)
    if collectors:
        print("Available collectors:", file=sys.stderr)
        for idx, row in enumerate(collectors, start=1):
            status = "password-set" if row.get("agentPasswordSet") else "password-missing"
            print(f"  {idx}. {row.get('name')} [{row.get('id')}] ({status})", file=sys.stderr)
        print("Enter collector number, collector name, or collector site id.", file=sys.stderr)

    site_raw = prompt_text("Collector site", initial.get("site", "")).strip()
    site = resolve_site_id(site_raw, collectors)

    current_password = str(initial.get("password") or "")
    if current_password:
        password_prompt = "Agent password (leave blank to keep current)"
        password = getpass.getpass(f"{password_prompt}: ").strip() or current_password
    else:
        password = getpass.getpass("Agent password: ").strip()

    poll_interval = prompt_text("Poll interval seconds", initial.get("poll_interval", DEFAULT_POLL_INTERVAL)).strip()

    return {
        "server": server,
        "site": site,
        "password": password,
        "poll_interval": poll_interval or DEFAULT_POLL_INTERVAL,
        "insecure": insecure,
    }


def collect_gui(initial, timeout_sec=DEFAULT_TIMEOUT_SEC):
    if not os.environ.get("DISPLAY"):
        return None
    try:
        import tkinter as tk
        from tkinter import messagebox
        from tkinter import ttk
    except Exception:
        return None

    result = {}
    root = tk.Tk()
    root.title("Cajal Agent Setup")
    root.resizable(False, False)

    frame = tk.Frame(root, padx=14, pady=12)
    frame.grid(row=0, column=0, sticky="nsew")

    tk.Label(frame, text="Cajal URL").grid(row=0, column=0, sticky="w")
    server_var = tk.StringVar(value=initial.get("server", ""))
    server_entry = tk.Entry(frame, width=52, textvariable=server_var)
    server_entry.grid(row=1, column=0, sticky="ew", pady=(0, 6))

    collector_row = tk.Frame(frame)
    collector_row.grid(row=2, column=0, sticky="ew", pady=(0, 4))
    collector_row.columnconfigure(0, weight=1)
    tk.Label(collector_row, text="Collector Site").grid(row=0, column=0, sticky="w")
    load_btn = tk.Button(collector_row, text="Load Collectors", width=16)
    load_btn.grid(row=0, column=1, sticky="e")

    site_var = tk.StringVar(value=initial.get("site", ""))
    site_entry = ttk.Combobox(frame, width=50, textvariable=site_var)
    site_entry.grid(row=3, column=0, sticky="ew", pady=(0, 4))

    collector_hint_var = tk.StringVar(value="Use collector name/id, or click Load Collectors.")
    collector_hint_label = tk.Label(frame, textvariable=collector_hint_var, anchor="w", justify="left", fg="#8a8a8a")
    collector_hint_label.grid(row=4, column=0, sticky="ew", pady=(0, 8))

    tk.Label(frame, text="Agent Password").grid(row=5, column=0, sticky="w")
    password_var = tk.StringVar(value=initial.get("password", ""))
    password_entry = tk.Entry(frame, width=52, textvariable=password_var, show="*")
    password_entry.grid(row=6, column=0, sticky="ew", pady=(0, 8))

    tk.Label(frame, text="Poll Interval (seconds)").grid(row=7, column=0, sticky="w")
    poll_var = tk.StringVar(value=initial.get("poll_interval", DEFAULT_POLL_INTERVAL))
    poll_entry = tk.Entry(frame, width=52, textvariable=poll_var)
    poll_entry.grid(row=8, column=0, sticky="ew", pady=(0, 8))

    insecure_var = tk.IntVar(value=1 if initial.get("insecure", "0") == "1" else 0)
    insecure_box = tk.Checkbutton(
        frame,
        text="Allow insecure TLS certificates",
        variable=insecure_var,
        onvalue=1,
        offvalue=0,
    )
    insecure_box.grid(row=9, column=0, sticky="w", pady=(0, 10))

    button_row = tk.Frame(frame)
    button_row.grid(row=10, column=0, sticky="e")

    collectors_cache = []

    def apply_collector_values(rows):
        values = [f"{row.get('name')} [{row.get('id')}]" for row in rows]
        site_entry["values"] = values
        current = str(site_var.get() or "").strip()
        resolved = resolve_site_id(current, rows)
        if not current and values:
            site_var.set(values[0])
        elif current and resolved:
            for idx, row in enumerate(rows):
                if row.get("id") == resolved:
                    site_var.set(values[idx])
                    break

    def load_collectors():
        nonlocal collectors_cache
        server = normalize_server(server_var.get())
        insecure = bool(insecure_var.get())
        if not server or not SERVER_PATTERN.match(server):
            collector_hint_var.set("Enter a valid Cajal URL first (http:// or https://).")
            return
        collector_hint_var.set("Loading collectors...")
        root.update_idletasks()
        try:
            rows = fetch_collectors(server, insecure=insecure, timeout_sec=timeout_sec)
            collectors_cache = rows
            apply_collector_values(rows)
            if rows:
                collector_hint_var.set(f"Loaded {len(rows)} collector site(s).")
            else:
                collector_hint_var.set("No collector sites found on server.")
        except Exception as exc:
            collector_hint_var.set(f"Collector load failed: {exc}")

    def close_without_save():
        root.destroy()

    def save_and_close():
        candidate = {
            "server": normalize_server(server_var.get()),
            "site": resolve_site_id(site_var.get().strip(), collectors_cache),
            "password": password_var.get(),
            "poll_interval": poll_var.get().strip() or DEFAULT_POLL_INTERVAL,
            "insecure": "1" if insecure_var.get() else "0",
        }
        errors = validate_config(candidate)
        if errors:
            messagebox.showerror("Cajal Agent Setup", "\n".join(errors), parent=root)
            return
        result.update(candidate)
        root.destroy()

    load_btn.configure(command=load_collectors)

    save_btn = tk.Button(button_row, text="Save", width=12, command=save_and_close)
    cancel_btn = tk.Button(button_row, text="Cancel", width=12, command=close_without_save)
    save_btn.grid(row=0, column=0, padx=(0, 8))
    cancel_btn.grid(row=0, column=1)

    root.bind("<Return>", lambda _event: save_and_close())
    root.bind("<Escape>", lambda _event: close_without_save())
    server_entry.focus_set()
    if normalize_server(initial.get("server", "")):
        root.after(80, load_collectors)
    root.mainloop()

    if not result:
        return None
    return result


def parse_args():
    parser = argparse.ArgumentParser(description="Configure Cajal Linux collector agent")
    parser.add_argument("--env-file", default=DEFAULT_ENV_FILE, help="Path to write agent env file")
    parser.add_argument("--server", default="", help="Pre-fill Cajal URL")
    parser.add_argument("--site", default="", help="Pre-fill collector site id/name")
    parser.add_argument("--password", default="", help="Pre-fill agent password")
    parser.add_argument("--poll-interval", default="", help="Pre-fill poll interval in seconds")
    parser.add_argument("--insecure", default="", help="Pre-fill insecure TLS (0/1)")
    parser.add_argument("--print-env", action="store_true", help="Print env content to stdout instead of writing file")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SEC, help="Network timeout in seconds")
    parser.add_argument("--skip-verify", action="store_true", help="Skip live register/poll verification before save")
    parser.add_argument("--strict-tools", action="store_true", help="Require speedtest CLI locally in addition to core tools")
    parser.add_argument("--list-collectors", action="store_true", help="List collector sites from server and exit")
    return parser.parse_args()


def build_initial_values(args, existing):
    server = normalize_server(args.server or existing.get("CAJAL_AGENT_SERVER") or "")
    site = str(args.site or existing.get("CAJAL_AGENT_SITE") or "").strip()
    password = str(args.password or existing.get("CAJAL_AGENT_PASSWORD") or "")
    poll_interval = str(args.poll_interval or existing.get("CAJAL_AGENT_POLL_INTERVAL") or DEFAULT_POLL_INTERVAL).strip()
    insecure = normalize_insecure(args.insecure or existing.get("CAJAL_AGENT_INSECURE") or "0")
    return {
        "server": server,
        "site": site,
        "password": password,
        "poll_interval": poll_interval,
        "insecure": insecure,
    }


def print_collectors_list(server, insecure=False, timeout_sec=DEFAULT_TIMEOUT_SEC):
    rows = fetch_collectors(server, insecure=insecure, timeout_sec=timeout_sec)
    if not rows:
        print("No collector sites found.")
        return 0
    print("Collector sites:")
    for idx, row in enumerate(rows, start=1):
        status = "password-set" if row.get("agentPasswordSet") else "password-missing"
        print(f"{idx}. {row.get('name')} [{row.get('id')}] ({status})")
    return 0


def main():
    args = parse_args()
    existing = parse_env_file(args.env_file)
    initial = build_initial_values(args, existing)
    timeout_sec = max(0.4, float(args.timeout or DEFAULT_TIMEOUT_SEC))

    if args.list_collectors:
        if not initial.get("server"):
            print("Server URL is required for --list-collectors (set --server or CAJAL_AGENT_SERVER).", file=sys.stderr)
            return 2
        try:
            return print_collectors_list(initial["server"], insecure=initial.get("insecure") == "1", timeout_sec=timeout_sec)
        except Exception as exc:
            print(f"Collector listing failed: {exc}", file=sys.stderr)
            return 1

    config = collect_gui(initial, timeout_sec=timeout_sec)
    if config is None and not args.print_env:
        config = collect_cli(initial, timeout_sec=timeout_sec)
    if config is None:
        print("No setup input collected.", file=sys.stderr)
        return 1

    errors = validate_config(config)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 2

    install_identity = generate_install_identity()
    config["install_id"] = install_identity["install_id"]
    config["installed_at"] = install_identity["installed_at"]

    tool_rows, tool_failed = local_tool_checks(strict_speedtest=bool(args.strict_tools))
    print_local_tool_report(tool_rows)
    if tool_failed:
        print("Missing required local tools. Install them and run setup again.", file=sys.stderr)
        return 4

    if not args.skip_verify:
        ok, message = verify_registration(config, timeout_sec=timeout_sec)
        if not ok:
            print(message, file=sys.stderr)
            print("Tip: fix server/site/password and try again, or use --skip-verify to override.", file=sys.stderr)
            return 3
        print(message, file=sys.stderr)

    content = render_env_content(config)
    if args.print_env:
        sys.stdout.write(content)
        return 0

    write_env_file(args.env_file, content)
    print(f"Wrote {args.env_file}")
    print("Run: sudo systemctl enable --now cajal-agent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
