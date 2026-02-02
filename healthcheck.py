#!/usr/bin/env python3
import os
import json
import time
import socket
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
import urllib.parse
import urllib.request


# -----------------------------
# Environment / Configuration
# -----------------------------
def env_str(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()

def env_int(key: str, default: int) -> int:
    v = env_str(key, str(default))
    return int(v)

def env_float(key: str, default: float) -> float:
    v = env_str(key, str(default))
    return float(v)

def env_csv(key: str, default: str) -> List[str]:
    raw = env_str(key, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


SLACK_WEBHOOK_URL = env_str("SLACK_WEBHOOK_URL")
if not SLACK_WEBHOOK_URL:
    raise RuntimeError("SLACK_WEBHOOK_URL is required")

SLACK_USERNAME = env_str("SLACK_USERNAME", "YK Web Watchdog")
SLACK_ICON_EMOJI = env_str("SLACK_ICON_EMOJI", ":dog:")
SLACK_POST_MODE = env_str("SLACK_POST_MODE", "json").lower()
if SLACK_POST_MODE not in ("json", "payload"):
    raise RuntimeError("SLACK_POST_MODE must be 'json' or 'payload'")

ENABLE_MENTIONS = env_str("ENABLE_MENTIONS", "1")  # Enable mentions (1=enabled, 0=disabled)
ALWAYS_MENTION = env_csv("ALWAYS_MENTION", "@박평우")  # Comma-separated list of mentions (only used if ENABLE_MENTIONS=1)
CHANNEL_MENTION_ON_FAIL = env_str("CHANNEL_MENTION_ON_FAIL", "1")  # Mention channel on failure (only used if ENABLE_MENTIONS=1)
SLACK_IMAGE_URL = env_str("SLACK_IMAGE_URL", "")  # Optional image URL for each notification
SLACK_EMOJI_ROTATION = env_str("SLACK_EMOJI_ROTATION", "1")  # Enable emoji rotation (1=enabled, 0=disabled)

TARGETS_RAW = env_str("TARGETS")
if not TARGETS_RAW:
    raise RuntimeError("TARGETS is required")
TARGETS = [u.strip() for u in TARGETS_RAW.split(",") if u.strip()]

HC_TIMEOUT_SEC = env_float("HC_TIMEOUT_SEC", 5.0)
HC_SLOW_MS = env_int("HC_SLOW_MS", 1500)

REPORT_MODE = env_str("REPORT_MODE", "always").lower()
if REPORT_MODE not in ("always", "on_change", "on_error"):
    raise RuntimeError("REPORT_MODE must be 'always', 'on_change', or 'on_error'")

# Daily report settings
DAILY_REPORT_TIME = env_str("DAILY_REPORT_TIME", "09:00")  # Format: HH:MM (24-hour)
DAILY_REPORT_ENABLED = env_str("DAILY_REPORT_ENABLED", "1")  # Enable daily report (1=enabled, 0=disabled)

STATE_FILE = env_str("STATE_FILE", "./state.json")

LOG_DIR = env_str("LOG_DIR", "./logs")
SLACK_MAX_CHARS = env_int("SLACK_MAX_CHARS", 3500)

HEADER_KEYS = [h.lower() for h in env_csv(
    "HEADER_KEYS",
    "strict-transport-security,cache-control,etag,last-modified,server,content-type,date,cf-cache-status,cf-ray,x-cache,via"
)]

CERT_WARN_DAYS = env_int("CERT_WARN_DAYS", 30)
CERT_ALERT_DAYS = env_int("CERT_ALERT_DAYS", 7)
CERT_MAX_SAN_ITEMS = env_int("CERT_MAX_SAN_ITEMS", 15)

MAX_REDIRECTS = env_int("MAX_REDIRECTS", 10)


# -----------------------------
# Models
# -----------------------------
@dataclass
class SslInfo:
    notafter: Optional[str]
    expires_in_days: Optional[int]
    issuer: Optional[str]
    subject: Optional[str]
    san: Optional[List[str]]
    san_covers_host: Optional[bool]


@dataclass
class CurlMetrics:
    url: str
    http_code: Optional[int]
    ok: bool
    total_ms: Optional[int]
    dns_ms: Optional[int]
    connect_ms: Optional[int]
    tls_ms: Optional[int]
    ttfb_ms: Optional[int]
    remote_ip: Optional[str]
    redirect_url: Optional[str]
    redirect_chain: Optional[List[str]]
    err: Optional[str]
    raw: Optional[Dict]
    headers: Optional[Dict[str, str]]
    ssl: Optional[SslInfo]


# -----------------------------
# Logging helpers
# -----------------------------
def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def today_ymd() -> str:
    return datetime.now().strftime("%Y-%m-%d")

def log_file_path() -> str:
    ensure_dir(LOG_DIR)
    return os.path.join(LOG_DIR, f"{today_ymd()}.log")

def append_log(line: str) -> None:
    with open(log_file_path(), "a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")

def now_local_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def parse_time_str(time_str: str) -> Tuple[int, int]:
    """Parse time string 'HH:MM' to (hour, minute)"""
    try:
        parts = time_str.split(":")
        return int(parts[0]), int(parts[1])
    except Exception:
        return 9, 0  # Default to 9:00

def should_send_daily_report() -> bool:
    """Check if it's time to send daily report"""
    if DAILY_REPORT_ENABLED != "1":
        return False
    
    state = load_state()
    global_state = state.get("_global", {})
    last_report_date = global_state.get("last_daily_report_date", "")
    today = today_ymd()
    
    # Already sent today
    if last_report_date == today:
        return False
    
    # Check if current time matches DAILY_REPORT_TIME
    report_hour, report_minute = parse_time_str(DAILY_REPORT_TIME)
    now = datetime.now()
    
    # Check if we're within the report time window (within 3 minutes)
    if now.hour == report_hour and report_minute <= now.minute < report_minute + 3:
        return True
    
    return False

def build_restart_report(last_run_time: str, current_time: str) -> Optional[str]:
    """Build report for restart - shows history since last run"""
    state = load_state()
    global_state = state.get("_global", {})
    check_history = global_state.get("_check_history", [])
    
    if not check_history:
        return None
    
    # Filter entries since last run
    # Parse last_run_time and current_time to compare
    try:
        last_dt = datetime.strptime(last_run_time, "%Y-%m-%d %H:%M:%S")
        current_dt = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
        
        # Get entries between last_run and current (before current check)
        filtered_entries = []
        for entry in check_history:
            entry_ts = entry.get("ts", "")
            try:
                entry_dt = datetime.strptime(entry_ts, "%Y-%m-%d %H:%M:%S")
                if last_dt < entry_dt < current_dt:
                    filtered_entries.append(entry)
            except Exception:
                continue
    except Exception:
        # If parsing fails, use all recent entries (last 10)
        filtered_entries = check_history[-10:]
    
    if not filtered_entries:
        return None
    
    # Analyze history
    total_checks = len(filtered_entries)
    failed_checks = sum(1 for e in filtered_entries if e.get("has_issue", False))
    success_checks = total_checks - failed_checks
    
    # Group by time periods
    issue_periods = []
    current_issue_start = None
    
    for entry in filtered_entries:
        ts = entry.get("ts", "")
        has_issue = entry.get("has_issue", False)
        
        if has_issue:
            if current_issue_start is None:
                current_issue_start = ts
        else:
            if current_issue_start is not None:
                issue_periods.append((current_issue_start, ts))
                current_issue_start = None
    
    # If issue was ongoing
    if current_issue_start is not None:
        issue_periods.append((current_issue_start, "재기동 시점까지 진행 중"))
    
    # Build report
    lines = [
        "🔄 *재기동 리포트*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"⏸️  마지막 실행: `{last_run_time}`",
        f"▶️  재기동 시간: `{current_time}`",
        f"🔍 기간 내 검사 횟수: `{total_checks}`회",
        f"✅ 성공: `{success_checks}`회 ({success_checks*100//total_checks if total_checks > 0 else 0}%)",
        f"❌ 실패: `{failed_checks}`회 ({failed_checks*100//total_checks if total_checks > 0 else 0}%)",
        ""
    ]
    
    if issue_periods:
        lines.append("⚠️ *문제 발생 시간대:*")
        for start, end in issue_periods:
            lines.append(f"   • `{start}` ~ `{end}`")
    else:
        lines.append("✅ *기간 내 문제 없음*")
    
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    return "\n".join(lines)

def build_daily_report() -> Optional[str]:
    """Build daily report from check history"""
    state = load_state()
    global_state = state.get("_global", {})
    check_history = global_state.get("_check_history", [])
    
    if not check_history:
        return None
    
    # Filter yesterday's entries (approximately)
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    yesterday_entries = [e for e in check_history if e.get("ts", "").startswith(yesterday)]
    
    if not yesterday_entries:
        return None
    
    # Analyze history
    total_checks = len(yesterday_entries)
    failed_checks = sum(1 for e in yesterday_entries if e.get("has_issue", False))
    success_checks = total_checks - failed_checks
    
    # Group by time periods
    issue_periods = []
    current_issue_start = None
    
    for entry in yesterday_entries:
        ts = entry.get("ts", "")
        has_issue = entry.get("has_issue", False)
        
        if has_issue:
            if current_issue_start is None:
                current_issue_start = ts
        else:
            if current_issue_start is not None:
                issue_periods.append((current_issue_start, ts))
                current_issue_start = None
    
    # If issue was ongoing at end of day
    if current_issue_start is not None:
        issue_periods.append((current_issue_start, "진행 중"))
    
    # Build report
    lines = [
        "📊 *일일 리포트*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📅 날짜: `{yesterday}`",
        f"🔍 총 검사 횟수: `{total_checks}`회",
        f"✅ 성공: `{success_checks}`회 ({success_checks*100//total_checks if total_checks > 0 else 0}%)",
        f"❌ 실패: `{failed_checks}`회 ({failed_checks*100//total_checks if total_checks > 0 else 0}%)",
        ""
    ]
    
    if issue_periods:
        lines.append("⚠️ *문제 발생 시간대:*")
        for start, end in issue_periods:
            lines.append(f"   • `{start}` ~ `{end}`")
    else:
        lines.append("✅ *전날 문제 없음*")
    
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    return "\n".join(lines)


# -----------------------------
# Networking helpers
# -----------------------------
def safe_int_ms(sec_str: str) -> Optional[int]:
    try:
        return int(float(sec_str) * 1000)
    except Exception:
        return None

def dns_lookup(host: str) -> Dict[str, List[str]]:
    res: Dict[str, List[str]] = {"A": [], "AAAA": []}
    try:
        infos = socket.getaddrinfo(host, None)
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if fam == socket.AF_INET and ip not in res["A"]:
                res["A"].append(ip)
            elif fam == socket.AF_INET6 and ip not in res["AAAA"]:
                res["AAAA"].append(ip)
    except Exception:
        pass
    return res

def run_cmd(cmd: List[str], timeout_sec: float) -> Tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


# -----------------------------
# Header / Redirect parsing
# -----------------------------
def parse_headers_from_curl_dump(raw_header_text: str) -> Dict[str, str]:
    """
    Parse the LAST response header block from curl -L -D - output.
    """
    text = raw_header_text.replace("\r\n", "\n").strip()
    if not text:
        return {}
    blocks = text.split("\n\n")
    last = blocks[-1]
    lines = [ln.strip() for ln in last.split("\n") if ln.strip()]

    hdrs: Dict[str, str] = {}
    for ln in lines[1:]:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        hdrs[k.strip().lower()] = v.strip()
    return hdrs

def normalize_url(base: str, location: str) -> str:
    return urllib.parse.urljoin(base, location)

def extract_redirect_chain_from_header_dump(start_url: str, raw_header_text: str) -> List[str]:
    """
    Reconstruct redirect chain by reading Location headers per header block.
    """
    text = raw_header_text.replace("\r\n", "\n").strip()
    if not text:
        return [start_url]

    blocks = text.split("\n\n")
    chain = [start_url]
    current = start_url

    for blk in blocks:
        lines = [ln.strip() for ln in blk.split("\n") if ln.strip()]
        if not lines:
            continue

        loc = None
        for ln in lines[1:]:
            if ln.lower().startswith("location:"):
                loc = ln.split(":", 1)[1].strip()
                break

        if loc:
            nxt = normalize_url(current, loc)
            chain.append(nxt)
            current = nxt

        if len(chain) >= MAX_REDIRECTS + 1:
            break

    collapsed: List[str] = []
    for u in chain:
        if not collapsed or collapsed[-1] != u:
            collapsed.append(u)
    return collapsed

def fetch_redirect_chain(url: str) -> Tuple[List[str], Optional[str]]:
    """
    Fetch redirect chain using curl -L -D - output.
    """
    cmd = [
        "curl", "-sS",
        "-L",
        "-D", "-",
        "-o", "/dev/null",
        "--max-time", str(HC_TIMEOUT_SEC),
        "--connect-timeout", str(HC_TIMEOUT_SEC),
        url,
    ]
    try:
        rc, out, err = run_cmd(cmd, timeout_sec=HC_TIMEOUT_SEC + 3.0)
        if rc != 0:
            return [url], (err.strip() or f"curl redirect rc={rc}")
        chain = extract_redirect_chain_from_header_dump(url, out)
        return chain, None
    except Exception as e:
        return [url], f"exception={repr(e)}"

def fetch_selected_headers(url: str) -> Dict[str, str]:
    """
    Fetch final response headers and pick keys defined in HEADER_KEYS.
    """
    cmd = [
        "curl", "-sS",
        "-I", "-L",
        "-D", "-",
        "-o", "/dev/null",
        "--max-time", str(HC_TIMEOUT_SEC),
        "--connect-timeout", str(HC_TIMEOUT_SEC),
        url,
    ]
    try:
        rc, out, err = run_cmd(cmd, timeout_sec=HC_TIMEOUT_SEC + 3.0)
        if rc != 0:
            return {"_error": (err.strip() or f"curl -I rc={rc}")}
        all_hdrs = parse_headers_from_curl_dump(out)
        selected: Dict[str, str] = {}
        for k in HEADER_KEYS:
            if k in all_hdrs:
                selected[k] = all_hdrs[k]
        return selected if selected else all_hdrs
    except Exception as e:
        return {"_error": f"exception={repr(e)}"}


# -----------------------------
# SSL parsing (notAfter + SAN + days left)
# -----------------------------
def parse_openssl_notafter_to_days_left(notafter: str) -> Optional[int]:
    """
    Convert 'Feb 25 23:59:59 2026 GMT' to remaining days (UTC).
    """
    try:
        s = notafter.replace("  ", " ").strip()
        if s.endswith(" GMT"):
            s = s[:-4].strip()
        dt = datetime.strptime(s, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        delta = dt - now_utc()
        return int(delta.total_seconds() // 86400)
    except Exception:
        return None

def shorten_dn(dn: Optional[str]) -> Optional[str]:
    """
    Keep O and CN fields for Slack readability.
    """
    if not dn:
        return None
    parts = [p.strip() for p in dn.split(",")]
    keep = []
    for p in parts:
        if p.startswith("O =") or p.startswith("CN =") or p.startswith("O=") or p.startswith("CN="):
            keep.append(p.replace(" = ", "=").replace(" =","=").replace("= ", "="))
    if keep:
        s = ", ".join(keep)
        return s if len(s) <= 180 else s[:180] + "…"
    return dn[:180] + ("…" if len(dn) > 180 else "")

def ssl_info(host: str) -> SslInfo:
    """
    Extract cert notAfter, issuer, subject, SAN list, and SAN coverage.
    """
    try:
        s_client = [
            "openssl", "s_client",
            "-servername", host,
            "-connect", f"{host}:443",
            "-showcerts",
        ]
        x509 = ["openssl", "x509", "-noout", "-enddate", "-issuer", "-subject", "-ext", "subjectAltName"]

        p1 = subprocess.Popen(
            s_client,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        try:
            out1, _err1 = p1.communicate(timeout=HC_TIMEOUT_SEC + 4.0)
        except subprocess.TimeoutExpired:
            p1.kill()
            return SslInfo(None, None, None, None, None, None)

        if p1.returncode != 0 or not out1:
            return SslInfo(None, None, None, None, None, None)

        p2 = subprocess.run(x509, input=out1, capture_output=True, text=True, timeout=HC_TIMEOUT_SEC + 4.0)
        if p2.returncode != 0:
            return SslInfo(None, None, None, None, None, None)

        notafter = issuer = subject = None
        san_list: List[str] = []
        in_san = False

        for ln in (p2.stdout or "").splitlines():
            ln = ln.strip()
            if ln.startswith("notAfter="):
                notafter = ln.replace("notAfter=", "").strip()
            elif ln.startswith("issuer="):
                issuer = ln.replace("issuer=", "").strip()
            elif ln.startswith("subject="):
                subject = ln.replace("subject=", "").strip()
            elif "X509v3 Subject Alternative Name" in ln:
                in_san = True
            elif in_san:
                if not ln or ln.startswith("X509v3") or ln.endswith(":"):
                    in_san = False
                else:
                    items = [x.strip() for x in ln.split(",")]
                    for it in items:
                        if it.startswith("DNS:"):
                            val = it.replace("DNS:", "").strip()
                            if val and val not in san_list:
                                san_list.append(val)

        expires_in_days = parse_openssl_notafter_to_days_left(notafter) if notafter else None

        # Coverage check (SAN-based, best-effort)
        covers: Optional[bool] = None
        if san_list:
            covers = False
            for san in san_list:
                if san == host:
                    covers = True
                    break
                if san.startswith("*."):
                    suffix = san[1:]  # ".yklawfirm.co.kr"
                    # Wildcard covers one level: *.yklawfirm.co.kr covers www.yklawfirm.co.kr but not yklawfirm.co.kr
                    # Check: host must end with suffix AND have exactly the same number of dots as suffix
                    # (because suffix already includes the dot after the wildcard)
                    if host.endswith(suffix):
                        host_dots = host.count(".")
                        suffix_dots = suffix.count(".")
                        # Example: www.yklawfirm.co.kr (3 dots) matches *.yklawfirm.co.kr -> .yklawfirm.co.kr (3 dots)
                        # The part before suffix should be exactly one label (no dots)
                        if host_dots == suffix_dots:
                            # Verify the prefix is exactly one label (no dots)
                            prefix = host[:-len(suffix)]  # "www" from "www.yklawfirm.co.kr"
                            if prefix and "." not in prefix:
                                covers = True
                                break

        # Limit SAN items for Slack
        if len(san_list) > CERT_MAX_SAN_ITEMS:
            san_list = san_list[:CERT_MAX_SAN_ITEMS] + ["…(truncated)"]

        return SslInfo(
            notafter=notafter,
            expires_in_days=expires_in_days,
            issuer=shorten_dn(issuer),
            subject=shorten_dn(subject),
            san=san_list if san_list else None,
            san_covers_host=covers,
        )
    except Exception:
        return SslInfo(None, None, None, None, None, None)


# -----------------------------
# State (on_change mode)
# -----------------------------
def load_state() -> Dict[str, Dict]:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

def save_state(state: Dict[str, Dict]) -> None:
    parent = os.path.dirname(os.path.abspath(STATE_FILE))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

def should_notify(results: List[CurlMetrics]) -> Tuple[bool, str]:
    if REPORT_MODE == "always":
        return True, "always"
    
    if REPORT_MODE == "on_error":
        # on_error mode: only notify when there's an issue, and keep notifying while issue persists
        prev = load_state()
        new_state = prev.copy()
        
        # Check if there's any issue now
        has_issue_now = any(not r.ok for r in results)
        prev_has_issue = prev.get("_global", {}).get("has_issue", False)
        
        # Update state for each URL
        for r in results:
            key = r.url
            new_state[key] = {
                "ok": r.ok,
                "http_code": r.http_code,
                "total_ms": r.total_ms,
                "ts": now_local_str(),
            }
        
        # Update global issue state
        if "_global" not in new_state:
            new_state["_global"] = {}
        
        # Record check history for daily report
        if "_check_history" not in new_state["_global"]:
            new_state["_global"]["_check_history"] = []
        
        check_entry = {
            "ts": now_local_str(),
            "has_issue": has_issue_now,
            "results": {r.url: {"ok": r.ok, "http_code": r.http_code} for r in results}
        }
        new_state["_global"]["_check_history"].append(check_entry)
        
        # Keep only last 24 hours of history (approximately 480 entries for 3-minute intervals)
        max_history = 480
        if len(new_state["_global"]["_check_history"]) > max_history:
            new_state["_global"]["_check_history"] = new_state["_global"]["_check_history"][-max_history:]
        
        new_state["_global"]["has_issue"] = has_issue_now
        new_state["_global"]["last_check"] = now_local_str()
        
        save_state(new_state)
        
        # Notify if: (1) issue just occurred, or (2) issue persists
        if has_issue_now:
            if not prev_has_issue:
                return True, "issue_detected"
            else:
                return True, "issue_persists"
        else:
            # Issue resolved, but don't notify
            return False, "issue_resolved"

    # on_change mode (existing logic)
    prev = load_state()
    new_state = prev.copy()
    changes: List[str] = []

    for r in results:
        key = r.url
        prev_ok = prev.get(key, {}).get("ok", None)
        new_state[key] = {
            "ok": r.ok,
            "http_code": r.http_code,
            "total_ms": r.total_ms,
            "ts": now_local_str(),
        }
        if prev_ok is None:
            changes.append(f"INIT {key} => {'UP' if r.ok else 'DOWN'}")
        elif bool(prev_ok) != bool(r.ok):
            changes.append(f"CHANGE {key}: {'UP' if prev_ok else 'DOWN'} -> {'UP' if r.ok else 'DOWN'}")

    save_state(new_state)
    return (len(changes) > 0), ("; ".join(changes) if changes else "no_change")


# -----------------------------
# Healthcheck core
# -----------------------------
def run_curl(url: str) -> CurlMetrics:
    write_out = (
        r'{"http_code":"%{http_code}",'
        r'"time_namelookup":"%{time_namelookup}",'
        r'"time_connect":"%{time_connect}",'
        r'"time_appconnect":"%{time_appconnect}",'
        r'"time_starttransfer":"%{time_starttransfer}",'
        r'"time_total":"%{time_total}",'
        r'"remote_ip":"%{remote_ip}",'
        r'"redirect_url":"%{redirect_url}"}'
    )

    cmd = [
        "curl", "-sS",
        "-L",
        "-o", "/dev/null",
        "--max-time", str(HC_TIMEOUT_SEC),
        "--connect-timeout", str(HC_TIMEOUT_SEC),
        "-w", write_out,
        url,
    ]

    start = time.time()
    raw = None
    http_code = None
    total_ms = None
    dns_ms = connect_ms = tls_ms = ttfb_ms = None
    remote_ip = redirect_url = None
    err = None

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.time() - start

        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()

        try:
            raw = json.loads(stdout)
            code_str = (raw.get("http_code") or "").strip()
            http_code = int(code_str) if code_str.isdigit() else None

            dns_ms = safe_int_ms(raw.get("time_namelookup", ""))
            connect_ms = safe_int_ms(raw.get("time_connect", ""))
            tls_ms = safe_int_ms(raw.get("time_appconnect", ""))
            ttfb_ms = safe_int_ms(raw.get("time_starttransfer", ""))
            total_ms = safe_int_ms(raw.get("time_total", ""))

            remote_ip = (raw.get("remote_ip") or "").strip() or None
            redirect_url = (raw.get("redirect_url") or "").strip() or None
        except Exception:
            err = f"Failed to parse curl write-out: {stdout[:250]}"

        ok = (http_code is not None) and (200 <= http_code < 400) and proc.returncode == 0

        if proc.returncode != 0 or not ok:
            base = f"curl_rc={proc.returncode}, stderr={stderr or 'none'}"
            err = (err + " | " if err else "") + base

        if total_ms is None:
            total_ms = int(elapsed * 1000)

    except Exception as e:
        ok = False
        err = f"exception={repr(e)}"

    # Extras: headers + redirects + ssl
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.split("@")[-1].split(":")[0] if parsed.netloc else ""

    headers = fetch_selected_headers(url)

    chain, chain_err = fetch_redirect_chain(url)
    if chain_err:
        err = (err + " | " if err else "") + f"redirect_chain_err={chain_err}"

    ssl_obj = None
    if parsed.scheme == "https" and host:
        ssl_obj = ssl_info(host)

    return CurlMetrics(
        url=url,
        http_code=http_code,
        ok=ok,
        total_ms=total_ms,
        dns_ms=dns_ms,
        connect_ms=connect_ms,
        tls_ms=tls_ms,
        ttfb_ms=ttfb_ms,
        remote_ip=remote_ip,
        redirect_url=redirect_url,
        redirect_chain=chain,
        err=err,
        raw=raw,
        headers=headers,
        ssl=ssl_obj,
    )


# -----------------------------
# Slack formatting
# -----------------------------
def get_rotating_emoji() -> str:
    """
    Returns a rotating emoji based on current time (changes every minute).
    """
    if SLACK_EMOJI_ROTATION != "1":
        return SLACK_ICON_EMOJI
    
    emojis = [":dog:", ":watchdog:", ":eyes:", ":mag:", ":satellite:", ":earth_asia:", ":globe_with_meridians:", ":computer:", ":rocket:", ":zap:"]
    # Use minute of hour to rotate emoji
    minute = datetime.now().minute
    return emojis[minute % len(emojis)]

def slack_post(payload_obj: Dict) -> None:
    if SLACK_POST_MODE == "payload":
        body = urllib.parse.urlencode({"payload": json.dumps(payload_obj, ensure_ascii=False)}).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
    else:
        body = json.dumps(payload_obj, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8"}

    req = urllib.request.Request(SLACK_WEBHOOK_URL, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=HC_TIMEOUT_SEC) as resp:
        _ = resp.read()

def short_url(u: str) -> str:
    try:
        p = urllib.parse.urlparse(u)
        path = p.path if p.path else "/"
        return f"{p.scheme}://{p.netloc}{path}"
    except Exception:
        return u

def chain_to_str(chain: Optional[List[str]]) -> str:
    if not chain or len(chain) <= 1:
        return "-"
    return " -> ".join(short_url(x) for x in chain)

def headers_pretty(h: Dict[str, str]) -> str:
    if not h:
        return "-"
    if "_error" in h:
        return f"(error) {h.get('_error')}"
    parts = []
    for k in HEADER_KEYS:
        if k in h:
            v = h[k]
            kk = k
            if k == "content-type":
                kk = "type"
            elif k == "cache-control":
                kk = "cache"
            elif k == "strict-transport-security":
                kk = "hsts"
            parts.append(f"{kk}={v}")
    if not parts:
        for i, (k, v) in enumerate(h.items()):
            if i >= 6:
                break
            parts.append(f"{k}={v}")
    return " | ".join(parts)

def build_slack_text(results: List[CurlMetrics], run_id: str, host: str) -> Tuple[str, bool]:
    """
    Returns (text, should_ping_channel_due_to_cert)
    """
    # Beautiful header format with emoji
    header = (
        f"🔍 *Health Check Report*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🆔 `{run_id}` | 🖥️ `{host}` | 🕐 `{now_local_str()}`\n"
        f"⏱️ Timeout: `{HC_TIMEOUT_SEC}s` | 🐌 Slow: `>={HC_SLOW_MS}ms` | 📊 Mode: `{REPORT_MODE}`"
    )

    lines: List[str] = [header, ""]
    cert_warn_hit = False

    for r in results:
        parsed = urllib.parse.urlparse(r.url)
        domain = parsed.netloc or r.url
        status_txt = str(r.http_code) if r.http_code is not None else "NO_STATUS"
        is_slow = (r.ok and r.total_ms is not None and r.total_ms >= HC_SLOW_MS)

        status_emoji = "🟢" if r.ok else "🔴"
        slow_emoji = " 🐢" if is_slow else ""

        cert_emoji = ""
        cert_line = "ssl: -"
        issuer_line = None
        san_line = "san: -"

        if parsed.scheme == "https" and r.ssl:
            left = r.ssl.expires_in_days
            left_str = f"{left}d" if left is not None else "-"
            cert_line = f"ssl: notAfter={r.ssl.notafter or '-'}  cert_expires_in={left_str}  subject={r.ssl.subject or '-'}"
            issuer_line = f"issuer: {r.ssl.issuer or '-'}"

            cover = ""
            if r.ssl.san_covers_host is True:
                cover = " (covers host ✅)"
            elif r.ssl.san_covers_host is False:
                cover = " (covers host ❌)"

            if r.ssl.san:
                san_line = "san" + cover + ": " + ", ".join(r.ssl.san)
            else:
                san_line = "san" + cover + ": -"

            # Cert alerting thresholds
            if left is not None:
                if left < 0:
                    cert_emoji = " 💥"
                    cert_warn_hit = True
                elif left <= CERT_ALERT_DAYS:
                    cert_emoji = " 🧨"
                    cert_warn_hit = True
                elif left <= CERT_WARN_DAYS:
                    cert_emoji = " ⚠️"
                    cert_warn_hit = True

        # Build beautiful formatted output for each domain
        # Domain header with status
        status_icon = "✅" if r.ok else "❌"
        domain_header = f"{status_icon} *{domain}*"
        if is_slow:
            domain_header += " 🐢 *SLOW*"
        if cert_emoji:
            domain_header += cert_emoji
        
        lines.append(domain_header)
        lines.append(f"   📊 Status: `{status_txt}` | ⏱️ Total: `{r.total_ms}ms` | 🌐 IP: `{r.remote_ip or '-'}`")
        
        # Redirects
        redirect_str = chain_to_str(r.redirect_chain)
        if redirect_str != "-":
            lines.append(f"   🔀 Redirects: `{redirect_str}`")
        
        # DNS
        dns = dns_lookup(domain)
        dns_a = ','.join(dns['A']) if dns['A'] else '-'
        dns_aaaa = ','.join(dns['AAAA']) if dns['AAAA'] else '-'
        lines.append(f"   🌍 DNS: A=`{dns_a}` AAAA=`{dns_aaaa}`")
        
        # Timing breakdown
        timing_parts = []
        if r.dns_ms is not None:
            timing_parts.append(f"DNS={r.dns_ms}ms")
        if r.connect_ms is not None:
            timing_parts.append(f"Conn={r.connect_ms}ms")
        if r.tls_ms is not None:
            timing_parts.append(f"TLS={r.tls_ms}ms")
        if r.ttfb_ms is not None:
            timing_parts.append(f"TTFB={r.ttfb_ms}ms")
        if r.total_ms is not None:
            timing_parts.append(f"Total={r.total_ms}ms")
        if timing_parts:
            lines.append(f"   ⚡ Timing: `{' | '.join(timing_parts)}`")
        
        # SSL Certificate info
        if parsed.scheme == "https" and r.ssl:
            ssl_info_parts = []
            if r.ssl.notafter:
                ssl_info_parts.append(f"Expires: `{r.ssl.notafter}`")
            if r.ssl.expires_in_days is not None:
                days_left = r.ssl.expires_in_days
                if days_left < 0:
                    ssl_info_parts.append(f"⚠️ *EXPIRED* ({abs(days_left)}d ago)")
                elif days_left <= CERT_ALERT_DAYS:
                    ssl_info_parts.append(f"🚨 *{days_left}d left*")
                elif days_left <= CERT_WARN_DAYS:
                    ssl_info_parts.append(f"⚠️ *{days_left}d left*")
                else:
                    ssl_info_parts.append(f"✅ {days_left}d left")
            
            if ssl_info_parts:
                lines.append(f"   🔒 SSL: {' | '.join(ssl_info_parts)}")
            
            if r.ssl.subject:
                lines.append(f"   📜 Subject: `{r.ssl.subject}`")
            
            if r.ssl.issuer:
                lines.append(f"   🏢 Issuer: `{r.ssl.issuer}`")
            
            if r.ssl.san:
                # Show covers host status only when it's explicitly True or False
                if r.ssl.san_covers_host is True:
                    cover_text = " (✅ covers host)"
                elif r.ssl.san_covers_host is False:
                    cover_text = " (❌ does not cover host)"
                else:
                    cover_text = ""  # Unknown status, don't show anything
                lines.append(f"   📋 SAN{cover_text}: `{', '.join(r.ssl.san)}`")
        
        # Headers
        headers_str = headers_pretty(r.headers or {})
        if headers_str and headers_str != "-":
            # Truncate long headers for readability
            if len(headers_str) > 200:
                headers_str = headers_str[:200] + "..."
            lines.append(f"   📨 Headers: `{headers_str}`")
        
        # Error
        if r.err:
            lines.append(f"   ⚠️ Error: `{r.err[:200]}{'...' if len(r.err) > 200 else ''}`")
        
        lines.append("")  # Empty line between domains

    # Add footer
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    text = "\n".join(lines).strip()
    if len(text) > SLACK_MAX_CHARS:
        text = text[: SLACK_MAX_CHARS - 250] + "\n\n⚠️ *메시지가 잘렸습니다*\n" + f"전체 로그: `{log_file_path()}`"

    return text, cert_warn_hit


# -----------------------------
# Main
# -----------------------------
def main() -> None:
    host = socket.gethostname()
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    current_time = now_local_str()

    append_log(f"[{now_local_str()}] run_id={run_id} start host={host}")

    # Check for restart (gap in execution)
    state = load_state()
    global_state = state.get("_global", {})
    last_check_time = global_state.get("last_check", None)
    is_restart = False
    
    if last_check_time:
        try:
            # Parse last check time and current time
            last_dt = datetime.strptime(last_check_time, "%Y-%m-%d %H:%M:%S")
            current_dt = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
            time_diff = (current_dt - last_dt).total_seconds()
            
            # If gap is more than 10 minutes (normal interval is 3 minutes), consider it a restart
            if time_diff > 600:  # 10 minutes
                is_restart = True
        except Exception:
            # If parsing fails, check if state file exists but is old
            is_restart = True
    else:
        # No previous check - first run or after deletion
        is_restart = True
    
    # Check if we should send daily report
    if should_send_daily_report():
        daily_report = build_daily_report()
        if daily_report:
            # Send daily report
            prefix_lines = []
            prefix_lines.append("🐕 *YK Watchdog*")
            prefix_lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            
            if ENABLE_MENTIONS == "1" and ALWAYS_MENTION:
                mentions = " ".join(ALWAYS_MENTION)
                prefix_lines.append(f"mentions: {mentions}")
            
            prefix = "\n".join(prefix_lines) + "\n\n"
            
            payload = {
                "text": prefix + daily_report,
                "username": SLACK_USERNAME,
                "icon_emoji": get_rotating_emoji(),
            }
            
            try:
                slack_post(payload)
                # Mark daily report as sent
                state = load_state()
                if "_global" not in state:
                    state["_global"] = {}
                state["_global"]["last_daily_report_date"] = today_ymd()
                save_state(state)
                append_log(f"[{now_local_str()}] run_id={run_id} daily_report=sent")
            except Exception as e:
                append_log(f"[{now_local_str()}] run_id={run_id} daily_report=failed err={repr(e)}")

    results = [run_curl(url) for url in TARGETS]

    append_log(json.dumps({
        "ts": now_local_str(),
        "run_id": run_id,
        "host": host,
        "config": {
            "timeout_sec": HC_TIMEOUT_SEC,
            "slow_ms": HC_SLOW_MS,
            "report_mode": REPORT_MODE,
            "targets": TARGETS,
            "header_keys": HEADER_KEYS,
            "cert_warn_days": CERT_WARN_DAYS,
            "cert_alert_days": CERT_ALERT_DAYS,
            "cert_max_san_items": CERT_MAX_SAN_ITEMS,
            "max_redirects": MAX_REDIRECTS,
        },
        "results": [asdict(r) for r in results],
    }, ensure_ascii=False))

    notify, reason = should_notify(results)
    append_log(f"[{now_local_str()}] run_id={run_id} notify={notify} reason={reason}")

    # If restart detected, always send current status (even if no issue)
    if is_restart:
        notify = True
        reason = "restart_detected"

    if not notify:
        append_log(f"[{now_local_str()}] run_id={run_id} end (no notify)")
        return

    text, cert_warn_hit = build_slack_text(results, run_id=run_id, host=host)
    
    # If restart detected, send restart report first, then current status
    if is_restart and last_check_time:
        restart_report = build_restart_report(last_check_time, current_time)
        if restart_report:
            # Send restart report first
            prefix_lines_restart = []
            prefix_lines_restart.append("🐕 *YK Watchdog*")
            prefix_lines_restart.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            
            if ENABLE_MENTIONS == "1" and ALWAYS_MENTION:
                mentions = " ".join(ALWAYS_MENTION)
                prefix_lines_restart.append(f"mentions: {mentions}")
            
            prefix_restart = "\n".join(prefix_lines_restart) + "\n\n"
            
            payload_restart = {
                "text": prefix_restart + restart_report,
                "username": SLACK_USERNAME,
                "icon_emoji": get_rotating_emoji(),
            }
            
            try:
                slack_post(payload_restart)
                append_log(f"[{now_local_str()}] run_id={run_id} restart_report=sent")
            except Exception as e:
                append_log(f"[{now_local_str()}] run_id={run_id} restart_report=failed err={repr(e)}")
        
        # Add restart indicator to current status message
        restart_header = (
            "🔄 *재기동 감지 - 현재 상태*\n"
            f"⏸️  마지막 실행: `{last_check_time}`\n"
            f"▶️  재기동 시간: `{current_time}`\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        )
        text = restart_header + text

    # Mention logic with beautiful formatting:
    # - Only add mentions if ENABLE_MENTIONS is enabled
    # - Always mention the owners (ALWAYS_MENTION - comma-separated list)
    # - If any site is DOWN OR cert warning threshold is hit, add <!channel> (when enabled)
    # - Add "YK Watchdog" prefix before mentions
    prefix_lines = []
    
    # Add beautiful "YK Watchdog" header
    prefix_lines.append("🐕 *YK Watchdog*")
    prefix_lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    # Add mentions only if enabled
    if ENABLE_MENTIONS == "1":
        # Add individual mentions
        if ALWAYS_MENTION:
            mentions = " ".join(ALWAYS_MENTION)
            prefix_lines.append(f"mentions: {mentions}")

        if CHANNEL_MENTION_ON_FAIL == "1":
            if any(not r.ok for r in results) or cert_warn_hit:
                prefix_lines.append("📢 <!channel>")
    # else:
    #     # Mentions disabled
    #     prefix_lines.append("mentions disabled")

    prefix = "\n".join(prefix_lines) + "\n\n"

    # Prepare payload with rotating emoji
    current_emoji = get_rotating_emoji()
    payload = {
        "text": prefix + text,
        "username": SLACK_USERNAME,
        "icon_emoji": current_emoji,
    }
    
    # Add image attachment if configured
    if SLACK_IMAGE_URL:
        # Slack webhook supports attachments for images
        # For JSON mode, we can add attachments array
        if SLACK_POST_MODE == "json":
            payload["attachments"] = [
                {
                    "image_url": SLACK_IMAGE_URL,
                    "fallback": "YK Watchdog Status Check"
                }
            ]
        # For payload mode, we need to include it in the payload string
        # This is handled by the payload encoding above

    try:
        slack_post(payload)
        append_log(f"[{now_local_str()}] run_id={run_id} slack=sent")
    except Exception as e:
        append_log(f"[{now_local_str()}] run_id={run_id} slack=failed err={repr(e)}")

    append_log(f"[{now_local_str()}] run_id={run_id} end")


if __name__ == "__main__":
    main()

