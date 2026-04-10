#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import socket
import subprocess
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


# =========================================================
# Env helpers
# =========================================================
def env_str(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def env_int(key: str, default: int) -> int:
    raw = env_str(key, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{key} must be int, got {raw!r}") from exc


def env_float(key: str, default: float) -> float:
    raw = env_str(key, str(default))
    try:
        return float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{key} must be float, got {raw!r}") from exc


def env_bool(key: str, default: bool = False) -> bool:
    raw = env_str(key, "1" if default else "0").lower()
    return raw in {"1", "true", "yes", "y", "on"}


def env_csv(key: str, default: str = "") -> List[str]:
    raw = env_str(key, default)
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


# =========================================================
# Config
# =========================================================
SLACK_WEBHOOK_URL = env_str("SLACK_WEBHOOK_URL")
if not SLACK_WEBHOOK_URL:
    raise RuntimeError("SLACK_WEBHOOK_URL is required")

SLACK_USERNAME = env_str("SLACK_USERNAME", "YK Web Watchdog")
SLACK_ICON_EMOJI = env_str("SLACK_ICON_EMOJI", ":dog:")
SLACK_POST_MODE = env_str("SLACK_POST_MODE", "json").lower()
if SLACK_POST_MODE not in {"json", "payload"}:
    raise RuntimeError("SLACK_POST_MODE must be json or payload")

SLACK_IMAGE_URL = env_str("SLACK_IMAGE_URL", "")
# Slack webhooks cap message length; long text is sent as multiple sequential posts (no truncation of headers/errors).
# If posts fail, try SLACK_MAX_CHARS around 3000-4000.
SLACK_MAX_CHARS = env_int("SLACK_MAX_CHARS", 4000)
SLACK_EMOJI_ROTATION = env_bool("SLACK_EMOJI_ROTATION", True)

ENABLE_MENTIONS = env_bool("ENABLE_MENTIONS", True)
ALWAYS_MENTION = env_csv("ALWAYS_MENTION", "@\ubc15\ud3c9\uc6b0")
CHANNEL_MENTION_ON_FAIL = env_bool("CHANNEL_MENTION_ON_FAIL", True)

HC_TIMEOUT_SEC = env_float("HC_TIMEOUT_SEC", 10.0)
HC_CONNECT_TIMEOUT_SEC = env_float("HC_CONNECT_TIMEOUT_SEC", HC_TIMEOUT_SEC)
HC_SLOW_MS = env_int("HC_SLOW_MS", 1500)

REPORT_MODE = env_str("REPORT_MODE", "on_error").lower()
if REPORT_MODE not in {"always", "on_change", "on_error"}:
    raise RuntimeError("REPORT_MODE must be always/on_change/on_error")

STATE_FILE = env_str("STATE_FILE", "./state.json")
LOG_DIR = env_str("LOG_DIR", "./logs")
MAX_HISTORY = env_int("MAX_HISTORY", 480)
CLEANUP_DAYS = env_int("CLEANUP_DAYS", 7)

DAILY_REPORT_ENABLED = env_bool("DAILY_REPORT_ENABLED", True)
DAILY_REPORT_TIME = env_str("DAILY_REPORT_TIME", "09:00")

CERT_WARN_DAYS = env_int("CERT_WARN_DAYS", 30)
CERT_ALERT_DAYS = env_int("CERT_ALERT_DAYS", 7)
HEADER_KEYS = [
    h.lower()
    for h in env_csv(
        "HEADER_KEYS",
        "strict-transport-security,cache-control,etag,last-modified,server,content-type,date,x-cache-status,via",
    )
]


# =========================================================
# Endpoint config
# External VM only: redirect/service checks only
# =========================================================
DEFAULT_ENDPOINTS = [
    {
        "name": "brand-apex",
        "display_name": "yklawfirm.co.kr",
        "type": "redirect",
        "url": "https://yklawfirm.co.kr/",
        "expect_status": [301, 302, 307, 308],
        "expect_location_prefix": "https://www.yklawfirm.co.kr/",
        "dns_host": "yklawfirm.co.kr",
        "ssl_host": "yklawfirm.co.kr",
    },
    {
        "name": "brand-www",
        "display_name": "www.yklawfirm.co.kr",
        "type": "service",
        "url": "https://www.yklawfirm.co.kr/",
        "expect_status": [200],
        "dns_host": "www.yklawfirm.co.kr",
        "ssl_host": "www.yklawfirm.co.kr",
    },

    {
        "name": "crime-apex",
        "display_name": "yklawfirm-crime.co.kr",
        "type": "redirect",
        "url": "https://yklawfirm-crime.co.kr/",
        "expect_status": [301, 302, 307, 308],
        "expect_location_prefix": "https://www.yklawfirm-crime.co.kr/",
        "dns_host": "yklawfirm-crime.co.kr",
        "ssl_host": "yklawfirm-crime.co.kr",
    },
    {
        "name": "crime-www",
        "display_name": "www.yklawfirm-crime.co.kr",
        "type": "service",
        "url": "https://www.yklawfirm-crime.co.kr/",
        "expect_status": [200],
        "dns_host": "www.yklawfirm-crime.co.kr",
        "ssl_host": "www.yklawfirm-crime.co.kr",
    },

    {
        "name": "divorce-apex",
        "display_name": "yklawfirm-divorce.co.kr",
        "type": "redirect",
        "url": "https://yklawfirm-divorce.co.kr/",
        "expect_status": [301, 302, 307, 308],
        "expect_location_prefix": "https://www.yklawfirm-divorce.co.kr/",
        "dns_host": "yklawfirm-divorce.co.kr",
        "ssl_host": "yklawfirm-divorce.co.kr",
    },
    {
        "name": "divorce-www",
        "display_name": "www.yklawfirm-divorce.co.kr",
        "type": "service",
        "url": "https://www.yklawfirm-divorce.co.kr/",
        "expect_status": [200],
        "dns_host": "www.yklawfirm-divorce.co.kr",
        "ssl_host": "www.yklawfirm-divorce.co.kr",
    },

    {
        "name": "civil-apex",
        "display_name": "yklawfirm-civil.co.kr",
        "type": "redirect",
        "url": "https://yklawfirm-civil.co.kr/",
        "expect_status": [301, 302, 307, 308],
        "expect_location_prefix": "https://www.yklawfirm-civil.co.kr/",
        "dns_host": "yklawfirm-civil.co.kr",
        "ssl_host": "yklawfirm-civil.co.kr",
    },
    {
        "name": "civil-www",
        "display_name": "www.yklawfirm-civil.co.kr",
        "type": "service",
        "url": "https://www.yklawfirm-civil.co.kr/",
        "expect_status": [200],
        "dns_host": "www.yklawfirm-civil.co.kr",
        "ssl_host": "www.yklawfirm-civil.co.kr",
    },

    {
        "name": "assault-apex",
        "display_name": "yklawfirm-assault.co.kr",
        "type": "redirect",
        "url": "https://yklawfirm-assault.co.kr/",
        "expect_status": [301, 302, 307, 308],
        "expect_location_prefix": "https://www.yklawfirm-assault.co.kr/",
        "dns_host": "yklawfirm-assault.co.kr",
        "ssl_host": "yklawfirm-assault.co.kr",
    },
    {
        "name": "assault-www",
        "display_name": "www.yklawfirm-assault.co.kr",
        "type": "service",
        "url": "https://www.yklawfirm-assault.co.kr/",
        "expect_status": [200],
        "dns_host": "www.yklawfirm-assault.co.kr",
        "ssl_host": "www.yklawfirm-assault.co.kr",
    },

    {
        "name": "inherit-apex",
        "display_name": "yklawfirm-inherit.co.kr",
        "type": "redirect",
        "url": "https://yklawfirm-inherit.co.kr/",
        "expect_status": [301, 302, 307, 308],
        "expect_location_prefix": "https://www.yklawfirm-inherit.co.kr/",
        "dns_host": "yklawfirm-inherit.co.kr",
        "ssl_host": "yklawfirm-inherit.co.kr",
    },
    {
        "name": "inherit-www",
        "display_name": "www.yklawfirm-inherit.co.kr",
        "type": "service",
        "url": "https://www.yklawfirm-inherit.co.kr/",
        "expect_status": [200],
        "dns_host": "www.yklawfirm-inherit.co.kr",
        "ssl_host": "www.yklawfirm-inherit.co.kr",
    },

    {
        "name": "drug-apex",
        "display_name": "yklawfirm-drug.co.kr",
        "type": "redirect",
        "url": "https://yklawfirm-drug.co.kr/",
        "expect_status": [301, 302, 307, 308],
        "expect_location_prefix": "https://www.yklawfirm-drug.co.kr/",
        "dns_host": "yklawfirm-drug.co.kr",
        "ssl_host": "yklawfirm-drug.co.kr",
    },
    {
        "name": "drug-www",
        "display_name": "www.yklawfirm-drug.co.kr",
        "type": "service",
        "url": "https://www.yklawfirm-drug.co.kr/",
        "expect_status": [200],
        "dns_host": "www.yklawfirm-drug.co.kr",
        "ssl_host": "www.yklawfirm-drug.co.kr",
    },

    {
        "name": "traffic-apex",
        "display_name": "yklawfirm-traffic.co.kr",
        "type": "redirect",
        "url": "https://yklawfirm-traffic.co.kr/",
        "expect_status": [301, 302, 307, 308],
        "expect_location_prefix": "https://www.yklawfirm-traffic.co.kr/",
        "dns_host": "yklawfirm-traffic.co.kr",
        "ssl_host": "yklawfirm-traffic.co.kr",
    },
    {
        "name": "traffic-www",
        "display_name": "www.yklawfirm-traffic.co.kr",
        "type": "service",
        "url": "https://www.yklawfirm-traffic.co.kr/",
        "expect_status": [200],
        "dns_host": "www.yklawfirm-traffic.co.kr",
        "ssl_host": "www.yklawfirm-traffic.co.kr",
    },

    {
        "name": "school-apex",
        "display_name": "yklawfirm-school.co.kr",
        "type": "redirect",
        "url": "https://yklawfirm-school.co.kr/",
        "expect_status": [301, 302, 307, 308],
        "expect_location_prefix": "https://www.yklawfirm-school.co.kr/",
        "dns_host": "yklawfirm-school.co.kr",
        "ssl_host": "yklawfirm-school.co.kr",
    },
    {
        "name": "school-www",
        "display_name": "www.yklawfirm-school.co.kr",
        "type": "service",
        "url": "https://www.yklawfirm-school.co.kr/",
        "expect_status": [200],
        "dns_host": "www.yklawfirm-school.co.kr",
        "ssl_host": "www.yklawfirm-school.co.kr",
    },
]


def load_endpoints() -> List[Dict[str, Any]]:
    endpoints_json = env_str("ENDPOINTS_JSON", "")
    if endpoints_json:
        data = json.loads(endpoints_json)
        if not isinstance(data, list):
            raise RuntimeError("ENDPOINTS_JSON must be a JSON list")
        return data
    return DEFAULT_ENDPOINTS


ENDPOINTS = load_endpoints()


# =========================================================
# Dataclasses
# =========================================================
@dataclass
class SslInfo:
    notafter: Optional[str]
    expires_in_days: Optional[int]
    issuer: Optional[str]
    subject: Optional[str]
    san: Optional[List[str]]
    san_covers_host: Optional[bool]


@dataclass
class RedirectProbe:
    status_code: Optional[int]
    location: Optional[str]
    ok: bool
    err: Optional[str]


@dataclass
class FinalProbe:
    status_code: Optional[int]
    ok: bool
    total_ms: Optional[int]
    dns_ms: Optional[int]
    connect_ms: Optional[int]
    tls_ms: Optional[int]
    ttfb_ms: Optional[int]
    remote_ip: Optional[str]
    err: Optional[str]
    headers: Optional[Dict[str, str]]
    redirect_chain: Optional[List[str]]


@dataclass
class EndpointResult:
    name: str
    site_group: str
    site_label: str
    display_name: str
    type: str
    url: str
    ok: bool
    status_class: str
    summary: str
    expected: str
    actual: str
    dns_host: Optional[str]
    dns_a: List[str]
    dns_aaaa: List[str]
    redirect_probe: Optional[RedirectProbe]
    final_probe: Optional[FinalProbe]
    ssl: Optional[SslInfo]
    consecutive_failures: int
    first_failed_at: Optional[str]
    last_ok_at: Optional[str]
    checked_at: str


# =========================================================
# Time / files
# =========================================================
def now_local() -> datetime:
    return datetime.now()


def now_local_str() -> str:
    return now_local().strftime("%Y-%m-%d %H:%M:%S")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def today_ymd() -> str:
    return now_local().strftime("%Y-%m-%d")


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def log_path() -> str:
    ensure_dir(LOG_DIR)
    return os.path.join(LOG_DIR, f"{today_ymd()}.log")


def append_log(line: str) -> None:
    with open(log_path(), "a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")


# =========================================================
# State
# =========================================================
def load_state() -> Dict[str, Any]:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def save_state(state: Dict[str, Any]) -> None:
    parent = os.path.dirname(os.path.abspath(STATE_FILE))
    if parent:
        ensure_dir(parent)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def get_global_state(state: Dict[str, Any]) -> Dict[str, Any]:
    if "_global" not in state or not isinstance(state["_global"], dict):
        state["_global"] = {}
    return state["_global"]


def update_endpoint_state(state: Dict[str, Any], result: EndpointResult) -> None:
    prev = state.get(result.name, {})
    if not isinstance(prev, dict):
        prev = {}

    prev_ok = prev.get("ok")
    prev_first_failed_at = prev.get("first_failed_at")
    prev_consecutive_failures = int(prev.get("consecutive_failures", 0) or 0)
    prev_last_ok_at = prev.get("last_ok_at")

    if result.ok:
        consecutive_failures = 0
        first_failed_at = None
        last_ok_at = result.checked_at
    else:
        consecutive_failures = prev_consecutive_failures + 1 if prev_ok is False else 1
        first_failed_at = prev_first_failed_at or result.checked_at
        last_ok_at = prev_last_ok_at

    result.consecutive_failures = consecutive_failures
    result.first_failed_at = first_failed_at
    result.last_ok_at = last_ok_at

    state[result.name] = {
        "name": result.name,
        "display_name": result.display_name,
        "ok": result.ok,
        "type": result.type,
        "status_class": result.status_class,
        "summary": result.summary,
        "checked_at": result.checked_at,
        "first_failed_at": first_failed_at,
        "last_ok_at": last_ok_at,
        "consecutive_failures": consecutive_failures,
        "actual": result.actual,
        "expected": result.expected,
    }


def add_history(state: Dict[str, Any], results: List[EndpointResult], has_issue: bool) -> None:
    g = get_global_state(state)
    history = g.setdefault("_check_history", [])
    if not isinstance(history, list):
        history = []
        g["_check_history"] = history

    history.append(
        {
            "ts": now_local_str(),
            "has_issue": has_issue,
            "results": {
                r.name: {
                    "ok": r.ok,
                    "type": r.type,
                    "summary": r.summary,
                }
                for r in results
            },
        }
    )
    if len(history) > MAX_HISTORY:
        del history[:-MAX_HISTORY]


def cleanup_old_files_and_state() -> None:
    cutoff = now_local() - timedelta(days=CLEANUP_DAYS)

    try:
        if os.path.isdir(LOG_DIR):
            for filename in os.listdir(LOG_DIR):
                if not filename.endswith(".log"):
                    continue
                try:
                    dt = datetime.strptime(filename[:-4], "%Y-%m-%d")
                except Exception:
                    continue
                if dt < cutoff:
                    try:
                        os.remove(os.path.join(LOG_DIR, filename))
                    except OSError:
                        pass
    except Exception:
        pass

    try:
        state = load_state()
        g = get_global_state(state)
        history = g.get("_check_history", [])
        if isinstance(history, list):
            filtered = []
            for item in history:
                ts = str(item.get("ts", ""))
                try:
                    dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    filtered.append(item)
                    continue
                if dt >= cutoff:
                    filtered.append(item)
            g["_check_history"] = filtered
            save_state(state)
    except Exception:
        pass


# =========================================================
# Daily / restart reports
# =========================================================
def parse_time_str(s: str) -> Tuple[int, int]:
    try:
        h, m = s.split(":", 1)
        hh = int(h)
        mm = int(m)
        if 0 <= hh <= 23 and 0 <= mm <= 59:
            return hh, mm
    except Exception:
        pass
    return 9, 0


def should_send_daily_report(state: Dict[str, Any]) -> bool:
    if not DAILY_REPORT_ENABLED:
        return False
    g = get_global_state(state)
    last_date = g.get("last_daily_report_date", "")
    if last_date == today_ymd():
        return False
    hour, minute = parse_time_str(DAILY_REPORT_TIME)
    now = now_local()
    return now.hour == hour and minute <= now.minute < minute + 3


def build_daily_report(state: Dict[str, Any]) -> Optional[str]:
    g = get_global_state(state)
    history = g.get("_check_history", [])
    if not isinstance(history, list) or not history:
        return None

    yesterday = (now_local() - timedelta(days=1)).strftime("%Y-%m-%d")
    rows = [x for x in history if str(x.get("ts", "")).startswith(yesterday)]
    if not rows:
        return None

    total = len(rows)
    fails = sum(1 for x in rows if x.get("has_issue"))
    success = total - fails

    lines = [
        "*\uc77c\uc77c \ub9ac\ud3ec\ud2b8*",
        f"\ub0a0\uc9dc: `{yesterday}`",
        f"\ucd1d \uac80\uc0ac: `{total}`\ud68c / \uc131\uacf5 `{success}` / \uc2e4\ud328 `{fails}`",
    ]
    return "\n".join(lines)


def detect_restart(state: Dict[str, Any], run_id: str, current_time: str) -> Tuple[bool, Optional[str]]:
    g = get_global_state(state)
    last_check_time = g.get("last_check")
    last_run_id = g.get("last_run_id")
    force_restart = bool(g.get("force_restart_report", False))

    if force_restart:
        g["force_restart_report"] = False
        return True, last_check_time

    if not last_check_time:
        return True, None

    try:
        last_dt = datetime.strptime(last_check_time, "%Y-%m-%d %H:%M:%S")
        current_dt = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
        if (current_dt - last_dt).total_seconds() > 300:
            return True, last_check_time
    except Exception:
        return True, last_check_time

    if last_run_id:
        try:
            prev_dt = datetime.strptime(last_run_id[:8] + last_run_id[9:], "%Y%m%d%H%M%S")
            cur_dt = datetime.strptime(run_id[:8] + run_id[9:], "%Y%m%d%H%M%S")
            if (cur_dt - prev_dt).total_seconds() > 300:
                return True, last_check_time
        except Exception:
            pass

    return False, last_check_time


def build_restart_report(state: Dict[str, Any], last_run_time: str, current_time: str) -> Optional[str]:
    g = get_global_state(state)
    history = g.get("_check_history", [])
    if not isinstance(history, list) or not history:
        return None

    try:
        last_dt = datetime.strptime(last_run_time, "%Y-%m-%d %H:%M:%S")
        current_dt = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
        rows = []
        for entry in history:
            ts = entry.get("ts", "")
            try:
                dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
            if last_dt < dt < current_dt:
                rows.append(entry)
    except Exception:
        rows = history[-10:]

    if not rows:
        return None

    total = len(rows)
    fails = sum(1 for x in rows if x.get("has_issue"))
    success = total - fails

    lines = [
        "*\uc7ac\uae30\ub3d9 \ub9ac\ud3ec\ud2b8*",
        f"\ub9c8\uc9c0\ub9c9 \uc2e4\ud589: `{last_run_time}`",
        f"\uc7ac\uae30\ub3d9 \uc2dc\uac01: `{current_time}`",
        f"\uae30\uac04 \ub0b4 \uac80\uc0ac: `{total}`\ud68c / \uc131\uacf5 `{success}` / \uc2e4\ud328 `{fails}`",
    ]
    return "\n".join(lines)


# =========================================================
# Low-level helpers
# =========================================================
def run_cmd(cmd: List[str], timeout_sec: float) -> Tuple[int, str, str]:
    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
    )
    return p.returncode, p.stdout or "", p.stderr or ""


def safe_int_ms(raw: str) -> Optional[int]:
    try:
        return int(float(raw) * 1000)
    except Exception:
        return None


def classify_error(err: Optional[str], status_code: Optional[int], endpoint_type: str) -> str:
    txt = (err or "").lower()
    if "resolving timed out" in txt or "could not resolve host" in txt:
        return "DNS"
    if "connection refused" in txt:
        return "TCP"
    if "ssl" in txt or "tls" in txt or "certificate" in txt:
        return "TLS"
    if "timed out" in txt:
        return "TIMEOUT"
    if endpoint_type == "redirect":
        return "REDIRECT"
    if status_code is not None and status_code >= 500:
        return "HTTP"
    return "HTTP"


def dns_lookup(host: str) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {"A": [], "AAAA": []}
    try:
        infos = socket.getaddrinfo(host, None)
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if fam == socket.AF_INET and ip not in result["A"]:
                result["A"].append(ip)
            elif fam == socket.AF_INET6 and ip not in result["AAAA"]:
                result["AAAA"].append(ip)
    except Exception:
        pass
    return result


def parse_headers_from_dump(raw_text: str) -> Dict[str, str]:
    text = raw_text.replace("\r\n", "\n").strip()
    if not text:
        return {}
    blocks = text.split("\n\n")
    last_block = blocks[-1]
    lines = [ln.strip() for ln in last_block.split("\n") if ln.strip()]
    if not lines:
        return {}
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return headers


def normalize_url(base: str, location: str) -> str:
    return urllib.parse.urljoin(base, location)


def fetch_header_chain(url: str) -> Tuple[str, Optional[str]]:
    cmd = [
        "curl",
        "-sS",
        "-L",
        "-D",
        "-",
        "-o",
        "/dev/null",
        "--max-time", str(HC_TIMEOUT_SEC),
        "--connect-timeout", str(HC_CONNECT_TIMEOUT_SEC),
        url,
    ]
    try:
        rc, out, err = run_cmd(cmd, HC_TIMEOUT_SEC + 3.0)
        if rc != 0:
            return "", err.strip() or f"curl rc={rc}"
        return out, None
    except Exception as exc:
        return "", repr(exc)


def extract_redirect_chain(start_url: str, raw_header_text: str) -> List[str]:
    text = raw_header_text.replace("\r\n", "\n").strip()
    if not text:
        return [start_url]

    chain = [start_url]
    current = start_url
    for block in text.split("\n\n"):
        lines = [ln.strip() for ln in block.split("\n") if ln.strip()]
        if not lines:
            continue
        loc = None
        for line in lines[1:]:
            if line.lower().startswith("location:"):
                loc = line.split(":", 1)[1].strip()
                break
        if loc:
            nxt = normalize_url(current, loc)
            chain.append(nxt)
            current = nxt

    deduped = []
    for item in chain:
        if not deduped or deduped[-1] != item:
            deduped.append(item)
    return deduped


def fetch_selected_headers(url: str) -> Dict[str, str]:
    cmd = [
        "curl",
        "-sS",
        "-I",
        "-L",
        "-D",
        "-",
        "-o",
        "/dev/null",
        "--max-time", str(HC_TIMEOUT_SEC),
        "--connect-timeout", str(HC_CONNECT_TIMEOUT_SEC),
        url,
    ]
    try:
        rc, out, err = run_cmd(cmd, HC_TIMEOUT_SEC + 3.0)
        if rc != 0:
            return {"_error": err.strip() or f"curl rc={rc}"}
        headers = parse_headers_from_dump(out)
        selected = {}
        for k in HEADER_KEYS:
            if k in headers:
                selected[k] = headers[k]
        return selected if selected else headers
    except Exception as exc:
        return {"_error": repr(exc)}


# =========================================================
# SSL helpers
# =========================================================
def parse_notafter_days_left(notafter: str) -> Optional[int]:
    try:
        text = notafter.replace("  ", " ").strip()
        if text.endswith(" GMT"):
            text = text[:-4].strip()
        dt = datetime.strptime(text, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        delta = dt - now_utc()
        return int(delta.total_seconds() // 86400)
    except Exception:
        return None


def shorten_dn(dn: Optional[str]) -> Optional[str]:
    if not dn:
        return None
    parts = [p.strip() for p in dn.split(",")]
    keep = []
    for p in parts:
        if p.startswith(("O=", "CN=", "O =", "CN =")):
            keep.append(p.replace(" = ", "=").replace(" =", "=").replace("= ", "="))
    if keep:
        return ", ".join(keep)
    return dn


def ssl_info(host: str) -> SslInfo:
    try:
        p1 = subprocess.Popen(
            [
                "openssl", "s_client",
                "-servername", host,
                "-connect", f"{host}:443",
                "-showcerts",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            out1, _ = p1.communicate(timeout=HC_TIMEOUT_SEC + 4.0)
        except subprocess.TimeoutExpired:
            p1.kill()
            return SslInfo(None, None, None, None, None, None)

        if p1.returncode != 0 or not out1:
            return SslInfo(None, None, None, None, None, None)

        p2 = subprocess.run(
            ["openssl", "x509", "-noout", "-enddate", "-issuer", "-subject", "-ext", "subjectAltName"],
            input=out1,
            capture_output=True,
            text=True,
            timeout=HC_TIMEOUT_SEC + 4.0,
        )
        if p2.returncode != 0:
            return SslInfo(None, None, None, None, None, None)

        notafter = None
        issuer = None
        subject = None
        san_list: List[str] = []
        in_san = False

        for line in (p2.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("notAfter="):
                notafter = line.replace("notAfter=", "").strip()
            elif line.startswith("issuer="):
                issuer = line.replace("issuer=", "").strip()
            elif line.startswith("subject="):
                subject = line.replace("subject=", "").strip()
            elif "X509v3 Subject Alternative Name" in line:
                in_san = True
            elif in_san:
                if not line or line.startswith("X509v3") or line.endswith(":"):
                    in_san = False
                else:
                    for item in [x.strip() for x in line.split(",")]:
                        if item.startswith("DNS:"):
                            val = item.replace("DNS:", "").strip()
                            if val and val not in san_list:
                                san_list.append(val)

        expires_in_days = parse_notafter_days_left(notafter) if notafter else None

        covers = None
        if san_list:
            covers = False
            for san in san_list:
                if san == host:
                    covers = True
                    break
                if san.startswith("*."):
                    suffix = san[1:]
                    if host.endswith(suffix):
                        prefix = host[:-len(suffix)]
                        if prefix and "." not in prefix:
                            covers = True
                            break

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


# =========================================================
# Curl probes
# =========================================================
def probe_single(url: str, follow_redirects: bool) -> FinalProbe:
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

    cmd = ["curl", "-sS"]
    if follow_redirects:
        cmd.append("-L")
    cmd += [
        "-o", "/dev/null",
        "--max-time", str(HC_TIMEOUT_SEC),
        "--connect-timeout", str(HC_CONNECT_TIMEOUT_SEC),
        "-w", write_out,
        url,
    ]

    raw = None
    err = None
    http_code = None
    total_ms = None
    dns_ms = None
    connect_ms = None
    tls_ms = None
    ttfb_ms = None
    remote_ip = None
    ok = False

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()

        try:
            raw = json.loads(stdout)
            code_str = str(raw.get("http_code", "")).strip()
            http_code = int(code_str) if code_str.isdigit() else None
            dns_ms = safe_int_ms(str(raw.get("time_namelookup", "")))
            connect_ms = safe_int_ms(str(raw.get("time_connect", "")))
            tls_ms = safe_int_ms(str(raw.get("time_appconnect", "")))
            ttfb_ms = safe_int_ms(str(raw.get("time_starttransfer", "")))
            total_ms = safe_int_ms(str(raw.get("time_total", "")))
            remote_ip = str(raw.get("remote_ip", "")).strip() or None
        except Exception:
            err = f"failed_to_parse_curl_output={stdout}"

        ok = proc.returncode == 0 and http_code is not None
        if proc.returncode != 0:
            msg = f"curl_rc={proc.returncode}, stderr={stderr or 'none'}"
            err = f"{err} | {msg}" if err else msg
    except Exception as exc:
        err = repr(exc)
        ok = False

    headers = fetch_selected_headers(url)
    chain = [url]
    chain_err = None
    if follow_redirects:
        raw_header_text, chain_err = fetch_header_chain(url)
        if raw_header_text:
            chain = extract_redirect_chain(url, raw_header_text)
        if chain_err:
            err = f"{err} | redirect_chain_err={chain_err}" if err else f"redirect_chain_err={chain_err}"

    return FinalProbe(
        status_code=http_code,
        ok=ok,
        total_ms=total_ms,
        dns_ms=dns_ms,
        connect_ms=connect_ms,
        tls_ms=tls_ms,
        ttfb_ms=ttfb_ms,
        remote_ip=remote_ip,
        err=err,
        headers=headers,
        redirect_chain=chain,
    )


def probe_redirect_first_hop(url: str) -> RedirectProbe:
    cmd = [
        "curl",
        "-sS",
        "-I",
        "-o", "/dev/null",
        "-D", "-",
        "--max-time", str(HC_TIMEOUT_SEC),
        "--connect-timeout", str(HC_CONNECT_TIMEOUT_SEC),
        url,
    ]
    try:
        rc, out, err = run_cmd(cmd, HC_TIMEOUT_SEC + 3.0)
        if rc != 0:
            return RedirectProbe(None, None, False, err.strip() or f"curl rc={rc}")

        text = out.replace("\r\n", "\n").strip()
        if not text:
            return RedirectProbe(None, None, False, "empty_header_response")

        lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
        if not lines:
            return RedirectProbe(None, None, False, "empty_header_lines")

        status_code = None
        m = re.match(r"HTTP/\S+\s+(\d{3})", lines[0])
        if m:
            status_code = int(m.group(1))

        location = None
        for line in lines[1:]:
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                break

        return RedirectProbe(status_code, location, status_code is not None, None)
    except Exception as exc:
        return RedirectProbe(None, None, False, repr(exc))


# =========================================================
# Endpoint checks
# =========================================================
def endpoint_expected_text(endpoint: Dict[str, Any]) -> str:
    t = endpoint["type"]
    if t == "redirect":
        statuses = endpoint.get("expect_status", [301, 302, 307, 308])
        prefix = endpoint.get("expect_location_prefix", "")
        return f"{'/'.join(str(x) for x in statuses)} -> {prefix}"
    statuses = endpoint.get("expect_status", [200])
    return "/".join(str(x) for x in statuses)


def short_url(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path or '/'}"
    except Exception:
        return url


def redirect_chain_text(chain: Optional[List[str]]) -> str:
    if not chain or len(chain) <= 1:
        return "-"
    return " -> ".join(short_url(x) for x in chain)


def endpoint_site_group(endpoint: Dict[str, Any]) -> str:
    raw = endpoint.get("site_group")
    if raw is not None and str(raw).strip():
        return str(raw).strip()
    name = endpoint.get("name") or ""
    if name.endswith("-apex"):
        return name[: -len("-apex")]
    if name.endswith("-www"):
        return name[: -len("-www")]
    return name


def endpoint_site_label(endpoint: Dict[str, Any]) -> str:
    raw = endpoint.get("site_label")
    if raw is not None and str(raw).strip():
        return str(raw).strip()
    display = endpoint.get("display_name") or endpoint.get("name") or ""
    if display.startswith("www."):
        return display[4:]
    return display


def role_label_for_check(endpoint_type: str) -> str:
    if endpoint_type == "redirect":
        return "\ub8e8\ud2b8(apex) \u2192 www"
    if endpoint_type == "service":
        return "www \uc9c1\uc811"
    return endpoint_type


def group_endpoint_results(
    results: List[EndpointResult],
) -> List[Tuple[str, List[EndpointResult]]]:
    order: List[str] = []
    bucket: Dict[str, List[EndpointResult]] = {}
    labels: Dict[str, str] = {}
    for r in results:
        g = r.site_group
        if g not in bucket:
            bucket[g] = []
            labels[g] = r.site_label
            order.append(g)
        bucket[g].append(r)

    def sort_key(res: EndpointResult) -> int:
        if res.type == "redirect":
            return 0
        if res.type == "service":
            return 1
        return 9

    return [(labels[g], sorted(bucket[g], key=sort_key)) for g in order]


def _site_check_pairs(items: List[EndpointResult]) -> List[Tuple[str, EndpointResult]]:
    """\ud55c \uc0ac\uc774\ud2b8 \ub0b4 \ub8e8\ud2b8(apex)\u2192www / www \uc9c1\uc811 \uc810\uac80\uc744 \ud55c \ub369\uc5b4\ub9ac\ub85c \ubcf4\uc5ec \uc8fc\uae30 \uc704\ud55c \uc21c\uc11c."""
    out: List[Tuple[str, EndpointResult]] = []
    redirect = next((x for x in items if x.type == "redirect"), None)
    service = next((x for x in items if x.type == "service"), None)
    if redirect:
        out.append(("\ub8e8\ud2b8(apex) \u2192 www", redirect))
    if service:
        out.append(("www \uc9c1\uc811", service))
    seen = {id(x) for _, x in out}
    for r in items:
        if id(r) in seen:
            continue
        out.append((r.type, r))
    return out


def site_composite_headline(items: List[EndpointResult]) -> str:
    parts: List[str] = []
    for label, r in _site_check_pairs(items):
        parts.append(f"{label} {'OK' if r.ok else 'FAIL'}")
    return " \u00b7 ".join(parts) if parts else "-"


def result_has_cert_warning(r: EndpointResult) -> bool:
    if not r.ssl or r.ssl.expires_in_days is None:
        return False
    d = r.ssl.expires_in_days
    return d < 0 or d <= CERT_WARN_DAYS


def build_issue_summary_text(results: List[EndpointResult]) -> str:
    lines: List[str] = ["*\uc694\uc57d (\ud604\uc7ac \ubb38\uc81c)*", ""]
    failed = [r for r in results if not r.ok]
    if failed:
        lines.append("\uc2e4\ud328\ud55c \uc810\uac80:")
        for site_label, items in group_endpoint_results(results):
            bad = [r for r in items if not r.ok]
            if not bad:
                continue
            bits: List[str] = []
            for r in bad:
                role = "\ub8e8\ud2b8\u2192www" if r.type == "redirect" else "www" if r.type == "service" else r.type
                bits.append(f"{role}: `{r.summary}` \u2014 `{r.actual}`")
            lines.append(f"- *{site_label}*: " + " | ".join(bits))
        lines.append("")
    else:
        lines.append("\uc2e4\ud328\ud55c \uc810\uac80: \uc5c6\uc74c")
        lines.append("")

    cert_lines: List[str] = []
    for r in results:
        if not result_has_cert_warning(r):
            continue
        d = r.ssl.expires_in_days if r.ssl else None
        who = r.ssl_host or r.display_name or r.name
        if d is not None and d < 0:
            cert_lines.append(f"- *{r.site_label}* / `{who}`: \ub9cc\ub8cc ({abs(d)}\uc77c \uc804)")
        elif d is not None:
            lvl = "\uc784\ubc15" if d <= CERT_ALERT_DAYS else "\uc8fc\uc758"
            cert_lines.append(f"- *{r.site_label}* / `{who}`: {lvl}, \ub0a8\uc740 {d}\uc77c")

    if cert_lines:
        lines.append("\uc778\uc99d\uc11c:")
        lines.extend(cert_lines)
    else:
        lines.append("\uc778\uc99d\uc11c \uc8fc\uc758: \uc5c6\uc74c")

    return "\n".join(lines).strip()


def build_recovery_summary_text(results: List[EndpointResult]) -> str:
    pairs = group_endpoint_results(results)
    n_checks = len(results)
    n_sites = len(pairs)
    lines = [
        "*\uc694\uc57d (\ubcf5\uad6c)*",
        "",
        f"\uc2e4\ud328\ud55c \uc810\uac80: \uc5c6\uc74c (`{n_checks}`\uac74 / `{n_sites}`\uac1c \uc0ac\uc774\ud2b8).",
    ]
    cert_any = any(result_has_cert_warning(r) for r in results)
    if cert_any:
        lines.append(
            "\uc778\uc99d\uc11c\ub294 \uc544\ub798 \ubcf8\ubb38\uc758 SSL \ud56d\ubaa9\uc5d0\uc11c "
            "\uc784\ubc15\xb7\uc8fc\uc758 \uc5ec\ubd80\ub97c \ud655\uc778\ud558\uc138\uc694."
        )
    else:
        lines.append("\uc778\uc99d\uc11c \uc8fc\uc758: \uc5c6\uc74c.")
    return "\n".join(lines).strip()


def render_subcheck_detail_lines(r: EndpointResult) -> Tuple[List[str], bool]:
    """\ud55c \uac1c\uc758 \uccb4\ud06c(\ub9ac\ub2e4\uc774\ub809\ud2b8 \ub610\ub294 \uc11c\ube44\uc2a4)\uc5d0 \ub300\ud55c \uc0c1\uc138 \uc904. \uba54\uc2dc\uc9c0 \uc798\ub77c\ub0b4\uc9c0 \uc54a\uc74c."""
    cert_warn_hit = False
    lines: List[str] = []

    lines.append(f"\uae30\ub300: `{r.expected}`")
    lines.append(f"\uc2e4\uce21: `{r.actual}`")
    lines.append(f"\ubd84\ub958: `{r.status_class}` \u00b7 \uc694\uc57d: `{r.summary}`")

    if r.consecutive_failures:
        lines.append(f"\uc5f0\uc18d \uc2e4\ud328: `{r.consecutive_failures}`\ud68c")
    if r.first_failed_at:
        lines.append(f"\ucd5c\ucd08 \uc2e4\ud328 \uc2dc\uac01: `{r.first_failed_at}`")
    if r.last_ok_at:
        lines.append(f"\uc9c1\uc804 \uc815\uc0c1 \uc2dc\uac01: `{r.last_ok_at}`")

    if r.redirect_probe:
        rp = r.redirect_probe
        lines.append(
            f"\uccab \uc751\ub2f5: status=`{rp.status_code or '-'}` \u00b7 "
            f"Location=`{rp.location or '-'}`"
        )
        if rp.err:
            lines.append(f"\uccab \uc751\ub2f5 \uc624\ub958: `{rp.err}`")

    if r.final_probe:
        fp = r.final_probe
        lines.append(
            f"\ucd5c\uc885: status=`{fp.status_code or '-'}` \u00b7 IP=`{fp.remote_ip or '-'}` \u00b7 "
            f"total=`{fp.total_ms if fp.total_ms is not None else '-'}ms`"
        )

        timing_parts = []
        if fp.dns_ms is not None:
            timing_parts.append(f"DNS={fp.dns_ms}ms")
        if fp.connect_ms is not None:
            timing_parts.append(f"Conn={fp.connect_ms}ms")
        if fp.tls_ms is not None:
            timing_parts.append(f"TLS={fp.tls_ms}ms")
        if fp.ttfb_ms is not None:
            timing_parts.append(f"TTFB={fp.ttfb_ms}ms")
        if fp.total_ms is not None:
            timing_parts.append(f"Total={fp.total_ms}ms")
        if timing_parts:
            lines.append(f"\ud0c0\uc774\ubc0d: `{' | '.join(timing_parts)}`")

        chain_str = redirect_chain_text(fp.redirect_chain)
        if chain_str != "-":
            lines.append(f"\ub9ac\ub2e4\uc774\ub809\ud2b8 \uccb4\uc778: `{chain_str}`")

        header_text = headers_pretty(fp.headers or {})
        if header_text and header_text != "-":
            lines.append(f"\uc751\ub2f5 \ud5e4\ub354: `{header_text}`")

        if fp.err:
            lines.append(f"\uc624\ub958: `{fp.err}`")

    if r.dns_host:
        lines.append(
            f"DNS(`{r.dns_host}`): A=`{','.join(r.dns_a) if r.dns_a else '-'}` "
            f"AAAA=`{','.join(r.dns_aaaa) if r.dns_aaaa else '-'}`"
        )

    if r.ssl:
        ssl_parts = []
        if r.ssl.notafter:
            ssl_parts.append(f"\ub9cc\ub8cc: `{r.ssl.notafter}`")
        if r.ssl.expires_in_days is not None:
            days_left = r.ssl.expires_in_days
            if days_left < 0:
                ssl_parts.append(f"\ub9cc\ub8cc\ub428 ({abs(days_left)}\uc77c \uc804)")
                cert_warn_hit = True
            elif days_left <= CERT_ALERT_DAYS:
                ssl_parts.append(f"\ub9cc\ub8cc \uc784\ubc15: \ub0a8\uc740 {days_left}\uc77c")
                cert_warn_hit = True
            elif days_left <= CERT_WARN_DAYS:
                ssl_parts.append(f"\uc8fc\uc758: \ub0a8\uc740 {days_left}\uc77c")
                cert_warn_hit = True
            else:
                ssl_parts.append(f"\uc815\uc0c1: \ub0a8\uc740 {days_left}\uc77c")
        if ssl_parts:
            lines.append(f"SSL: {' | '.join(ssl_parts)}")
        if r.ssl.subject:
            lines.append(f"SSL Subject: `{r.ssl.subject}`")
        if r.ssl.issuer:
            lines.append(f"SSL Issuer: `{r.ssl.issuer}`")
        if r.ssl.san:
            if r.ssl.san_covers_host is True:
                coverage = " (\ud638\uc2a4\ud2b8 SAN \ud3ec\ud568)"
            elif r.ssl.san_covers_host is False:
                coverage = " (\ud638\uc2a4\ud2b8 SAN \ubd88\uc77c\uce58)"
            else:
                coverage = ""
            lines.append(f"SAN{coverage}: `{', '.join(r.ssl.san)}`")

    return lines, cert_warn_hit


def check_endpoint(endpoint: Dict[str, Any], state: Dict[str, Any]) -> EndpointResult:
    checked_at = now_local_str()
    display_name = endpoint.get("display_name") or endpoint.get("name") or endpoint["url"]
    site_group = endpoint_site_group(endpoint)
    site_label = endpoint_site_label(endpoint)
    endpoint_type = endpoint["type"]
    url = endpoint["url"]

    dns_host = endpoint.get("dns_host")
    ssl_host = endpoint.get("ssl_host")

    dns_a: List[str] = []
    dns_aaaa: List[str] = []
    if dns_host:
        dns_info = dns_lookup(dns_host)
        dns_a = dns_info["A"]
        dns_aaaa = dns_info["AAAA"]

    ssl_obj = ssl_info(ssl_host) if ssl_host and url.startswith("https://") else None

    expected = endpoint_expected_text(endpoint)
    redirect_probe = None
    final_probe = None
    ok = False
    status_class = "HTTP"
    summary = ""
    actual = ""

    if endpoint_type == "redirect":
        redirect_probe = probe_redirect_first_hop(url)
        final_probe = probe_single(url, follow_redirects=True)

        expect_status = set(int(x) for x in endpoint.get("expect_status", [301, 302, 307, 308]))
        expect_prefix = endpoint.get("expect_location_prefix", "")

        first_ok = (
            redirect_probe.status_code in expect_status and
            bool(redirect_probe.location) and
            str(redirect_probe.location).startswith(expect_prefix)
        )
        final_ok = final_probe.status_code is not None and 200 <= final_probe.status_code < 400 and (final_probe.err is None)

        ok = first_ok and final_ok
        actual = (
            f"{redirect_probe.status_code or 'NO_STATUS'} -> {redirect_probe.location or '-'}"
            f" | final={final_probe.status_code or 'NO_STATUS'}"
        )
        status_class = classify_error(
            redirect_probe.err or final_probe.err,
            redirect_probe.status_code or final_probe.status_code,
            endpoint_type,
        )
        summary = "redirect_ok" if ok else "redirect_mismatch"

    else:
        final_probe = probe_single(url, follow_redirects=True)
        expected_status = set(int(x) for x in endpoint.get("expect_status", [200]))
        ok = final_probe.status_code in expected_status and final_probe.err is None
        actual = str(final_probe.status_code or "NO_STATUS")
        status_class = classify_error(final_probe.err, final_probe.status_code, endpoint_type)
        summary = "service_ok" if ok else "service_down"

    prev = state.get(endpoint["name"], {}) if isinstance(state.get(endpoint["name"]), dict) else {}
    consecutive_failures = int(prev.get("consecutive_failures", 0) or 0)
    first_failed_at = prev.get("first_failed_at")
    last_ok_at = prev.get("last_ok_at")

    return EndpointResult(
        name=endpoint["name"],
        site_group=site_group,
        site_label=site_label,
        display_name=display_name,
        type=endpoint_type,
        url=url,
        ok=ok,
        status_class=status_class,
        summary=summary,
        expected=expected,
        actual=actual,
        dns_host=dns_host,
        dns_a=dns_a,
        dns_aaaa=dns_aaaa,
        redirect_probe=redirect_probe,
        final_probe=final_probe,
        ssl=ssl_obj,
        consecutive_failures=consecutive_failures,
        first_failed_at=first_failed_at,
        last_ok_at=last_ok_at,
        checked_at=checked_at,
    )


# =========================================================
# Notification rules
# =========================================================
def should_notify(results: List[EndpointResult], state: Dict[str, Any]) -> Tuple[bool, str]:
    if REPORT_MODE == "always":
        return True, "always"

    g = get_global_state(state)
    has_issue_now = any(not r.ok for r in results)
    prev_has_issue = bool(g.get("has_issue", False))

    if REPORT_MODE == "on_error":
        if has_issue_now and not prev_has_issue:
            return True, "issue_detected"
        if has_issue_now and prev_has_issue:
            return True, "issue_persists"
        if not has_issue_now and prev_has_issue:
            return True, "issue_resolved"
        return False, "all_ok"

    changed = []
    for r in results:
        prev = state.get(r.name, {})
        prev_ok = prev.get("ok")
        prev_actual = prev.get("actual")
        if prev_ok is None:
            changed.append(f"INIT {r.name}")
        elif bool(prev_ok) != bool(r.ok) or str(prev_actual) != str(r.actual):
            changed.append(f"CHANGE {r.name}")

    return (len(changed) > 0), ("; ".join(changed) if changed else "no_change")


# =========================================================
# Slack helpers
# =========================================================
def get_rotating_emoji() -> str:
    if not SLACK_EMOJI_ROTATION:
        return SLACK_ICON_EMOJI
    emojis = [
        ":dog:",
        ":eyes:",
        ":mag:",
        ":satellite:",
        ":earth_asia:",
        ":globe_with_meridians:",
        ":computer:",
        ":rocket:",
        ":zap:",
    ]
    return emojis[now_local().minute % len(emojis)]


def slack_post(payload_obj: Dict[str, Any]) -> None:
    if SLACK_POST_MODE == "payload":
        body = urllib.parse.urlencode(
            {"payload": json.dumps(payload_obj, ensure_ascii=False)}
        ).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
    else:
        body = json.dumps(payload_obj, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8"}

    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=body,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HC_TIMEOUT_SEC) as resp:
        _ = resp.read()


def _chunk_text_for_slack(s: str, first_limit: int, rest_limit: int) -> List[str]:
    if not s:
        return []
    parts: List[str] = []
    i = 0
    n = len(s)
    while i < n:
        lim = first_limit if not parts else rest_limit
        remain = n - i
        if remain <= lim:
            parts.append(s[i:])
            break
        end = i + lim
        window = s[i:end]
        nl = window.rfind("\n")
        if nl > lim // 4:
            end = i + nl + 1
        parts.append(s[i:end])
        i = end
    return parts


def _split_slack_messages(full_text: str) -> List[str]:
    max_len = max(500, SLACK_MAX_CHARS)
    if len(full_text) <= max_len:
        return [full_text]
    return _chunk_text_for_slack(full_text, max_len, max_len)


def slack_post_text_batched(full_text: str, *, attach_image: bool = False) -> None:
    chunks = _split_slack_messages(full_text)
    for idx, ch in enumerate(chunks):
        payload: Dict[str, Any] = {
            "text": ch,
            "username": SLACK_USERNAME,
            "icon_emoji": get_rotating_emoji(),
        }
        if (
            attach_image
            and idx == 0
            and SLACK_IMAGE_URL
            and SLACK_POST_MODE == "json"
        ):
            payload["attachments"] = [
                {
                    "image_url": SLACK_IMAGE_URL,
                    "fallback": "YK Watchdog Status Check",
                }
            ]
        slack_post(payload)


def headers_pretty(h: Dict[str, str]) -> str:
    if not h:
        return "-"
    if "_error" in h:
        return f"(error) {h.get('_error')}"
    parts = []
    mapping = {
        "content-type": "type",
        "cache-control": "cache",
        "strict-transport-security": "hsts",
    }
    for k in HEADER_KEYS:
        if k in h:
            parts.append(f"{mapping.get(k, k)}={h[k]}")
    if not parts:
        for k, v in h.items():
            parts.append(f"{k}={v}")
    return " | ".join(parts)


def build_slack_prefix(results: List[EndpointResult], cert_warn_hit: bool) -> str:
    lines = ["*YK Watchdog*"]
    if ENABLE_MENTIONS and ALWAYS_MENTION:
        lines.append(f"mentions: {' '.join(ALWAYS_MENTION)}")

    if ENABLE_MENTIONS and CHANNEL_MENTION_ON_FAIL:
        if any(not r.ok for r in results) or cert_warn_hit:
            lines.append("<!channel>")

    return "\n".join(lines) + "\n\n"


def build_resolved_text(results: List[EndpointResult], run_id: str, host: str) -> str:
    lines = [
        "*\uc804\uccb4 \ubcf5\uad6c\ub428*",
        f"run `{run_id}` \u00b7 host `{host}` \u00b7 `{now_local_str()}`",
        "",
    ]
    for site_label, items in group_endpoint_results(results):
        lines.append(f"*{site_label}*  {site_composite_headline(items)}")
        lines.append("")
    lines.append(build_recovery_summary_text(results))
    return "\n".join(lines).strip()


def build_slack_text(results: List[EndpointResult], run_id: str, host: str) -> Tuple[str, bool]:
    lines = [
        "*\ud5ec\uc2a4\uccb4\ud06c*",
        f"run `{run_id}` \u00b7 host `{host}` \u00b7 `{now_local_str()}`",
        f"timeout `{HC_TIMEOUT_SEC}s` \u00b7 slow>=`{HC_SLOW_MS}ms` \u00b7 mode `{REPORT_MODE}`",
        "",
    ]

    cert_warn_hit = False

    for site_label, items in group_endpoint_results(results):
        site_ok = all(x.ok for x in items)
        tag = "OK" if site_ok else "FAIL"
        lines.append(f"*{site_label}* [{tag}]  {site_composite_headline(items)}")
        lines.append("")
        for role_label, r in _site_check_pairs(items):
            sub = "OK" if r.ok else "FAIL"
            lines.append(f"  {role_label} [{sub}]  `{r.name}` \u00b7 `{r.display_name}`")
            detail_lines, cw = render_subcheck_detail_lines(r)
            cert_warn_hit = cert_warn_hit or cw
            for dl in detail_lines:
                lines.append(f"    {dl}")
            lines.append("")
        lines.append("")

    lines.append(build_issue_summary_text(results))
    text = "\n".join(lines).strip()
    return text, cert_warn_hit


# =========================================================
# Main
# =========================================================
def main() -> None:
    host = socket.gethostname()
    run_id = now_local().strftime("%Y%m%d-%H%M%S")
    current_time = now_local_str()

    append_log(f"[{current_time}] run_id={run_id} start host={host}")

    if now_local().minute < 3:
        cleanup_old_files_and_state()

    state = load_state()
    is_restart, last_check_time = detect_restart(state, run_id, current_time)

    if should_send_daily_report(state):
        report = build_daily_report(state)
        if report:
            try:
                slack_post_text_batched(
                    build_slack_prefix([], False) + report,
                    attach_image=False,
                )
                get_global_state(state)["last_daily_report_date"] = today_ymd()
                append_log(f"[{now_local_str()}] run_id={run_id} daily_report=sent")
            except Exception as exc:
                append_log(f"[{now_local_str()}] run_id={run_id} daily_report=failed err={repr(exc)}")

    results = [check_endpoint(ep, state) for ep in ENDPOINTS]

    for r in results:
        update_endpoint_state(state, r)

    has_issue_now = any(not r.ok for r in results)

    # Compare against previous run's g["has_issue"] (still from load_state). If we set
    # g["has_issue"] before this call, prev_has_issue always equals has_issue_now and
    # issue_detected / issue_resolved never fire correctly.
    notify, reason = should_notify(results, state)
    if is_restart:
        notify = True
        reason = "restart_detected"

    g = get_global_state(state)
    g["has_issue"] = has_issue_now
    g["last_check"] = now_local_str()
    g["last_run_id"] = run_id

    add_history(state, results, has_issue_now)

    append_log(
        json.dumps(
            {
                "ts": now_local_str(),
                "run_id": run_id,
                "host": host,
                "config": {
                    "timeout_sec": HC_TIMEOUT_SEC,
                    "slow_ms": HC_SLOW_MS,
                    "report_mode": REPORT_MODE,
                    "endpoints": ENDPOINTS,
                    "header_keys": HEADER_KEYS,
                    "cert_warn_days": CERT_WARN_DAYS,
                    "cert_alert_days": CERT_ALERT_DAYS,
                },
                "results": [asdict(r) for r in results],
            },
            ensure_ascii=False,
        )
    )

    append_log(f"[{now_local_str()}] run_id={run_id} notify={notify} reason={reason}")
    save_state(state)

    if not notify:
        append_log(f"[{now_local_str()}] run_id={run_id} end (no notify)")
        return

    if reason == "issue_resolved":
        text = build_resolved_text(results, run_id, host)
        cert_warn_hit = any(result_has_cert_warning(r) for r in results)
    else:
        text, cert_warn_hit = build_slack_text(results, run_id, host)

    if is_restart and last_check_time:
        restart_report = build_restart_report(state, last_check_time, current_time)
        if restart_report:
            try:
                slack_post_text_batched(
                    build_slack_prefix([], False) + restart_report,
                    attach_image=False,
                )
                append_log(f"[{now_local_str()}] run_id={run_id} restart_report=sent")
            except Exception as exc:
                append_log(f"[{now_local_str()}] run_id={run_id} restart_report=failed err={repr(exc)}")

        restart_header = (
            "*\uc7ac\uae30\ub3d9 \ud6c4 \ud604\uc7ac \uc0c1\ud0dc*\n"
            f"\uc774\uc804 \uc2e4\ud589: `{last_check_time}`\n"
            f"\uc774\ubc88 \uc2e4\ud589: `{current_time}`\n\n"
        )
        text = restart_header + text

    try:
        slack_post_text_batched(
            build_slack_prefix(results, cert_warn_hit) + text,
            attach_image=bool(SLACK_IMAGE_URL and SLACK_POST_MODE == "json"),
        )
        append_log(f"[{now_local_str()}] run_id={run_id} slack=sent")
    except Exception as exc:
        append_log(f"[{now_local_str()}] run_id={run_id} slack=failed err={repr(exc)}")

    append_log(f"[{now_local_str()}] run_id={run_id} end")


if __name__ == "__main__":
    main()