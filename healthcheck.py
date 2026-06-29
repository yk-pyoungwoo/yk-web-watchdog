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
from typing import Any, Dict, List, Optional, Set, Tuple


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
# Hourly all-OK heartbeat (script alive); defaults to SLACK_WEBHOOK_URL if unset.
SLACK_HEARTBEAT_WEBHOOK_URL = (
    env_str("SLACK_HEARTBEAT_WEBHOOK_URL", "") or SLACK_WEBHOOK_URL
)
# Incoming webhooks cannot reply in threads (no thread_ts). Use summary messages instead.
# Threading would require SLACK_BOT_TOKEN + chat.postMessage (not implemented).

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
ALWAYS_MENTION = env_csv("ALWAYS_MENTION", "")
CHANNEL_MENTION_ON_FAIL = env_bool("CHANNEL_MENTION_ON_FAIL", True)
# Always mention this user in every Slack alert, regardless of mention options.
FORCED_USER_MENTION = "<@U0A2YSXBXLG>"
# CC on homepage issue alerts only (not hourly heartbeat). Slack user ID format.
ISSUE_CC_MENTION = env_str("ISSUE_CC_MENTION", "<@U0AMKCT217S>")

HC_TIMEOUT_SEC = env_float("HC_TIMEOUT_SEC", 10.0)
HC_CONNECT_TIMEOUT_SEC = env_float("HC_CONNECT_TIMEOUT_SEC", HC_TIMEOUT_SEC)
HC_SLOW_MS = env_int("HC_SLOW_MS", 1500)

REPORT_MODE = env_str("REPORT_MODE", "on_error").lower()
if REPORT_MODE not in {"always", "on_change", "on_error"}:
    raise RuntimeError("REPORT_MODE must be always/on_change/on_error")

STATE_FILE = env_str("STATE_FILE", "./state.json")
RESTART_FLAG_FILE = env_str(
    "RESTART_FLAG_FILE",
    os.path.join(os.path.dirname(os.path.abspath(STATE_FILE)), ".restart_requested"),
)
LOG_DIR = env_str("LOG_DIR", "./logs")
MAX_HISTORY = env_int("MAX_HISTORY", 480)
CLEANUP_DAYS = env_int("CLEANUP_DAYS", 7)

DAILY_REPORT_ENABLED = env_bool("DAILY_REPORT_ENABLED", True)
DAILY_REPORT_TIME = env_str("DAILY_REPORT_TIME", "09:00")

# Notification policy (checks run every ~3 min via systemd; Slack is separate):
# - All OK: heartbeat once per hour at the top of the hour (minute 0–2 window).
# - Restart/resume after >5 min gap (or ./run/restart.sh): full restart alert to both
#   SLACK_WEBHOOK_URL and SLACK_HEARTBEAT_WEBHOOK_URL (deduped if URLs match).
# - First failure: alert immediately (issue_detected).
# - Still failing after ISSUE_REPEAT_MIN_FAILURES consecutive checks: alert again, then
#   every ISSUE_REMINDER_INTERVAL_SEC until recovered (issue_persists).
# - Recovery: one alert (issue_resolved).
# REPORT_MODE=always sends on every check (not recommended).
ISSUE_REPEAT_MIN_FAILURES = env_int("ISSUE_REPEAT_MIN_FAILURES", 2)
ISSUE_REMINDER_INTERVAL_SEC = env_int("ISSUE_REMINDER_INTERVAL_SEC", 180)

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
# Endpoint config (external VM: bare domain redirect + www host service)
# =========================================================
ENDPOINT_SUFFIX_BARE = "-bare"  # hostname without www (e.g. example.com)
ENDPOINT_SUFFIX_WWW = "-www"  # hostname with www (e.g. www.example.com)
LEGACY_SUFFIX_APEX = "-apex"
LEGACY_SUFFIX_ROOT = "-root"
LEGACY_SUFFIX_PRIMARY = "-primary"

REDIRECT_EXPECT_STATUS = [301, 302, 307, 308]
SERVICE_EXPECT_STATUS = [200]

LABEL_BARE = "Bare domain (no www) → redirect"
LABEL_WWW = "WWW host (direct)"
LABEL_BARE_SHORT = "bare→www"
LABEL_WWW_SHORT = "www"

# (site_key, bare hostname, www hostname)
SITE_HOSTS: List[Tuple[str, str, str]] = [
    ("brand", "yklawfirm.co.kr", "www.yklawfirm.co.kr"),
    ("crime", "yklawfirm-crime.co.kr", "www.yklawfirm-crime.co.kr"),
    ("divorce", "yklawfirm-divorce.co.kr", "www.yklawfirm-divorce.co.kr"),
    ("civil", "yklawfirm-civil.co.kr", "www.yklawfirm-civil.co.kr"),
    ("assault", "yklawfirm-assault.co.kr", "www.yklawfirm-assault.co.kr"),
    ("inherit", "yklawfirm-inherit.co.kr", "www.yklawfirm-inherit.co.kr"),
    ("drug", "yklawfirm-drug.co.kr", "www.yklawfirm-drug.co.kr"),
    ("traffic", "yklawfirm-traffic.co.kr", "www.yklawfirm-traffic.co.kr"),
    ("school", "yklawfirm-school.co.kr", "www.yklawfirm-school.co.kr"),
    ("estate", "yklawfirm-estate.co.kr", "www.yklawfirm-estate.co.kr"),
    ("military", "yklawfirm-military.co.kr", "www.yklawfirm-military.co.kr"),    
    ("regeneration", "yklawfirm-regeneration.co.kr", "www.yklawfirm-regeneration.co.kr"),    
    ("medical", "yklawfirm-medical.co.kr", "www.yklawfirm-medical.co.kr"),
]

# (site_key, punycode host, display label)
CLONE_SITES: List[Tuple[str, str, str]] = [
    ("crime-clone-center", "xn--yk-4q4jsse25dzwg.com", "YK형사센터.com"),
    ("crime-clone-lawyer", "xn--yk-291jq3kba7993acha.com", "YK형사변호사.com"),
    ("drug-clone-center", "xn--yk-xf0jg0wtpfqnu.com", "YK마약센터.com"),
    ("drug-clone-lawyer", "xn--yk-xf0j71hprgltiwt5a.com", "YK마약변호사.com"),
    ("divorce-clone-center", "xn--yk-h34jm9rbsnplh.com", "YK이혼센터.com"),
    ("divorce-clone-lawyer", "xn--yk-291jr3k7rkb6w0a.com", "YK이혼변호사.com"),
    ("assault-clone-center", "xn--yk-b61jl6mvb553eilo.com", "YK성범죄센터.com"),
    ("assault-clone-lawyer", "xn--yk-b61jvf26qzwa310bih0a.com", "YK성범죄변호사.com"),
]


def _endpoint_pair(site_key: str, bare_host: str, www_host: str) -> List[Dict[str, Any]]:
    return [
        {
            "name": f"{site_key}{ENDPOINT_SUFFIX_BARE}",
            "display_name": bare_host,
            "type": "redirect",
            "url": f"https://{bare_host}/",
            "expect_status": REDIRECT_EXPECT_STATUS,
            "expect_location_prefix": f"https://{www_host}/",
            "dns_host": bare_host,
            "ssl_host": bare_host,
        },
        {
            "name": f"{site_key}{ENDPOINT_SUFFIX_WWW}",
            "display_name": www_host,
            "type": "service",
            "url": f"https://{www_host}/",
            "expect_status": SERVICE_EXPECT_STATUS,
            "dns_host": www_host,
            "ssl_host": www_host,
        },
    ]


def _clone_endpoint(site_key: str, punycode_host: str, display_label: str) -> Dict[str, Any]:
    return {
        "name": site_key,
        "display_name": display_label,
        "site_group": site_key,
        "site_label": display_label,
        "type": "service",
        "url": f"https://{punycode_host}/",
        "expect_status": SERVICE_EXPECT_STATUS,
        "dns_host": punycode_host,
        "ssl_host": punycode_host,
    }


def _legacy_endpoint_renames() -> Dict[str, str]:
    renames: Dict[str, str] = {}
    for site_key, _, _ in SITE_HOSTS:
        bare = f"{site_key}{ENDPOINT_SUFFIX_BARE}"
        www = f"{site_key}{ENDPOINT_SUFFIX_WWW}"
        for legacy in (LEGACY_SUFFIX_APEX, LEGACY_SUFFIX_ROOT):
            renames[f"{site_key}{legacy}"] = bare
        renames[f"{site_key}{LEGACY_SUFFIX_PRIMARY}"] = www
    return renames


DEFAULT_ENDPOINTS: List[Dict[str, Any]] = []
for _site_key, _bare_host, _www_host in SITE_HOSTS:
    DEFAULT_ENDPOINTS.extend(_endpoint_pair(_site_key, _bare_host, _www_host))
for _sk, _puny, _label in CLONE_SITES:
    DEFAULT_ENDPOINTS.append(_clone_endpoint(_sk, _puny, _label))


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
def _migrate_state_endpoint_keys(state: Dict[str, Any]) -> bool:
    """Rename legacy endpoint keys (e.g. brand-apex → brand-bare) in state and history."""
    changed = False
    renames = _legacy_endpoint_renames()

    for old, new in renames.items():
        if old not in state or not isinstance(state.get(old), dict):
            continue
        if new not in state:
            state[new] = state.pop(old)
        else:
            del state[old]
        changed = True

    g = state.get("_global")
    if isinstance(g, dict):
        history = g.get("_check_history")
        if isinstance(history, list):
            for entry in history:
                results = entry.get("results")
                if not isinstance(results, dict):
                    continue
                for old, new in renames.items():
                    if old in results and new not in results:
                        results[new] = results.pop(old)
                        changed = True
                    elif old in results:
                        del results[old]
                        changed = True
    return changed


def load_state() -> Dict[str, Any]:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return {}
            if _migrate_state_endpoint_keys(data):
                save_state(data)
            return data
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


def add_history(
    state: Dict[str, Any], results: List[EndpointResult], has_issue: bool
) -> None:
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
    # Fires once per day in a short window (aligned with ~3 min systemd timer).
    return now.hour == hour and minute <= now.minute < minute + 3


def _endpoint_display_names() -> Dict[str, str]:
    names: Dict[str, str] = {}
    for ep in ENDPOINTS:
        key = ep.get("name", "")
        if key:
            names[key] = ep.get("display_name") or key
    return names


def _history_rows_for_date(history: List[Any], ymd: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in history:
        if not isinstance(item, dict):
            continue
        ts = str(item.get("ts", ""))
        if ts.startswith(ymd):
            rows.append(item)
    rows.sort(key=lambda x: str(x.get("ts", "")))
    return rows


def _incident_episodes(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    episodes: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for row in rows:
        ts = str(row.get("ts", ""))
        if row.get("has_issue"):
            if current is None:
                current = {"start": ts, "end": ts, "checks": 1}
            else:
                current["end"] = ts
                current["checks"] += 1
        elif current is not None:
            episodes.append(current)
            current = None
    if current is not None:
        episodes.append(current)
    return episodes


def _aggregate_endpoint_failures(
    rows: List[Dict[str, Any]],
) -> List[Tuple[str, int, str, str]]:
    """Return [(endpoint_name, fail_count, display, sample_summary), ...] sorted by count."""
    display = _endpoint_display_names()
    counts: Dict[str, int] = {}
    samples: Dict[str, str] = {}
    roles: Dict[str, str] = {}

    for row in rows:
        results = row.get("results")
        if not isinstance(results, dict):
            continue
        for name, info in results.items():
            if not isinstance(info, dict) or info.get("ok") is not False:
                continue
            counts[name] = counts.get(name, 0) + 1
            if name not in samples:
                samples[name] = str(info.get("summary", ""))
            if name not in roles:
                t = info.get("type", "")
                roles[name] = role_label_for_check(t, short=True) if t else ""

    ranked = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    out: List[Tuple[str, int, str, str]] = []
    for name, cnt in ranked:
        disp = display.get(name, name)
        role = roles.get(name, "")
        label = f"{role} · `{disp}`" if role else f"`{disp}`"
        out.append((name, cnt, label, samples.get(name, "")))
    return out


def build_daily_report(state: Dict[str, Any]) -> str:
    g = get_global_state(state)
    history = g.get("_check_history", [])
    if not isinstance(history, list):
        history = []

    report_date = (now_local() - timedelta(days=1)).strftime("%Y-%m-%d")
    rows = _history_rows_for_date(history, report_date)

    total = len(rows)
    issue_runs = sum(1 for x in rows if x.get("has_issue"))
    ok_runs = total - issue_runs
    uptime_pct = (ok_runs / total * 100.0) if total else 100.0

    endpoint_failures = _aggregate_endpoint_failures(rows)
    episodes = _incident_episodes(rows)

    header = [
        "*Daily Incident Report*",
        f"Report date: `{report_date}` (sent `{now_local_str()}`)",
        f"Checks recorded: `{total}` (issue runs `{issue_runs}`, clean `{ok_runs}`)",
    ]

    detail_lines: List[str] = ["*Details*", ""]

    if not rows:
        detail_lines.append(
            f"No check history for `{report_date}`. "
            "The watchdog may have been offline or state was reset."
        )
    elif not issue_runs and not endpoint_failures:
        detail_lines.append(f"No incidents on `{report_date}`. All checks were healthy.")
    else:
        detail_lines.append(
            f"Issue rate: `{issue_runs}/{total}` runs ({uptime_pct:.1f}% clean)."
        )
        detail_lines.append("")

        if episodes:
            detail_lines.append("Incident windows (consecutive issue runs):")
            for i, ep in enumerate(episodes, 1):
                detail_lines.append(
                    f"{i}. `{ep['start']}` → `{ep['end']}` "
                    f"({ep['checks']} check(s))"
                )
            detail_lines.append("")

        if endpoint_failures:
            detail_lines.append("Endpoints with failures:")
            for _name, cnt, label, sample in endpoint_failures:
                line = f"- {label}: `{cnt}` failed check(s)"
                if sample:
                    line += f" — last summary `{sample}`"
                detail_lines.append(line)
            detail_lines.append("")

    # Current snapshot from persisted endpoint state
    detail_lines.append("Current endpoint state (as of this report):")
    failing_now: List[str] = []
    for ep in ENDPOINTS:
        name = ep.get("name", "")
        st = state.get(name, {})
        if not isinstance(st, dict):
            continue
        disp = ep.get("display_name", name)
        ok = st.get("ok")
        cf = int(st.get("consecutive_failures", 0) or 0)
        if ok is False:
            failing_now.append(
                f"- `{disp}` (`{name}`): FAIL · consecutive `{cf}` · "
                f"`{st.get('summary', '-')}`"
            )
    if failing_now:
        detail_lines.extend(failing_now)
    else:
        detail_lines.append("- All endpoints OK in state file.")

    summary_lines = ["*Summary*", ""]
    if not rows:
        summary_lines.append("No data for the report period.")
    elif not issue_runs:
        summary_lines.append(
            f"`{report_date}`: no incidents. Monitoring healthy ({total} checks)."
        )
    else:
        top = endpoint_failures[0] if endpoint_failures else None
        summary_lines.append(
            f"`{report_date}`: `{issue_runs}` issue run(s), "
            f"`{len(episodes)}` incident window(s), "
            f"`{len(endpoint_failures)}` endpoint(s) affected."
        )
        if top:
            summary_lines.append(
                f"Most affected: {top[2]} (`{top[1]}` failed checks)."
            )
        if failing_now:
            summary_lines.append(
                f"Still failing now: `{len(failing_now)}` endpoint(s) — see Details."
            )
        else:
            summary_lines.append("All endpoints OK at report time.")

    sections = [
        "\n".join(header).strip(),
        "\n".join(detail_lines).strip(),
        "\n".join(summary_lines).strip(),
    ]
    return "\n\n".join(sections)


def consume_restart_flag() -> bool:
    """Set by ./run/restart.sh or manual systemctl start (via run/pre_start.sh)."""
    if not os.path.isfile(RESTART_FLAG_FILE):
        return False
    try:
        os.remove(RESTART_FLAG_FILE)
    except OSError:
        pass
    return True


def detect_restart(
    state: Dict[str, Any], run_id: str, current_time: str
) -> Tuple[bool, Optional[str]]:
    g = get_global_state(state)
    last_check_time = g.get("last_check")
    last_run_id = g.get("last_run_id")
    force_restart = bool(g.get("force_restart_report", False))

    if consume_restart_flag():
        # Ignore spurious flags on normal ~3 min timer cadence (pre_start mis-detection).
        elapsed = seconds_since_timestamp(current_time, last_check_time)
        if elapsed is not None and elapsed <= 300:
            append_log(
                f"[{current_time}] run_id={run_id} restart_flag=ignored "
                f"elapsed_sec={elapsed:.0f}"
            )
        else:
            return True, last_check_time

    if force_restart:
        g["force_restart_report"] = False
        return True, last_check_time

    if not last_check_time:
        return True, None

    elapsed = seconds_since_timestamp(current_time, last_check_time)
    if elapsed is None or elapsed > 300:
        return True, last_check_time

    if last_run_id:
        try:
            prev_dt = datetime.strptime(
                last_run_id[:8] + last_run_id[9:], "%Y%m%d%H%M%S"
            )
            cur_dt = datetime.strptime(run_id[:8] + run_id[9:], "%Y%m%d%H%M%S")
            if (cur_dt - prev_dt).total_seconds() > 300:
                return True, last_check_time
        except Exception:
            pass

    return False, last_check_time


def build_restart_report(
    state: Dict[str, Any], last_run_time: str, current_time: str
) -> Optional[str]:
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


def build_restart_notice_text(
    host: str,
    last_check_time: str,
    current_time: str,
    results: List[EndpointResult],
) -> str:
    n = len(results)
    fail_n = sum(1 for r in results if not r.ok)
    lines = [
        "*\uc7ac\uae30\ub3d9 \uac10\uc9c0 \u2014 \ubaa8\ub2c8\ud130\ub9c1 \uc7ac\uac1c*",
        f"\ud638\uc2a4\ud2b8: `{host}`",
        f"\uc774\uc804 \uc2e4\ud589: `{last_check_time}`",
        f"\ud604\uc7ac \uc2e4\ud589: `{current_time}`",
    ]
    if fail_n:
        lines.append(f"\ud604\uc7ac \uc0c1\ud0dc: *\uc774\uc0c1* \u2014 `{fail_n}`/`{n}` \uc2e4\ud328")
    else:
        lines.append(f"\ud604\uc7ac \uc0c1\ud0dc: *\uc815\uc0c1* \u2014 `{n}`\uac1c \uccb4\ud06c \ubaa8\ub450 \ud1b5\uacfc")
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


def classify_error(
    err: Optional[str], status_code: Optional[int], endpoint_type: str
) -> str:
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
        "--max-time",
        str(HC_TIMEOUT_SEC),
        "--connect-timeout",
        str(HC_CONNECT_TIMEOUT_SEC),
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
        "--max-time",
        str(HC_TIMEOUT_SEC),
        "--connect-timeout",
        str(HC_CONNECT_TIMEOUT_SEC),
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
                "openssl",
                "s_client",
                "-servername",
                host,
                "-connect",
                f"{host}:443",
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
            [
                "openssl",
                "x509",
                "-noout",
                "-enddate",
                "-issuer",
                "-subject",
                "-ext",
                "subjectAltName",
            ],
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
                        prefix = host[: -len(suffix)]
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
        "-o",
        "/dev/null",
        "--max-time",
        str(HC_TIMEOUT_SEC),
        "--connect-timeout",
        str(HC_CONNECT_TIMEOUT_SEC),
        "-w",
        write_out,
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
            err = (
                f"{err} | redirect_chain_err={chain_err}"
                if err
                else f"redirect_chain_err={chain_err}"
            )

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
        "-o",
        "/dev/null",
        "-D",
        "-",
        "--max-time",
        str(HC_TIMEOUT_SEC),
        "--connect-timeout",
        str(HC_CONNECT_TIMEOUT_SEC),
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


def _strip_endpoint_role_suffix(name: str) -> str:
    for suffix in (
        ENDPOINT_SUFFIX_BARE,
        ENDPOINT_SUFFIX_WWW,
        LEGACY_SUFFIX_APEX,
        LEGACY_SUFFIX_ROOT,
        LEGACY_SUFFIX_PRIMARY,
    ):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def endpoint_site_group(endpoint: Dict[str, Any]) -> str:
    raw = endpoint.get("site_group")
    if raw is not None and str(raw).strip():
        return str(raw).strip()
    name = endpoint.get("name") or ""
    return _strip_endpoint_role_suffix(name) or name


def endpoint_site_label(endpoint: Dict[str, Any]) -> str:
    raw = endpoint.get("site_label")
    if raw is not None and str(raw).strip():
        return str(raw).strip()
    display = endpoint.get("display_name") or endpoint.get("name") or ""
    if display.startswith("www."):
        return display[4:]
    return display


def role_label_for_check(endpoint_type: str, *, short: bool = False) -> str:
    if endpoint_type == "redirect":
        return LABEL_BARE_SHORT if short else LABEL_BARE
    if endpoint_type == "service":
        return LABEL_WWW_SHORT if short else LABEL_WWW
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
    """Order checks per site: bare-domain redirect, then www host."""
    out: List[Tuple[str, EndpointResult]] = []
    redirect = next((x for x in items if x.type == "redirect"), None)
    service = next((x for x in items if x.type == "service"), None)
    if redirect:
        out.append((role_label_for_check("redirect"), redirect))
    if service:
        out.append((role_label_for_check("service"), service))
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


def endpoint_is_slow(r: EndpointResult) -> bool:
    fp = r.final_probe
    if not fp or fp.total_ms is None:
        return False
    return fp.total_ms >= HC_SLOW_MS


def endpoint_needs_detail(r: EndpointResult) -> bool:
    """Include probe/SSL detail in Slack only for failures, TLS ≤30d, or slow responses."""
    if not r.ok:
        return True
    if result_has_cert_warning(r):
        return True
    if endpoint_is_slow(r):
        return True
    return False


def results_need_detail_block(results: List[EndpointResult]) -> bool:
    return any(endpoint_needs_detail(r) for r in results)


def cert_warning_lines(results: List[EndpointResult]) -> List[str]:
    lines: List[str] = []
    for r in results:
        if not result_has_cert_warning(r):
            continue
        d = r.ssl.expires_in_days if r.ssl else None
        who = r.display_name or r.name
        if d is not None and d < 0:
            lines.append(f"· `{who}`: expired ({abs(d)}d ago)")
        elif d is not None:
            lvl = "critical" if d <= CERT_ALERT_DAYS else "warning"
            lines.append(f"· `{who}`: {lvl}, {d}d left")
    return lines


def _count_checks_by_role(results: List[EndpointResult]) -> Tuple[int, int, int, int]:
    bare_ok = bare_fail = www_ok = www_fail = 0
    for r in results:
        if r.type == "redirect":
            if r.ok:
                bare_ok += 1
            else:
                bare_fail += 1
        elif r.type == "service":
            if r.ok:
                www_ok += 1
            else:
                www_fail += 1
    return bare_ok, bare_fail, www_ok, www_fail


def build_footer_summary_lines(
    results: List[EndpointResult], *, kind: str
) -> List[str]:
    """Short recap placed at the end of every Slack report (details come first)."""
    pairs = group_endpoint_results(results)
    n_checks = len(results)
    n_sites = len(pairs)
    n_ok = sum(1 for r in results if r.ok)
    n_fail = n_checks - n_ok
    sites_ok = sum(1 for _, items in pairs if all(x.ok for x in items))
    bare_ok, bare_fail, www_ok, www_fail = _count_checks_by_role(results)

    lines: List[str] = [
        f"Sites: `{sites_ok}/{n_sites}` OK \u00b7 Checks: `{n_ok}/{n_checks}` OK",
        (
            f"Bare domain (no www): `{bare_ok}` OK"
            + (f", `{bare_fail}` FAIL" if bare_fail else "")
        ),
        (
            f"WWW host (direct): `{www_ok}` OK"
            + (f", `{www_fail}` FAIL" if www_fail else "")
        ),
    ]

    if kind == "recovery":
        lines.insert(0, "All endpoints recovered; no active failures.")
    elif kind in {"ok", "heartbeat"}:
        lines.insert(0, "All endpoints healthy.")
    elif n_fail:
        lines.insert(0, f"Active failures: `{n_fail}` check(s) across site(s).")

    failed = [r for r in results if not r.ok]
    if failed:
        lines.append("")
        lines.append("Failed checks:")
        for site_label, items in pairs:
            bad = [r for r in items if not r.ok]
            if not bad:
                continue
            bits: List[str] = []
            for r in bad:
                role = role_label_for_check(r.type, short=True)
                bits.append(f"{role}: `{r.summary}` \u2014 `{r.actual}`")
            lines.append(f"- *{site_label}*: " + " | ".join(bits))

    cert_lines: List[str] = []
    for r in results:
        if not result_has_cert_warning(r):
            continue
        d = r.ssl.expires_in_days if r.ssl else None
        who = r.display_name or r.name
        if d is not None and d < 0:
            cert_lines.append(
                f"- *{r.site_label}* / `{who}`: expired ({abs(d)}d ago)"
            )
        elif d is not None:
            lvl = "critical" if d <= CERT_ALERT_DAYS else "warning"
            cert_lines.append(f"- *{r.site_label}* / `{who}`: {lvl}, {d}d left")

    lines.append("")
    if cert_lines:
        lines.append("TLS certificate:")
        lines.extend(cert_lines)
    else:
        lines.append("TLS certificate: no warnings")

    return lines


def build_run_meta_lines(run_id: str, host: str) -> List[str]:
    return [
        f"run `{run_id}` \u00b7 host `{host}` \u00b7 `{now_local_str()}`",
        (
            f"timeout `{HC_TIMEOUT_SEC}s` \u00b7 slow\u2265`{HC_SLOW_MS}ms` "
            f"\u00b7 mode `{REPORT_MODE}`"
        ),
    ]


def build_site_details_lines(
    results: List[EndpointResult],
    *,
    only_notable: bool = False,
) -> Tuple[List[str], bool]:
    lines: List[str] = []
    cert_warn_hit = False
    for site_label, items in group_endpoint_results(results):
        pairs = _site_check_pairs(items)
        if only_notable:
            pairs = [(lbl, r) for lbl, r in pairs if endpoint_needs_detail(r)]
            if not pairs:
                continue

        site_ok = all(x.ok for x in items)
        tag = "OK" if site_ok else "FAIL"
        lines.append(f"*{site_label}* [{tag}]  {site_composite_headline(items)}")
        lines.append("")
        for role_label, r in pairs:
            sub = "OK" if r.ok else "FAIL"
            lines.append(
                f"  {role_label} [{sub}]  `{r.name}` \u00b7 `{r.display_name}`"
            )
            detail_lines, cw = render_subcheck_detail_lines(r)
            cert_warn_hit = cert_warn_hit or cw
            for dl in detail_lines:
                lines.append(f"    {dl}")
            lines.append("")
        lines.append("")
    return lines, cert_warn_hit


def build_slack_report(
    results: List[EndpointResult],
    run_id: str,
    host: str,
    *,
    title: str,
    subtitle: str = "",
    summary_kind: str,
    detail_mode: str = "auto",
) -> Tuple[str, bool]:
    """
    Slack body: header → optional details → summary (summary always last).
    detail_mode: summary (compact), auto (details only if notable), full (all probes).
    """
    cert_warn_hit = any(result_has_cert_warning(r) for r in results)
    header: List[str] = [f"*{title}*"]
    if subtitle:
        header.append(subtitle)
    if detail_mode != "summary":
        header.extend(build_run_meta_lines(run_id, host))

    summary_lines = build_footer_summary_lines(results, kind=summary_kind)
    sections: List[str] = ["\n".join(header).strip()]

    include_details = detail_mode == "full" or (
        detail_mode == "auto" and results_need_detail_block(results)
    )
    if include_details:
        only_notable = detail_mode != "full"
        detail_lines, cw = build_site_details_lines(results, only_notable=only_notable)
        cert_warn_hit = cert_warn_hit or cw
        if detail_lines:
            sections.append("*Details*\n\n" + "\n".join(detail_lines).strip())

    sections.append("*Summary*\n\n" + "\n".join(summary_lines).strip())
    return "\n\n".join(sections), cert_warn_hit


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
                ssl_parts.append(
                    f"\ub9cc\ub8cc \uc784\ubc15: \ub0a8\uc740 {days_left}\uc77c"
                )
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
    display_name = (
        endpoint.get("display_name") or endpoint.get("name") or endpoint["url"]
    )
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

        expect_status = set(
            int(x) for x in endpoint.get("expect_status", [301, 302, 307, 308])
        )
        expect_prefix = endpoint.get("expect_location_prefix", "")

        first_ok = (
            redirect_probe.status_code in expect_status
            and bool(redirect_probe.location)
            and str(redirect_probe.location).startswith(expect_prefix)
        )
        final_ok = (
            final_probe.status_code is not None
            and 200 <= final_probe.status_code < 400
            and (final_probe.err is None)
        )

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
        status_class = classify_error(
            final_probe.err, final_probe.status_code, endpoint_type
        )
        summary = "service_ok" if ok else "service_down"

    prev = (
        state.get(endpoint["name"], {})
        if isinstance(state.get(endpoint["name"]), dict)
        else {}
    )
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
def max_consecutive_failures(results: List[EndpointResult]) -> int:
    failing = [r for r in results if not r.ok]
    if not failing:
        return 0
    return max(r.consecutive_failures for r in failing)


def seconds_since_timestamp(current_time_str: str, last_time_str: Any) -> Optional[float]:
    if not last_time_str:
        return None
    try:
        last_dt = datetime.strptime(str(last_time_str), "%Y-%m-%d %H:%M:%S")
        cur_dt = datetime.strptime(current_time_str, "%Y-%m-%d %H:%M:%S")
        return (cur_dt - last_dt).total_seconds()
    except Exception:
        return None


def issue_reminder_due(g: Dict[str, Any], current_time_str: str) -> bool:
    elapsed = seconds_since_timestamp(current_time_str, g.get("last_issue_alert_at"))
    if elapsed is None:
        return True
    return elapsed >= ISSUE_REMINDER_INTERVAL_SEC


def mark_issue_alert_sent(g: Dict[str, Any], current_time_str: str) -> None:
    g["last_issue_alert_at"] = current_time_str


def should_notify(
    results: List[EndpointResult],
    state: Dict[str, Any],
    current_time_str: str,
) -> Tuple[bool, str]:
    if REPORT_MODE == "always":
        return True, "always"

    g = get_global_state(state)
    has_issue_now = any(not r.ok for r in results)
    prev_has_issue = bool(g.get("has_issue", False))
    max_cf = max_consecutive_failures(results)

    if REPORT_MODE == "on_error":
        if not has_issue_now and prev_has_issue:
            return True, "issue_resolved"
        if has_issue_now and not prev_has_issue:
            # First failed check while previously healthy — alert immediately.
            return True, "issue_detected"
        if has_issue_now and prev_has_issue:
            if max_cf < ISSUE_REPEAT_MIN_FAILURES:
                return False, "issue_awaiting_repeat_threshold"
            if issue_reminder_due(g, current_time_str):
                return True, "issue_persists"
            return False, "issue_reminder_throttled"
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


def ok_heartbeat_hour_key() -> str:
    return now_local().strftime("%Y-%m-%d-%H")


def should_send_ok_heartbeat(state: Dict[str, Any]) -> bool:
    """Fire once per hour in the first ~3 min window (aligned with systemd timer)."""
    now = now_local()
    if now.minute >= 3:
        return False
    g = get_global_state(state)
    return g.get("last_ok_heartbeat_hour", "") != ok_heartbeat_hour_key()


def send_restart_slack_alerts(
    state: Dict[str, Any],
    results: List[EndpointResult],
    *,
    run_id: str,
    host: str,
    current_time: str,
    last_check_time: Optional[str],
    has_issue_now: bool,
) -> None:
    """On restart, always notify both main and heartbeat Slack channels."""
    g = get_global_state(state)
    prev_check = last_check_time or "(\uc774\uc804 \uae30\ub85d \uc5c6\uc74c)"

    main_text = build_restart_notice_text(host, prev_check, current_time, results)
    if last_check_time:
        gap_report = build_restart_report(state, last_check_time, current_time)
        if gap_report:
            main_text = gap_report + "\n\n" + main_text

    cert_warn_hit = any(result_has_cert_warning(r) for r in results)
    if has_issue_now:
        detail, cert_warn_hit = build_slack_text(
            results, run_id, host, reason="restart_detected"
        )
        main_text = main_text + "\n\n" + detail

    main_prefix = build_slack_prefix(
        results, cert_warn_hit, include_issue_cc=has_issue_now
    )
    heartbeat_prefix = build_slack_prefix(
        results, cert_warn_hit, include_issue_cc=False
    )

    restart_channels: List[Tuple[str, str, str, bool]] = [
        ("restart_main", SLACK_WEBHOOK_URL, main_prefix, True),
        (
            "restart_heartbeat",
            SLACK_HEARTBEAT_WEBHOOK_URL,
            heartbeat_prefix,
            False,
        ),
    ]
    seen_webhooks: Set[str] = set()
    for label, webhook_url, prefix, attach_image in restart_channels:
        if webhook_url in seen_webhooks:
            append_log(
                f"[{now_local_str()}] run_id={run_id} {label}=skipped "
                f"(duplicate webhook)"
            )
            continue
        seen_webhooks.add(webhook_url)
        try:
            slack_post_text_batched(
                prefix + main_text,
                attach_image=attach_image
                and bool(SLACK_IMAGE_URL and SLACK_POST_MODE == "json"),
                webhook_url=webhook_url,
            )
            append_log(f"[{now_local_str()}] run_id={run_id} {label}=sent")
        except Exception as exc:
            append_log(
                f"[{now_local_str()}] run_id={run_id} {label}=failed err={repr(exc)}"
            )

    if has_issue_now:
        mark_issue_alert_sent(g, current_time)
    else:
        g["last_ok_heartbeat_hour"] = ok_heartbeat_hour_key()
    g["last_ok_heartbeat_sent_at"] = current_time
    save_state(state)


def maybe_run_ok_heartbeat_slack(
    state: Dict[str, Any],
    results: List[EndpointResult],
    *,
    run_id: str,
    host: str,
    current_time: str,
    notify: bool,
    has_issue_now: bool,
) -> None:
    if has_issue_now or notify or REPORT_MODE == "always":
        return

    if not should_send_ok_heartbeat(state):
        return

    g = get_global_state(state)
    try:
        text, cert_warn_hit = build_ok_heartbeat_text(results, run_id, host)
        slack_post_text_batched(
            build_slack_prefix(results, cert_warn_hit) + text,
            attach_image=False,
            webhook_url=SLACK_HEARTBEAT_WEBHOOK_URL,
        )
        g["last_ok_heartbeat_hour"] = ok_heartbeat_hour_key()
        g["last_ok_heartbeat_sent_at"] = current_time
        save_state(state)
        append_log(f"[{now_local_str()}] run_id={run_id} ok_heartbeat=sent")
    except Exception as exc:
        append_log(
            f"[{now_local_str()}] run_id={run_id} ok_heartbeat=failed err={repr(exc)}"
        )


def build_ok_heartbeat_text(
    results: List[EndpointResult], run_id: str, host: str
) -> Tuple[str, bool]:
    """Hourly all-OK message: single-line completion summary."""
    cert_warn_hit = any(result_has_cert_warning(r) for r in results)
    n_checks = len(results)
    line = (
        f"*Monitoring OK* · `{now_local_str()}` · host `{host}` · "
        f"all `{n_checks}` checks passed"
    )
    cert_n = sum(1 for r in results if result_has_cert_warning(r))
    if cert_n:
        w = "warning" if cert_n == 1 else "warnings"
        line += f" · TLS certificate: `{cert_n}` {w}"
    return line, cert_warn_hit


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


def slack_post(
    payload_obj: Dict[str, Any], *, webhook_url: str = SLACK_WEBHOOK_URL
) -> None:
    if SLACK_POST_MODE == "payload":
        body = urllib.parse.urlencode(
            {"payload": json.dumps(payload_obj, ensure_ascii=False)}
        ).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
    else:
        body = json.dumps(payload_obj, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8"}

    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HC_TIMEOUT_SEC) as resp:
        _ = resp.read()


def _chunk_text_for_slack(s: str, limit: int) -> List[str]:
    if not s:
        return []
    parts: List[str] = []
    i = 0
    n = len(s)
    while i < n:
        remain = n - i
        if remain <= limit:
            parts.append(s[i:])
            break
        end = i + limit
        window = s[i:end]
        nl = window.rfind("\n")
        if nl > limit // 4:
            end = i + nl + 1
        parts.append(s[i:end])
        i = end
    return parts


def _slack_chunk_limit() -> int:
    # Slack webhooks ~4000 chars; keep margin for part headers (never truncate content).
    return max(500, SLACK_MAX_CHARS - 250)


def _split_slack_messages(full_text: str) -> List[str]:
    limit = _slack_chunk_limit()
    if len(full_text) <= limit:
        return [full_text]

    raw_sections = [s.strip() for s in full_text.split("\n\n") if s.strip()]
    packed: List[str] = []
    current: List[str] = []
    current_len = 0

    for sec in raw_sections:
        sep = "\n\n" if current else ""
        add_len = len(sep) + len(sec)
        if current and current_len + add_len > limit:
            packed.append("\n\n".join(current))
            current = []
            current_len = 0
        if len(sec) > limit:
            if current:
                packed.append("\n\n".join(current))
                current = []
                current_len = 0
            packed.extend(_chunk_text_for_slack(sec, limit))
            continue
        current.append(sec)
        current_len += (len(sep) + len(sec)) if current_len else len(sec)

    if current:
        packed.append("\n\n".join(current))

    if not packed:
        return _chunk_text_for_slack(full_text, limit)
    return packed


def slack_post_text_batched(
    full_text: str,
    *,
    attach_image: bool = False,
    webhook_url: str = SLACK_WEBHOOK_URL,
) -> None:
    chunks = _split_slack_messages(full_text)
    total = len(chunks)
    for idx, ch in enumerate(chunks):
        body = ch
        if total > 1:
            body = f"_(part {idx + 1}/{total})_\n\n{ch}"
        payload: Dict[str, Any] = {
            "text": body,
            "username": SLACK_USERNAME,
            "icon_emoji": get_rotating_emoji(),
        }
        if attach_image and idx == 0 and SLACK_IMAGE_URL and SLACK_POST_MODE == "json":
            payload["attachments"] = [
                {
                    "image_url": SLACK_IMAGE_URL,
                    "fallback": "YK Watchdog Status Check",
                }
            ]
        slack_post(payload, webhook_url=webhook_url)


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


def build_slack_prefix(
    results: List[EndpointResult],
    cert_warn_hit: bool,
    *,
    include_issue_cc: bool = False,
) -> str:
    lines = ["*YK Watchdog*"]
    mention_tokens: List[str] = list(ALWAYS_MENTION) if ENABLE_MENTIONS else []
    if FORCED_USER_MENTION not in mention_tokens:
        mention_tokens.append(FORCED_USER_MENTION)
    if mention_tokens:
        mention_line = " ".join(mention_tokens)
        has_fail = any(not r.ok for r in results) or cert_warn_hit
        if include_issue_cc and ISSUE_CC_MENTION and has_fail:
            mention_line += f" (cc. {ISSUE_CC_MENTION})"
        lines.append(f"mentions: {mention_line}")

    if ENABLE_MENTIONS and CHANNEL_MENTION_ON_FAIL:
        if any(not r.ok for r in results) or cert_warn_hit:
            lines.append("<!channel>")

    return "\n".join(lines) + "\n\n"


def build_resolved_text(results: List[EndpointResult], run_id: str, host: str) -> str:
    mode = "auto" if results_need_detail_block(results) else "summary"
    text, _ = build_slack_report(
        results,
        run_id,
        host,
        title="Recovered",
        subtitle="All endpoints are healthy again.",
        summary_kind="recovery",
        detail_mode=mode,
    )
    return text


def build_slack_text(
    results: List[EndpointResult],
    run_id: str,
    host: str,
    *,
    reason: str = "",
) -> Tuple[str, bool]:
    has_fail = any(not r.ok for r in results)
    if reason == "issue_persists":
        detail_mode = "summary"
    elif reason in ("issue_detected", "restart_detected"):
        detail_mode = "auto"
    elif has_fail:
        detail_mode = "auto"
    else:
        detail_mode = "summary"

    if not has_fail and detail_mode == "summary":
        return build_ok_heartbeat_text(results, run_id, host)

    return build_slack_report(
        results,
        run_id,
        host,
        title="Healthcheck",
        subtitle="Issue detected." if has_fail else "Status update.",
        summary_kind="issue" if has_fail else "ok",
        detail_mode=detail_mode,
    )


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
                append_log(
                    f"[{now_local_str()}] run_id={run_id} daily_report=failed err={repr(exc)}"
                )
        else:
            append_log(
                f"[{now_local_str()}] run_id={run_id} daily_report=skipped (empty)"
            )

    results = [check_endpoint(ep, state) for ep in ENDPOINTS]

    for r in results:
        update_endpoint_state(state, r)

    has_issue_now = any(not r.ok for r in results)

    # Compare against previous run's g["has_issue"] (still from load_state). If we set
    # g["has_issue"] before this call, prev_has_issue always equals has_issue_now and
    # issue_detected / issue_resolved never fire correctly.
    notify, reason = should_notify(results, state, current_time)

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

    restart_reason = "restart_detected" if is_restart else reason
    append_log(
        f"[{now_local_str()}] run_id={run_id} notify={notify or is_restart} "
        f"reason={restart_reason}"
    )
    save_state(state)

    if is_restart:
        send_restart_slack_alerts(
            state,
            results,
            run_id=run_id,
            host=host,
            current_time=current_time,
            last_check_time=last_check_time,
            has_issue_now=has_issue_now,
        )
        append_log(f"[{now_local_str()}] run_id={run_id} end (restart)")
        return

    maybe_run_ok_heartbeat_slack(
        state,
        results,
        run_id=run_id,
        host=host,
        current_time=current_time,
        notify=notify,
        has_issue_now=has_issue_now,
    )

    if not notify:
        append_log(f"[{now_local_str()}] run_id={run_id} end (no notify)")
        return

    if reason == "issue_resolved":
        text = build_resolved_text(results, run_id, host)
        cert_warn_hit = any(result_has_cert_warning(r) for r in results)
    else:
        text, cert_warn_hit = build_slack_text(results, run_id, host, reason=reason)

    try:
        slack_post_text_batched(
            build_slack_prefix(results, cert_warn_hit, include_issue_cc=True) + text,
            attach_image=bool(SLACK_IMAGE_URL and SLACK_POST_MODE == "json"),
        )
        append_log(f"[{now_local_str()}] run_id={run_id} slack=sent")
        if has_issue_now:
            mark_issue_alert_sent(g, current_time)
        else:
            g["last_ok_heartbeat_hour"] = ok_heartbeat_hour_key()
            g["last_ok_heartbeat_sent_at"] = current_time
        save_state(state)
    except Exception as exc:
        append_log(f"[{now_local_str()}] run_id={run_id} slack=failed err={repr(exc)}")

    append_log(f"[{now_local_str()}] run_id={run_id} end")


if __name__ == "__main__":
    main()
