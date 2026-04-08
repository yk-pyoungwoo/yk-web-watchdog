#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import socket
import subprocess
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


# =========================================================
# Environment helpers
# =========================================================
def env_str(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def env_int(key: str, default: int) -> int:
    raw = env_str(key, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{key} must be int, got: {raw!r}") from exc


def env_float(key: str, default: float) -> float:
    raw = env_str(key, str(default))
    try:
        return float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{key} must be float, got: {raw!r}") from exc


def env_csv(key: str, default: str = "") -> List[str]:
    raw = env_str(key, default)
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def env_bool(key: str, default: bool = False) -> bool:
    raw = env_str(key, "1" if default else "0").lower()
    return raw in {"1", "true", "yes", "y", "on"}


# =========================================================
# Configuration
# =========================================================
SLACK_WEBHOOK_URL = env_str("SLACK_WEBHOOK_URL")
if not SLACK_WEBHOOK_URL:
    raise RuntimeError("SLACK_WEBHOOK_URL is required")

SLACK_USERNAME = env_str("SLACK_USERNAME", "YK Web Watchdog")
SLACK_ICON_EMOJI = env_str("SLACK_ICON_EMOJI", ":dog:")
SLACK_POST_MODE = env_str("SLACK_POST_MODE", "json").lower()
if SLACK_POST_MODE not in {"json", "payload"}:
    raise RuntimeError("SLACK_POST_MODE must be 'json' or 'payload'")

ENABLE_MENTIONS = env_bool("ENABLE_MENTIONS", True)
ALWAYS_MENTION = env_csv("ALWAYS_MENTION", "@박평우")
CHANNEL_MENTION_ON_FAIL = env_bool("CHANNEL_MENTION_ON_FAIL", True)
SLACK_IMAGE_URL = env_str("SLACK_IMAGE_URL", "")
SLACK_EMOJI_ROTATION = env_bool("SLACK_EMOJI_ROTATION", True)

TARGETS_RAW = env_str("TARGETS")
if not TARGETS_RAW:
    raise RuntimeError("TARGETS is required")
TARGETS = [u.strip() for u in TARGETS_RAW.split(",") if u.strip()]

HC_TIMEOUT_SEC = env_float("HC_TIMEOUT_SEC", 5.0)
HC_SLOW_MS = env_int("HC_SLOW_MS", 1500)

REPORT_MODE = env_str("REPORT_MODE", "always").lower()
if REPORT_MODE not in {"always", "on_change", "on_error"}:
    raise RuntimeError("REPORT_MODE must be 'always', 'on_change', or 'on_error'")

DAILY_REPORT_TIME = env_str("DAILY_REPORT_TIME", "09:00")
DAILY_REPORT_ENABLED = env_bool("DAILY_REPORT_ENABLED", True)

STATE_FILE = env_str("STATE_FILE", "./state.json")
LOG_DIR = env_str("LOG_DIR", "./logs")
SLACK_MAX_CHARS = env_int("SLACK_MAX_CHARS", 3500)

HEADER_KEYS = [
    h.lower()
    for h in env_csv(
        "HEADER_KEYS",
        "strict-transport-security,cache-control,etag,last-modified,server,content-type,date,cf-cache-status,cf-ray,x-cache,via",
    )
]

CERT_WARN_DAYS = env_int("CERT_WARN_DAYS", 30)
CERT_ALERT_DAYS = env_int("CERT_ALERT_DAYS", 7)
CERT_MAX_SAN_ITEMS = env_int("CERT_MAX_SAN_ITEMS", 15)
MAX_REDIRECTS = env_int("MAX_REDIRECTS", 10)
MAX_HISTORY = env_int("MAX_HISTORY", 480)
CLEANUP_DAYS = env_int("CLEANUP_DAYS", 7)


# =========================================================
# Models
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
    raw: Optional[Dict[str, Any]]
    headers: Optional[Dict[str, str]]
    ssl: Optional[SslInfo]


# =========================================================
# Time / file helpers
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


def log_file_path() -> str:
    ensure_dir(LOG_DIR)
    return os.path.join(LOG_DIR, f"{today_ymd()}.log")


def append_log(line: str) -> None:
    with open(log_file_path(), "a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")


# =========================================================
# State helpers
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


def add_check_history(state: Dict[str, Any], results: List[CurlMetrics], has_issue: bool) -> None:
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
                r.url: {"ok": r.ok, "http_code": r.http_code, "total_ms": r.total_ms}
                for r in results
            },
        }
    )
    if len(history) > MAX_HISTORY:
        del history[:-MAX_HISTORY]


# =========================================================
# Cleanup helpers
# =========================================================
def cleanup_old_files_and_state() -> None:
    cutoff_dt = now_local() - timedelta(days=CLEANUP_DAYS)

    # log cleanup
    try:
        if os.path.isdir(LOG_DIR):
            for filename in os.listdir(LOG_DIR):
                if not filename.endswith(".log"):
                    continue
                date_str = filename[:-4]
                try:
                    file_dt = datetime.strptime(date_str, "%Y-%m-%d")
                except ValueError:
                    continue
                if file_dt < cutoff_dt:
                    try:
                        os.remove(os.path.join(LOG_DIR, filename))
                        append_log(f"[{now_local_str()}] cleanup: removed old log file {filename}")
                    except OSError as exc:
                        append_log(f"[{now_local_str()}] cleanup: failed to remove {filename}: {repr(exc)}")
    except Exception as exc:
        append_log(f"[{now_local_str()}] cleanup: log cleanup error: {repr(exc)}")

    # state cleanup
    try:
        state = load_state()
        g = get_global_state(state)
        history = g.get("_check_history", [])
        if isinstance(history, list):
            filtered = []
            removed = 0
            for entry in history:
                ts = entry.get("ts", "")
                try:
                    dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    if dt >= cutoff_dt:
                        filtered.append(entry)
                    else:
                        removed += 1
                except Exception:
                    filtered.append(entry)

            if removed > 0:
                g["_check_history"] = filtered
                save_state(state)
                append_log(f"[{now_local_str()}] cleanup: removed {removed} old history entries")
    except Exception as exc:
        append_log(f"[{now_local_str()}] cleanup: state cleanup error: {repr(exc)}")


# =========================================================
# Daily / restart report helpers
# =========================================================
def parse_time_str(time_str: str) -> Tuple[int, int]:
    try:
        hour_s, minute_s = time_str.split(":", 1)
        hour = int(hour_s)
        minute = int(minute_s)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError
        return hour, minute
    except Exception:
        return 9, 0


def should_send_daily_report(state: Dict[str, Any]) -> bool:
    if not DAILY_REPORT_ENABLED:
        return False

    g = get_global_state(state)
    last_report_date = g.get("last_daily_report_date", "")
    if last_report_date == today_ymd():
        return False

    report_hour, report_minute = parse_time_str(DAILY_REPORT_TIME)
    now = now_local()
    return now.hour == report_hour and report_minute <= now.minute < report_minute + 3


def build_restart_report(state: Dict[str, Any], last_run_time: str, current_time: str) -> Optional[str]:
    g = get_global_state(state)
    history = g.get("_check_history", [])
    if not isinstance(history, list) or not history:
        return None

    try:
        last_dt = datetime.strptime(last_run_time, "%Y-%m-%d %H:%M:%S")
        current_dt = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
        filtered_entries = []
        for entry in history:
            ts = entry.get("ts", "")
            try:
                entry_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                if last_dt < entry_dt < current_dt:
                    filtered_entries.append(entry)
            except Exception:
                continue
    except Exception:
        filtered_entries = history[-10:]

    if not filtered_entries:
        return None

    total_checks = len(filtered_entries)
    failed_checks = sum(1 for e in filtered_entries if e.get("has_issue", False))
    success_checks = total_checks - failed_checks

    issue_periods: List[Tuple[str, str]] = []
    current_issue_start: Optional[str] = None

    for entry in filtered_entries:
        ts = entry.get("ts", "")
        has_issue = bool(entry.get("has_issue", False))
        if has_issue:
            if current_issue_start is None:
                current_issue_start = ts
        else:
            if current_issue_start is not None:
                issue_periods.append((current_issue_start, ts))
                current_issue_start = None

    if current_issue_start is not None:
        issue_periods.append((current_issue_start, "재기동 시점까지 진행 중"))

    lines = [
        "🔄 *재기동 리포트*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"⏸️  마지막 실행: `{last_run_time}`",
        f"▶️  재기동 시간: `{current_time}`",
        f"🔍 기간 내 검사 횟수: `{total_checks}`회",
        f"✅ 성공: `{success_checks}`회 ({(success_checks * 100 // total_checks) if total_checks else 0}%)",
        f"❌ 실패: `{failed_checks}`회 ({(failed_checks * 100 // total_checks) if total_checks else 0}%)",
        "",
    ]

    if issue_periods:
        lines.append("⚠️ *문제 발생 시간대:*")
        for start, end in issue_periods:
            lines.append(f"   • `{start}` ~ `{end}`")
    else:
        lines.append("✅ *기간 내 문제 없음*")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return "\n".join(lines)


def build_daily_report(state: Dict[str, Any]) -> Optional[str]:
    g = get_global_state(state)
    history = g.get("_check_history", [])
    if not isinstance(history, list) or not history:
        return None

    yesterday = (now_local() - timedelta(days=1)).strftime("%Y-%m-%d")
    entries = [e for e in history if str(e.get("ts", "")).startswith(yesterday)]
    if not entries:
        return None

    total_checks = len(entries)
    failed_checks = sum(1 for e in entries if e.get("has_issue", False))
    success_checks = total_checks - failed_checks

    issue_periods: List[Tuple[str, str]] = []
    current_issue_start: Optional[str] = None

    for entry in entries:
        ts = entry.get("ts", "")
        has_issue = bool(entry.get("has_issue", False))
        if has_issue:
            if current_issue_start is None:
                current_issue_start = ts
        else:
            if current_issue_start is not None:
                issue_periods.append((current_issue_start, ts))
                current_issue_start = None

    if current_issue_start is not None:
        issue_periods.append((current_issue_start, "진행 중"))

    lines = [
        "📊 *일일 리포트*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📅 날짜: `{yesterday}`",
        f"🔍 총 검사 횟수: `{total_checks}`회",
        f"✅ 성공: `{success_checks}`회 ({(success_checks * 100 // total_checks) if total_checks else 0}%)",
        f"❌ 실패: `{failed_checks}`회 ({(failed_checks * 100 // total_checks) if total_checks else 0}%)",
        "",
    ]

    if issue_periods:
        lines.append("⚠️ *문제 발생 시간대:*")
        for start, end in issue_periods:
            lines.append(f"   • `{start}` ~ `{end}`")
    else:
        lines.append("✅ *전날 문제 없음*")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return "\n".join(lines)


# =========================================================
# Command helpers
# =========================================================
def run_cmd(cmd: List[str], timeout_sec: float) -> Tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def safe_int_ms(sec_str: str) -> Optional[int]:
    try:
        return int(float(sec_str) * 1000)
    except Exception:
        return None


# =========================================================
# DNS / header / redirect helpers
# =========================================================
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


def parse_headers_from_curl_dump(raw_header_text: str) -> Dict[str, str]:
    text = raw_header_text.replace("\r\n", "\n").strip()
    if not text:
        return {}

    blocks = text.split("\n\n")
    last = blocks[-1]
    lines = [ln.strip() for ln in last.split("\n") if ln.strip()]
    if not lines:
        return {}

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def normalize_url(base: str, location: str) -> str:
    return urllib.parse.urljoin(base, location)


def extract_redirect_chain_from_header_dump(start_url: str, raw_header_text: str) -> List[str]:
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
        for line in lines[1:]:
            if line.lower().startswith("location:"):
                loc = line.split(":", 1)[1].strip()
                break

        if loc:
            nxt = normalize_url(current, loc)
            chain.append(nxt)
            current = nxt

        if len(chain) >= MAX_REDIRECTS + 1:
            break

    deduped: List[str] = []
    for url in chain:
        if not deduped or deduped[-1] != url:
            deduped.append(url)
    return deduped


def fetch_redirect_chain(url: str) -> Tuple[List[str], Optional[str]]:
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
        str(HC_TIMEOUT_SEC),
        url,
    ]
    try:
        rc, out, err = run_cmd(cmd, HC_TIMEOUT_SEC + 3.0)
        if rc != 0:
            return [url], err.strip() or f"curl redirect rc={rc}"
        return extract_redirect_chain_from_header_dump(url, out), None
    except Exception as exc:
        return [url], f"exception={repr(exc)}"


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
        str(HC_TIMEOUT_SEC),
        url,
    ]
    try:
        rc, out, err = run_cmd(cmd, HC_TIMEOUT_SEC + 3.0)
        if rc != 0:
            return {"_error": err.strip() or f"curl -I rc={rc}"}
        all_headers = parse_headers_from_curl_dump(out)
        selected: Dict[str, str] = {}
        for key in HEADER_KEYS:
            if key in all_headers:
                selected[key] = all_headers[key]
        return selected if selected else all_headers
    except Exception as exc:
        return {"_error": f"exception={repr(exc)}"}


# =========================================================
# SSL helpers
# =========================================================
def parse_openssl_notafter_to_days_left(notafter: str) -> Optional[int]:
    try:
        value = notafter.replace("  ", " ").strip()
        if value.endswith(" GMT"):
            value = value[:-4].strip()
        dt = datetime.strptime(value, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
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
        if p.startswith(("O =", "CN =", "O=", "CN=")):
            keep.append(p.replace(" = ", "=").replace(" =", "=").replace("= ", "="))

    if keep:
        joined = ", ".join(keep)
        return joined if len(joined) <= 180 else joined[:180] + "…"

    return dn[:180] + ("…" if len(dn) > 180 else "")


def ssl_info(host: str) -> SslInfo:
    try:
        s_client = [
            "openssl",
            "s_client",
            "-servername",
            host,
            "-connect",
            f"{host}:443",
            "-showcerts",
        ]
        x509 = [
            "openssl",
            "x509",
            "-noout",
            "-enddate",
            "-issuer",
            "-subject",
            "-ext",
            "subjectAltName",
        ]

        p1 = subprocess.Popen(
            s_client,
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
            x509,
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

        expires_in_days = parse_openssl_notafter_to_days_left(notafter) if notafter else None

        covers: Optional[bool] = None
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


# =========================================================
# Health check
# =========================================================
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
        "curl",
        "-sS",
        "-L",
        "-o",
        "/dev/null",
        "--max-time",
        str(HC_TIMEOUT_SEC),
        "--connect-timeout",
        str(HC_TIMEOUT_SEC),
        "-w",
        write_out,
        url,
    ]

    start_ts = time.time()

    raw = None
    http_code = None
    total_ms = None
    dns_ms = None
    connect_ms = None
    tls_ms = None
    ttfb_ms = None
    remote_ip = None
    redirect_url = None
    err = None
    ok = False

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.time() - start_ts

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
            redirect_url = str(raw.get("redirect_url", "")).strip() or None
        except Exception:
            err = f"Failed to parse curl write-out: {stdout[:250]}"

        ok = proc.returncode == 0 and http_code is not None and 200 <= http_code < 400

        if proc.returncode != 0 or not ok:
            base = f"curl_rc={proc.returncode}, stderr={stderr or 'none'}"
            err = f"{err} | {base}" if err else base

        if total_ms is None:
            total_ms = int(elapsed * 1000)

    except Exception as exc:
        err = f"exception={repr(exc)}"
        ok = False

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.split("@")[-1].split(":")[0] if parsed.netloc else ""

    headers = fetch_selected_headers(url)
    redirect_chain, redirect_err = fetch_redirect_chain(url)
    if redirect_err:
        err = f"{err} | redirect_chain_err={redirect_err}" if err else f"redirect_chain_err={redirect_err}"

    ssl_obj = ssl_info(host) if parsed.scheme == "https" and host else None

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
        redirect_chain=redirect_chain,
        err=err,
        raw=raw,
        headers=headers,
        ssl=ssl_obj,
    )


# =========================================================
# Notify decision
# =========================================================
def should_notify(results: List[CurlMetrics], state: Dict[str, Any]) -> Tuple[bool, str]:
    if REPORT_MODE == "always":
        return True, "always"

    g = get_global_state(state)
    has_issue_now = any(not r.ok for r in results)
    prev_has_issue = bool(g.get("has_issue", False))

    for r in results:
        state[r.url] = {
            "ok": r.ok,
            "http_code": r.http_code,
            "total_ms": r.total_ms,
            "ts": now_local_str(),
        }

    add_check_history(state, results, has_issue_now)
    g["has_issue"] = has_issue_now
    g["last_check"] = now_local_str()

    if REPORT_MODE == "on_error":
        if has_issue_now and not prev_has_issue:
            return True, "issue_detected"
        if has_issue_now and prev_has_issue:
            return True, "issue_persists"
        if not has_issue_now and prev_has_issue:
            return True, "issue_resolved"
        return False, "all_ok"

    # on_change
    changes: List[str] = []
    for r in results:
        prev_ok = state.get(r.url, {}).get("ok", None)
        if prev_ok is None:
            changes.append(f"INIT {r.url} => {'UP' if r.ok else 'DOWN'}")
        elif bool(prev_ok) != bool(r.ok):
            changes.append(f"CHANGE {r.url}: {'UP' if prev_ok else 'DOWN'} -> {'UP' if r.ok else 'DOWN'}")

    return len(changes) > 0, "; ".join(changes) if changes else "no_change"


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


def short_url(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path or '/'}"
    except Exception:
        return url


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
            display_key = {
                "content-type": "type",
                "cache-control": "cache",
                "strict-transport-security": "hsts",
            }.get(k, k)
            parts.append(f"{display_key}={h[k]}")
    if not parts:
        for i, (k, v) in enumerate(h.items()):
            if i >= 6:
                break
            parts.append(f"{k}={v}")
    return " | ".join(parts)


def build_slack_text(results: List[CurlMetrics], run_id: str, host: str) -> Tuple[str, bool]:
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
        is_slow = r.ok and r.total_ms is not None and r.total_ms >= HC_SLOW_MS

        domain_header = f"{'✅' if r.ok else '❌'} *{domain}*"
        if is_slow:
            domain_header += " 🐢 *SLOW*"

        lines.append(domain_header)
        lines.append(
            f"   📊 Status: `{status_txt}` | ⏱️ Total: `{r.total_ms}ms` | 🌐 IP: `{r.remote_ip or '-'}`"
        )

        redirect_str = chain_to_str(r.redirect_chain)
        if redirect_str != "-":
            lines.append(f"   🔀 Redirects: `{redirect_str}`")

        dns = dns_lookup(domain)
        dns_a = ",".join(dns["A"]) if dns["A"] else "-"
        dns_aaaa = ",".join(dns["AAAA"]) if dns["AAAA"] else "-"
        lines.append(f"   🌍 DNS: A=`{dns_a}` AAAA=`{dns_aaaa}`")

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

        if parsed.scheme == "https" and r.ssl:
            ssl_parts = []
            if r.ssl.notafter:
                ssl_parts.append(f"Expires: `{r.ssl.notafter}`")
            if r.ssl.expires_in_days is not None:
                days_left = r.ssl.expires_in_days
                if days_left < 0:
                    ssl_parts.append(f"⚠️ *EXPIRED* ({abs(days_left)}d ago)")
                    cert_warn_hit = True
                elif days_left <= CERT_ALERT_DAYS:
                    ssl_parts.append(f"🚨 *{days_left}d left*")
                    cert_warn_hit = True
                elif days_left <= CERT_WARN_DAYS:
                    ssl_parts.append(f"⚠️ *{days_left}d left*")
                    cert_warn_hit = True
                else:
                    ssl_parts.append(f"✅ {days_left}d left")
            if ssl_parts:
                lines.append(f"   🔒 SSL: {' | '.join(ssl_parts)}")
            if r.ssl.subject:
                lines.append(f"   📜 Subject: `{r.ssl.subject}`")
            if r.ssl.issuer:
                lines.append(f"   🏢 Issuer: `{r.ssl.issuer}`")
            if r.ssl.san:
                if r.ssl.san_covers_host is True:
                    cover_text = " (✅ covers host)"
                elif r.ssl.san_covers_host is False:
                    cover_text = " (❌ does not cover host)"
                else:
                    cover_text = ""
                lines.append(f"   📋 SAN{cover_text}: `{', '.join(r.ssl.san)}`")

        header_text = headers_pretty(r.headers or {})
        if header_text and header_text != "-":
            if len(header_text) > 200:
                header_text = header_text[:200] + "..."
            lines.append(f"   📨 Headers: `{header_text}`")

        if r.err:
            short_err = r.err[:200] + ("..." if len(r.err) > 200 else "")
            lines.append(f"   ⚠️ Error: `{short_err}`")

        lines.append("")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    text = "\n".join(lines).strip()

    if len(text) > SLACK_MAX_CHARS:
        text = text[: SLACK_MAX_CHARS - 250] + "\n\n⚠️ *메시지가 잘렸습니다*"

    return text, cert_warn_hit


def build_resolved_text(results: List[CurlMetrics], run_id: str, host: str) -> str:
    lines = [
        "✅ *All Services Recovered*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🆔 `{run_id}` | 🖥️ `{host}` | 🕐 `{now_local_str()}`",
        "",
        "🎉 *All monitored services are now operating normally.*",
        "",
    ]

    for r in results:
        parsed = urllib.parse.urlparse(r.url)
        domain = parsed.netloc or r.url
        status_txt = str(r.http_code) if r.http_code is not None else "OK"
        total_txt = f"{r.total_ms}ms" if r.total_ms is not None else "-"
        lines.append(f"🟢 `{domain}` - Status: `{status_txt}` | Time: `{total_txt}`")

    return "\n".join(lines)


def build_slack_prefix(results: List[CurlMetrics], cert_warn_hit: bool) -> str:
    lines = [
        "🐕 *YK Watchdog*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ]

    if ENABLE_MENTIONS and ALWAYS_MENTION:
        lines.append(f"mentions: {' '.join(ALWAYS_MENTION)}")

    if ENABLE_MENTIONS and CHANNEL_MENTION_ON_FAIL:
        if any(not r.ok for r in results) or cert_warn_hit:
            lines.append("📢 <!channel>")

    return "\n".join(lines) + "\n\n"


# =========================================================
# Restart detection
# =========================================================
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
        daily_report = build_daily_report(state)
        if daily_report:
            payload = {
                "text": build_slack_prefix([], False) + daily_report,
                "username": SLACK_USERNAME,
                "icon_emoji": get_rotating_emoji(),
            }
            try:
                slack_post(payload)
                get_global_state(state)["last_daily_report_date"] = today_ymd()
                append_log(f"[{now_local_str()}] run_id={run_id} daily_report=sent")
            except Exception as exc:
                append_log(f"[{now_local_str()}] run_id={run_id} daily_report=failed err={repr(exc)}")

    results = [run_curl(url) for url in TARGETS]

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
                    "targets": TARGETS,
                    "header_keys": HEADER_KEYS,
                    "cert_warn_days": CERT_WARN_DAYS,
                    "cert_alert_days": CERT_ALERT_DAYS,
                    "cert_max_san_items": CERT_MAX_SAN_ITEMS,
                    "max_redirects": MAX_REDIRECTS,
                },
                "results": [asdict(r) for r in results],
            },
            ensure_ascii=False,
        )
    )

    notify, reason = should_notify(results, state)
    if is_restart:
        notify = True
        reason = "restart_detected"

    append_log(f"[{now_local_str()}] run_id={run_id} notify={notify} reason={reason}")

    g = get_global_state(state)
    g["last_run_id"] = run_id
    save_state(state)

    if not notify:
        append_log(f"[{now_local_str()}] run_id={run_id} end (no notify)")
        return

    if reason == "issue_resolved":
        text = build_resolved_text(results, run_id, host)
        cert_warn_hit = False
    else:
        text, cert_warn_hit = build_slack_text(results, run_id, host)

    if is_restart and last_check_time:
        restart_report = build_restart_report(state, last_check_time, current_time)
        if restart_report:
            payload_restart = {
                "text": build_slack_prefix([], False) + restart_report,
                "username": SLACK_USERNAME,
                "icon_emoji": get_rotating_emoji(),
            }
            try:
                slack_post(payload_restart)
                append_log(f"[{now_local_str()}] run_id={run_id} restart_report=sent")
            except Exception as exc:
                append_log(f"[{now_local_str()}] run_id={run_id} restart_report=failed err={repr(exc)}")

        text = (
            "🔄 *재기동 감지 - 현재 상태*\n"
            f"⏸️  마지막 실행: `{last_check_time}`\n"
            f"▶️  재기동 시간: `{current_time}`\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            + text
        )

    payload = {
        "text": build_slack_prefix(results, cert_warn_hit) + text,
        "username": SLACK_USERNAME,
        "icon_emoji": get_rotating_emoji(),
    }

    if SLACK_IMAGE_URL and SLACK_POST_MODE == "json":
        payload["attachments"] = [
            {
                "image_url": SLACK_IMAGE_URL,
                "fallback": "YK Watchdog Status Check",
            }
        ]

    try:
        slack_post(payload)
        append_log(f"[{now_local_str()}] run_id={run_id} slack=sent")
    except Exception as exc:
        append_log(f"[{now_local_str()}] run_id={run_id} slack=failed err={repr(exc)}")

    append_log(f"[{now_local_str()}] run_id={run_id} end")


if __name__ == "__main__":
    main()