# -*- coding: utf-8 -*-


# by Futureppo

import html
import json
import os
import random
import re
import ssl
import string
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests

# mail.tm — 完全免费，无 API key，8 QPS/IP 限流
MAILTM_BASE_URL = "https://api.mail.tm"
MAILTM_DOMAIN = None              # None = 每次启动自动获取首个可用域名
_MAILTM_DOMAIN_CACHE = {"value": None}
# 全局限速：按固定间隔放行，低于官方 8 QPS 上限留余量（Semaphore 限并发不限速率会超限）
MAILTM_QPS = 6

CONSOLE_BASE_URL = "https://console.typesafe.ai"
CONSOLE_DEPLOYMENT_ID = "cc6f6dca06537cc04123caaaf50ca5a76d506a92"   

PROXY_POOL = [     
    "",
]                                

API_KEY_NAME = "1111"
ACCOUNT_COUNT = 100
CONCURRENCY = 64
MAX_RETRIES_PER_ACCOUNT = 2
MAIL_POLL_INTERVAL_SECONDS = 1.0
MAIL_POLL_MAX_WAIT_SECONDS = 30
REQUEST_TIMEOUT = 30
TLS_ECDH_CURVE = "prime256v1"    
OUTPUT_JSON_PATH = str(Path(__file__).resolve().parent / "accounts.json")
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0"
)

LOGIN_PAGE_URL = f"{CONSOLE_BASE_URL}/login"
MAGIC_LINK_RE = re.compile(
    r"https://login\.typesafe\.ai/v1/magic_links/redirect"
    r"\?public_token=(?P<public_token>[^&\s\"'<>]+)"
    r"&stytch_token_type=magic_links&token=(?P<token>[^&\s\"'<>]+)"
)
LOGIN_CACHE = {"action_id": None, "index": None, "blob": None}
LOGIN_LOCK = threading.Lock()
WRITE_LOCK = threading.Lock()


class SignupDisabled(Exception):
    """console 拒绝新开户（SELF_SERVE_DISABLED）。"""


CIRCUIT = {"open": False, "reason": None}
CIRCUIT_LOCK = threading.Lock()


def open_circuit(reason):
    with CIRCUIT_LOCK:
        if not CIRCUIT["open"]:
            CIRCUIT["open"] = True
            CIRCUIT["reason"] = reason
            log(f"熔断：注册通道关闭 — {reason}")


class RateLimiter:
    """线程安全间隔节流器：按固定间隔放行，平滑全局 QPS。"""

    def __init__(self, qps):
        self.interval = 1.0 / max(float(qps), 0.1)
        self._lock = threading.Lock()
        self._next_at = 0.0

    def acquire(self):
        with self._lock:
            now = time.monotonic()
            wait = self._next_at - now
            self._next_at = max(now, self._next_at) + self.interval
        if wait > 0:
            time.sleep(wait)


_MAILTM_RATE = RateLimiter(MAILTM_QPS)


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


class TlsAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, ctx, **kw):
        self._ctx = ctx
        super().__init__(**kw)

    def init_poolmanager(self, *a, **kw):
        kw["ssl_context"] = self._ctx
        return super().init_poolmanager(*a, **kw)

    def proxy_manager_for(self, proxy, **kw):
        kw["ssl_context"] = self._ctx
        return super().proxy_manager_for(proxy, **kw)


class ProxyPool:
    def __init__(self, proxies):
        self.proxies = [p for p in proxies if p]
        self.index = 0
        self.lock = threading.Lock()

    def acquire(self):
        if not self.proxies:
            return None
        with self.lock:
            proxy = self.proxies[self.index % len(self.proxies)]
            self.index += 1
            return proxy


PROXIES = ProxyPool(PROXY_POOL)


def build_session(proxy=None):
    ctx = ssl.create_default_context()
    try:
        ctx.set_ecdh_curve(TLS_ECDH_CURVE)
    except Exception:
        pass
    s = requests.Session()
    s.mount("https://", TlsAdapter(ctx, max_retries=requests.adapters.Retry(total=2, backoff_factor=1, status_forcelist=[502, 503, 504])))
    s.headers.update({"User-Agent": USER_AGENT, "accept-language": "zh-CN,zh;q=0.9,en;q=0.7"})
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def _mailtm_headers(token=None):
    h = {"Content-Type": "application/json", "accept": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _mailtm_request(s, method, path, *, token=None, json_body=None):
    """带全局限速与 429 指数退避的 mail.tm 请求。"""
    last_err = None
    for attempt in range(4):
        _MAILTM_RATE.acquire()
        url = f"{MAILTM_BASE_URL}{path}"
        try:
            if method == "GET":
                r = s.get(url, headers=_mailtm_headers(token), timeout=REQUEST_TIMEOUT)
            else:
                r = s.post(url, headers=_mailtm_headers(token), json=json_body, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            last_err = exc
            time.sleep(1.5 ** attempt)
            continue
        if r.status_code == 429:
            try:
                retry_after = float(r.headers.get("Retry-After", ""))
            except ValueError:
                retry_after = 1.5 ** attempt
            time.sleep(max(retry_after, 0.5))
            continue
        r.raise_for_status()
        return r.json()
    raise RuntimeError(f"mail.tm 限流重试耗尽: {path} last={last_err}")


def _get_mailtm_domain(s):
    """进程内缓存域名，只请求一次。"""
    if _MAILTM_DOMAIN_CACHE["value"]:
        return _MAILTM_DOMAIN_CACHE["value"]
    if MAILTM_DOMAIN:
        _MAILTM_DOMAIN_CACHE["value"] = MAILTM_DOMAIN
        return MAILTM_DOMAIN
    data = _mailtm_request(s, "GET", "/domains")
    if isinstance(data, list):
        members = data
    else:
        members = data.get("hydra:member") or data.get("member") or []
    members = [m for m in members if m.get("isActive", True)]
    if not members:
        raise RuntimeError("mail.tm 未返回可用域名")
    domain = members[0]["domain"]
    _MAILTM_DOMAIN_CACHE["value"] = domain
    return domain


def create_mailbox(s):
    """创建 mail.tm 账号并获取 Bearer token。"""
    domain = _get_mailtm_domain(s)
    local = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    address = f"{local}@{domain}"
    password = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    account = _mailtm_request(s, "POST", "/accounts", json_body={"address": address, "password": password})
    token_data = _mailtm_request(s, "POST", "/token", json_body={"address": address, "password": password})
    return {
        "id": account["id"],
        "full_address": address,
        "token": token_data["token"],
        "domain": domain,
    }


def wait_magic_link(s, mailbox, after_iso):
    """
    轮询 mail.tm 收件箱，提取 typesafe magic link。
    mailbox: create_mailbox 返回的 dict（含 id/full_address/token）
    """
    bearer = mailbox["token"]
    deadline = time.time() + MAIL_POLL_MAX_WAIT_SECONDS
    while True:
        data = _mailtm_request(s, "GET", "/messages", token=bearer)
        items = data if isinstance(data, list) else (data.get("hydra:member") or data.get("member") or [])
        for item in items:
            created = item.get("createdAt") or ""
            if after_iso and created.replace("Z", "+00:00") <= after_iso:
                continue
            frm = item.get("from") or {}
            tag = ((frm.get("address") or "") + (item.get("subject") or "")).lower()
            if "typesafe" not in tag:
                continue
            detail = _mailtm_request(s, "GET", f"/messages/{item['id']}", token=bearer)
            text = detail.get("text") or ""
            html_parts = detail.get("html") or []
            if isinstance(html_parts, list):
                html_joined = "\n".join(html_parts)
            else:
                html_joined = str(html_parts)
            hay = "\n".join([text, html_joined])
            m = MAGIC_LINK_RE.search(hay)
            if m:
                return {
                    "email_id": detail.get("id"),
                    "sender": (frm.get("address") or ""),
                    "subject": detail.get("subject"),
                    "received_at": detail.get("createdAt"),
                    "public_token": m.group("public_token"),
                    "token": m.group("token"),
                    "magic_link": m.group(0),
                }
        if time.time() >= deadline:
            raise TimeoutError(f"等待 magic link 邮件超时（{MAIL_POLL_MAX_WAIT_SECONDS}s）")
        time.sleep(MAIL_POLL_INTERVAL_SECONDS)


def login_action(s, refresh=False):
    if not refresh:
        with LOGIN_LOCK:
            if LOGIN_CACHE["blob"]:
                return dict(LOGIN_CACHE)
    with LOGIN_LOCK:
        if not refresh and LOGIN_CACHE["blob"]:
            return dict(LOGIN_CACHE)
        page = s.get(LOGIN_PAGE_URL, headers={"accept": "text/html,application/xhtml+xml"}, timeout=REQUEST_TIMEOUT).text
        dpl = re.search(r"dpl=([0-9a-f]{20,})", page)
        if dpl and dpl.group(1) != CONSOLE_DEPLOYMENT_ID:
            log(f"控制台部署更新 {CONSOLE_DEPLOYMENT_ID} -> {dpl.group(1)}")
            globals()["CONSOLE_DEPLOYMENT_ID"] = dpl.group(1)
        pos = page.find('type="email"')
        indexes = re.findall(r"\\?\$ACTION_(\d+):0", page[:pos])
        index = indexes[-1]
        ref = json.loads(html.unescape(re.search(r'\\?\$ACTION_%s:0" value="([^"]+)"' % index, page).group(1)))
        blob = re.search(r'\\?\$ACTION_%s:2" value="([^"]+)"' % index, page)
        if not blob:
            raise RuntimeError("登录页未解析到加密 action 参数，请重新抓包更新脚本")
        LOGIN_CACHE.update({"action_id": ref["id"], "index": index, "blob": html.unescape(blob.group(1))})
        return dict(LOGIN_CACHE)


def send_magic_link(s, email):
    for refresh in (False, True):
        action = login_action(s, refresh=refresh)
        b = "----WebKitFormBoundary" + uuid.uuid4().hex[:16]
        idx = action["index"]
        body = (
            f'--{b}\r\nContent-Disposition: form-data; name="1"\r\n\r\n{action["blob"]}\r\n'
            f'--{b}\r\nContent-Disposition: form-data; name="_{idx}_email"\r\n\r\n{email}\r\n'
            f'--{b}\r\nContent-Disposition: form-data; name="0"\r\n\r\n["$@1","$K{idx}"]\r\n'
            f"--{b}--\r\n"
        ).encode()
        r = s.post(
            LOGIN_PAGE_URL, data=body, timeout=REQUEST_TIMEOUT,
            headers={
                "content-type": f"multipart/form-data; boundary={b}", "next-action": action["action_id"],
                "accept": "text/x-component", "origin": CONSOLE_BASE_URL, "referer": LOGIN_PAGE_URL,
                "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty",
            },
        )
        redirect = r.headers.get("x-action-redirect", "")
        if r.status_code == 200 and "sent=true" in redirect:
            return {"action_id": action["action_id"], "form_index": idx, "x_action_redirect": redirect}
    raise RuntimeError(f"发送 magic link 失败：HTTP {r.status_code} redirect={redirect!r}")


def auth_callback(s, token):
    r = s.post(
        f"{CONSOLE_BASE_URL}/api/auth/callback",
        json={"token": token, "tokenType": "magic_links", "preferredOrgId": None},
        headers={
            "content-type": "application/json", "accept": "*/*", "origin": CONSOLE_BASE_URL,
            "referer": f"{CONSOLE_BASE_URL}/auth/callback?stytch_token_type=magic_links&token={token}",
            "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty",
        },
        timeout=REQUEST_TIMEOUT,
    )
    if r.status_code == 403 and "SELF_SERVE_DISABLED" in r.text:
        open_circuit("SELF_SERVE_DISABLED：New signups are temporarily disabled")
        raise SignupDisabled(r.text[:200])
    if r.status_code >= 400:
        raise RuntimeError(f"auth callback HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


def create_api_key(s, name):
    r = s.post(
        f"{CONSOLE_BASE_URL}/api/api-keys",
        json={"name": name},
        headers={
            "content-type": "application/json", "accept": "*/*", "origin": CONSOLE_BASE_URL,
            "referer": f"{CONSOLE_BASE_URL}/keys", "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors", "sec-fetch-dest": "empty",
        },
        timeout=REQUEST_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def save_account(record):
    with WRITE_LOCK:
        path = Path(OUTPUT_JSON_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        accounts = []
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                accounts = data if isinstance(data, list) else data.get("accounts", [])
            except (json.JSONDecodeError, OSError):
                accounts = []
        accounts.append(record)
        for i, item in enumerate(accounts, 1):
            item["index"] = i
        payload = json.dumps(accounts, ensure_ascii=False, indent=2)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(payload, encoding="utf-8")
        for attempt in range(4):
            try:
                os.replace(tmp, path)
                return True
            except OSError:
                time.sleep(0.1 * (attempt + 1))
        try:
            path.write_text(payload, encoding="utf-8")
            log(f"提示：{path.name} 被占用，已改为原地覆盖写入")
            return True
        except OSError as exc:
            pending = path.with_suffix(".pending.jsonl")
            with pending.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            log(f"提示：写入 accounts.json 失败（{exc}），本条已追加到 {pending.name}")
            return False


def register_one(slot):
    if CIRCUIT["open"]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return {
            "status": "blocked", "slot": slot, "proxy": "direct",
            "registered_at": now_iso, "finished_at": now_iso, "duration_seconds": 0.0,
            "error": f"circuit_open: {CIRCUIT['reason']}",
        }
    proxy = PROXIES.acquire()
    s = build_session(proxy)     
    mail = build_session()      
    started = time.time()
    rec = {
        "status": "running", "slot": slot, "proxy": proxy or "direct",
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        mailbox = create_mailbox(mail)
        rec["mailbox"] = mailbox
        rec["email"] = mailbox["full_address"]
        sent_at = datetime.now(timezone.utc).isoformat()
        rec["send_magic_link"] = send_magic_link(s, rec["email"])
        link = wait_magic_link(mail, mailbox, sent_at)
        rec["magic_link"] = link
        cb = auth_callback(s, link["token"])
        rec["callback"] = cb
        rec["user_id"] = cb.get("userId")
        rec["backend_user_id"] = cb.get("backendUserId")
        org = ((cb.get("org_memberships") or [{}])[0].get("org") or {})
        rec["organization_id"] = org.get("id") or cb.get("selectedOrgId")
        rec["organization_name"] = org.get("name")
        key = create_api_key(s, API_KEY_NAME)
        rec["api_key"] = key.get("api_key")
        rec["api_key_id"] = key.get("id")
        rec["api_key_created"] = key.get("created")
        rec["cookies"] = {c.name: c.value for c in s.cookies}
        rec["status"] = "ok"
    except SignupDisabled as exc:
        rec["status"] = "blocked"
        rec["error"] = f"SignupDisabled: {exc}"
        rec["cookies"] = {c.name: c.value for c in s.cookies}
    except Exception as exc:
        rec["status"] = "failed"
        detail = f"{type(exc).__name__}: {exc}"
        resp = getattr(exc, "response", None)
        if resp is not None:
            try:
                detail += f" body={resp.text[:200]}"
            except Exception:
                pass
        rec["error"] = detail
        rec["cookies"] = {c.name: c.value for c in s.cookies}
    finally:
        rec["finished_at"] = datetime.now(timezone.utc).isoformat()
        rec["duration_seconds"] = round(time.time() - started, 2)
    return rec


class Progress:
    def __init__(self, total):
        self.total = total
        self.done = self.ok = self.fail = 0
        self.started = time.time()
        self.lock = threading.Lock()

    def add(self, ok):
        with self.lock:
            self.done += 1
            self.ok += ok
            self.fail += not ok
            return self.render()

    def render(self):
        elapsed = time.time() - self.started
        avg = elapsed / self.done if self.done else 0
        rate = 60 / avg if avg else 0
        return (
            f"进度 {self.done}/{self.total} ({self.done * 100 // self.total}%) | ok {self.ok} fail {self.fail}"
            f" | 用时 {elapsed:.1f}s | 平均 {avg:.2f}s/个 | {rate:.1f} 个/分 | 预计剩 {avg * (self.total - self.done):.1f}s"
        )


def probe():
    """单账号全流程探测注册窗口。退出码：0=已恢复 2=仍关闭 1=其他失败。"""
    rec = register_one(0)
    if rec.get("email") or rec.get("status") == "ok":
        try:
            save_account(rec)
        except Exception:
            pass
    summary = {k: rec.get(k) for k in ("status", "error", "email", "api_key", "duration_seconds")}
    print("PROBE " + json.dumps(summary, ensure_ascii=False), flush=True)
    if rec["status"] == "ok":
        return 0
    if rec["status"] == "blocked":
        return 2
    return 1


def main():
    if "--probe" in sys.argv[1:]:
        return probe()
    log(f"开始注册 {ACCOUNT_COUNT} 个账号（并发 {CONCURRENCY}，代理池 {len(PROXIES.proxies)} 个，mail.tm 直连）-> {OUTPUT_JSON_PATH}")
    progress = Progress(ACCOUNT_COUNT)

    def run_slot(slot):
        for attempt in range(1, MAX_RETRIES_PER_ACCOUNT + 2):
            rec = register_one(slot)
            if rec["status"] in ("ok", "blocked"):
                break
        rec["attempt"] = attempt
        try:
            save_account(rec)
        except Exception as exc:
            log(f"      保存异常（已忽略，不影响继续注册）: {type(exc).__name__}: {exc}")
        line = progress.add(rec["status"] == "ok")
        via = rec.get("proxy", "direct").split("@")[-1]
        if rec["status"] == "ok":
            log(f"#{rec['index']:<3} ok   {rec['duration_seconds']:>5.2f}s  {rec['email']:<32} via {via:<24} {rec['api_key']}")
        else:
            log(f"#{rec['index']:<3} fail {rec['duration_seconds']:>5.2f}s  {rec.get('email', '-'):<32} via {via:<24} {rec.get('error', '')}")
        log(f"      {line}")
        return rec["status"] == "ok"

    workers = min(CONCURRENCY, ACCOUNT_COUNT) if ACCOUNT_COUNT > 1 else 1
    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(run_slot, i) for i in range(1, ACCOUNT_COUNT + 1)]
            results = []
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    log(f"任务异常（已忽略）: {type(exc).__name__}: {exc}")
                    results.append(False)
    else:
        results = [run_slot(i) for i in range(1, ACCOUNT_COUNT + 1)]

    total_ok = sum(results)
    log(f"结束：成功 {total_ok}/{ACCOUNT_COUNT}，总耗时 {time.time() - progress.started:.1f}s -> {OUTPUT_JSON_PATH}")
    return 0 if total_ok == ACCOUNT_COUNT else 1


if __name__ == "__main__":
    sys.exit(main())
