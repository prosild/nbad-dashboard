"""포트폴리오 스택 계정 시드: 공개 계정만 활성으로 두고 나머지 계정은 비활성으로 만든다.

공개 계정은 둘이다.
- demo(VIEWER, 읽기 전용, 비밀번호 DEMO_PASSWORD 필수).
- trial-analyst(ANALYST, 체험용 분석가, T33. 비밀번호 TRIAL_ANALYST_PASSWORD). 비어 있으면 만들지 않고 알리며,
  이미 있으면 다른 계정처럼 비활성으로 둔다(T33 이전 공개 스택과 같다). 이 계정이 바꾼 것은 sandbox-reset이 매시 정각에 되돌린다.
두 계정의 허용 캡처는 같다.

허용 캡처는 환경 변수 DEMO_CAPTURE_PATTERNS(쉼표 구분)로 정한다. 비어 있으면 cic17-*,syn1-*,lab-20261119,lab-20261122
(Kali 실습망 캡처 lab-20261119·lab-20261122만 정확한 ID로 공개하고, 시험 캡처 lab-20261201·첫 VM 실행 lab-20261118·
시험 뒤 유휴 구간 lab-20261123 같은 나머지 실습망 캡처는 시연 화면에서 숨긴다, 2026-11-21·2026-11-23 결정). 패턴이 바뀌면 관리자 API로 갱신한다.

compose.portfolio.yml의 demo-seed 서비스(zeekad-pipeline 이미지의 Python)로 실행한다. 다시 실행해도 안전하다(멱등).
1. zeekad_dashboard를 dashboard_app 계정으로 읽어 현재 상태를 확인한다. 이미 목표 상태면 아무것도 바꾸지 않고 끝낸다.
2. 바꿀 것이 있으면 가능한 단계는 앱 관리자 API(감사 로그 USER_ADMIN_CHANGE)로 한다. admin 로그인은
   BOOTSTRAP_ADMIN_PASSWORD + BOOTSTRAP_ADMIN_TOTP_SECRET으로 계산한 TOTP 코드로 한다.
3. API가 없는 단계만 직접 SQL로 하고, 같은 트랜잭션에서 감사 로그(actor portfolio-seed)를 남긴다.
   - admin 비활성화: UserAdminService가 자기 계정 비활성화를 막는다.
   - 관리자 API가 필요한데 admin이 비활성인 경우의 일시 활성화(API 단계를 마치면 곧바로 다시 비활성화).
   - 이미 있는 demo의 비밀번호 변경: 비밀번호 변경 API가 없다(createUser는 기존 아이디를 거부한다).
     해시는 앱과 같은 BCrypt(strength 12)를 pgcrypto(crypt + gen_salt('bf', 12))로 만든다.
비밀번호·TOTP 시크릿·세션 값은 출력하지 않는다. 비밀번호는 환경 변수로만 받는다(명령줄 인자로 받지 않는다).
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

import psycopg

DEMO_USERNAME = "demo"
DEMO_ROLE = "VIEWER"
ANALYST_USERNAME = "trial-analyst"
ANALYST_ROLE = "ANALYST"
DEFAULT_ANALYST_DISPLAY_NAME = "포트폴리오 방문자 (분석가 체험)"
DEFAULT_DEMO_PATTERNS = "cic17-*,syn1-*,lab-20261119,lab-20261122"
ADMIN_USERNAME = "admin"
SEED_ACTOR = "portfolio-seed"


def env(name, required=True, default=None):
    value = os.environ.get(name, default)
    if required and (value is None or value == ""):
        sys.exit(f"seed: environment variable {name} is empty")
    return value


def log(message):
    print(f"seed: {message}", flush=True)


def demo_patterns():
    """DEMO_CAPTURE_PATTERNS(쉼표 구분)를 정리한 목록. 비어 있으면 기본값. 순서는 DB 조회 순서와 같게 정렬한다."""
    raw = os.environ.get("DEMO_CAPTURE_PATTERNS", "").strip() or DEFAULT_DEMO_PATTERNS
    patterns = sorted({p.strip() for p in raw.split(",") if p.strip()})
    if not patterns:
        sys.exit("seed: DEMO_CAPTURE_PATTERNS has no pattern")
    return patterns


class Db:
    """dashboard_app 계정 접속(zeekad_dashboard: 사용자·감사 로그, postgres: pgcrypto 해시 계산)."""

    def __init__(self):
        self.params = dict(host=env("SEED_DB_HOST", default="postgres"), port=int(env("SEED_DB_PORT", default="5432")),
                           user="dashboard_app", password=env("DASHBOARD_APP_PASSWORD"))

    def app(self):
        return psycopg.connect(dbname="zeekad_dashboard", **self.params)

    def crypto(self):
        return psycopg.connect(dbname="postgres", autocommit=True, **self.params)

    def read_users(self):
        with self.app() as conn:
            rows = conn.execute(
                "SELECT u.id, u.username, u.display_name, u.role, u.enabled, u.totp_enabled, u.password_hash,"
                " (u.locked_until IS NOT NULL AND u.locked_until > now()) AS locked,"
                " COALESCE(array_agg(a.capture_pattern ORDER BY a.capture_pattern)"
                "          FILTER (WHERE a.capture_pattern IS NOT NULL), '{}') AS patterns"
                " FROM users u LEFT JOIN user_capture_access a ON a.user_id = u.id"
                " GROUP BY u.id ORDER BY u.id").fetchall()
        cols = ["id", "username", "display_name", "role", "enabled", "totp_enabled", "password_hash", "locked", "patterns"]
        return {r[1]: dict(zip(cols, r)) for r in rows}

    def audit_count(self):
        with self.app() as conn:
            return conn.execute("SELECT count(*) FROM audit_logs").fetchone()[0]

    def password_matches(self, raw_password, password_hash):
        with self.crypto() as conn:
            return conn.execute("SELECT public.crypt(%s, %s) = %s",
                                (raw_password, password_hash, password_hash)).fetchone()[0]

    def bcrypt_hash(self, raw_password):
        with self.crypto() as conn:
            return conn.execute("SELECT public.crypt(%s, public.gen_salt('bf', 12))", (raw_password,)).fetchone()[0]

    def sql_change(self, operation, target, reason, statement, params):
        """API가 없는 변경 한 건을 감사 로그와 같은 트랜잭션으로 실행한다."""
        with self.app() as conn:
            conn.execute(statement, params)
            conn.execute(
                "INSERT INTO audit_logs (actor_username, actor_role, action_type, detail_json, client_ip)"
                " VALUES (%s, 'SYSTEM', 'USER_ADMIN_CHANGE', %s, NULL)",
                (SEED_ACTOR, json.dumps({"operation": operation, "targetUsername": target, "via": "direct SQL",
                                         "reason": reason}, ensure_ascii=False)))
        log(f"SQL {operation} {target} ({reason})")


class Api:
    """앱 JSON API 클라이언트. 세션·CSRF 쿠키는 Secure 속성이라 직접 Cookie 헤더로 보낸다."""

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.cookies = {}

    def call(self, method, path, body=None, csrf=False, expect=200):
        headers = {"Accept": "application/json"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if csrf:
            headers["X-XSRF-TOKEN"] = self.cookies.get("XSRF-TOKEN", "")
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif method != "GET":
            data = b""
        request = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        for header in response.headers.get_all("Set-Cookie") or []:
            name, _, rest = header.partition("=")
            value = rest.split(";", 1)[0]
            if value == "" or "max-age=0" in header.lower():
                self.cookies.pop(name.strip(), None)
            else:
                self.cookies[name.strip()] = value
        status = response.status if hasattr(response, "status") else response.code
        raw = response.read()
        payload = json.loads(raw) if raw and raw.lstrip().startswith((b"{", b"[")) else None
        if status != expect:
            code = payload.get("code") if isinstance(payload, dict) else None
            raise RuntimeError(f"{method} {path} -> HTTP {status} (code={code}), expected {expect}")
        return payload

    def login_admin(self, password, totp_secret):
        self.call("GET", "/api/auth/csrf")
        result = self.call("POST", "/api/auth/login", {"username": ADMIN_USERNAME, "password": password}, csrf=True)
        if result.get("nextRoute") != "/login/totp":
            raise RuntimeError(f"admin login nextRoute={result.get('nextRoute')} (TOTP must already be enabled)")
        self.call("POST", "/api/auth/totp/verify", {"code": totp_code(totp_secret)}, csrf=True)
        log("API admin login + TOTP verified")

    def users(self):
        return {u["username"]: u for u in self.call("GET", "/api/admin/users")["users"]}

    def logout(self):
        self.call("POST", "/api/auth/logout", csrf=True)


def totp_code(secret, at=None):
    """RFC 6238 TOTP(SHA-1, 30초, 6자리). security-scan.ps1의 Get-TotpCode와 같은 계산이다."""
    clean = secret.strip().upper().replace(" ", "").rstrip("=")
    key = base64.b32decode(clean + "=" * (-len(clean) % 8))
    counter = int((at if at is not None else time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1000000:06d}"


class Target:
    """활성으로 둘 공개 계정의 목표 상태(비밀번호는 출력하지 않는다)."""

    def __init__(self, username, role, password, display_name, patterns):
        self.username = username
        self.role = role
        self.password = password
        self.display_name = display_name
        self.patterns = patterns


def account_problems(users, target, db):
    """공개 계정이 목표 상태와 다른 점. 값(비밀번호·해시)은 담지 않는다."""
    demo = users.get(target.username)
    if demo is None:
        return ["missing"]
    problems = []
    if (demo["role"] != target.role or sorted(demo["patterns"]) != target.patterns
            or demo["display_name"] != target.display_name):
        problems.append("access")
    if not demo["enabled"]:
        problems.append("disabled")
    if demo["locked"]:
        problems.append("locked")
    if not db.password_matches(target.password, demo["password_hash"]):
        problems.append("password")
    return problems


def all_problems(users, targets, db):
    return {t.username: account_problems(users, t, db) for t in targets}


def has_problems(problems):
    return any(problems.values())


def describe(users):
    return "; ".join(f"{u['username']}(role={u['role']}, enabled={u['enabled']}, patterns={list(u['patterns'])})"
                     for u in users.values())


def main():
    demo_capture_patterns = demo_patterns()
    targets = [Target(DEMO_USERNAME, DEMO_ROLE, env("DEMO_PASSWORD"),
                      env("DEMO_DISPLAY_NAME", default="포트폴리오 방문자 (읽기 전용)"), demo_capture_patterns)]
    analyst_password = os.environ.get("TRIAL_ANALYST_PASSWORD", "")
    if analyst_password:
        targets.append(Target(ANALYST_USERNAME, ANALYST_ROLE, analyst_password,
                              os.environ.get("TRIAL_ANALYST_DISPLAY_NAME", "").strip() or DEFAULT_ANALYST_DISPLAY_NAME,
                              demo_capture_patterns))
    else:
        log(f"TRIAL_ANALYST_PASSWORD is empty: {ANALYST_USERNAME} is not created and stays disabled if it exists")
    public_names = {t.username for t in targets}
    admin_password = env("BOOTSTRAP_ADMIN_PASSWORD")
    admin_totp_secret = env("BOOTSTRAP_ADMIN_TOTP_SECRET")
    for name in ("BOOTSTRAP_VIEWER1_PASSWORD", "BOOTSTRAP_ANALYST1_PASSWORD", "BOOTSTRAP_ANALYST2_PASSWORD"):
        env(name)
    db = Db()
    api_base = env("SEED_API_BASE_URL", default="http://dashboard-app:8080")

    users = db.read_users()
    audit_before = db.audit_count()
    log(f"current users: {describe(users)}")
    log(f"public accounts target: {sorted(public_names)}, capture patterns: {demo_capture_patterns}")
    if ADMIN_USERNAME not in users:
        sys.exit("seed: bootstrap account admin is missing (BOOTSTRAP_ADMIN_PASSWORD must be set before the first app start)")

    problems = all_problems(users, targets, db)
    others_enabled = [name for name, u in users.items()
                      if name not in public_names and name != ADMIN_USERNAME and u["enabled"]]
    admin_enabled = users[ADMIN_USERNAME]["enabled"]
    plan = ", ".join(f"{name}={p or 'ok'}" for name, p in problems.items())
    log(f"plan: {plan}, enabled non-public accounts={others_enabled + ([ADMIN_USERNAME] if admin_enabled else []) or 'none'}")

    if not has_problems(problems) and not others_enabled and not admin_enabled:
        log(f"RESULT: NO_CHANGES (audit_logs rows={audit_before})")
        return

    # 1) API가 없는 비밀번호 변경은 SQL로(이미 있는 계정만. 새 계정은 createUser API가 비밀번호를 정한다).
    for t in targets:
        if "password" in problems[t.username] and "missing" not in problems[t.username]:
            db.sql_change("SET_PASSWORD", t.username, "no password-change API; createUser rejects existing username",
                          "UPDATE users SET password_hash = %s, failed_attempts = 0, locked_until = NULL, updated_at = now()"
                          " WHERE username = %s", (db.bcrypt_hash(t.password), t.username))

    # 2) 관리자 API 단계: 공개 계정 생성·수정·활성화·잠금 해제, 다른 계정 비활성화.
    #    API 단계가 실패해도 3)의 admin 비활성화는 반드시 실행한다(finally).
    api_needed = any(set(p) - {"password"} for p in problems.values()) or bool(others_enabled)
    try:
        if api_needed:
            run_api_steps(db, api_base, admin_enabled, admin_password, admin_totp_secret, targets, problems)
    finally:
        # 3) admin 비활성화는 API가 막으므로(자기 계정) SQL로.
        if db.read_users()[ADMIN_USERNAME]["enabled"]:
            db.sql_change("DISABLE", ADMIN_USERNAME, "UserAdminService rejects disabling the signed-in account",
                          "UPDATE users SET enabled = FALSE, updated_at = now() WHERE username = %s", (ADMIN_USERNAME,))

    users = db.read_users()
    remaining = {name: p for name, p in all_problems(users, targets, db).items() if p}
    still_enabled = [name for name, u in users.items() if name not in public_names and u["enabled"]]
    log(f"final users: {describe(users)}")
    if remaining or still_enabled:
        sys.exit(f"seed: target state not reached (public accounts={remaining}, enabled={still_enabled})")
    log(f"RESULT: CHANGED (audit_logs rows {audit_before} -> {db.audit_count()})")


def run_api_steps(db, api_base, admin_enabled, admin_password, admin_totp_secret, targets, problems):
    if not admin_enabled:
        db.sql_change("TEMP_ENABLE", ADMIN_USERNAME, "admin API session for seeding; disabled again right after",
                      "UPDATE users SET enabled = TRUE, failed_attempts = 0, locked_until = NULL, updated_at = now()"
                      " WHERE username = %s", (ADMIN_USERNAME,))
    api = Api(api_base)
    api.login_admin(admin_password, admin_totp_secret)
    current = api.users()
    for t in targets:
        account = current.get(t.username)
        wrong = problems[t.username]
        if account is None:
            api.call("POST", "/api/admin/users", {"username": t.username, "displayName": t.display_name,
                                                  "password": t.password, "role": t.role,
                                                  "capturePatterns": t.patterns}, csrf=True, expect=201)
            log(f"API CREATE_USER {t.username}")
            continue
        if "access" in wrong:
            api.call("PUT", f"/api/admin/users/{account['id']}", {"displayName": t.display_name, "role": t.role,
                                                                   "capturePatterns": t.patterns}, csrf=True)
            log(f"API UPDATE_USER {t.username}")
        if not account["enabled"]:
            api.call("POST", f"/api/admin/users/{account['id']}/toggle-enabled", csrf=True)
            log(f"API TOGGLE_ENABLED {t.username} -> enabled")
        if "locked" in wrong:
            api.call("POST", f"/api/admin/users/{account['id']}/unlock", csrf=True)
            log(f"API UNLOCK_ACCOUNT {t.username}")
    # toggle-enabled는 상태를 뒤집으므로 방금 읽은 상태가 활성일 때만 부른다.
    public_names = {t.username for t in targets}
    for name, user in api.users().items():
        if name not in public_names and name != ADMIN_USERNAME and user["enabled"]:
            api.call("POST", f"/api/admin/users/{user['id']}/toggle-enabled", csrf=True)
            log(f"API TOGGLE_ENABLED {name} -> disabled")
    api.logout()


if __name__ == "__main__":
    main()
