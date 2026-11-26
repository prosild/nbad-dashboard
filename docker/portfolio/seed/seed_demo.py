"""포트폴리오 스택 계정 시드: 공개 계정만 활성으로 두고 나머지 계정은 비활성으로 만든다.

공개 계정은 둘이다.
- demo(VIEWER, 읽기 전용, 비밀번호 DEMO_PASSWORD 필수).
- trial-analyst(ANALYST, 체험용 분석가, T33. 비밀번호 TRIAL_ANALYST_PASSWORD). 비어 있으면 만들지 않고 알리며,
  이미 있으면 다른 계정처럼 비활성으로 둔다(T33 이전 공개 스택과 같다). 이 계정이 바꾼 것은 sandbox-reset이 매시 정각에 되돌린다.
두 계정의 허용 캡처는 같다.

허용 캡처는 환경 변수 DEMO_CAPTURE_PATTERNS(쉼표 구분)로 정한다. 비어 있으면 cic17-*,syn1-*,lab-20261119,lab-20261122,lab-20261126
(Kali 실습망 캡처 lab-20261119·lab-20261122와 오탐 규칙 뒤 재실행 lab-20261126만 정확한 ID로 공개하고, 시험 캡처 lab-20261201·
첫 VM 실행 lab-20261118·시험 뒤 유휴 구간 lab-20261123·규칙 전 유휴 날 lab-20261124·lab-20261125 같은 나머지 실습망 캡처는
시연 화면에서 숨긴다, 2026-11-21·2026-11-23·2026-11-26 결정). 패턴이 바뀌면 관리자 API로 갱신한다.

T54 분석이 끝난 예시: 자료 파일(SEED_EXAMPLES_FILE, 기본 /seed/demo_examples.json)의 인시던트를 시연 분석가 계정
demo-analyst(ANALYST, 평소 비활성)로 앱 API를 불러 착수 → (정탐이면) 대응 조치 → 담당 해제 → 종결까지 기록한다.
기록 시각은 앱·zeek_AD 함수가 정하는 실제 시각이다(꾸미지 않는다). 종결 뒤에는 담당을 바꿀 수 없어 해제가 종결 앞이다.
- 판정 먼저, 쓰기는 나중: 로그인 전에 DB 읽기만으로 예시마다 상태를 판정한다. zeekad 쪽(최신 큐의 작업 번호·순위, 상태·판정·마지막 변경자)은
  앱과 같은 읽기 계정 dashboard_ro(DASHBOARD_RO_PASSWORD)로 계약 뷰를 읽고, 앱 DB 쪽(담당자, demo-analyst의 조치 수)은 dashboard_app으로 읽는다.
  하나라도 어긋나면 아무것도 쓰지 않고(계정도 켜지 않고) 예시별 이유와 함께 0이 아닌 코드로 끝낸다. 최신 큐에 없는 예시는 건너뛴다.
- demo-analyst의 비밀번호는 예시를 기록해야 하는 실행마다 무작위로 만들고 쓰고 나면 버린다(출력·저장하지 않는다).
  계정이 없으면 createUser에 주고, 있으면 공개 계정과 같은 SQL 해시 교체 + 감사 행으로 바꾼다. 기록이 끝나면 곧바로 끈다.
- zeek_AD 표, 대응 조치 표, 담당 표에는 SQL로 쓰지 않는다(예시의 기록은 모두 앱 API를 거친다).

T52 중요 자산: 자료 파일(SEED_ASSETS_FILE, 기본 /seed/critical_assets.json)과 앱의 중요 자산 목록을 같게 맞춘다.
없는 것은 만들고, 이름·설명이 다르면 고치고, 파일에 없는 것은 지운다(관리자 API, 감사 CRITICAL_ASSET_CHANGE). 주소는 바꾸지 않는다(지우고 만든다).
- 파일 검증 먼저: 꼴, 주소(IPv4 하나의 정확한 꼴), 중복 주소, 이름·설명 길이를 바꾸기 전에 본다. 0개도 거부한다
  (빈 파일이나 깨진 파일이 목록 전부를 지우지 않게). 어긋나면 아무것도 바꾸지 않고 0이 아닌 코드로 끝낸다.
- 판정은 앱 DB 읽기(dashboard_app)로 한다. 자산만 달라도 관리자 단계를 돈다. 계정·예시·자산이 모두 같으면 로그인하지 않는다(NO_CHANGES).
- 관리자 단계 안에서 T54 단계(공개 계정 → 예시 → 계정 끄기) 뒤, 로그아웃 앞에 둔다. 로그 한 줄:
  critical-assets: created=<n> updated=<n> deleted=<n> kept=<n>
- 앱 DB에 critical_assets 표가 없으면(T52 앞 이미지) 아무것도 바꾸지 않고 멈춘다.

compose.portfolio.yml의 demo-seed 서비스(zeekad-pipeline 이미지의 Python)로 실행한다. 다시 실행해도 안전하다(멱등).
1. zeekad_dashboard를 dashboard_app 계정으로 읽어 현재 상태를 확인하고, 예시의 상태를 판정한다. 이미 목표 상태면 아무것도 바꾸지 않고 끝낸다.
2. 바꿀 것이 있으면 가능한 단계는 앱 관리자 API(감사 로그 USER_ADMIN_CHANGE)로 한다. admin 로그인은
   BOOTSTRAP_ADMIN_PASSWORD + BOOTSTRAP_ADMIN_TOTP_SECRET으로 계산한 TOTP 코드로 한다(한 실행에 한 번).
3. API가 없는 단계만 직접 SQL로 하고, 같은 트랜잭션에서 감사 로그(actor portfolio-seed)를 남긴다(users 표만).
   - admin 비활성화: UserAdminService가 자기 계정 비활성화를 막는다.
   - 관리자 API가 필요한데 admin이 비활성인 경우의 일시 활성화(API 단계를 마치면 곧바로 다시 비활성화).
   - 이미 있는 demo·trial-analyst·demo-analyst의 비밀번호 변경: 비밀번호 변경 API가 없다(createUser는 기존 아이디를 거부한다).
     해시는 앱과 같은 BCrypt(strength 12)를 pgcrypto(crypt + gen_salt('bf', 12))로 만든다.
   - API 단계가 실패해도 켜져 있는 demo-analyst를 끈다(finally, admin과 같은 방식).
비밀번호·TOTP 시크릿·세션 값과 예시 글은 출력하지 않는다. 비밀번호는 환경 변수로만 받는다(명령줄 인자로 받지 않는다).
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
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
DEFAULT_DEMO_PATTERNS = "cic17-*,syn1-*,lab-20261119,lab-20261122,lab-20261126"
ADMIN_USERNAME = "admin"
SEED_ACTOR = "portfolio-seed"
# T54 시연 분석가: 예시를 기록하는 동안만 켠다. 잠금 제외 목록에 넣지 않는다.
EXAMPLE_USERNAME = "demo-analyst"
EXAMPLE_ROLE = "ANALYST"
EXAMPLE_DISPLAY_NAME = "시연 분석가"
EXAMPLE_PATTERNS = ["lab-20261119", "lab-20261122"]
DEFAULT_EXAMPLES_FILE = "/seed/demo_examples.json"
RESOLUTIONS = ("true_positive", "false_positive", "benign")
# T52 중요 자산(앱 CriticalAssetService와 같은 상한·꼴)
DEFAULT_ASSETS_FILE = "/seed/critical_assets.json"
MAX_ASSETS = 200
ASSET_NAME_MAX = 100
ASSET_DESCRIPTION_MAX = 300
IPV4_OCTET = r"(?:0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
IPV4_EXACT = re.compile(r"\A" + IPV4_OCTET + r"(?:\." + IPV4_OCTET + r"){3}\Z")


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
        """API가 없는 변경 한 건(users 표)을 감사 로그와 같은 트랜잭션으로 실행한다."""
        with self.app() as conn:
            conn.execute(statement, params)
            conn.execute(
                "INSERT INTO audit_logs (actor_username, actor_role, action_type, detail_json, client_ip)"
                " VALUES (%s, 'SYSTEM', 'USER_ADMIN_CHANGE', %s, NULL)",
                (SEED_ACTOR, json.dumps({"operation": operation, "targetUsername": target, "via": "direct SQL",
                                         "reason": reason}, ensure_ascii=False)))
        log(f"SQL {operation} {target} ({reason})")

    def read_example_app_state(self, incident_ids):
        """앱 DB 읽기(T54): 인시던트별 현재 담당자 아이디(없으면 None)와 demo-analyst가 쓴 대응 조치 수."""
        with self.app() as conn:
            assignees = dict(conn.execute(
                "SELECT a.incident_id, u.username FROM incident_assignments a"
                " LEFT JOIN users u ON u.id = a.assignee_user_id WHERE a.incident_id = ANY(%s)",
                (incident_ids,)).fetchall())
            actions = dict(conn.execute(
                "SELECT incident_id, count(*) FROM incident_response_actions"
                " WHERE actor_username = %s AND incident_id = ANY(%s) GROUP BY incident_id",
                (EXAMPLE_USERNAME, incident_ids)).fetchall())
        return assignees, actions

    def current_assignee(self, incident_id):
        assignees, _ = self.read_example_app_state([incident_id])
        return assignees.get(incident_id)

    def read_critical_assets(self):
        """앱 DB 읽기(T52): 주소 → (이름, 설명). 표가 없으면(T52 앞 앱 이미지) None."""
        with self.app() as conn:
            exists = conn.execute("SELECT to_regclass('public.critical_assets') IS NOT NULL").fetchone()[0]
            if not exists:
                return None
            rows = conn.execute("SELECT host_ip, name, description FROM critical_assets ORDER BY id").fetchall()
        return {host: (name, description) for host, name, description in rows}


class ZeekadReader:
    """zeekad 계약 뷰 읽기 전용(T54). 앱이 쓰는 읽기 계정 dashboard_ro로 붙는다(새 비밀값이 아니다)."""

    def __init__(self):
        self.params = dict(host=env("SEED_DB_HOST", default="postgres"), port=int(env("SEED_DB_PORT", default="5432")),
                           user="dashboard_ro", password=env("DASHBOARD_RO_PASSWORD"), dbname="zeekad")

    def read(self, incident_ids):
        """최신 큐의 행(작업 번호·순위·캡처)과 상태 행(상태·판정·마지막 변경자).
        계약 뷰 dashboard.incident_status는 인시던트 × 성공 작업마다 한 행이고 zeek_AD 상태 표를 incident_id로 LEFT JOIN한다.
        상태 행이 없으면 zeekad_status가 'open'으로 채워지고 updated_by가 NULL이다(updated_by는 상태 표에서 NOT NULL).
        그래서 updated_by가 있는 행만 상태 행으로 본다(없으면 신규). 같은 인시던트의 행은 같은 상태 값을 갖는다."""
        with psycopg.connect(**self.params) as conn:
            conn.read_only = True
            queue = {}
            for incident_id, job_id, queue_rank, capture_id in conn.execute(
                    "SELECT incident_id, job_id, queue_rank, capture_id FROM dashboard.latest_incident_queue"
                    " WHERE incident_id = ANY(%s) ORDER BY incident_id, job_id, queue_rank", (incident_ids,)).fetchall():
                queue.setdefault(incident_id, []).append(
                    {"job_id": job_id, "queue_rank": queue_rank, "capture_id": capture_id})
            status = {}
            for incident_id, st, resolution, updated_by in conn.execute(
                    "SELECT DISTINCT ON (incident_id) incident_id, zeekad_status, zeekad_resolution, updated_by"
                    " FROM dashboard.incident_status WHERE incident_id = ANY(%s) AND updated_by IS NOT NULL"
                    " ORDER BY incident_id, updated_at DESC NULLS LAST", (incident_ids,)).fetchall():
                status[incident_id] = {"status": norm(st), "resolution": norm(resolution), "updated_by": updated_by}
        return queue, status


def norm(value):
    return None if value is None else str(value).strip().lower()


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

    def login_analyst(self, username, password):
        """분석가 로그인(TOTP 없음, T54 예시 기록용 세션)."""
        self.call("GET", "/api/auth/csrf")
        result = self.call("POST", "/api/auth/login", {"username": username, "password": password}, csrf=True)
        if result.get("nextRoute") != "/":
            raise RuntimeError(f"{username} login nextRoute={result.get('nextRoute')} (expected an analyst session)")
        log(f"API {username} login")

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


# ───────────────────────── T54 분석이 끝난 예시 ─────────────────────────

RESPONSE_ACTIONS = ("block_ip", "isolate_host", "lock_account", "handover", "monitor", "none", "other")
MAX_TEXT_CODE_POINTS = 500  # 앱의 FreeTextLimits.MAX_CODE_POINTS(상태 변경 사유)와 대응 조치 메모 상한
INCIDENT_ID_SHAPE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\|[0-9A-Fa-f.:]+\|(originator|responder)\|\d+$")


def pattern_allows(patterns, capture_id):
    """허용 캡처 패턴(정확한 ID 또는 끝의 * 접두)에 맞는가. 앱의 CapturePatternMatcher와 같은 규칙."""
    for p in patterns:
        if p.endswith("*"):
            if capture_id.startswith(p[:-1]):
                return True
        elif capture_id == p:
            return True
    return False


def load_examples():
    """자료 파일의 예시 목록. 꼴이 틀리면 아무것도 바꾸기 전에 멈춘다. 빈 목록이면 계정만 맞춘다."""
    path = os.environ.get("SEED_EXAMPLES_FILE", "").strip() or DEFAULT_EXAMPLES_FILE
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as error:
        sys.exit(f"seed: cannot read examples file {path} ({type(error).__name__})")
    examples = doc.get("examples") if isinstance(doc, dict) else None
    if not isinstance(examples, list):
        sys.exit(f"seed: examples file {path} has no 'examples' list")

    def text_ok(value):
        return isinstance(value, str) and value.strip() != "" and len(value.strip()) <= MAX_TEXT_CODE_POINTS

    seen = set()
    for ex in examples:
        if not isinstance(ex, dict):
            sys.exit(f"seed: examples file {path}: an example is not an object")
        key, incident_id, action = ex.get("key"), ex.get("incidentId"), ex.get("responseAction")
        shape = INCIDENT_ID_SHAPE.match(incident_id) if isinstance(incident_id, str) else None
        bad = []
        if not isinstance(key, str) or not key:
            bad.append("key")
        if shape is None:
            bad.append("incidentId")
        elif not pattern_allows(EXAMPLE_PATTERNS, shape.group(1)):
            bad.append(f"capture {shape.group(1)} is outside the {EXAMPLE_USERNAME} capture patterns")
        if ex.get("resolution") not in RESOLUTIONS:
            bad.append("resolution")
        if not text_ok(ex.get("startReason")) or not text_ok(ex.get("closeReason")):
            bad.append("startReason/closeReason")
        if action is not None and (not isinstance(action, dict) or action.get("action") not in RESPONSE_ACTIONS
                                   or (action.get("note") is not None and not text_ok(action.get("note")))
                                   or (action.get("action") in ("none", "other") and not text_ok(action.get("note")))):
            bad.append("responseAction")
        if ex.get("resolution") == "true_positive" and action is None:
            bad.append("responseAction (required for true_positive)")
        if incident_id in seen:
            bad.append("duplicate incidentId")
        seen.add(incident_id)
        if bad:
            sys.exit(f"seed: examples file {path}: example {key!r} invalid: {', '.join(bad)}")
    return examples, path


class ExamplePlan:
    """예시 하나의 판정. kind: skipped(최신 큐에 없음) · kept(목표 상태) · apply(기록할 것) · fail(어긋남)."""

    def __init__(self, example, kind, reason="", steps=(), job_id=None, queue_rank=None):
        self.example = example
        self.kind = kind
        self.reason = reason
        self.steps = list(steps)
        self.job_id = job_id
        self.queue_rank = queue_rank

    @property
    def label(self):
        return f"{self.example['key']} ({self.example['incidentId']})"


def plan_example(example, queue_rows, status, assignee, actor_actions):
    """DB에서 읽은 값만으로 예시 하나의 할 일을 정한다(쓰지 않는다). handoff/T54.md 3절의 표.
    정탐의 대응 조치는 demo-analyst의 조치가 0일 때만 기록한다(다시 실행할 때 같은 조치를 겹쳐 쓰지 않는다)."""
    rows = queue_rows or []
    if not rows:
        return ExamplePlan(example, "skipped", "not in the latest queue (another snapshot or an ID typo)")
    if len(rows) > 1:
        return ExamplePlan(example, "fail", f"{len(rows)} rows in the latest queue (expected one)")
    job_id, queue_rank = rows[0]["job_id"], rows[0]["queue_rank"]
    true_positive = example["resolution"] == "true_positive"
    need_action = true_positive and actor_actions == 0
    if status is None:
        if assignee is not None:
            return ExamplePlan(example, "fail", f"new (no status row) but assigned to {assignee}")
        steps = ["start"] + (["response-action"] if need_action else []) + ["release", "close"]
        return ExamplePlan(example, "apply", "new", steps, job_id, queue_rank)
    st, by = status["status"], status["updated_by"]
    if st == "investigating":
        if by != EXAMPLE_USERNAME:
            return ExamplePlan(example, "fail", f"investigating, last changed by {by} (not {EXAMPLE_USERNAME})")
        if assignee not in (None, EXAMPLE_USERNAME):
            return ExamplePlan(example, "fail", f"investigating, assigned to {assignee}")
        steps = (["response-action"] if need_action else []) + (["release"] if assignee else []) + ["close"]
        return ExamplePlan(example, "apply", f"investigating by {EXAMPLE_USERNAME} (resume)", steps, job_id, queue_rank)
    if st == "closed":
        wrong = []
        if status["resolution"] != example["resolution"]:
            wrong.append(f"resolution {status['resolution']} (expected {example['resolution']})")
        if by != EXAMPLE_USERNAME:
            wrong.append(f"last changed by {by} (not {EXAMPLE_USERNAME})")
        if assignee is not None:
            wrong.append(f"still assigned to {assignee}; the API cannot release a closed incident (409 INCIDENT_CLOSED)")
        if true_positive and actor_actions == 0:
            wrong.append(f"true positive without a response action by {EXAMPLE_USERNAME}")
        if wrong:
            return ExamplePlan(example, "fail", "closed but " + "; ".join(wrong))
        return ExamplePlan(example, "kept", "closed as planned", job_id=job_id, queue_rank=queue_rank)
    return ExamplePlan(example, "fail", f"unexpected status {st!r} (status row by {by})")


def plan_examples(examples, db):
    """예시 전부를 DB 읽기만으로 판정한다. 예시가 없으면 zeekad에 붙지 않는다."""
    if not examples:
        return []
    ids = [ex["incidentId"] for ex in examples]
    queue, status = ZeekadReader().read(ids)
    assignees, actions = db.read_example_app_state(ids)
    return [plan_example(ex, queue.get(ex["incidentId"]), status.get(ex["incidentId"]),
                         assignees.get(ex["incidentId"]), actions.get(ex["incidentId"], 0)) for ex in examples]


def examples_summary(plans):
    """실행 앞의 판정으로 센다: 기록한 것(apply), 그대로 둔 것(kept), 건너뛴 것(skipped)과 그 ID."""
    count = {kind: [p for p in plans if p.kind == kind] for kind in ("apply", "kept", "skipped")}
    return (f"examples: applied={len(count['apply'])} kept={len(count['kept'])} skipped={len(count['skipped'])}"
            + (f" skipped_ids=[{', '.join(p.example['incidentId'] for p in count['skipped'])}]"
               if count["skipped"] else ""))


def example_account_problems(users):
    """demo-analyst의 목표 상태(있음, ANALYST, 표시 이름, 허용 캡처)와 다른 점. 켜짐은 다른 비공개 계정처럼 따로 본다."""
    account = users.get(EXAMPLE_USERNAME)
    if account is None:
        return ["missing"]
    if (account["role"] != EXAMPLE_ROLE or sorted(account["patterns"]) != sorted(EXAMPLE_PATTERNS)
            or account["display_name"] != EXAMPLE_DISPLAY_NAME):
        return ["access"]
    return []


def record_examples(db, api_base, plans, password):
    """분석가 세션(demo-analyst)으로 예시를 기록한다. 담당 해제는 종결 앞이다(종결 뒤에는 담당을 바꿀 수 없다)."""
    analyst = Api(api_base)
    analyst.login_analyst(EXAMPLE_USERNAME, password)
    try:
        for plan in plans:
            ex = plan.example
            base = f"/api/incidents/{plan.job_id}/rank/{plan.queue_rank}"
            done = []
            if "start" in plan.steps:
                analyst.call("POST", base + "/transition", {"toStatus": "investigating", "reason": ex["startReason"]},
                             csrf=True)
                done.append("start")
            if "response-action" in plan.steps:
                action = ex["responseAction"]
                analyst.call("POST", base + "/response-actions",
                             {"action": action["action"], "note": action.get("note")}, csrf=True)
                done.append(f"response-action {action['action']}")
            # 착수 때 앱이 미배정이면 행위자를 담당자로 지정한다. 지금 담당자를 다시 읽어 그 계정이면 해제한다.
            assignee = db.current_assignee(ex["incidentId"])
            if assignee == EXAMPLE_USERNAME:
                analyst.call("POST", base + "/assignment", {"assignee": None, "expected": EXAMPLE_USERNAME}, csrf=True)
                done.append("release")
            elif assignee is not None:
                raise RuntimeError(f"example {plan.label}: assigned to {assignee} before closing; not closed")
            if db.current_assignee(ex["incidentId"]) is not None:
                raise RuntimeError(f"example {plan.label}: still assigned after release; not closed")
            analyst.call("POST", base + "/transition", {"toStatus": "closed", "resolution": ex["resolution"],
                                                       "reason": ex["closeReason"]}, csrf=True)
            done.append(f"close {ex['resolution']}")
            log(f"API example {plan.label}: {', '.join(done)}")
    finally:
        try:
            analyst.logout()
        except Exception as error:  # 계정은 곧 꺼진다. 로그아웃 실패로 원래 오류를 덮지 않는다.
            log(f"{EXAMPLE_USERNAME} logout failed ({type(error).__name__})")


# ───────────────────────── T52 중요 자산 ─────────────────────────

def clean_asset_text(value):
    """앱과 같은 다듬기: 앞뒤 공백을 지운다. 설명의 빈 글은 없음(None)이다."""
    return value.strip() if isinstance(value, str) else value


def load_assets():
    """자료 파일의 중요 자산(주소 → (이름, 설명)). 바꾸기 전에 꼴·주소·중복·길이를 보고 0개도 거부한다.
    어긋나면 아무것도 바꾸지 않고 멈춘다(빈 파일이나 깨진 파일이 목록 전부를 지우지 않게)."""
    path = os.environ.get("SEED_ASSETS_FILE", "").strip() or DEFAULT_ASSETS_FILE
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as error:
        sys.exit(f"seed: cannot read critical assets file {path} ({type(error).__name__}); nothing was changed")
    assets = doc.get("assets") if isinstance(doc, dict) else None
    if not isinstance(assets, list):
        sys.exit(f"seed: critical assets file {path} has no 'assets' list; nothing was changed")
    if not assets:
        sys.exit(f"seed: critical assets file {path} has no asset (an empty list would delete every asset); nothing was changed")
    if len(assets) > MAX_ASSETS:
        sys.exit(f"seed: critical assets file {path} has {len(assets)} assets (limit {MAX_ASSETS}); nothing was changed")

    def text_ok(value, limit, required):
        if value is None:
            return not required
        if not isinstance(value, str):
            return False
        clean = value.strip()
        if required and clean == "":
            return False
        return len(clean) <= limit and not any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in clean)

    wanted = {}
    for index, asset in enumerate(assets):
        if not isinstance(asset, dict):
            sys.exit(f"seed: critical assets file {path}: entry #{index + 1} is not an object; nothing was changed")
        host = asset.get("hostIp")
        bad = []
        if not isinstance(host, str) or IPV4_EXACT.match(host) is None:
            bad.append("hostIp (one exact IPv4 address, no range, no spaces)")
        elif host in wanted:
            bad.append("duplicate hostIp")
        if not text_ok(asset.get("name"), ASSET_NAME_MAX, True):
            bad.append(f"name (1..{ASSET_NAME_MAX} characters, no control characters)")
        if not text_ok(asset.get("description"), ASSET_DESCRIPTION_MAX, False):
            bad.append(f"description (up to {ASSET_DESCRIPTION_MAX} characters, no control characters)")
        if bad:
            sys.exit(f"seed: critical assets file {path}: entry #{index + 1} invalid: {', '.join(bad)}; nothing was changed")
        description = clean_asset_text(asset.get("description"))
        wanted[host] = (clean_asset_text(asset["name"]), description or None)
    return wanted, path


def plan_assets(wanted, current):
    """파일(wanted)과 앱(current)의 차이: 만들 주소, 고칠 주소, 지울 주소, 그대로인 주소."""
    create = [h for h in wanted if h not in current]
    change = [h for h in wanted if h in current and tuple(current[h]) != wanted[h]]
    remove = [h for h in current if h not in wanted]
    kept = [h for h in wanted if h in current and tuple(current[h]) == wanted[h]]
    return {"create": create, "change": change, "remove": remove, "kept": kept}


def assets_summary(plan):
    return (f"critical-assets: created={len(plan['create'])} updated={len(plan['change'])} "
            f"deleted={len(plan['remove'])} kept={len(plan['kept'])}")


def sync_critical_assets(api, wanted):
    """관리자 세션 안에서 앱의 목록을 파일과 같게 맞춘다. 세션 안에서 다시 읽은 목록으로 정한다(상한 때문에 지우기가 먼저)."""
    listed = api.call("GET", "/api/admin/critical-assets")["items"]
    by_host = {item["hostIp"]: item for item in listed}
    plan = plan_assets(wanted, {h: (i["name"], i["description"]) for h, i in by_host.items()})
    for host in plan["remove"]:
        api.call("POST", f"/api/admin/critical-assets/{by_host[host]['id']}/delete", csrf=True)
        log(f"API CRITICAL_ASSET_DELETE {host}")
    for host in plan["change"]:
        name, description = wanted[host]
        api.call("PUT", f"/api/admin/critical-assets/{by_host[host]['id']}", {"name": name, "description": description},
                 csrf=True)
        log(f"API CRITICAL_ASSET_CHANGE {host}")
    for host in plan["create"]:
        name, description = wanted[host]
        api.call("POST", "/api/admin/critical-assets", {"hostIp": host, "name": name, "description": description},
                 csrf=True, expect=201)
        log(f"API CRITICAL_ASSET_CREATE {host}")
    log(assets_summary(plan))
    return plan


def disable_example_account_sql(db):
    """finally: 켜져 있는 demo-analyst를 SQL로 끈다(관리자 세션이 깨졌을 때도). 감사 행을 같은 트랜잭션에 남긴다."""
    account = db.read_users().get(EXAMPLE_USERNAME)
    if account is not None and account["enabled"]:
        db.sql_change("DISABLE", EXAMPLE_USERNAME, "demo example recording ended (admin API session did not disable it)",
                      "UPDATE users SET enabled = FALSE, updated_at = now() WHERE username = %s", (EXAMPLE_USERNAME,))


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
    examples, examples_path = load_examples()
    wanted_assets, assets_path = load_assets()
    db = Db()
    api_base = env("SEED_API_BASE_URL", default="http://dashboard-app:8080")

    users = db.read_users()
    audit_before = db.audit_count()
    log(f"current users: {describe(users)}")
    log(f"public accounts target: {sorted(public_names)}, capture patterns: {demo_capture_patterns}")
    if ADMIN_USERNAME not in users:
        sys.exit("seed: bootstrap account admin is missing (BOOTSTRAP_ADMIN_PASSWORD must be set before the first app start)")

    # 0) 예시 판정(T54): 쓰기 전에 DB 읽기만으로 전부 본다. 하나라도 어긋나면 아무것도 쓰지 않는다(계정도 켜지 않는다).
    plans = plan_examples(examples, db)
    log(f"examples file {examples_path}: {len(examples)} example(s); "
        + (", ".join(f"{p.example['key']}={p.kind}({p.reason})" for p in plans) or "none"))
    failures = [p for p in plans if p.kind == "fail"]
    if failures:
        for p in failures:
            log(f"example {p.label}: FAIL {p.reason}")
        sys.exit(f"seed: {len(failures)} example(s) are in an unexpected state; nothing was changed")
    to_apply = [p for p in plans if p.kind == "apply"]
    example_problems = example_account_problems(users)

    # 0') 중요 자산 판정(T52): 앱 DB 읽기만으로 파일과 견준다. 표가 없으면(T52 앞 앱 이미지) 아무것도 바꾸지 않는다.
    current_assets = db.read_critical_assets()
    if current_assets is None:
        sys.exit("seed: app database has no critical_assets table (app image before T52); nothing was changed")
    asset_plan = plan_assets(wanted_assets, current_assets)
    asset_changes = bool(asset_plan["create"] or asset_plan["change"] or asset_plan["remove"])
    log(f"critical assets file {assets_path}: {len(wanted_assets)} asset(s); plan {assets_summary(asset_plan)}")

    problems = all_problems(users, targets, db)
    others_enabled = [name for name, u in users.items()
                      if name not in public_names and name != ADMIN_USERNAME and u["enabled"]]
    admin_enabled = users[ADMIN_USERNAME]["enabled"]
    plan = ", ".join(f"{name}={p or 'ok'}" for name, p in problems.items())
    log(f"plan: {plan}, {EXAMPLE_USERNAME}={example_problems or 'ok'}, examples to record={len(to_apply)}, "
        f"enabled non-public accounts={others_enabled + ([ADMIN_USERNAME] if admin_enabled else []) or 'none'}")

    if (not has_problems(problems) and not others_enabled and not admin_enabled and not example_problems and not to_apply
            and not asset_changes):
        log(examples_summary(plans))
        log(assets_summary(asset_plan))
        log(f"RESULT: NO_CHANGES (audit_logs rows={audit_before})")
        return

    # 1) API가 없는 비밀번호 변경은 SQL로(이미 있는 계정만. 새 계정은 createUser API가 비밀번호를 정한다).
    for t in targets:
        if "password" in problems[t.username] and "missing" not in problems[t.username]:
            db.sql_change("SET_PASSWORD", t.username, "no password-change API; createUser rejects existing username",
                          "UPDATE users SET password_hash = %s, failed_attempts = 0, locked_until = NULL, updated_at = now()"
                          " WHERE username = %s", (db.bcrypt_hash(t.password), t.username))

    # 2) 관리자 API 단계: 공개 계정 생성·수정·활성화·잠금 해제, demo-analyst 맞추기와 예시 기록, 다른 계정 비활성화.
    #    API 단계가 실패해도 3)의 demo-analyst·admin 비활성화는 반드시 실행한다(finally).
    api_needed = (any(set(p) - {"password"} for p in problems.values()) or bool(others_enabled)
                  or bool(example_problems) or bool(to_apply) or asset_changes)
    try:
        if api_needed:
            run_api_steps(db, api_base, admin_enabled, admin_password, admin_totp_secret, targets, problems,
                          example_problems, to_apply, wanted_assets)
        else:
            # 관리자 단계를 돌지 않으면(비밀번호만 바뀐 경우) 자산은 그대로다
            log(assets_summary(asset_plan))
    finally:
        # 3) 예시를 기록하던 계정이 켜진 채 남지 않게 한다(관리자 세션이 깨졌을 수 있어 SQL로).
        disable_example_account_sql(db)
        # admin 비활성화는 API가 막으므로(자기 계정) SQL로.
        if db.read_users()[ADMIN_USERNAME]["enabled"]:
            db.sql_change("DISABLE", ADMIN_USERNAME, "UserAdminService rejects disabling the signed-in account",
                          "UPDATE users SET enabled = FALSE, updated_at = now() WHERE username = %s", (ADMIN_USERNAME,))

    users = db.read_users()
    remaining = {name: p for name, p in all_problems(users, targets, db).items() if p}
    still_enabled = [name for name, u in users.items() if name not in public_names and u["enabled"]]
    example_remaining = example_account_problems(users)
    not_done = [f"{p.label}={p.kind}({p.reason})" for p in plan_examples(examples, db) if p.kind not in ("kept", "skipped")]
    final_assets = plan_assets(wanted_assets, db.read_critical_assets() or {})
    assets_left = {k: v for k, v in final_assets.items() if k != "kept" and v}
    log(f"final users: {describe(users)}")
    if remaining or still_enabled or example_remaining or not_done or assets_left:
        sys.exit(f"seed: target state not reached (public accounts={remaining}, enabled={still_enabled}, "
                 f"{EXAMPLE_USERNAME}={example_remaining or 'ok'}, examples={not_done or 'ok'}, "
                 f"critical assets={assets_left or 'ok'})")
    log(examples_summary(plans))
    log(f"RESULT: CHANGED (audit_logs rows {audit_before} -> {db.audit_count()})")


def run_api_steps(db, api_base, admin_enabled, admin_password, admin_totp_secret, targets, problems,
                  example_problems, to_apply, wanted_assets):
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

    # T54 demo-analyst: 없으면 만들고(createUser는 계정을 켠 채 만든다) 접근 설정을 맞춘다. 예시를 기록할 때만
    # 이번 실행의 무작위 비밀번호를 정하고 켠다. 비밀번호는 출력·저장하지 않고 이 함수 안에서 버린다.
    account = current.get(EXAMPLE_USERNAME)
    password = secrets.token_urlsafe(32) if (to_apply or account is None) else None
    if account is None:
        api.call("POST", "/api/admin/users", {"username": EXAMPLE_USERNAME, "displayName": EXAMPLE_DISPLAY_NAME,
                                              "password": password, "role": EXAMPLE_ROLE,
                                              "capturePatterns": EXAMPLE_PATTERNS}, csrf=True, expect=201)
        log(f"API CREATE_USER {EXAMPLE_USERNAME}")
    else:
        if "access" in example_problems:
            api.call("PUT", f"/api/admin/users/{account['id']}", {"displayName": EXAMPLE_DISPLAY_NAME,
                                                                   "role": EXAMPLE_ROLE,
                                                                   "capturePatterns": EXAMPLE_PATTERNS}, csrf=True)
            log(f"API UPDATE_USER {EXAMPLE_USERNAME}")
        if to_apply:
            # 이미 있는 계정의 비밀번호는 API로 바꿀 수 없다: 공개 계정과 같은 SQL 해시 교체 + 감사 행.
            db.sql_change("SET_PASSWORD", EXAMPLE_USERNAME,
                          "no password-change API; one-time random password for recording demo examples (not stored)",
                          "UPDATE users SET password_hash = %s, failed_attempts = 0, locked_until = NULL, updated_at = now()"
                          " WHERE username = %s", (db.bcrypt_hash(password), EXAMPLE_USERNAME))
            if not account["enabled"]:
                api.call("POST", f"/api/admin/users/{account['id']}/toggle-enabled", csrf=True)
                log(f"API TOGGLE_ENABLED {EXAMPLE_USERNAME} -> enabled")
    try:
        if to_apply:
            record_examples(db, api_base, to_apply, password)
    finally:
        password = None
    # toggle-enabled는 상태를 뒤집으므로 방금 읽은 상태가 활성일 때만 부른다. demo-analyst를 먼저 끄고 나머지를 끈다.
    example_account = api.users().get(EXAMPLE_USERNAME)
    if example_account is not None and example_account["enabled"]:
        api.call("POST", f"/api/admin/users/{example_account['id']}/toggle-enabled", csrf=True)
        log(f"API TOGGLE_ENABLED {EXAMPLE_USERNAME} -> disabled")
    public_names = {t.username for t in targets}
    for name, user in api.users().items():
        if name not in public_names and name != ADMIN_USERNAME and user["enabled"]:
            api.call("POST", f"/api/admin/users/{user['id']}/toggle-enabled", csrf=True)
            log(f"API TOGGLE_ENABLED {name} -> disabled")
    # T52 중요 자산: T54 단계 뒤, 같은 관리자 세션에서 파일과 같게 맞춘다(감사 CRITICAL_ASSET_CHANGE)
    sync_critical_assets(api, wanted_assets)
    api.logout()


if __name__ == "__main__":
    main()
