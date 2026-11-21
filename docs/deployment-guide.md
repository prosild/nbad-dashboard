# zeek_ad_dashboard 배포 및 운영 가이드

`zeek_ad_dashboard`를 VMware Ubuntu Server 배포 VM 한 대(zeek_AD와 같은 Docker Compose)나 로컬 개발·검증 환경에 올리고 운영하는 절차와 보안 설정을 적습니다.

---

## 1. 아키텍처 및 네트워크 경계 개요

### 1.1 VMware 실습·운영 토폴로지
- **배포 VM (Ubuntu Server 1대)**: `zeek_AD` 파이프라인(PostgreSQL 17, 근거 FastAPI `api` 등)과 `zeek_ad_dashboard`(`dashboard-app`, `nginx-waf`)를 **같은 Docker Compose 프로젝트 또는 공유 Docker 네트워크**로 기동합니다.
- **공격 VM (Kali Linux)**: 격리된 실습망(Host-Only / Internal 가상 네트워크)으로만 공격 트래픽을 전송합니다.
- **사용자 접속 (Windows 호스트 브라우저)**: Windows 브라우저에서 배포 VM의 IP 또는 호스트명(`https://<VM_IP>`)으로 접속합니다. 외부 요청은 `nginx-waf`로만 들어옵니다.

### 1.2 대시보드 컨테이너 구성
- **`nginx-waf` (`docker/nginx-waf/Dockerfile`)**: `owasp/modsecurity-crs:nginx-alpine` 기반 앞단 리버스 프록시 + ModSecurity v3 WAF(OWASP CRS `PARANOIA=1`, `SecRuleEngine On`, `USER nginx`).
  - 외부 트래픽은 `nginx-waf`의 HTTPS(`${WAF_HTTPS_PORT:-443}` → 컨테이너 `8443`) 및 HTTP(`${WAF_HTTP_PORT:-80}` → 컨테이너 `8080`, HTTPS로 `301` 리다이렉트) 포트만 통과합니다.
  - `/actuator/**` 경로는 앞단 Nginx에서 `403 Forbidden`으로 즉시 차단합니다.
  - `compose.yml`의 `ALLOWED_METHODS: "GET HEAD POST PUT OPTIONS"`로 CRS 허용 메서드(기본 `GET HEAD POST OPTIONS`)에 `PUT`만 더합니다. SPA의 사용자 수정 요청 `PUT /api/admin/users/{id}` 때문입니다. 앱이 쓰지 않는 `DELETE`·`PATCH`는 허용하지 않습니다. `PARANOIA`·`BLOCKING_PARANOIA=1`, `ANOMALY_INBOUND=5`, `MODSEC_RULE_ENGINE=on`은 그대로이고 WAF 예외 규칙은 두지 않습니다.
  - `Server` 헤더와 와일드카드 CORS 헤더를 지웁니다(같은 출처에서 SPA 정적 셸과 JSON API를 함께 서빙하므로 CORS 헤더가 필요 없음). HTTPS 응답에는 `Strict-Transport-Security` 헤더를 더합니다. 백엔드(`dashboard-app`)가 붙인 `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, `COOP/COEP/CORP`, `Permissions-Policy` 헤더는 그대로 둡니다.
  - **클라이언트 IP 규칙**(`T14`): 이 스택은 WAF가 맨 앞이라 클라이언트가 직접 붙습니다. `compose.yml`은 `SET_REAL_IP_FROM: "127.0.0.1"`, `REAL_IP_HEADER: "X-Forwarded-For"`, `REAL_IP_RECURSIVE: "on"`이라서 `127.0.0.1` 밖에서 온 연결은 접속 주소가 곧 클라이언트 IP입니다. 방문자가 보낸 `X-Real-IP`·`X-Forwarded-For`는 무시합니다. 앞단 프록시용 설정 변수는 두지 않습니다.
    - 사설망 대역(`10/8`·`172.16/12`·`192.168/16`)을 통째로 신뢰하면 안 됩니다. VMware NAT·Docker 게이트웨이처럼 같은 사설망에서 오는 누구나 헤더 하나로 감사 로그 `client_ip`와 ModSecurity 기록 IP를 바꿀 수 있기 때문입니다(`T14` 이전 설정에서 재현됨).
    - 앞단 프록시(로드밸런서 등) 뒤에 둘 때는 포트폴리오 스택(`compose.portfolio.yml` + `docker/portfolio/nginx/zeekad-portfolio-http.conf.template`)처럼 `set_real_ip_from <그 프록시 주소만>`·`real_ip_header X-Forwarded-For`·`real_ip_recursive on`을 **http 문맥** conf 템플릿으로 따로 붙입니다. 이미지의 `SET_REAL_IP_FROM`은 `location` 안에 펼쳐져 realip가 늦게 적용되므로 ModSecurity 기록에 프록시 주소가 남을 수 있습니다. 신뢰 범위에는 실제 프록시 주소만 넣습니다.
  - **앱에 넘기는 전달 헤더**(공유 템플릿 `includes/proxy_backend.conf.template`, 모든 스택 공통): `X-Forwarded-For`는 방문자 값 뒤에 덧붙이지 않고 nginx가 정한 클라이언트 IP(`$remote_addr`) 하나로 덮어씁니다. `X-Real-IP`·`X-Forwarded-Proto`·`X-Forwarded-Port`도 nginx가 정한 값으로 덮어씁니다. `Forwarded`·`X-Forwarded-Host`·`X-Forwarded-Prefix`·`X-Forwarded-Ssl`은 빈 값으로 지워 앱에 보내지 않습니다.
  - **업스트림 이름 재해석**: `proxy_pass`가 변수(`$zeekad_backend`)라 nginx가 `dashboard-app` 이름을 요청 때 Docker 내장 DNS(`127.0.0.11`, 이미지 `nginx.conf`의 `resolver`, `RESOLVER_CONFIG="valid=10s ipv6=off"`)로 다시 해석합니다. 앱 컨테이너를 다시 만들어 IP가 바뀌어도 `nginx-waf`를 재시작할 필요가 없습니다. 앱이 멈춘 동안에는 `502`(`/50x.html`)를 냅니다.
- **`dashboard-app` (`Dockerfile`)**: `eclipse-temurin:17-jre-alpine` 기반 비루트(`appuser`) Spring Boot + MyBatis JSON REST API 서버입니다. 같은 jar 안의 React SPA 정적 번들(`BOOT-INF/classes/static/index.html`, `static/assets/*`)도 함께 서빙합니다. 최종 이미지에는 Node.js·npm·`node_modules`가 없습니다(Node는 빌드 단계에서만 사용).
  - `expose: ["8080"]`만 있어 Docker 내부 네트워크(`dashboard-net`)에서만 닿고 호스트 포트는 열지 않습니다.
  - `server.forward-headers-strategy: framework`로 앞단 WAF가 보낸 전달 헤더(`Forwarded`가 있으면 그것, 없으면 `X-Forwarded-Proto`·`X-Forwarded-Host`·`X-Forwarded-Port`·`X-Forwarded-Prefix`)를 요청 주소·리다이렉트 URL에 반영합니다. 클라이언트 IP는 `X-Forwarded-For`의 **맨 왼쪽** 값을 씁니다(감사 로그 `client_ip`). `X-Real-IP`는 앱이 쓰지 않습니다.
  - 앱은 받은 전달 헤더를 그대로 믿습니다. 이 값이 안전하려면 앱에 `nginx-waf`만 닿아야 합니다. 그래서 `dashboard-app` 포트(`8080`)를 호스트나 WAF 밖으로 열면(`ports:`) 안 됩니다. 정적 테스트가 세 compose 파일의 `dashboard-app`에 `ports:`가 없는지 확인합니다.
  - 이 전제의 한계: 같은 Docker 네트워크의 다른 컨테이너(`zeek_AD`의 `api`·파이프라인·PostgreSQL 등)는 `dashboard-app:8080`에 직접 붙어 전달 헤더를 꾸밀 수 있습니다. 그 컨테이너가 탈취되면 감사 로그 IP를 바꿀 수 있습니다. 근본 대책(앱이 WAF에서 온 전달 헤더만 믿게 하기, WAF↔앱 전용 내부 네트워크 등)은 후속 과제입니다.
  - 프로덕션 `bootJar`에는 H2 드라이버와 `application-test.yml`이 들어가지 않습니다.

### 1.3 SPA 라우팅과 `/api/**` 경계
- **SPA 화면 경로**: `/login`, `/login/totp`, `/login/totp/setup`, `/`, `/incidents`, `/incidents/{jobId}/rank/{queueRank}`, `/reviews`, `/operations`, `/admin/users`, `/admin/audit-logs`는 서버가 `index.html`(SPA 셸)로 포워딩하고 화면은 브라우저의 React가 그립니다. 비인증 사용자는 `/login`을 제외한 화면 경로에서 `302 /login`으로 이동합니다. `/admin/**` 화면은 `ADMIN`만 열 수 있습니다.
- **정적 자산**: `/assets/*.js`·`/assets/*.css`·`/index.html`은 인증 없이 받습니다(`Content-Type` `text/javascript`·`text/css`, `X-Content-Type-Options: nosniff`). CSP는 `script-src 'self'; style-src 'self'`로 인라인 스크립트·스타일을 허용하지 않습니다.
- **JSON API (`/api/**`)**: SPA 폴백 대상이 아닙니다. 비인증 요청은 `401` JSON(`code: UNAUTHENTICATED`), 인증된 세션의 없는 경로는 `404` JSON(`code: NOT_FOUND`)이며 `index.html`을 돌려주지 않습니다. 관리자는 1차 로그인 뒤 TOTP 검증 전까지 업무 API가 `403`(`TOTP_VERIFICATION_REQUIRED`)입니다.
- **CSRF**: SPA는 `GET /api/auth/csrf`로 `XSRF-TOKEN` 쿠키(`Secure; SameSite=Lax`, JS가 읽도록 HttpOnly 아님)를 받고 쓰기 요청마다 그 값을 `X-XSRF-TOKEN` 헤더로 보냅니다(이중 제출). 세션 쿠키 `ZEEKAD_SESSION`은 `Secure; HttpOnly; SameSite=Lax`입니다. 로그인·TOTP 뒤에는 토큰이 바뀌므로 클라이언트는 요청마다 최신 쿠키 값을 씁니다.

---

## 2. 데이터 계약 v2.1 및 PostgreSQL 17 / FastAPI 연동

### 2.1 PostgreSQL 데이터베이스 3중 경계
대시보드는 PostgreSQL 17 서버 하나(Compose 배포: `postgres:5432` 등 서비스명, 로컬 개발: `127.0.0.1:55432`) 안에서 논리 DB와 계정을 셋으로 나눠 씁니다.

1. **대시보드 자체 DB (`zeekad_dashboard`, 계정 `dashboard_app`)**
   - 대시보드가 시작할 때 Flyway(`classpath:db/migration/postgresql`)가 `users`, `user_capture_access`, `audit_logs` 테이블과 `audit_logs` `UPDATE`/`DELETE` 차단 트리거(`trg_audit_logs_immutable`)를 만듭니다.
   - `dashboard_app` 계정은 `zeekad_dashboard` 데이터베이스의 DDL/DML 권한만 있습니다.
2. **`zeekad` 읽기 전용 계정 (`dashboard_ro`)**
   - `zeekad` 데이터베이스의 `dashboard` 스키마에 있는 데이터 계약 뷰 14종(v1 5종 · v2 7종 · v2.1 `latest_incident_queue` 1종 · migration 017 `feedback_summary` 1종)의 `SELECT` 권한만 줍니다.
     - v1 (5종): `incident_queue`, `incident_model_scores`, `asset_names`, `scoring_jobs`, `model_bundles`
     - v2 (7종): `incident_reports`, `send_decisions`, `slack_deliveries`(`zeekad_thread_parent`, `zeekad_reply_broadcast` 포함), `slack_summaries`, `incident_status`, `incident_status_history`, `analyst_review_queue`(`zeekad_review_resumed_at`, `zeekad_review_resume_failed` 포함)
     - v2.1 (1종): `latest_incident_queue` (캡처별 가장 최근 성공 작업의 사건 큐 + `zeekad_report_job_id`, `zeekad_report_kind`, `zeekad_would_send`, `zeekad_status`, `zeekad_resolution`, `status_updated_at`, `zeekad_review_action`, `zeekad_review_pending`)
     - migration 017 (1종): `feedback_summary` (캡처 × 모델 묶음 × `zeekad_picked_by`['all' 전체 포함] 분석가 결론 집계: 사건/알림/결론 수, TP/FP/Benign 분포, `zeekad_precision`, `zeekad_alert_precision`, `zeekad_alert_resolved_rate`)
   - 원본 테이블(`raw_*`) 권한과 `INSERT`/`UPDATE`/`DELETE` 권한은 주지 않습니다.
3. **`zeekad` 쓰기 함수 전용 계정 (`dashboard_rw`)**
   - `zeekad` 데이터베이스의 `dashboard` 스키마 `USAGE`와 아래 두 함수의 `EXECUTE` 권한만 줍니다.
     - `dashboard.transition_incident(p_job, p_incident, p_to, p_actor, p_reason, p_resolution)`
     - `dashboard.decide_review(p_job, p_incident, p_action, p_analyst, p_note)`

### 2.2 v2.1 · migration 014~016 조인 규칙, Slack 스레드, 검토 재개 및 결합 v2
- 실습망 캡처(`lab-YYYYMMDD`)는 5분마다 전체를 다시 계산하므로 같은 캡처에 `job_id`가 여러 개 생깁니다.
- **조사 큐 기본 화면**: `dashboard.latest_incident_queue`를 조회해 캡처별 최신 성공 작업의 사건만 표시합니다(지난 작업을 직접 고르거나 성공 작업이 없으면 `incident_queue`로 폴백).
- **보고서·전송판단·검토 조인**: `incident_reports`, `send_decisions`, `analyst_review_queue`는 `(zeekad_report_job_id, incident_id)`로 조인합니다. `zeekad_report_job_id`가 `NULL`이면 `"보고서 없음"`으로 표시합니다.
- **Slack 기록 `incident_id` 단독 조회 및 스레드 표시**: `slack_deliveries`는 처음 알린 작업에만 기록됩니다(보고서를 뒤 작업에서 다시 만들어도 그대로). 그래서 `job_id`나 `zeekad_report_job_id`로 조인하지 않고 `incident_id`만으로 찾습니다. 화면에서는 `coalesce(zeekad_thread_parent, incident_id)`로 묶어 Slack 채널 스레드 모양(머리 알림 → 후속 답글)으로 보입니다. `zeekad_reply_broadcast`가 `true`이면 `"채널 재알림(broadcast)"` 배지를 붙입니다.
- **분석가 검토 결정 및 30초 주기 재개 흐름**: `/reviews` 및 사건 상세 화면에서 `ANALYST`·`ADMIN`이 미결정(`zeekad_review_action IS NULL`) 요청을 `confirm`(조사 진행) 또는 `dismiss`(오탐 종료)로 결정하면 `dashboard.decide_review`를 부릅니다. 같은 사건에 여러 작업의 요청이 있으면 `zeekad_report_job_id`의 요청만 보입니다. 결정한 뒤 파이프라인이 30초 주기로 재개해 반영할 때까지 `"반영 중"`으로 표시합니다. 끝나면 `"반영됨"`(`zeekad_review_resumed_at`), 실패하면 `"반영 실패(운영자 확인)"`(`zeekad_review_resume_failed`)입니다.
- **모델 묶음 `zeekad-fusion/3` (결합 v2) 및 30분 초과 사건**: 결합 v2 champion 번들 `zeekad-fusion/3`은 여러 탐지 창을 합쳐 30분보다 긴 사건을 만들 수 있습니다. 대시보드는 사건 길이에 상한이 있다고 가정하지 않고 그대로 보여 줍니다.
- **모델 점수·근거 API·상태 변경**: `incident_model_scores`, 근거 API(`GET /api/v1/jobs/{job_id}/incidents/{rank}`), `transition_incident`의 `p_job`은 현재 화면 큐의 `job_id`(최신 작업)를 사용합니다.
- **사건 상태 및 이력**: 상태는 `incident_id`에 붙어 있어 새 채점 작업이 생겨도 이어집니다. `incident_status_history`는 `incident_id` 기준으로 모든 작업의 이력을 모아 최신순으로 보여 줍니다.
- **운영 상태 분석가 결론 집계(`feedback_summary`)**: `/operations` 화면에서 `dashboard.feedback_summary`를 `SELECT *` 방어 매핑과 허용 캡처 IDOR 필터로 조회해 보여 줍니다. 맨 위 상태 카드(파이프라인·모델 판정·경보) 아래에 캡처별 `'all'`(모든 모델 합계) 행만 기본으로 보이고 탐지 모델별 행은 펼쳐서 봅니다. 정탐률은 판정 10건 미만이면 "표본 부족"으로 보입니다(값은 툴팁). 미탐(재현율)은 이 집계로 알 수 없다고 안내합니다(T20, 정의는 `docs/ui-terminology.md` '운영 지표 정의'). 첫 화면(`/`)은 같은 API로 그리는 관제 현황판입니다.

### 2.3 근거 FastAPI (`evidence.v1`) 연동
- 대시보드 백엔드는 `ZEEKAD_EVIDENCE_API_URL`로 `GET /api/v1/jobs`, `GET /api/v1/captures/{capture_id}/queue`, `GET /api/v1/jobs/{job_id}/incidents/{rank}`를 부릅니다(읽기 전용).
- 통합 Compose 배포에서는 `http://api:8000`(실제 `zeek_AD` 서비스명에 맞춤), 로컬 개발에서는 `http://127.0.0.1:8000`이나 `http://host.docker.internal:8000`을 씁니다.
- FastAPI가 멈춰도 사건 상세 화면의 DB 뷰 정보(모델 창 비율, 보고서, 전송 판단, Slack 기록, 검토 상태, 상태 이력)는 폴백 안내와 함께 그대로 보입니다.

### 2.4 실습망 시험 데이터(`lab-20261119`) 참고 메모
- `lab-20261119` 등 실습망 시험 데이터에는 가상 재생·스크립트 시험용 호스트 트래픽(예: Kali 공격 VM `10.10.0.50`, 배포 VM `10.10.0.10`)이 포함될 수 있습니다.
- 대시보드 코드(백엔드·SPA)는 특정 시험 날짜나 IP를 하드코딩하지 않습니다. `asset_names`·`host_ip`와 `VIEWER` 마스킹 규칙대로 표시합니다. 분석할 때는 이 IP가 실습망 시험 호스트라는 점을 감안해 정상·공격을 판단합니다.

---

## 3. 환경 변수 설정 (`.env`)

저장소의 [`.env.example`](../.env.example)을 `.env`로 복사한 뒤 배포 환경에 맞게 값을 채웁니다. `.env`는 `.gitignore`와 `.dockerignore`에 있어 Git 커밋이나 Docker 이미지에 들어가지 않습니다.

```bash
cp .env.example .env
```

| 변수명 | 설명 | VMware Compose 배포 예시 | 로컬 개발 / Docker 호스트 연동 예시 |
|---|---|---|---|
| `DASHBOARD_DB_HOST` | 대시보드 자체 DB 호스트 | `postgres` (`zeek_AD` DB 서비스명) | `127.0.0.1` (bootRun) / `host.docker.internal` |
| `DASHBOARD_DB_PORT` | 대시보드 자체 DB 포트 | `5432` | `55432` |
| `DASHBOARD_DB_NAME` | 대시보드 자체 DB 이름 | `zeekad_dashboard` | `zeekad_dashboard` |
| `DASHBOARD_DB_USER` | 대시보드 자체 DB 계정 | `dashboard_app` | `dashboard_app` |
| `DASHBOARD_APP_PASSWORD` | 대시보드 자체 DB 비밀번호 | 긴 난수 비밀번호 | 긴 난수 비밀번호 |
| `ZEEKAD_DB_HOST` | `zeekad` DB 호스트 | `postgres` (`zeek_AD` DB 서비스명) | `127.0.0.1` (bootRun) / `host.docker.internal` |
| `ZEEKAD_DB_PORT` | `zeekad` DB 포트 | `5432` | `55432` |
| `ZEEKAD_DB_NAME` | `zeekad` DB 이름 | `zeekad` | `zeekad` |
| `ZEEKAD_RO_USER` | `zeekad` 읽기 전용 계정 | `dashboard_ro` | `dashboard_ro` |
| `ZEEKAD_RO_PASSWORD` | `zeekad` 읽기 전용 비밀번호 | 긴 난수 비밀번호 | 긴 난수 비밀번호 |
| `ZEEKAD_RW_USER` | `zeekad` 상태 전이 전용 계정 | `dashboard_rw` | `dashboard_rw` |
| `ZEEKAD_RW_PASSWORD` | `zeekad` 상태 전이 비밀번호 | 긴 난수 비밀번호 | 긴 난수 비밀번호 |
| `ZEEKAD_EVIDENCE_API_URL` | FastAPI 근거 API 주소 | `http://api:8000` | `http://127.0.0.1:8000` / `http://host.docker.internal:8000` |
| `DASHBOARD_COOKIE_SECURE` | 세션 쿠키 `Secure` 속성 (HTTPS 앞단 WAF 필수 `true`) | `true` | `true` (HTTP 단독 테스트 시만 `false`) |
| `DASHBOARD_SESSION_IDLE_TIMEOUT` | Spring 세션 유휴 만료 | `30m` | `30m` |
| `DASHBOARD_MAX_FAILED_ATTEMPTS` | 로그인 연속 실패 잠금 횟수 | `5` | `5` |
| `DASHBOARD_LOCKOUT_MINUTES` | 계정 잠금 유지 시간(분) | `15` | `15` |
| `DASHBOARD_LOCKOUT_EXEMPT_USERNAMES` | 계정 잠금 제외 공유 조회 계정(T29). 쉼표 목록, 대소문자·앞뒤 공백 무시. 로그인 때 DB 역할이 VIEWER인 계정만 빠진다(ANALYST·ADMIN은 목록에 있어도 잠긴다). 빠진 계정은 틀려도 실패 수·잠금을 바꾸지 않는다(실패 감사 `LOGIN_FAILURE`는 `lockoutExempt: true`로 남는다). **비밀번호를 공개한 공유 조회 계정만 넣는다**: 비공개 비밀번호 계정을 넣으면 여러 IP에서 대입할 때 막을 것이 IP당 로그인 속도 제한뿐이다. 목록의 계정이 없거나 VIEWER가 아니면 시작할 때 경고 로그(이름만)를 남기고 시작은 막지 않는다 | 비움 | 비움 |
| `DASHBOARD_IDLE_TIMEOUT_MINUTES` | 필터 유휴 만료(분) | `30` | `30` |
| `DASHBOARD_ABSOLUTE_TIMEOUT_MINUTES` | 필터 절대 만료(분) | `480` | `480` |
| `DASHBOARD_TIME_ANCHOR` | 기준 시각(T23). 인시던트 큐의 상대 기간(최근 1시간·24시간·7일·30일)을 이 시각에서 거꾸로 센다. `now` = 서버 현재 시각(데이터가 계속 들어오는 운영). `latest-data` = 그 사용자가 볼 수 있는 캡처의 성공 탐지 작업 완료 시각 최대값(데이터가 더 늘지 않는 고정 스냅샷, 과거 데이터 조사용). `latest-data`면 모든 화면 맨 위에 "고정 스냅샷 · 기준 시각"을 보이고 새 인시던트 자동 갱신을 끈다. 다른 값이면 앱이 시작하지 않는다 | `now` | `now` |
| `DASHBOARD_LIVE_CAPTURE_PATTERNS` | 수집원 분류(T23). 맞는 캡처는 "실습망 센서", 나머지는 "가져온 데이터". 쉼표 목록, 패턴 문법은 허용 캡처와 같다(`접두어*`). 잘못된 패턴이면 시작하지 않는다 | `lab-*` | `lab-*` |
| `DASHBOARD_SENSOR_STALE_AFTER`, `DASHBOARD_SENSOR_DOWN_AFTER` | 센서 상태(T24). 기준 시각 − 센서의 마지막 채점이 stale 이하면 정상, down 이하면 지연, 넘으면 중단(가장 최근 끝난 작업이 실패면 실패). Spring Duration(`15m`, `PT15M`). 0 이하이거나 stale ≥ down이면 시작하지 않는다. `compose.yml`은 넘기지 않아 기본값을 쓴다(바꾸려면 `dashboard-app` environment에 더한다) | `15m`, `1h` | `15m`, `1h` |
| `DASHBOARD_SLA_ACK_HIGH`, `DASHBOARD_SLA_ACK_MEDIUM`, `DASHBOARD_SLA_ACK_LOW` | 착수 목표(T25). 실습망 신규 인시던트가 탐지 뒤 지금 우선순위의 목표를 넘기면 "착수 지연"(가져온 데이터는 따지지 않는다). Spring Duration(`30m`, `4h`). 0 이하이거나 high ≤ medium ≤ low가 아니면 시작하지 않는다. `compose.yml`은 넘기지 않아 기본값을 쓴다 | `30m`, `4h`, `24h` | `30m`, `4h`, `24h` |
| `DASHBOARD_BOOTSTRAP_PASSWORD` | `users` 테이블이 비어 있을 때 4계정 시드용 공통 비밀번호 | 초기 기동 후 비움 권장 | 초기 기동 후 비움 권장 |
| `BOOTSTRAP_VIEWER1_PASSWORD` ~ `BOOTSTRAP_ADMIN_PASSWORD` | 계정별 개별 부트스트랩 비밀번호(선택) | 선택 | 선택 |
| `BOOTSTRAP_ADMIN_TOTP_SECRET` | `admin` TOTP Base32 시크릿(비우면 `/login/totp/setup`에서 등록) | 선택 | 선택 |
| `WAF_HTTP_PORT`, `WAF_HTTPS_PORT` | 호스트에 노출할 WAF HTTP/HTTPS 포트 | `80`, `443` | `18080`, `18443` (충돌 회피 시) |
| `SSL_REDIRECT_PORT` | HTTP → HTTPS `301` 리다이렉트 대상 포트 | `443` (`${WAF_HTTPS_PORT}`) | `18443` |
| `WAF_SERVER_NAME`, `SERVER_NAME` | Nginx `server_name` | 배포 VM IP 또는 도메인 | `localhost` |
| `PROXY_HOST_HEADER` | 백엔드로 전달할 `Host` 헤더 | `$http_host` (`compose.yml` 기본 `$$http_host`) | `$http_host` |
| `SSL_CERT_FILE`, `SSL_CERT_KEY_FILE` | WAF TLS 인증서/개인키 컨테이너 내부 경로 | `/etc/nginx/ssl/server.crt`, `/etc/nginx/ssl/server.key` | `/etc/nginx/conf/server.crt`, `/etc/nginx/conf/server.key` (자동 생성) |

---

## 4. 이미지 빌드 및 VMware Ubuntu Server 배포 절차

### 4.1 Docker 이미지 빌드 (`Dockerfile` & `docker/nginx-waf/Dockerfile`)
프로젝트 루트에서 Spring Boot 애플리케이션(`Dockerfile`)과 ModSecurity WAF(`docker/nginx-waf/Dockerfile`) 이미지를 함께 빌드합니다. 호스트에 Node.js·JDK가 없어도 됩니다.

`Dockerfile`은 3단계 멀티스테이지 빌드입니다.
1. **`frontend` (`node:24-alpine`)**: `frontend/package.json`·`package-lock.json`만 먼저 복사해 `npm ci`(빌드 도구가 devDependencies이므로 `--omit=dev`를 쓰지 않음) → 나머지 `frontend/` 복사 → `npm run build`로 `frontend/dist` 생성.
2. **`builder` (`eclipse-temurin:17-jdk-alpine`)**: `src/main`과 1단계의 `frontend/dist`를 받아 `./gradlew bootJar`. `build.gradle` `processResources`가 `frontend/dist`를 jar의 `static/`으로 넣습니다. Gradle은 Node·npm을 호출하지 않습니다.
3. **런타임 (`eclipse-temurin:17-jre-alpine`)**: `apk upgrade`, 비루트 `appuser`, `HEALTHCHECK`(`/login`), jar만 복사. Node.js 런타임 컨테이너는 배포 스택에 두지 않습니다.

`.dockerignore`가 `frontend/node_modules`·`frontend/dist`·`frontend/.vite`를 빌드 컨텍스트에서 빼므로 Windows 호스트 산출물이 이미지에 섞이지 않습니다. `RUN apk upgrade` 레이어를 빌드 캐시에서 다시 쓰면 그 뒤 나온 Alpine 보안 패치가 들어가지 않습니다. 그래서 배포·보안 재검증 전에는 `docker compose build --pull --no-cache`로 다시 빌드합니다.

```bash
docker compose build
```

따로 빌드하려면:
```bash
docker build -t zeek-ad-dashboard-app:local -f Dockerfile .
docker build -t zeek-ad-dashboard-waf:local -f docker/nginx-waf/Dockerfile ./docker/nginx-waf
```

### 4.2 `zeek_AD`와 통합 기동 방법 (2가지 중 선택)

#### 방법 A: 동일 Docker Compose 파일 병합 실행 (권장)
`zeek_AD`의 `compose.yml`과 `zeek_ad_dashboard/compose.yml`을 같은 프로젝트로 합쳐 기동합니다. `zeek_AD` 네트워크와 `dashboard-net`이 다르면 `compose.override.yml`에서 `dashboard-app`의 `networks`에 `zeek_AD` 네트워크를 함께 연결하거나 두 Compose의 네트워크 이름을 통일합니다.

```bash
docker compose -f /opt/zeek_AD/compose.yml -f /opt/zeek_ad_dashboard/compose.yml --env-file /opt/zeek_ad_dashboard/.env config -q
docker compose -f /opt/zeek_AD/compose.yml -f /opt/zeek_ad_dashboard/compose.yml --env-file /opt/zeek_ad_dashboard/.env up -d --build
```

#### 방법 B: 별도 Compose 스택 + `zeek_AD` 외부 네트워크 연동
`zeek_AD`가 이미 `zeek_ad_default` 같은 Docker 네트워크에서 실행 중이면 `zeek_ad_dashboard/compose.yml`의 `networks.dashboard-net`을 주석 안내대로 `external: true`로 바꾼 뒤 띄웁니다.

```yaml
networks:
  dashboard-net:
    external: true
    name: ${ZEEKAD_DOCKER_NETWORK:-zeek_ad_default}
```

```bash
docker compose config -q
docker compose up -d --build
docker compose ps
```

### 4.3 초기 접속 및 `lab-*` 접근 패턴 부여
1. Windows 브라우저에서 `https://<배포_VM_IP>`로 접속합니다.
2. `admin` 계정으로 로그인하면 SPA가 `/login/totp/setup`(최초, QR 등록) 또는 `/login/totp`(등록 후)로 이동합니다. TOTP를 마친 뒤 `/admin/users`에서 계정을 관리합니다.
3. 기본 시드 계정의 허용 패턴(`viewer1`/`analyst1`: `cic17-*`, `analyst2`: `syn1-*`, `admin`: `*`) 외에 실습망 캡처(`lab-YYYYMMDD`)를 볼 분석가·조회자는 `/admin/users`에서 해당 계정의 허용 캡처 패턴에 `lab-*`(또는 `cic17-*,lab-*`)를 추가·저장합니다.
4. 계정 설정을 마치면 `.env`에서 `DASHBOARD_BOOTSTRAP_PASSWORD` 등 부트스트랩 변수를 비우고 `docker compose up -d`로 다시 적용하기를 권장합니다.

---

## 5. Nginx + ModSecurity WAF TLS 인증서 운영 방법 (VM IP SAN 지원)

`owasp/modsecurity-crs:nginx-alpine`의 내장 진입점 스크립트(`/docker-entrypoint.d/10-generate-certificate.sh`)는 고치지 않고 그대로 씁니다. 환경에 따라 아래 두 방식 중 하나를 고릅니다.

1. **기본 자체 서명 인증서(자동 생성)**:
   - `SSL_CERT_FILE=/etc/nginx/conf/server.crt`, `SSL_CERT_KEY_FILE=/etc/nginx/conf/server.key`(기본값)를 그대로 두면 컨테이너가 시작할 때 `localhost`용 EC P-256 자체 서명 인증서를 만듭니다. Git과 이미지에는 개인키가 남지 않습니다.
2. **배포 VM IP SAN 포함 자체 서명 / 사내 CA 인증서 마운트(권장)**:
   - Windows 브라우저에서 `https://<VM_IP>`로 접속할 때 IP SAN 경고를 줄이려면 VM IP를 SAN에 넣은 인증서를 Ubuntu Server의 `./docker/certs/`에 만들어 마운트합니다(`compose.yml`이 `./docker/certs:/etc/nginx/ssl:ro`를 기본으로 마운트함).
   - `nginx-waf` 컨테이너는 비루트 `nginx`(`uid=101`, `gid=101`)로 실행되므로 개인키 권한을 `101:101` 소유 · `600`으로 설정해야 합니다.

```bash
mkdir -p ./docker/certs
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 365 \
  -keyout ./docker/certs/server.key \
  -out ./docker/certs/server.crt \
  -subj "/CN=<VM_IP>" \
  -addext "subjectAltName=IP:<VM_IP>,DNS:localhost"
sudo chown 101:101 ./docker/certs/server.key ./docker/certs/server.crt
chmod 600 ./docker/certs/server.key
chmod 644 ./docker/certs/server.crt
```

`.env`에 아래 항목을 지정한 뒤 `nginx-waf`를 재시작합니다.
```dotenv
WAF_SERVER_NAME=<VM_IP>
SERVER_NAME=<VM_IP>
SSL_CERT_FILE=/etc/nginx/ssl/server.crt
SSL_CERT_KEY_FILE=/etc/nginx/ssl/server.key
```
```bash
docker compose up -d nginx-waf
```

---

## 6. 로컬 독립 E2E 검증 구성 (임시 PostgreSQL 17 포함)

외부 PostgreSQL 없이 Docker Compose 오버라이드(`docker/verify/compose.verify.yml`)로 실제 PostgreSQL 17 + Flyway + `latest_incident_queue` + `dashboard.transition_incident` + `dashboard.decide_review` + Slack 스레드 + WAF + Trivy + OWASP ZAP을 한 번에 검증합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/security-scan.ps1 -EvidenceDir "handoff/<ID>/evidence"
```
- 단계: CycloneDX SBOM → 이미지 빌드 → Trivy(SBOM / FS(`frontend/package-lock.json` npm 포함, `frontend/node_modules`·`frontend/dist` 제외) / 앱·WAF 이미지) → PostgreSQL 17 + WAF E2E → OWASP ZAP 베이스라인.
- E2E는 JSON API로 진행합니다: `GET /api/auth/csrf`로 `XSRF-TOKEN`을 받고 `X-XSRF-TOKEN` 헤더 + JSON 본문으로 `POST /api/auth/login`, 관리자는 `POST /api/auth/totp/verify`. 응답은 JSON 필드로 판정하고 WAF 차단은 `403` + 앱 JSON 오류가 아님 + `nginx-waf` ModSecurity 감사 로그의 규칙 ID로 판정합니다. 결과는 `waf-e2e-verification.txt`에 남습니다.
- ZAP은 정보성 경고만 있어도 종료 코드 `2`이므로 `zap-baseline.json`의 위험 등급별 경고 수로 판정합니다. High·Medium·Low가 하나라도 있으면 실패입니다. 허용하는 예외는 모든 인스턴스가 `XSRF-TOKEN`인 Low `10010`(Cookie No HttpOnly Flag) 하나입니다(이중 제출 CSRF라 JS가 읽어야 하는 쿠키).
- E2E `[9]`(`T14`)는 클라이언트 IP·전달 헤더 위조를 봅니다: 전달 헤더 없이 로그인한 `viewer1`의 감사 로그 `client_ip`를 기준 B로 잡습니다. 그다음 `X-Real-IP`·`X-Forwarded-For`·`Forwarded: for=`를 하나씩(그리고 `X-Forwarded-Host`·`X-Forwarded-Prefix`까지 모두) 붙인 로그인 성공·실패와 조합 헤더를 붙인 WAF 차단 요청의 ModSecurity `client_ip`가 모두 B인지 확인합니다. `X-Forwarded-Host`·`Forwarded: host=`·`X-Forwarded-Prefix`를 붙인 비인증 리다이렉트 `Location`이 헤더 없을 때와 같은지도 확인합니다. 감사 로그는 `verify-postgres`에서 읽기 전용 `SELECT`로 읽습니다.
- E2E는 `127.0.0.1`로 접속하므로 모든 요청에 CRS `920350`(숫자 IP Host, 3점)이 붙습니다. 실제 배포에서는 `WAF_SERVER_NAME`의 호스트명으로 접속하는 것을 권장합니다.
- 실행할 때만 난수 비밀번호를 만들어 `docker/verify/compose.verify.yml`을 띄웁니다. 검증이 끝나면 `docker compose down -v`로 임시 컨테이너와 볼륨을 지웁니다.
