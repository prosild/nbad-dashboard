# zeek_ad_dashboard 배포 및 운영 가이드

이 문서는 `zeek_ad_dashboard`를 **VMware Ubuntu Server 단일 배포 VM(zeek_AD 통합 Docker Compose)** 또는 **로컬 개발·검증 환경**에 배포·운영하기 위한 절차와 보안 설정 기준을 설명합니다.

---

## 1. 아키텍처 및 네트워크 경계 개요

### 1.1 VMware 실습·운영 토폴로지
- **배포 VM (Ubuntu Server 1대)**: `zeek_AD` 파이프라인(PostgreSQL 17, 근거 FastAPI `api` 등)과 `zeek_ad_dashboard`(`dashboard-app`, `nginx-waf`)를 **같은 Docker Compose 프로젝트 또는 공유 Docker 네트워크**로 기동합니다.
- **공격 VM (Kali Linux)**: 격리된 실습망(Host-Only / Internal 가상 네트워크)으로만 공격 트래픽을 전송합니다.
- **사용자 접속 (Windows 호스트 브라우저)**: Windows 브라우저에서 배포 VM의 IP 또는 호스트명(`https://<VM_IP>`)으로 접속합니다. 외부 요청은 반드시 `nginx-waf`를 통해서만 유입됩니다.

### 1.2 대시보드 컨테이너 구성
- **`nginx-waf` (`docker/nginx-waf/Dockerfile`)**: `owasp/modsecurity-crs:nginx-alpine` 기반 앞단 리버스 프록시 + ModSecurity v3 WAF(OWASP CRS `PARANOIA=1`, `SecRuleEngine On`, `USER nginx`).
  - 외부 트래픽은 `nginx-waf`의 HTTPS(`${WAF_HTTPS_PORT:-443}` → 컨테이너 `8443`) 및 HTTP(`${WAF_HTTP_PORT:-80}` → 컨테이너 `8080`, HTTPS로 `301` 리다이렉트) 포트만 통과합니다.
  - `/actuator/**` 경로는 앞단 Nginx에서 `403 Forbidden`으로 즉시 차단합니다.
  - `Server` 헤더 및 와일드카드 CORS 헤더를 제거하고, HTTPS 응답에 `Strict-Transport-Security` 헤더를 추가하며, 백엔드(`dashboard-app`)의 `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, `COOP/COEP/CORP`, `Permissions-Policy` 헤더를 보존합니다.
- **`dashboard-app` (`Dockerfile`)**: `eclipse-temurin:17-jre-alpine` 기반 비루트(`appuser`) Spring Boot + MyBatis 웹 서버.
  - `expose: ["8080"]`으로 Docker 내부 네트워크(`dashboard-net`)에서만 접근 가능하며 호스트 포트를 직접 열지 않습니다.
  - `server.forward-headers-strategy: framework`로 앞단 WAF가 전달하는 `X-Forwarded-Proto`, `X-Forwarded-For`, `X-Real-IP`, `Host`를 처리합니다.
  - 프로덕션 `bootJar`에는 H2 드라이버 및 `application-test.yml`이 포함되지 않습니다.

---

## 2. 데이터 계약 v2.1 및 PostgreSQL 17 / FastAPI 연동

### 2.1 PostgreSQL 데이터베이스 3중 경계
대시보드는 단일 물리 PostgreSQL 17 서버(Compose 배포: `postgres:5432` 등 서비스명, 로컬 개발: `127.0.0.1:55432`) 안에서 논리 DB와 계정을 다음 3중 경계로 분리하여 사용합니다.

1. **대시보드 자체 DB (`zeekad_dashboard`, 계정 `dashboard_app`)**
   - 대시보드 기동 시 Flyway(`classpath:db/migration/postgresql`)가 자동으로 `users`, `user_capture_access`, `audit_logs` 테이블 및 `audit_logs` `UPDATE`/`DELETE` 차단 트리거(`trg_audit_logs_immutable`)를 생성합니다.
   - `dashboard_app` 계정은 `zeekad_dashboard` 데이터베이스의 DDL/DML 권한만 보유합니다.
2. **`zeekad` 읽기 전용 계정 (`dashboard_ro`)**
   - `zeekad` 데이터베이스의 `dashboard` 스키마 내 데이터 계약 **13종 뷰**(v1 5종 · v2 7종 · v2.1 `latest_incident_queue` 1종)에 대한 `SELECT` 권한만 부여합니다.
     - v1 (5종): `incident_queue`, `incident_model_scores`, `asset_names`, `scoring_jobs`, `model_bundles`
     - v2 (7종): `incident_reports`, `send_decisions`, `slack_deliveries`(`zeekad_thread_parent`, `zeekad_reply_broadcast` 포함), `slack_summaries`, `incident_status`, `incident_status_history`, `analyst_review_queue`(`zeekad_review_resumed_at`, `zeekad_review_resume_failed` 포함)
     - v2.1 (1종): `latest_incident_queue` (캡처별 가장 최근 성공 작업의 사건 큐 + `zeekad_report_job_id`, `zeekad_report_kind`, `zeekad_would_send`, `zeekad_status`, `zeekad_resolution`, `status_updated_at`, `zeekad_review_action`, `zeekad_review_pending`)
   - 원본 테이블(`raw_*`) 및 `INSERT`/`UPDATE`/`DELETE` 권한은 부여하지 않습니다.
3. **`zeekad` 쓰기 함수 전용 계정 (`dashboard_rw`)**
   - `zeekad` 데이터베이스의 `dashboard` 스키마 `USAGE`와 다음 두 함수에 대한 `EXECUTE` 권한만 부여합니다.
     - `dashboard.transition_incident(p_job, p_incident, p_to, p_actor, p_reason, p_resolution)`
     - `dashboard.decide_review(p_job, p_incident, p_action, p_analyst, p_note)`

### 2.2 v2.1 · migration 014~016 조인 규칙, Slack 스레드, 검토 재개 및 결합 v2
- 실습망 캡처(`lab-YYYYMMDD`)는 5분마다 전체를 재계산하므로 동일 캡처에 여러 `job_id`가 생성됩니다.
- **조사 큐 기본 화면**: `dashboard.latest_incident_queue`를 조회해 캡처별 최신 성공 작업의 사건만 표시합니다(과거 작업 명시 선택 또는 성공 작업 부재 시 `incident_queue`로 폴백).
- **보고서·전송판단·검토 조인**: `incident_reports`, `send_decisions`, `analyst_review_queue`는 `(zeekad_report_job_id, incident_id)`로 조인하며 `zeekad_report_job_id`가 `NULL`이면 `"보고서 없음"`으로 표시합니다.
- **Slack 기록 `incident_id` 단독 조회 및 스레드 표시**: `slack_deliveries`는 보고서가 뒤 작업에서 재생성되더라도 처음 알린 작업에만 기록되므로 `job_id`나 `zeekad_report_job_id`로 조인하지 않고 **`incident_id`만으로 조회**합니다. 화면에서는 `coalesce(zeekad_thread_parent, incident_id)`로 묶어 Slack 채널 스레드 모양(머리 알림 → 후속 답글)으로 표시하고 `zeekad_reply_broadcast`가 `true`이면 `"채널 재알림(broadcast)"` 배지를 함께 표시합니다.
- **분석가 검토 결정 및 30초 주기 재개 흐름**: `/reviews` 및 사건 상세 화면에서 `ANALYST`·`ADMIN`이 미결정(`zeekad_review_action IS NULL`) 요청을 `confirm`(조사 진행) 또는 `dismiss`(오탐 종료)로 결정하면 `dashboard.decide_review`가 호출됩니다. 같은 사건에 여러 작업 요청이 있으면 `zeekad_report_job_id`의 요청만 표시하며, 결정 직후에는 파이프라인이 **30초 주기로 재개**해 반영할 때까지 `"반영 중"`으로 표시되고 완료 시 `"반영됨"`(`zeekad_review_resumed_at`), 실패 시 `"반영 실패(운영자 확인)"`(`zeekad_review_resume_failed`)으로 표시됩니다.
- **모델 묶음 `zeekad-fusion/3` (결합 v2) 및 30분 초과 사건**: 결합 v2 champion 번들 `zeekad-fusion/3`은 여러 탐지 창을 합쳐 **30분보다 긴 사건**을 생성할 수 있으며, 대시보드는 사건 길이 상한 가정 없이 그대로 조회·표시합니다.
- **모델 점수·근거 API·상태 변경**: `incident_model_scores`, 근거 API(`GET /api/v1/jobs/{job_id}/incidents/{rank}`), `transition_incident`의 `p_job`은 현재 화면 큐의 `job_id`(최신 작업)를 사용합니다.
- **사건 상태 및 이력**: 상태는 `incident_id`에 귀속되어 새 채점 작업이 생성되어도 승계되며, `incident_status_history`는 `incident_id` 기준으로 전체 작업의 이력을 모아 시간 역순으로 표시합니다.

### 2.3 근거 FastAPI (`evidence.v1`) 연동
- 대시보드 백엔드는 `ZEEKAD_EVIDENCE_API_URL`을 통해 `GET /api/v1/jobs`, `GET /api/v1/captures/{capture_id}/queue`, `GET /api/v1/jobs/{job_id}/incidents/{rank}`를 호출합니다(읽기 전용).
- 통합 Compose 배포에서는 `http://api:8000`(실제 `zeek_AD` 서비스명에 맞춤)을 사용하고, 로컬 개발 환경에서는 `http://127.0.0.1:8000` 또는 `http://host.docker.internal:8000`으로 연결합니다.
- FastAPI가 일시 중단되더라도 사건 상세 페이지의 DB 뷰 정보(모델 창 비율, 보고서, 전송 판단, Slack 기록, 검토 상태, 상태 이력)는 폴백 안내와 함께 정상 표시됩니다.

### 2.4 실습망 시험 데이터(`lab-20261119`) 참고 메모
- `lab-20261119` 등 실습망 시험 데이터에는 가상 재생·스크립트 시험용 호스트 트래픽(예: Kali 공격 VM `10.10.0.50`, 배포 VM `10.10.0.10`)이 포함될 수 있습니다.
- 대시보드 애플리케이션 코드와 템플릿은 특정 시험 날짜나 IP 라벨을 하드코딩하지 않고 `asset_names`·`host_ip`·`VIEWER` 마스킹 규칙에 따라 중립적으로 표시합니다. 운영·분석 시 해당 IP가 실습망 시험 호스트임을 참고하여 정상/공격 여부를 판별하세요.

---

## 3. 환경 변수 설정 (`.env`)

저장소의 [`.env.example`](../.env.example)을 `.env`로 복사한 뒤 배포 환경에 맞게 값을 채웁니다. `.env` 파일은 `.gitignore` 및 `.dockerignore`에 등록되어 있으므로 Git 커밋이나 Docker 이미지에 포함되지 않습니다.

```bash
cp .env.example .env
```

| 변수명 | 설명 | VMware Compose 배포 예시 | 로컬 개발 / Docker 호스트 연동 예시 |
|---|---|---|---|
| `DASHBOARD_DB_HOST` | 대시보드 자체 DB 호스트 | `postgres` (`zeek_AD` DB 서비스명) | `127.0.0.1` (bootRun) / `host.docker.internal` |
| `DASHBOARD_DB_PORT` | 대시보드 자체 DB 포트 | `5432` | `55432` |
| `DASHBOARD_DB_NAME` | 대시보드 자체 DB 이름 | `zeekad_dashboard` | `zeekad_dashboard` |
| `DASHBOARD_DB_USER` | 대시보드 자체 DB 계정 | `dashboard_app` | `dashboard_app` |
| `DASHBOARD_APP_PASSWORD` | 대시보드 자체 DB 비밀번호 | 강력한 난수 비밀번호 | 강력한 난수 비밀번호 |
| `ZEEKAD_DB_HOST` | `zeekad` DB 호스트 | `postgres` (`zeek_AD` DB 서비스명) | `127.0.0.1` (bootRun) / `host.docker.internal` |
| `ZEEKAD_DB_PORT` | `zeekad` DB 포트 | `5432` | `55432` |
| `ZEEKAD_DB_NAME` | `zeekad` DB 이름 | `zeekad` | `zeekad` |
| `ZEEKAD_RO_USER` | `zeekad` 읽기 전용 계정 | `dashboard_ro` | `dashboard_ro` |
| `ZEEKAD_RO_PASSWORD` | `zeekad` 읽기 전용 비밀번호 | 강력한 난수 비밀번호 | 강력한 난수 비밀번호 |
| `ZEEKAD_RW_USER` | `zeekad` 상태 전이 전용 계정 | `dashboard_rw` | `dashboard_rw` |
| `ZEEKAD_RW_PASSWORD` | `zeekad` 상태 전이 비밀번호 | 강력한 난수 비밀번호 | 강력한 난수 비밀번호 |
| `ZEEKAD_EVIDENCE_API_URL` | FastAPI 근거 API 주소 | `http://api:8000` | `http://127.0.0.1:8000` / `http://host.docker.internal:8000` |
| `DASHBOARD_COOKIE_SECURE` | 세션 쿠키 `Secure` 속성 (HTTPS 앞단 WAF 필수 `true`) | `true` | `true` (HTTP 단독 테스트 시만 `false`) |
| `DASHBOARD_SESSION_IDLE_TIMEOUT` | Spring 세션 유휴 만료 | `30m` | `30m` |
| `DASHBOARD_MAX_FAILED_ATTEMPTS` | 로그인 연속 실패 잠금 횟수 | `5` | `5` |
| `DASHBOARD_LOCKOUT_MINUTES` | 계정 잠금 유지 시간(분) | `15` | `15` |
| `DASHBOARD_IDLE_TIMEOUT_MINUTES` | 필터 유휴 만료(분) | `30` | `30` |
| `DASHBOARD_ABSOLUTE_TIMEOUT_MINUTES` | 필터 절대 만료(분) | `480` | `480` |
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
프로젝트 루트에서 Spring Boot 애플리케이션(`Dockerfile`)과 ModSecurity WAF(`docker/nginx-waf/Dockerfile`) 이미지를 함께 빌드할 수 있습니다.

```bash
docker compose build
```

개별 빌드가 필요한 경우:
```bash
docker build -t zeek-ad-dashboard-app:local -f Dockerfile .
docker build -t zeek-ad-dashboard-waf:local -f docker/nginx-waf/Dockerfile ./docker/nginx-waf
```

### 4.2 `zeek_AD`와 통합 기동 방법 (2가지 중 선택)

#### 방법 A: 동일 Docker Compose 파일 병합 실행 (권장)
`zeek_AD`의 `compose.yml`과 `zeek_ad_dashboard/compose.yml`을 같은 프로젝트로 합쳐 기동합니다. `zeek_AD`가 사용하는 네트워크 이름과 `dashboard-net`이 분리되어 있는 경우, `compose.override.yml`에서 `dashboard-app`의 `networks`에 `zeek_AD` 네트워크를 함께 연결하거나 두 Compose의 네트워크 이름을 통일합니다.

```bash
docker compose -f /opt/zeek_AD/compose.yml -f /opt/zeek_ad_dashboard/compose.yml --env-file /opt/zeek_ad_dashboard/.env config -q
docker compose -f /opt/zeek_AD/compose.yml -f /opt/zeek_ad_dashboard/compose.yml --env-file /opt/zeek_ad_dashboard/.env up -d --build
```

#### 방법 B: 별도 Compose 스택 + `zeek_AD` 외부 네트워크 연동
`zeek_AD`가 이미 `zeek_ad_default` 같은 Docker 네트워크에서 실행 중이면 `zeek_ad_dashboard/compose.yml`의 `networks.dashboard-net`을 주석 안내대로 `external: true`로 전환하고 기동합니다.

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
2. `admin` 계정으로 로그인해 `/login/totp/setup`에서 TOTP 2단계 인증을 등록하고 `/admin/users`에서 초기 비밀번호를 변경합니다.
3. 기본 시드 계정의 허용 패턴(`viewer1`/`analyst1`: `cic17-*`, `analyst2`: `syn1-*`, `admin`: `*`) 외에 **실습망 캡처(`lab-YYYYMMDD`)를 조회할 분석가·조회자**는 `/admin/users`에서 해당 계정의 허용 캡처 패턴에 `lab-*`(또는 `cic17-*,lab-*`)를 추가·저장합니다.
4. 초기 계정 설정이 완료되면 `.env`에서 `DASHBOARD_BOOTSTRAP_PASSWORD` 등 부트스트랩 변수를 비우고 `docker compose up -d`로 재적용하는 것을 권장합니다.

---

## 5. Nginx + ModSecurity WAF TLS 인증서 운영 방법 (VM IP SAN 지원)

`owasp/modsecurity-crs:nginx-alpine`의 내장 진입점 스크립트(`/docker-entrypoint.d/10-generate-certificate.sh`)는 수정하지 않고 그대로 사용하며, 환경에 따라 아래 두 방식 중 하나를 선택합니다.

1. **기본 자체 서명 인증서(자동 생성)**:
   - `SSL_CERT_FILE=/etc/nginx/conf/server.crt`, `SSL_CERT_KEY_FILE=/etc/nginx/conf/server.key`(기본값)를 유지하면 컨테이너 시작 시 런타임에 `localhost`용 EC P-256 자체 서명 인증서를 자동 생성합니다. Git과 이미지에는 개인키가 남지 않습니다.
2. **배포 VM IP SAN 포함 자체 서명 / 사내 CA 인증서 마운트(권장)**:
   - Windows 브라우저에서 `https://<VM_IP>`로 접속할 때 IP SAN 경고를 줄이려면 Ubuntu Server의 `./docker/certs/` 경로에 VM IP SAN이 포함된 인증서를 생성해 마운트합니다(`compose.yml`이 `./docker/certs:/etc/nginx/ssl:ro`를 기본 마운트함).
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

외부 PostgreSQL 없이 Docker Compose 오버라이드(`docker/verify/compose.verify.yml`)로 실제 PostgreSQL 17 + Flyway + `latest_incident_queue` + `dashboard.transition_incident` + `dashboard.decide_review` + Slack 스레드 + WAF + Trivy + OWASP ZAP을 통합 검증할 수 있습니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/security-scan.ps1
```
- 실행 시점에만 난수 비밀번호를 생성해 `docker/verify/compose.verify.yml`을 기동하고, 검증 완료 후 `docker compose down -v`로 임시 컨테이너와 볼륨을 완전히 삭제합니다.
