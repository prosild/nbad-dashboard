# zeek_ad_dashboard 배포 및 운영 가이드

이 문서는 `zeek_ad_dashboard`를 **로컬 Docker 환경** 또는 **시놀로지 NAS(Container Manager / Docker Compose)** 환경에 배포·운영하기 위한 절차와 보안 설정 기준을 설명합니다.

---

## 1. 아키텍처 개요

- **`nginx-waf` (`docker/nginx-waf/`)**: `owasp/modsecurity-crs:nginx-alpine` 기반 앞단 리버스 프록시 + ModSecurity v3 WAF(OWASP CRS `PARANOIA=1`, `SecRuleEngine On`).
  - 외부 트래픽은 `nginx-waf`의 HTTPS(`8443` → 호스트 `${WAF_HTTPS_PORT}`) 및 HTTP(`8080` → 호스트 `${WAF_HTTP_PORT}`, HTTPS로 `301` 리다이렉트) 포트만 통과합니다.
  - `/actuator/**` 경로는 앞단 Nginx에서 `403 Forbidden`으로 즉시 차단합니다.
  - `Server` 헤더 및 와일드카드 CORS 헤더를 제거하고, HTTPS 응답에 `Strict-Transport-Security` 헤더를 추가하며, 백엔드(`dashboard-app`)의 `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy` 헤더를 보존합니다.
- **`dashboard-app` (`Dockerfile`)**: `eclipse-temurin:17-jre-alpine` 기반 비루트(`appuser`) Spring Boot + MyBatis 웹 서버.
  - `expose: ["8080"]`으로 Docker 내부 네트워크(`dashboard-net`)에서만 접근 가능하며 호스트 포트를 직접 열지 않습니다.
  - `server.forward-headers-strategy: framework`로 앞단 WAF가 전달하는 `X-Forwarded-Proto`, `X-Forwarded-For`, `X-Real-IP`, `Host`를 처리합니다.
  - 프로덕션 `bootJar`에는 H2 드라이버 및 `application-test.yml`이 포함되지 않습니다.

---

## 2. 사전 준비 (PostgreSQL 17 및 FastAPI)

### 2.1 PostgreSQL 데이터베이스 분리 구성
대시보드는 단일 물리 PostgreSQL 서버(예: `127.0.0.1:55432` 또는 NAS 호스트/내부 IP) 안에서 논리 DB와 계정을 다음 3중 경계로 분리하여 사용합니다.

1. **대시보드 자체 DB (`zeekad_dashboard`, 계정 `dashboard_app`)**
   - 대시보드 기동 시 Flyway(`classpath:db/migration/postgresql`)가 자동으로 `users`, `user_capture_access`, `audit_logs` 테이블 및 `audit_logs` `UPDATE`/`DELETE` 차단 트리거(`trg_audit_logs_immutable`)를 생성합니다.
   - `dashboard_app` 계정은 `zeekad_dashboard` 데이터베이스의 소유자 또는 DDL/DML 권한만 보유합니다.
2. **`zeekad` 읽기 전용 계정 (`dashboard_ro`)**
   - `zeekad` 데이터베이스의 `dashboard` 스키마 내 데이터 계약 v1·v2 뷰 12종에 대한 `SELECT` 권한만 부여합니다.
   - 원본 테이블(`raw_*`) 및 `INSERT`/`UPDATE`/`DELETE` 권한은 부여하지 않습니다.
3. **`zeekad` 상태 변경 전용 계정 (`dashboard_rw`)**
   - `zeekad` 데이터베이스의 `dashboard` 스키마 `USAGE`와 `dashboard.transition_incident(p_job, p_incident, p_to, p_actor, p_reason, p_resolution)` 함수 `EXECUTE` 권한만 부여합니다.

> [!IMPORTANT]
> 운영 PostgreSQL 서버의 `pg_hba.conf` 및 `postgresql.conf`(`listen_addresses`)에서 Docker 브리지 대역(`host.docker.internal` 또는 NAS Docker 서브넷) 접속이 허용되어 있어야 합니다.

### 2.2 근거 FastAPI (`evidence.v1`) 연동
- 대시보드 백엔드는 `ZEEKAD_EVIDENCE_API_URL`을 통해 `GET /api/v1/jobs`, `GET /api/v1/captures/{capture_id}/queue`, `GET /api/v1/jobs/{job_id}/incidents/{rank}`를 호출합니다.
- 호스트에서 FastAPI가 `8000` 포트로 실행 중인 경우 `compose.yml`의 `extra_hosts: ["host.docker.internal:host-gateway"]`를 통해 `http://host.docker.internal:8000`으로 연결할 수 있습니다.
- FastAPI가 일시 중단되더라도 사건 상세 페이지의 DB 뷰 정보(모델 창 비율, 보고서, 전송 판단, Slack 기록, 상태 이력)는 폴백 안내와 함께 정상 표시됩니다.

---

## 3. 환경 변수 설정 (`.env`)

저장소의 [`.env.example`](../.env.example)을 `.env`로 복사한 뒤 운영 환경에 맞게 값을 채웁니다. `.env` 파일은 `.gitignore` 및 `.dockerignore`에 등록되어 있으므로 Git 커밋이나 Docker 이미지에 포함되지 않습니다.

```powershell
Copy-Item .env.example .env
```

| 변수명 | 설명 | 기본값/예시 |
|---|---|---|
| `DASHBOARD_DB_HOST`, `DASHBOARD_DB_PORT`, `DASHBOARD_DB_NAME` | 대시보드 자체 DB 접속 정보 | `host.docker.internal`, `55432`, `zeekad_dashboard` |
| `DASHBOARD_DB_USER`, `DASHBOARD_APP_PASSWORD` | 대시보드 DB 계정/비밀번호 | `dashboard_app` / 강력한 난수 비밀번호 |
| `ZEEKAD_DB_HOST`, `ZEEKAD_DB_PORT`, `ZEEKAD_DB_NAME` | `zeekad` DB 접속 정보 | `host.docker.internal`, `55432`, `zeekad` |
| `ZEEKAD_RO_USER`, `ZEEKAD_RO_PASSWORD` | `zeekad` 읽기 전용 계정/비밀번호 | `dashboard_ro` / 강력한 난수 비밀번호 |
| `ZEEKAD_RW_USER`, `ZEEKAD_RW_PASSWORD` | `zeekad` 상태 전이 함수 전용 계정/비밀번호 | `dashboard_rw` / 강력한 난수 비밀번호 |
| `ZEEKAD_EVIDENCE_API_URL` | FastAPI 근거 API 주소 | `http://host.docker.internal:8000` |
| `DASHBOARD_COOKIE_SECURE` | 세션 쿠키 `Secure` 속성(HTTPS WAF 앞단 필수 `true`) | `true` |
| `DASHBOARD_BOOTSTRAP_PASSWORD` | `users` 테이블이 비어 있을 때 기본 4계정(`viewer1`, `analyst1`, `analyst2`, `admin`) 초기 시드용 비밀번호 | 초기 기동 후 비움 권장 |
| `BOOTSTRAP_ADMIN_TOTP_SECRET` | `admin` TOTP Base32 시크릿(비우면 최초 로그인 시 `/login/totp/setup`에서 등록) | 선택 |
| `WAF_HTTP_PORT`, `WAF_HTTPS_PORT` | 호스트에 노출할 WAF HTTP/HTTPS 포트 | `8080`, `8443` (NAS 역프록시·직접 서비스에 맞게 조정) |
| `WAF_SERVER_NAME` | Nginx `server_name` | `localhost` 또는 실제 도메인 |

---

## 4. 로컬 Docker 배포 및 확인

### 4.1 운영 구성 기동 (외부 PostgreSQL 17 연결)
```powershell
docker compose config -q
docker compose up -d --build
docker compose ps
```
접속 주소: `https://localhost:8443` (`http://localhost:8080` 접속 시 HTTPS로 `301` 리다이렉트)

### 4.2 로컬 독립 E2E 검증 구성 (임시 PostgreSQL 17 컨테이너 포함)
외부 PostgreSQL 없이 Docker Compose 오버라이드(`docker/verify/compose.verify.yml`)로 실제 PostgreSQL 17 + Flyway + `dashboard.transition_incident` + WAF를 통합 검증할 수 있습니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/security-scan.ps1
```
- 이 스크립트는 실행 시점에만 난수 비밀번호를 생성해 `docker/verify/compose.verify.yml`을 기동하고, 검증 완료 후 `docker compose down -v`로 임시 컨테이너와 볼륨을 완전히 삭제합니다.

---

## 5. 시놀로지 NAS Docker 이관 절차

1. **소스/패키지 배치**: NAS 공유 폴더(예: `/volume1/docker/zeek_ad_dashboard`)에 프로젝트 소스를 배치하고 `.env`에 NAS 환경의 `DASHBOARD_DB_HOST`, `ZEEKAD_DB_HOST`, `ZEEKAD_EVIDENCE_API_URL`, 비밀번호를 입력합니다.
   - PostgreSQL이 같은 NAS의 Docker 또는 호스트에 있는 경우 NAS 내부 고정 IP 또는 `host.docker.internal`(Container Manager Docker 20.10+)을 지정합니다.
2. **포트 충돌 회피**: 시놀로지 DSM 역프록시나 Web Station이 `80`/`443` 포트를 이미 사용 중이면 `.env`에서 `WAF_HTTP_PORT=18080`, `WAF_HTTPS_PORT=18443` 등 비충돌 포트를 지정하거나 DSM 제어판 리버스 프록시 뒤단에 연결합니다.
3. **Container Manager(또는 SSH) 실행**:
   ```sh
   docker compose config -q
   docker compose up -d --build
   ```
4. **초기 관리자 로그인 및 부트스트랩 변수 정리**:
   - `admin` 계정으로 로그인해 `/login/totp/setup`에서 TOTP 2단계 인증을 등록하고 `/admin/users`에서 초기 비밀번호를 변경·관리합니다.
   - 초기 계정 생성이 완료되면 `.env`에서 `DASHBOARD_BOOTSTRAP_PASSWORD` 등 부트스트랩 변수를 비우고 재기동할 수 있습니다.

---

## 6. Nginx + ModSecurity WAF TLS 인증서 운영 방법

- **기본 동작(개발·내부 데모)**: Git 및 Docker 이미지에는 어떠한 TLS 개인키(`*.key`, `*.pem`)도 포함되지 않습니다. `nginx-waf` 컨테이너 시작 시 `/docker-entrypoint.d/10-generate-certificate.sh`가 `/etc/nginx/conf/server.key` 부재를 감지하면 런타임에 EC P-256 자체 서명 인증서를 자동 생성합니다.
- **운영/사내 CA 또는 Let's Encrypt 인증서 적용**:
  1. NAS 호스트의 안전한 경로(예: `/volume1/docker/zeek_ad_dashboard/certs`, `chmod 600 server.key`)에 `server.crt`(또는 `fullchain.pem`)와 `server.key`를 배치합니다.
  2. `compose.yml`의 `nginx-waf` 서비스 `volumes:`에 읽기 전용(`:ro`)으로 마운트합니다:
     ```yaml
     volumes:
       - ./certs/server.crt:/etc/nginx/conf/server.crt:ro
       - ./certs/server.key:/etc/nginx/conf/server.key:ro
     ```
  3. `/etc/nginx/conf/server.key`가 이미 마운트되어 있으면 컨테이너 시작 스크립트는 새 키를 생성하지 않고 마운트된 인증서를 그대로 사용합니다.
  4. 인증서 갱신 후에는 `docker compose restart nginx-waf`로 무중단 반영에 준하는 빠른 재로드를 수행합니다.
