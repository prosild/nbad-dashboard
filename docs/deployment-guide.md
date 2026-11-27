# zeek_ad_dashboard 배포 및 운영 가이드

`zeek_ad_dashboard`를 VMware Ubuntu Server 배포 VM 한 대(zeek_AD와 같은 Docker Compose)나 로컬 개발·검증 환경에 올리고 운영하는 절차와 보안 설정을 적습니다.

탐지 파이프라인의 이름은 NBAD(Network Behavior Anomaly Detection, 저장소 `network-behavior-anomaly-detection`)입니다. 처음 이름 zeek_AD는 패키지·DB(`zeekad`)·컨테이너·설정 키에 그대로 남아 있고 이 문서의 본문도 그 이름을 씁니다.

---

## 1. 아키텍처 및 네트워크 경계 개요

### 1.1 VMware 실습·운영 토폴로지
- **배포 VM (Ubuntu Server 1대)**: `zeek_AD` 파이프라인(PostgreSQL 17, 근거 FastAPI `api` 등)과 `zeek_ad_dashboard`(`dashboard-app`, `nginx-waf`)를 **같은 Docker Compose 프로젝트 또는 공유 Docker 네트워크**로 기동합니다.
- **공격 VM (Kali Linux)**: 격리된 실습망(Host-Only / Internal 가상 네트워크)으로만 공격 트래픽을 전송합니다.
- **사용자 접속 (Windows 호스트 브라우저)**: Windows 브라우저에서 배포 VM의 IP 또는 호스트명(`https://<VM_IP>`)으로 접속합니다. 외부 요청은 `nginx-waf`로만 들어옵니다.

### 1.2 대시보드 컨테이너 구성
- **`nginx-waf` (`docker/nginx-waf/Dockerfile`)**: `owasp/modsecurity-crs:4.30.0-nginx-alpine-202611190211` 기반 앞단 리버스 프록시 + ModSecurity v3 WAF(OWASP CRS `PARANOIA=1`, `SecRuleEngine On`, `USER nginx`).
  - 기반 이미지는 태그와 digest(`@sha256:f7b4ec03…5412`)로 고정합니다. 빌드할 때마다 nginx·ModSecurity·CRS 판이 바뀌지 않습니다.
  - 이 기반에 든 `libxml2` `2.13.9-r2`는 HIGH 취약점(`CVE-2026-86144`)이 있어 `libxml2`만 `2.13.9-r3` 이상으로 올립니다. 판은 하한만 고정하므로 빌드할 때 Alpine 저장소에 있는 그 이상 판이 들어옵니다. 하한을 채우는 판이 없으면 빌드가 실패합니다. 다른 패키지는 올리지 않습니다(4.1).
  - 외부 트래픽은 `nginx-waf`의 HTTPS(`${WAF_HTTPS_PORT:-443}` → 컨테이너 `8443`) 및 HTTP(`${WAF_HTTP_PORT:-80}` → 컨테이너 `8080`, HTTPS로 `301` 리다이렉트) 포트만 통과합니다.
  - `/actuator/**` 경로는 앞단 Nginx에서 `403 Forbidden`으로 즉시 차단합니다.
  - `compose.yml`의 `ALLOWED_METHODS: "GET HEAD POST PUT OPTIONS"`로 CRS 허용 메서드(기본 `GET HEAD POST OPTIONS`)에 `PUT`만 더합니다. SPA의 사용자 수정 요청 `PUT /api/admin/users/{id}` 때문입니다. 앱이 쓰지 않는 `DELETE`·`PATCH`는 허용하지 않습니다(`T52`의 중요 자산 지우기도 `POST /api/admin/critical-assets/{id}/delete`입니다). `PARANOIA`·`BLOCKING_PARANOIA=1`, `ANOMALY_INBOUND=5`, `MODSEC_RULE_ENGINE=on`은 그대로이고 WAF 예외 규칙은 두지 않습니다.
  - **감사 로그에 남기는 것(`T59`)**: ModSecurity 감사 로그(JSON 한 줄, 컨테이너 출력)는 `404`가 아닌 `4xx`와 `5xx` 응답, 그리고 규칙이 걸린 요청을 적습니다. WAF 이미지가 부분을 `AHZ`로 줄여(`Dockerfile`의 `MODSEC_AUDIT_LOG_PARTS`) 접속 주소·시각·`unique_id`·메서드·요청 주소·응답 코드와 걸린 규칙의 메시지만 남깁니다. 요청·응답의 헤더와 본문은 남기지 않습니다. 기반 기본값 `ABIJDEFHZ`에서는 세션 쿠키·CSRF 토큰·`Set-Cookie` 값이 컨테이너 로그에 남았습니다. 이 값은 `compose.yml`에서 덮지 않습니다. 차단된 요청의 User-Agent는 감사 줄에 없으므로 접근 로그에서 같은 시각·요청 주소의 줄로 찾습니다. `Host`는 접근 로그 서식에 없고 감사 줄의 `hostname`(포트를 뺀 이름)에 남습니다. 고치기 전과 뒤는 `scripts/waf-audit-log-check.ps1`로 확인합니다([보안 검증 보고서](security-verification-report.md) 6절).
  - `Server` 헤더와 와일드카드 CORS 헤더를 지웁니다(같은 출처에서 SPA 정적 셸과 JSON API를 함께 서빙하므로 CORS 헤더가 필요 없음). HTTPS 응답에는 `Strict-Transport-Security` 헤더를 더합니다. 백엔드(`dashboard-app`)가 붙인 `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, `COOP/COEP/CORP`, `Permissions-Policy` 헤더는 그대로 둡니다.
  - **클라이언트 IP 규칙**(`T14`): 이 스택은 WAF가 맨 앞이라 클라이언트가 직접 붙습니다. `compose.yml`은 `SET_REAL_IP_FROM: "127.0.0.1"`, `REAL_IP_HEADER: "X-Forwarded-For"`, `REAL_IP_RECURSIVE: "on"`이라서 `127.0.0.1` 밖에서 온 연결은 접속 주소가 곧 클라이언트 IP입니다. 방문자가 보낸 `X-Real-IP`·`X-Forwarded-For`는 무시합니다. 앞단 프록시용 설정 변수는 두지 않습니다.
    - 사설망 대역(`10/8`·`172.16/12`·`192.168/16`)을 통째로 신뢰하면 안 됩니다. VMware NAT·Docker 게이트웨이처럼 같은 사설망에서 오는 누구나 헤더 하나로 감사 로그 `client_ip`와 ModSecurity 기록 IP를 바꿀 수 있기 때문입니다(`T14` 이전 설정에서 재현됨).
    - 앞단 프록시(로드밸런서 등) 뒤에 둘 때는 포트폴리오 스택(`compose.portfolio.yml` + `docker/portfolio/nginx/zeekad-portfolio-http.conf.template`)처럼 `set_real_ip_from <그 프록시 주소만>`·`real_ip_header X-Forwarded-For`·`real_ip_recursive on`을 **http 문맥** conf 템플릿으로 따로 붙입니다. 이미지의 `SET_REAL_IP_FROM`은 `location` 안에 펼쳐져 realip가 늦게 적용되므로 ModSecurity 기록에 프록시 주소가 남을 수 있습니다. 신뢰 범위에는 실제 프록시 주소만 넣습니다.
  - **앱에 넘기는 전달 헤더**(공유 템플릿 `includes/proxy_backend.conf.template`, 모든 스택 공통): `X-Forwarded-For`는 방문자 값 뒤에 덧붙이지 않고 nginx가 정한 클라이언트 IP(`$remote_addr`) 하나로 덮어씁니다. `X-Real-IP`·`X-Forwarded-Proto`·`X-Forwarded-Port`도 nginx가 정한 값으로 덮어씁니다. `Forwarded`·`X-Forwarded-Host`·`X-Forwarded-Prefix`·`X-Forwarded-Ssl`은 빈 값으로 지워 앱에 보내지 않습니다.
  - **권한과 상태 확인(`T61`)**: `compose.yml`의 `nginx-waf`는 capability 없이(`cap_drop: [ALL]`) 권한 상승 금지(`no-new-privileges`)로 돕니다. 이미지가 `nginx` 계정으로 컨테이너 안 `8080`·`8443`을 열고 호스트의 `80`·`443`은 Docker가 잇기 때문에 capability가 필요 없습니다. 상태 확인(compose의 `healthcheck`와 이미지의 `HEALTHCHECK`)은 `wget -q --spider --header "Host: localhost" http://127.0.0.1:8080/healthz`입니다. `T60`까지는 `Host`가 숫자 주소라 CRS `920350`에 걸려 응답이 `200`인데도 감사 줄이 10초마다 하나씩 남았습니다. 접속 주소는 `127.0.0.1` 그대로입니다(`localhost` 이름으로 접속하면 IPv6로 풀릴 수 있습니다). WAF 규칙은 끄거나 예외를 두지 않았습니다. 바깥에서 숫자 주소 `Host`로 `/healthz`를 부르면 지금처럼 감사 줄이 남습니다. 보안 스캔 E2E `[T61d]`·`[T61e]`가 봅니다(6절).
  - **업스트림 이름 재해석**: `proxy_pass`가 변수(`$zeekad_backend`)라 nginx가 `dashboard-app` 이름을 요청 때 Docker 내장 DNS(`127.0.0.11`, 이미지 `nginx.conf`의 `resolver`, `RESOLVER_CONFIG="valid=10s ipv6=off"`)로 다시 해석합니다. 앱 컨테이너를 다시 만들어 IP가 바뀌어도 `nginx-waf`를 재시작할 필요가 없습니다. 앱이 멈춘 동안에는 `502`(`/50x.html`)를 냅니다.
- **`dashboard-app` (`Dockerfile`)**: `eclipse-temurin:17-jre-alpine` 기반 비루트(`appuser`) Spring Boot + MyBatis JSON REST API 서버입니다. 같은 jar 안의 React SPA 정적 번들(`BOOT-INF/classes/static/index.html`, `static/assets/*`)도 함께 서빙합니다. 최종 이미지에는 Node.js·npm·`node_modules`가 없습니다(Node는 빌드 단계에서만 사용).
  - `expose: ["8080"]`만 있어 Docker 내부 네트워크(`dashboard-net`)에서만 닿고 호스트 포트는 열지 않습니다.
  - `compose.yml`의 `dashboard-app`도 capability 없이(`cap_drop: [ALL]`) 권한 상승 금지(`no-new-privileges`)로 돕니다(`T61`. 같은 이미지가 포트폴리오 스택에서 이미 그렇게 돕니다). 이미지가 일반 계정(`appuser`)으로 `8080`을 열어 capability가 필요 없습니다.
  - **전달 헤더 신뢰(`T32`)**: `server.forward-headers-strategy: native`(Tomcat `RemoteIpValve`)로 `X-Forwarded-For`·`X-Forwarded-Proto`·`X-Forwarded-Port`·`X-Forwarded-Host`를 처리합니다. 연결한 주소(TCP 상대)가 `dashboard.security.trusted-proxies`(환경 변수 `DASHBOARD_TRUSTED_PROXIES`, 쉼표 목록)에 있을 때만 이 헤더를 적용하고 목록 밖에서 온 연결은 모두 무시합니다. 그때 클라이언트 IP(감사 로그 `client_ip`)는 연결 주소이고 scheme·port는 실제 연결 값입니다. `Forwarded`·`X-Forwarded-Prefix`는 앱이 쓰지 않습니다(WAF가 지웁니다).
    - 목록에는 IPv4·IPv6 주소를 그대로만 씁니다. 대역(CIDR)·호스트 이름·정규식이 있으면 앱이 시작하지 않습니다. 호스트 이름을 DNS로 찾아보지 않습니다. 앞뒤 공백은 지우고 빈 항목은 버립니다. IPv6는 Tomcat 표기(예: `0:0:0:0:0:0:0:1`)로 바꿔 넣고 시작 로그에 남깁니다.
    - 목록이 비면(앱 기본값) 아무 연결도 믿지 않습니다. 이때 감사 로그 IP는 WAF 주소가 되고 시작할 때 경고 로그를 남깁니다.
    - Spring Boot 기본 `internal-proxies`는 사설망 전체(`127/8` 포함)라 앱이 그것을 신뢰 목록의 정확 일치 패턴으로 바꿉니다(`TrustedProxyValveCustomizer`). 실제 Tomcat 엔진의 `RemoteIpValve`가 하나가 아니거나 패턴이 목록과 다르면 앱이 시작하지 않습니다. Tomcat `server.tomcat.remoteip.trusted-proxies`는 쓰지 않습니다.
  - **WAF 고정 주소**: `compose.yml`은 `dashboard-net`에 고정 서브넷 `${DASHBOARD_SUBNET:-10.203.49.0/24}`과 동적 배정 범위 `${DASHBOARD_IP_RANGE:-10.203.49.0/25}`를 주고 `nginx-waf`를 그 범위 밖 `${DASHBOARD_WAF_IP:-10.203.49.250}`에 고정합니다. 앱 `DASHBOARD_TRUSTED_PROXIES`도 같은 변수입니다. 그래서 같은 네트워크의 다른 컨테이너(`zeek_AD`의 `api`·파이프라인·PostgreSQL 등)가 `dashboard-app:8080`에 직접 붙어 전달 헤더를 꾸며도 감사 로그 IP는 그 컨테이너 주소입니다(보안 스캔 E2E `[16]`).
    - 서브넷을 바꾸면 `DASHBOARD_WAF_IP`도 그 서브넷 안, `DASHBOARD_IP_RANGE` 밖으로 바꿉니다. 포트폴리오 스택(`10.203.48.0/24`)과 겹치지 않아 한 PC에 같이 떠도 됩니다.
    - `T32` 전에 띄운 스택은 네트워크를 한 번 다시 만들어야 합니다(`docker compose down` 뒤 `up -d`, 볼륨은 그대로).
    - `zeek_AD` 외부 네트워크로 바꿔 쓸 때(4.2 방법 B)는 그 네트워크 서브넷 안의 빈 주소를 `DASHBOARD_WAF_IP`로 줍니다. 서브넷을 정할 수 없으면 `nginx-waf`의 `ipv4_address`를 지우고 `DASHBOARD_TRUSTED_PROXIES`를 비웁니다. 그러면 감사 로그 IP가 WAF 주소가 되지만 다른 컨테이너가 꾸밀 수는 없습니다.
  - `dashboard-app` 포트(`8080`)는 호스트나 WAF 밖으로 열지(`ports:`) 않습니다. 정적 테스트가 세 compose 파일의 `dashboard-app`에 `ports:`가 없는지 확인합니다. 신뢰 목록과 겹쳐 지키는 장치입니다.
  - 남은 위험: 같은 bridge 네트워크에서 `NET_RAW` 권한으로 패킷 출처 주소를 꾸미는 공격은 이 방식으로 막지 못합니다. `T61`부터 이 파일의 두 서비스에는 capability가 없지만 같은 네트워크에 붙는 `zeek_AD` 서비스(4.2 병합·외부 네트워크)의 권한은 이 파일이 정하지 않습니다. 포트폴리오 스택은 네트워크를 둘로 나누고 모든 서비스에서 capability를 뺐습니다([`docs/portfolio-deployment.md`](portfolio-deployment.md) 1.1).
  - 프로덕션 `bootJar`에는 H2 드라이버와 `application-test.yml`이 들어가지 않습니다.
- **컨테이너 로그 한도(`T58`)**: `compose.yml`의 두 서비스는 로그 드라이버 `json-file`에 `max-size: "10m"`, `max-file: "5"`를 씁니다(컨테이너마다 50MB까지, 넘으면 오래된 파일부터 지워집니다). `nginx-waf`의 접근 로그와 ModSecurity 기록에는 접속 주소가 들어 있습니다. Docker는 로그를 기간으로 지우지 못하므로 이것은 크기 한도입니다. 요청이 적으면 오래된 줄이 남고 컨테이너를 다시 만들면 모두 사라집니다. 이미 떠 있는 컨테이너에는 걸리지 않으므로 반영하려면 서비스를 다시 만듭니다(`docker compose ... up -d --force-recreate`). 함께 병합해 쓰는 `zeek_AD` compose의 서비스에는 이 설정이 걸리지 않습니다.

### 1.3 SPA 라우팅과 `/api/**` 경계
- **SPA 화면 경로**: `/login`, `/login/totp`, `/login/totp/setup`, `/`, `/incidents`, `/incidents/{jobId}/rank/{queueRank}`, `/incidents/{인시던트 번호}`(`T27`, 숫자만), `/hosts`(`T46`), `/reviews`, `/operations`, `/admin/users`, `/admin/audit-logs`, `/admin/critical-assets`(`T52`)는 서버가 `index.html`(SPA 셸)로 포워딩하고 화면은 브라우저의 React가 그립니다(목록은 `SpaForwardController`). `T27`부터 이 화면 경로의 GET·HEAD는 인증이 없거나 세션이 끝났거나 `ADMIN` TOTP를 마치지 않았어도 `302` 대신 데이터 없는 SPA 셸을 `200`(`Cache-Control: no-store`)으로 줍니다(`SpaShell`). 화면이 원래 주소를 들고 로그인·TOTP 화면으로 보냅니다. 데이터는 `/api/**`가 막으므로 셸에는 업무 정보가 없습니다. `/admin/**` 화면의 데이터는 `ADMIN`만 받습니다.
- **없는 주소**(`T50`): 위 목록에 없는 경로를 로그인한 사용자가 브라우저로 열면(`GET`이고 `Accept`에서 `text/html`이 `application/json`보다 앞) 서버가 같은 SPA 셸을 `404`(`Cache-Control: no-store`)로 주고 화면이 "페이지를 찾을 수 없습니다"를 그립니다. 그 밖의 요청(`/api/**`·`/assets/**`·`/actuator/**` 경로, JSON을 앞세우거나 `Accept`가 없는 요청, `GET`이 아닌 요청)은 지금처럼 `404` JSON(`code: NOT_FOUND`)입니다. 두 응답 모두 `Vary: Accept`를 붙입니다. 로그인하지 않은 요청도 지금과 같습니다(위 목록에 없는 화면 경로의 `GET`은 `302`로 `/login`, `/api/**`는 `401` JSON, 인증 없이 받는 정적 경로의 없는 파일은 `404` JSON).
- **정적 자산**: `/assets/*.js`·`/assets/*.css`·`/index.html`은 인증 없이 받습니다(`Content-Type` `text/javascript`·`text/css`, `X-Content-Type-Options: nosniff`). CSP는 `script-src 'self'; style-src 'self'`로 인라인 스크립트·스타일을 허용하지 않습니다.
- **JSON API (`/api/**`)**: SPA 폴백 대상이 아닙니다. 비인증 요청은 `401` JSON(`code: UNAUTHENTICATED`), 인증된 세션의 없는 경로는 `404` JSON(`code: NOT_FOUND`)이며 `index.html`을 돌려주지 않습니다. 관리자는 1차 로그인 뒤 TOTP 검증 전까지 업무 API가 `403`(`TOTP_VERIFICATION_REQUIRED`)입니다. TOTP 확인(`POST /api/auth/totp/verify`)의 틀린 코드는 `400`(`INVALID_TOTP_CODE`)이고 비밀번호 실패와 같은 횟수에 더해집니다(`T60`). 한도에 닿거나 계정이 잠겨 있으면 `423`(`ACCOUNT_LOCKED`)을 주고 그 세션을 끝냅니다. 잠긴 계정은 코드를 보지 않습니다. 이 구성(`compose.yml`)에는 IP당 속도 제한이 없어 계정 잠금만 시도 수를 묶습니다. 공개 스택은 로그인과 TOTP 확인을 같은 속도 제한에 둡니다([`docs/portfolio-deployment.md`](portfolio-deployment.md)).
- **CSRF**: SPA는 `GET /api/auth/csrf`로 `XSRF-TOKEN` 쿠키(`Secure; SameSite=Lax`, JS가 읽도록 HttpOnly 아님)를 받고 쓰기 요청마다 그 값을 `X-XSRF-TOKEN` 헤더로 보냅니다(이중 제출). 세션 쿠키 `ZEEKAD_SESSION`은 `Secure; HttpOnly; SameSite=Lax`입니다. 로그인·TOTP 뒤에는 토큰이 바뀌므로 클라이언트는 요청마다 최신 쿠키 값을 씁니다.

---

## 2. 데이터 계약 v2.1 및 PostgreSQL 17 / FastAPI 연동

### 2.1 PostgreSQL 데이터베이스 3중 경계
대시보드는 PostgreSQL 17 서버 하나(Compose 배포: `postgres:5432` 등 서비스명, 로컬 개발: `127.0.0.1:55432`) 안에서 논리 DB와 계정을 셋으로 나눠 씁니다.

1. **대시보드 자체 DB (`zeekad_dashboard`, 계정 `dashboard_app`)**
   - 대시보드가 시작할 때 Flyway(`classpath:db/migration/postgresql`)가 다음을 만듭니다.
     - `V1`: `users`, `user_capture_access`, `audit_logs` 테이블과 `audit_logs` `UPDATE`/`DELETE` 차단 트리거(`trg_audit_logs_immutable`)
     - `V2`(`T25`): 담당자 `incident_assignments`와 추가만 하는 이력 `incident_assignment_history`(변경·삭제 차단 트리거)
     - `V3`(`T27`): 인시던트 번호 `incident_refs`(추가만, 변경·삭제 차단 트리거)
     - `V4`(`T58`): 감사 로그 보관 기한. `audit_logs` 트리거 함수가 `DELETE`를 한 경우에만 통과시킵니다(표식 `dashboard.audit_retention_purge`가 `on`이고 행이 30일보다 오래됨). `UPDATE`는 늘 거부하고 `TRUNCATE`도 새 트리거 `trg_audit_logs_no_truncate`가 거부합니다. 기한이 지난 행을 지우는 함수 `public.purge_expired_audit_logs(<일>)`를 만듭니다(`SECURITY DEFINER`, `search_path` 고정, `PUBLIC` 실행 불가).
     - `V5`(`T56`): 대응 조치 기록 `incident_response_actions`(분석가가 인시던트에 한 조치를 적은 기록. 종류는 일곱 값만 받습니다). 기록은 고칠 수 없습니다. 트리거가 `UPDATE`와 `TRUNCATE`를 늘 거부하고 `DELETE`는 표식 `dashboard.response_actions_reset`이 `on`일 때만 통과시킵니다. 앱에는 이 표를 고치거나 지우는 API와 SQL이 없고 표식을 켜는 코드도 없습니다. 공개 데모에서만 배포 도구(`sandbox-setup.sh`)가 만든 초기화 함수가 기준선 뒤에 덧붙은 기록을 지웁니다([`portfolio-deployment.md`](portfolio-deployment.md) 1.3). 다른 배포에서는 기록이 지워지지 않습니다.
     - `V6`(`T52`): 중요 자산 `critical_assets`(주소 IPv4 하나 `UNIQUE`, 이름 100자, 설명 300자, 만든·고친 사람과 시각). 관리자가 화면(`/admin/critical-assets`)이나 API로 등록·고치기·지우기를 하고 변경마다 감사 `CRITICAL_ASSET_CHANGE`(detail `operation`·`hostIp`·`name`)를 같은 트랜잭션에 남깁니다. 등록한 주소가 호스트인 미종결 인시던트는 자동 분류 우선순위가 한 단계 올라갑니다(4.3).
   - `dashboard_app` 계정은 `zeekad_dashboard` 데이터베이스의 DDL/DML 권한만 있습니다.
   - **감사 로그 보관 기한(`T58`)**: 앱은 기한을 모르고 감사 로그를 지우지 않습니다(앱 코드와 설정에 삭제가 없습니다). 기한을 설정하지 않으면 아무것도 지워지지 않습니다. 실제 관제에서는 접속 기록을 오래 남겨야 하므로 이것이 기본입니다.
     - 기한을 두려면 앱 밖의 예약 작업이 하루 한 번 `SELECT * FROM public.purge_expired_audit_logs(<일>);`를 부릅니다(예: cron이 `psql -d zeekad_dashboard -c "SELECT * FROM public.purge_expired_audit_logs(365)"`). 함수는 지운 수와 기준 시각을 돌려주고 한 행이라도 지웠으면 감사 행 하나(`AUDIT_RETENTION_PURGE`, 행위자 `audit-retention`, 역할 `SYSTEM`)를 남깁니다.
     - 바닥값은 30일입니다. 함수는 30일보다 짧은 기한을 예외로 거부하고 트리거도 30일 안의 행은 표식이 켜져 있어도 지우지 못하게 합니다. 이 값은 SQL에 있고 설정으로 줄일 수 없습니다.
     - 실행 권한은 부를 계정에 따로 줍니다: `GRANT EXECUTE ON FUNCTION public.purge_expired_audit_logs(integer) TO <역할>;`. 표 권한은 필요 없습니다(함수가 소유자 권한으로 지웁니다).
     - 표식은 권한 경계가 아니라 실수 방지입니다. 사용자 정의 설정은 어느 역할이든 세션에서 켤 수 있습니다. 권한 경계는 표 소유권(슈퍼유저를 빼면 표를 지울 권한이 있는 계정은 소유자 `dashboard_app`뿐)과 바닥값입니다. 표 소유자는 트리거를 끌 수 있습니다(남은 위험, [`security-verification-report.md`](security-verification-report.md)).
     - 공개 데모 스택은 초기화 서비스가 하루 한 번 90일로 부릅니다([`portfolio-deployment.md`](portfolio-deployment.md) 1.3). PostgreSQL에서 이 동작을 직접 보는 시험은 `scripts/audit-retention-check.ps1`입니다(일회용 컨테이너. H2 시험은 이 SQL을 보지 못합니다).
2. **`zeekad` 읽기 전용 계정 (`dashboard_ro`)**
   - `zeekad` 데이터베이스의 `dashboard` 스키마에 있는 데이터 계약 뷰 14종(v1 5종 · v2 7종 · v2.1 `latest_incident_queue` 1종 · migration 017 `feedback_summary` 1종)의 `SELECT` 권한만 줍니다.
     - v1 (5종): `incident_queue`, `incident_model_scores`, `asset_names`, `scoring_jobs`, `model_bundles`
     - v2 (7종): `incident_reports`, `send_decisions`, `slack_deliveries`(`zeekad_thread_parent`, `zeekad_reply_broadcast` 포함), `slack_summaries`, `incident_status`, `incident_status_history`, `analyst_review_queue`(`zeekad_review_resumed_at`, `zeekad_review_resume_failed` 포함)
     - v2.1 (1종): `latest_incident_queue` (캡처별 가장 최근 성공 작업의 사건 큐 + `zeekad_report_job_id`, `zeekad_report_kind`, `zeekad_would_send`, `zeekad_status`, `zeekad_resolution`, `status_updated_at`, `zeekad_review_action`, `zeekad_review_pending`)
     - migration 017 (1종): `feedback_summary` (캡처 × 모델 묶음 × `zeekad_picked_by`['all' 전체 포함] 분석가 결론 집계: 사건/알림/결론 수, TP/FP/Benign 분포, `zeekad_precision`, `zeekad_alert_precision`, `zeekad_alert_resolved_rate`)
   - 원본 테이블(`raw_*`) 권한과 `INSERT`/`UPDATE`/`DELETE` 권한은 주지 않습니다.
3. **`zeekad` 쓰기 함수 전용 계정 (`dashboard_rw`)**
   - `zeekad` 데이터베이스의 `dashboard` 스키마 `USAGE`와 아래 세 함수의 `EXECUTE` 권한만 줍니다. 세 함수 모두 zeek_AD가 만들고 소유하며(`SECURITY DEFINER`) 계약은 zeek_AD `docs/data-contract-v2.md`에 있습니다.
     - `dashboard.transition_incident(p_job, p_incident, p_to, p_actor, p_reason, p_resolution)`: 상태 변경(신규 → 분석 중 → 종결, 앞으로만)
     - `dashboard.decide_review(p_job, p_incident, p_action, p_analyst, p_note)`: 에스컬레이션 결정
     - `dashboard.reopen_incident(p_job, p_incident, p_actor, p_reason, p_expected_resolution)`: 종결한 인시던트 다시 열기(`T53`, zeek_AD migration `018_incident_reopen.sql`, 계약은 "쓰기: 종결한 사건 다시 열기" 절). 종결일 때만 분석 중으로 돌리고 판정을 비우며 이력에 `closed → investigating` 한 행을 남깁니다. `p_expected_resolution`(화면이 보던 판정)이 지금 판정과 다르면 거부합니다. 권한은 migration이 `dashboard_rw`에만 줍니다.
   - 대시보드 API `POST /api/incidents/{jobId}/rank/{queueRank}/reopen`(본문 `{"reason", "expectedResolution"}`, CSRF 필요)이 세 번째 함수를 부릅니다. 역할은 상태 변경과 같은 `ANALYST`·`ADMIN`이고 화면의 판정을 늘 보냅니다. 함수가 없는 zeek_AD DB(migration 018 전)에서는 `501`(`REOPEN_UNAVAILABLE`, "이 환경의 탐지 DB에는 다시 열기 기능이 아직 없습니다.")을 돌려주고 나머지 기능은 그대로 씁니다. 실행 권한이 없을 때(`42501`)도 같습니다. 그래서 앱 이미지와 migration 018은 어느 것을 먼저 넣어도 됩니다.

### 2.2 v2.1 · migration 014~016 조인 규칙, Slack 스레드, 검토 재개 및 결합 v2
- 실습망 캡처(`lab-YYYYMMDD`)는 5분마다 전체를 다시 계산하므로 같은 캡처에 `job_id`가 여러 개 생깁니다.
- **조사 큐 기본 화면**: `dashboard.latest_incident_queue`를 조회해 캡처별 최신 성공 작업의 사건만 표시합니다(지난 작업을 직접 고르거나 성공 작업이 없으면 `incident_queue`로 폴백).
- **보고서·전송판단·검토 조인**: `incident_reports`, `send_decisions`, `analyst_review_queue`는 `(zeekad_report_job_id, incident_id)`로 조인합니다. `zeekad_report_job_id`가 `NULL`이면 `"보고서 없음"`으로 표시합니다.
- **Slack 기록 `incident_id` 단독 조회 및 스레드 표시**: `slack_deliveries`는 처음 알린 작업에만 기록됩니다(보고서를 뒤 작업에서 다시 만들어도 그대로). 그래서 `job_id`나 `zeekad_report_job_id`로 조인하지 않고 `incident_id`만으로 찾습니다. 화면에서는 `coalesce(zeekad_thread_parent, incident_id)`로 묶어 Slack 채널 스레드 모양(머리 알림 → 후속 답글)으로 보입니다. `zeekad_reply_broadcast`가 `true`이면 `"채널 재알림(broadcast)"` 배지를 붙입니다.
- **분석가 검토 결정 및 30초 주기 재개 흐름**: `/reviews` 및 사건 상세 화면에서 `ANALYST`·`ADMIN`이 미결정(`zeekad_review_action IS NULL`) 요청을 `confirm`(조사 진행) 또는 `dismiss`(오탐 종료)로 결정하면 `dashboard.decide_review`를 부릅니다. 같은 사건에 여러 작업의 요청이 있으면 `zeekad_report_job_id`의 요청만 보입니다. 결정한 뒤 파이프라인이 30초 주기로 재개해 반영할 때까지 `"반영 중"`으로 표시합니다. 끝나면 `"반영됨"`(`zeekad_review_resumed_at`), 실패하면 `"반영 실패(운영자 확인)"`(`zeekad_review_resume_failed`)입니다.
- **모델 묶음 `zeekad-fusion/3` (결합 v2) 및 30분 초과 사건**: 결합 v2 champion 번들 `zeekad-fusion/3`은 여러 탐지 창을 합쳐 30분보다 긴 사건을 만들 수 있습니다. 대시보드는 사건 길이에 상한이 있다고 가정하지 않고 그대로 보여 줍니다.
- **모델 점수·근거 API·상태 변경**: `incident_model_scores`, 근거 API(`GET /api/v1/jobs/{job_id}/incidents/{rank}`), `transition_incident`의 `p_job`은 현재 화면 큐의 `job_id`(최신 작업)를 사용합니다.
- **사건 상태 및 이력**: 상태는 `incident_id`에 붙어 있어 새 채점 작업이 생겨도 이어집니다. `incident_status_history`는 `incident_id` 기준으로 모든 작업의 이력을 모아 최신순으로 보여 줍니다.
- **운영 상태 분석가 결론 집계(`feedback_summary`)**: `/operations` 화면에서 `dashboard.feedback_summary`를 `SELECT *` 방어 매핑과 허용 캡처 IDOR 필터로 조회해 보여 줍니다. 맨 위 상태 카드(파이프라인·분석가 판정·경보) 아래에 캡처별 `'all'`(모든 모델 합계) 행만 기본으로 보이고 탐지 모델별 행은 펼쳐서 봅니다. 정탐률은 판정 10건 미만이면 "표본 부족"으로 보입니다(값은 툴팁). 미탐(재현율)은 이 집계로 알 수 없다고 안내합니다(T20, 정의는 `docs/ui-terminology.md` '운영 지표 정의'). 첫 화면(`/`)은 같은 API로 그리는 관제 현황판입니다.

### 2.3 근거 FastAPI (`evidence.v1`) 연동
- 대시보드 백엔드는 `ZEEKAD_EVIDENCE_API_URL`로 `GET /api/v1/jobs`, `GET /api/v1/captures/{capture_id}/queue`, `GET /api/v1/jobs/{job_id}/incidents/{rank}`를 부릅니다(읽기 전용).
- 통합 Compose 배포에서는 `http://api:8000`(실제 `zeek_AD` 서비스명에 맞춤), 로컬 개발에서는 `http://127.0.0.1:8000`이나 `http://host.docker.internal:8000`을 씁니다.
- FastAPI가 멈추거나 깨진 응답(HTTP가 아닌 응답, 모양이 다른 JSON)을 줘도 사건 상세 화면의 DB 뷰 정보(모델 창 비율, 보고서, 전송 판단, Slack 기록, 검토 상태, 상태 이력)는 폴백 안내와 함께 그대로 보입니다. 증적만 "상세 증적을 불러오지 못했습니다"가 됩니다. 이때 앱 로그에는 경로, 예외 종류, (있으면) HTTP 상태 수만 남고 응답 본문은 남지 않습니다.

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
| `DASHBOARD_MAX_FAILED_ATTEMPTS` | 연속 실패 잠금 횟수. 비밀번호 실패와 관리자 TOTP 확인 실패를 합쳐 센다(`T60`). 관리자가 아닌 계정은 비밀번호가 맞으면 횟수가 되돌아가고 관리자는 TOTP 확인(처음이면 등록 완료)까지 성공해야 되돌아간다 | `5` | `5` |
| `DASHBOARD_LOCKOUT_MINUTES` | 계정 잠금 유지 시간(분). 잠긴 동안에는 맞는 비밀번호와 맞는 TOTP 코드도 `423`이다 | `15` | `15` |
| `DASHBOARD_LOCKOUT_EXEMPT_USERNAMES` | 계정 잠금 제외 공유 계정(T29, T33에서 넓힘). 쉼표 목록, 대소문자·앞뒤 공백 무시. 로그인 때 DB 역할이 VIEWER 또는 ANALYST인 계정만 빠진다(ADMIN은 목록에 있어도 잠긴다). 빠진 계정은 틀려도 실패 수·잠금을 바꾸지 않는다(실패 감사 `LOGIN_FAILURE`는 `lockoutExempt: true`로 남는다). **비밀번호를 공개한 공유 계정만 넣는다**: 실제 분석가 이름을 넣으면 그 계정도 잠기지 않아 여러 IP에서 대입할 때 막을 것이 IP당 로그인 속도 제한뿐이다. 목록의 계정이 없거나 VIEWER·ANALYST가 아니면 시작할 때 경고 로그(이름만)를 남기고 시작은 막지 않는다 | 비움 | 비움 |
| `DASHBOARD_IDLE_TIMEOUT_MINUTES` | 필터 유휴 만료(분) | `30` | `30` |
| `DASHBOARD_ABSOLUTE_TIMEOUT_MINUTES` | 필터 절대 만료(분) | `480` | `480` |
| `DASHBOARD_TIME_ANCHOR` | 기준 시각(T23). 인시던트 큐의 상대 기간(최근 1시간·24시간·7일·30일)을 이 시각에서 거꾸로 센다. `now` = 서버 현재 시각(데이터가 계속 들어오는 운영). `latest-data` = 그 사용자가 볼 수 있는 캡처의 성공 탐지 작업 완료 시각 최대값(데이터가 더 늘지 않는 고정 스냅샷, 과거 데이터 조사용). `latest-data`면 모든 화면 맨 위에 "고정 스냅샷 · 기준 시각"을 보이고 새 인시던트 자동 갱신을 끈다. 다른 값이면 앱이 시작하지 않는다 | `now` | `now` |
| `DASHBOARD_LIVE_CAPTURE_PATTERNS` | 수집원 분류(T23). 맞는 캡처는 "실습망 센서", 나머지는 "가져온 데이터". 쉼표 목록, 패턴 문법은 허용 캡처와 같다(`접두어*`). 잘못된 패턴이면 시작하지 않는다 | `lab-*` | `lab-*` |
| `DASHBOARD_SENSOR_STALE_AFTER`, `DASHBOARD_SENSOR_DOWN_AFTER` | 센서 상태(T24). 기준 시각 − 센서의 마지막 채점이 stale 이하면 정상, down 이하면 지연, 넘으면 중단(가장 최근 끝난 작업이 실패면 실패). Spring Duration(`15m`, `PT15M`). 0 이하이거나 stale ≥ down이면 시작하지 않는다. `compose.yml`은 넘기지 않아 기본값을 쓴다(바꾸려면 `dashboard-app` environment에 더한다) | `15m`, `1h` | `15m`, `1h` |
| `DASHBOARD_SLA_ACK_HIGH`, `DASHBOARD_SLA_ACK_MEDIUM`, `DASHBOARD_SLA_ACK_LOW` | 착수 목표(T25). 실습망 신규 인시던트가 탐지 뒤 지금 우선순위의 목표를 넘기면 "착수 지연"(가져온 데이터는 따지지 않는다). Spring Duration(`30m`, `4h`). 0 이하이거나 high ≤ medium ≤ low가 아니면 시작하지 않는다. `compose.yml`은 넘기지 않아 기본값을 쓴다 | `30m`, `4h`, `24h` | `30m`, `4h`, `24h` |
| `DASHBOARD_LOGIN_NOTICE` | 로그인 화면 안내 문구(T21). 일반 텍스트이고 줄바꿈을 그대로 보인다. 300자를 넘으면 시작하지 않는다. 비밀번호는 넣지 않는다 | 비움(안내 없음) | 비움 |
| `DASHBOARD_LOGIN_NOTICE_LINK_URL` | 안내 문구 아래에 붙는 링크의 주소(T50). `https` 주소만 받는다(호스트가 있고 `user@`가 없어야 한다, 200자 이하, 공백·제어 문자·양방향 문자 없음). 라벨과 안내 문구가 함께 있을 때만 보인다. 검사에 걸리면 링크만 내리지 않고 시작 로그에 이유를 남긴다(값은 남기지 않는다) | 비움(링크 없음) | 비움 |
| `DASHBOARD_LOGIN_NOTICE_LINK_LABEL` | 그 링크의 글(T50). 일반 텍스트 40자 이하, 제어 문자·양방향 문자 없음. 링크는 새 창으로 열린다 | 비움 | 비움 |
| `DASHBOARD_BOOTSTRAP_PASSWORD` | `users` 테이블이 비어 있을 때 4계정 시드용 공통 비밀번호 | 초기 기동 후 비움 권장 | 초기 기동 후 비움 권장 |
| `BOOTSTRAP_VIEWER1_PASSWORD` ~ `BOOTSTRAP_ADMIN_PASSWORD` | 계정별 개별 부트스트랩 비밀번호(선택) | 선택 | 선택 |
| `BOOTSTRAP_ADMIN_TOTP_SECRET` | `admin` TOTP Base32 시크릿(비우면 `/login/totp/setup`에서 등록) | 선택 | 선택 |
| `DASHBOARD_TRUSTED_PROXIES` | 전달 헤더(`X-Forwarded-*`)를 믿을 프록시 주소(T32, 1.2). 쉼표 목록, IPv4·IPv6 주소 그대로만(대역·호스트 이름이면 시작 실패). 비면 아무도 믿지 않는다. `compose.yml`은 `DASHBOARD_WAF_IP`를 넘긴다 | 비움(앱) | `compose.yml`이 `${DASHBOARD_WAF_IP:-10.203.49.250}` |
| `DASHBOARD_SUBNET`, `DASHBOARD_IP_RANGE`, `DASHBOARD_WAF_IP` | `dashboard-net` 고정 서브넷·동적 배정 범위·`nginx-waf` 고정 주소(T32, 1.2). WAF 주소는 서브넷 안, 범위 밖 | `10.203.49.0/24`, `10.203.49.0/25`, `10.203.49.250` | 겹치는 네트워크가 있을 때만 바꾼다 |
| `WAF_HTTP_PORT`, `WAF_HTTPS_PORT` | 호스트에 노출할 WAF HTTP/HTTPS 포트 | `80`, `443` | `18080`, `18443` (충돌 회피 시) |
| `SSL_REDIRECT_PORT` | HTTP → HTTPS `301` 리다이렉트 대상 포트 | `443` (`${WAF_HTTPS_PORT}`) | `18443` |
| `WAF_SERVER_NAME`, `SERVER_NAME` | Nginx `server_name` | 배포 VM IP 또는 도메인 | `localhost` |
| `PROXY_HOST_HEADER` | 백엔드로 전달할 `Host` 헤더 | `$http_host` (`compose.yml` 기본 `$$http_host`) | `$http_host` |
| `SSL_CERT_FILE`, `SSL_CERT_KEY_FILE` | WAF TLS 인증서/개인키 컨테이너 내부 경로 | `/etc/nginx/ssl/server.crt`, `/etc/nginx/ssl/server.key` | `/etc/nginx/conf/server.crt`, `/etc/nginx/conf/server.key` (자동 생성) |

감사 로그 보관 기한과 컨테이너 로그 한도(`T58`)는 앱 환경 변수가 아닙니다. 기한은 예약 작업이 DB 함수에 넘기는 인자이고(2.1) 로그 한도는 `compose.yml`의 `logging` 설정입니다(1.2).

---

## 4. 이미지 빌드 및 VMware Ubuntu Server 배포 절차

### 4.1 Docker 이미지 빌드 (`Dockerfile` & `docker/nginx-waf/Dockerfile`)
프로젝트 루트에서 Spring Boot 애플리케이션(`Dockerfile`)과 ModSecurity WAF(`docker/nginx-waf/Dockerfile`) 이미지를 함께 빌드합니다. 호스트에 Node.js·JDK가 없어도 됩니다.

`Dockerfile`은 3단계 멀티스테이지 빌드입니다.
1. **`frontend` (`node:24-alpine`)**: `frontend/package.json`·`package-lock.json`만 먼저 복사해 `npm ci`(빌드 도구가 devDependencies이므로 `--omit=dev`를 쓰지 않음) → 나머지 `frontend/` 복사 → `npm run build`로 `frontend/dist` 생성.
2. **`builder` (`eclipse-temurin:17-jdk-alpine`)**: `src/main`과 1단계의 `frontend/dist`를 받아 `./gradlew bootJar`. `build.gradle` `processResources`가 `frontend/dist`를 jar의 `static/`으로 넣습니다. Gradle은 Node·npm을 호출하지 않습니다.
3. **런타임 (`eclipse-temurin:17-jre-alpine`)**: `apk upgrade`, 비루트 `appuser`, `HEALTHCHECK`(`/login`), jar만 복사. Node.js 런타임 컨테이너는 배포 스택에 두지 않습니다.

`.dockerignore`가 `frontend/node_modules`·`frontend/dist`·`frontend/.vite`를 빌드 컨텍스트에서 빼므로 Windows 호스트 산출물이 이미지에 섞이지 않습니다. `RUN apk upgrade` 레이어를 빌드 캐시에서 다시 쓰면 그 뒤 나온 Alpine 보안 패치가 들어가지 않습니다. WAF Dockerfile의 `libxml2` 올리기 레이어도 같습니다. 그래서 배포·보안 재검증 전에는 `docker compose build --pull --no-cache`로 다시 빌드합니다. WAF 기반은 digest로 고정했으므로 `--pull`은 그 digest를 받아 올 뿐 새 기반을 가져오지 않습니다.

```bash
docker compose build
```

따로 빌드하려면:
```bash
docker build -t zeek-ad-dashboard-app:local -f Dockerfile .
docker build -t zeek-ad-dashboard-waf:local -f docker/nginx-waf/Dockerfile ./docker/nginx-waf
```

#### WAF 기반 이미지 올리기
WAF 이미지에서는 전체 `apk upgrade`를 하지 않습니다. 기반의 ModSecurity nginx 모듈은 상류가 특정 nginx 판에 맞춰 빌드한 것이라, nginx 패키지가 함께 올라가면 모듈과 어긋날 수 있습니다. 기반을 올릴 때는 아래 순서를 따릅니다.
1. Docker Hub `owasp/modsecurity-crs`에서 `<CRS 판>-nginx-alpine-<날짜>` 형식의 새 태그와 그 index digest를 확인합니다.
2. `docker/nginx-waf/Dockerfile`의 `FROM` 태그와 digest를 함께 바꿉니다.
3. 새 기반에 `libxml2` `2.13.9-r3` 이상이 이미 들어 있으면(`docker run --rm --entrypoint apk <새 기반> list -I libxml2`) Dockerfile의 `libxml2` 올리기 `RUN` 줄을 지웁니다.
4. `docker compose -f compose.yml -f docker/verify/compose.verify.yml build --pull --no-cache`로 다시 빌드하고 Trivy로 WAF 이미지를 스캔합니다.
5. `scripts/security-scan.ps1`(E2E·ZAP)과 배포 전 리허설을 다시 돌립니다.

CRS 판이 바뀌면 `compose.yml`의 CRS 변수(`ALLOWED_METHODS`, `PARANOIA`·`BLOCKING_PARANOIA`, `ANOMALY_INBOUND`)가 그대로 적용되는지 확인합니다. 그리고 E2E의 WAF 차단 판정과 ZAP 결과를 다시 봅니다. 지금은 WAF 오탐 예외 규칙이 없습니다.

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
2. `admin` 계정으로 로그인하면 SPA가 `/login/totp/setup`(최초, QR 등록) 또는 `/login/totp`(등록 후)로 이동합니다. TOTP를 마친 뒤 `/admin/users`에서 계정을 관리합니다. TOTP 코드를 비밀번호 실패와 합쳐 5번 틀리면 계정이 15분 잠기고 화면이 로그인 화면으로 돌아갑니다(`T60`). 다른 관리자가 `/admin/users`에서 잠금을 풀거나 15분 뒤 다시 로그인합니다.
3. 기본 시드 계정의 허용 패턴(`viewer1`/`analyst1`: `cic17-*`, `analyst2`: `syn1-*`, `admin`: `*`) 외에 실습망 캡처(`lab-YYYYMMDD`)를 볼 분석가·조회자는 `/admin/users`에서 해당 계정의 허용 캡처 패턴에 `lab-*`(또는 `cic17-*,lab-*`)를 추가·저장합니다.
4. 계정 설정을 마치면 `.env`에서 `DASHBOARD_BOOTSTRAP_PASSWORD` 등 부트스트랩 변수를 비우고 `docker compose up -d`로 다시 적용하기를 권장합니다.
5. (선택, `T52`) 핵심 서버를 `/admin/critical-assets`(메뉴 "중요 자산")에 등록합니다. 주소는 IPv4 하나만 받습니다(대역·범위·IPv6·호스트 이름은 받지 않고 같은 주소는 `409` `CRITICAL_ASSET_EXISTS`, 200개까지). 그 주소가 호스트인 미종결 인시던트는 자동 분류 우선순위가 한 단계 올라가고(Low → Medium, Medium → High) 같은 우선순위 안에서 먼저 보이며 착수 목표도 올린 우선순위의 것을 씁니다. 조회자에게는 표지만 보이고 이름은 보이지 않습니다. 설명은 관리자 화면에만 있습니다. API: `GET`·`POST /api/admin/critical-assets`, `PUT /api/admin/critical-assets/{id}`(이름·설명만. 주소를 바꾸려면 지우고 새로 만듭니다), `POST /api/admin/critical-assets/{id}/delete`(본문 없음).

---

## 5. Nginx + ModSecurity WAF TLS 인증서 운영 방법 (VM IP SAN 지원)

WAF 기반 이미지(`owasp/modsecurity-crs`)의 내장 진입점 스크립트(`/docker-entrypoint.d/10-generate-certificate.sh`)는 고치지 않고 그대로 씁니다. 환경에 따라 아래 두 방식 중 하나를 고릅니다.

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

외부 PostgreSQL 없이 Docker Compose 오버라이드(`docker/verify/compose.verify.yml`)로 실제 PostgreSQL 17 + Flyway + `latest_incident_queue` + `dashboard.transition_incident` + `dashboard.decide_review` + `dashboard.reopen_incident`(`T53`) + Slack 스레드 + WAF + Trivy + OWASP ZAP을 한 번에 검증합니다. 검증 스택의 세 함수는 zeek_AD 함수와 계약(검사 순서·SQLSTATE·행 값)이 같은 대역입니다(`docker/verify/init/02-init-zeekad-schema.sql`. 표 이름과 소유자가 실제와 달라 zeek_AD migration 파일을 그대로 실행할 수 없습니다).

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/security-scan.ps1 -EvidenceDir "build/security-evidence"
```
- 단계: CycloneDX SBOM → 이미지 빌드 → Trivy(SBOM / FS(`frontend/package-lock.json` npm 포함, `frontend/node_modules`·`frontend/dist` 제외) / 앱·WAF 이미지) → PostgreSQL 17 + WAF E2E → OWASP ZAP 베이스라인.
- E2E는 JSON API로 진행합니다: `GET /api/auth/csrf`로 `XSRF-TOKEN`을 받고 `X-XSRF-TOKEN` 헤더 + JSON 본문으로 `POST /api/auth/login`, 관리자는 `POST /api/auth/totp/verify`. 응답은 JSON 필드로 판정하고 WAF 차단은 `403` + 앱 JSON 오류가 아님 + `nginx-waf` ModSecurity 감사 로그의 규칙 ID로 판정합니다. 그 요청의 감사 줄은 요청 주소에 붙인 `probe=<표식>`으로 찾습니다(`T59`부터. 감사 줄에 요청 헤더가 없어 전처럼 `X-E2E-Probe` 헤더로는 찾을 수 없습니다). 결과는 `waf-e2e-verification.txt`에 남습니다.
- ZAP은 정보성 경고만 있어도 종료 코드 `2`이므로 `zap-baseline.json`의 위험 등급별 경고 수로 판정합니다. High·Medium·Low가 하나라도 있으면 실패입니다. 허용하는 예외는 모든 인스턴스가 `XSRF-TOKEN`인 Low `10010`(Cookie No HttpOnly Flag) 하나입니다(이중 제출 CSRF라 JS가 읽어야 하는 쿠키).
- E2E `[9]`(`T14`)는 클라이언트 IP·전달 헤더 위조를 봅니다: 전달 헤더 없이 로그인한 `viewer1`의 감사 로그 `client_ip`를 기준 B로 잡습니다. 그다음 `X-Real-IP`·`X-Forwarded-For`·`Forwarded: for=`를 하나씩(그리고 `X-Forwarded-Host`·`X-Forwarded-Prefix`까지 모두) 붙인 로그인 성공·실패와 조합 헤더를 붙인 WAF 차단 요청의 ModSecurity `client_ip`가 모두 B인지 확인합니다. `X-Forwarded-Host`·`Forwarded: host=`·`X-Forwarded-Prefix`를 붙인 비인증 리다이렉트 `Location`이 헤더 없을 때와 같은지도 확인합니다. 감사 로그는 `verify-postgres`에서 읽기 전용 `SELECT`로 읽습니다.
- E2E `[16]`(`T32`)는 전달 헤더 신뢰를 봅니다. `nginx-waf` 주소가 `10.203.49.250`이고 앱 신뢰 목록이 같은 값인지 확인합니다. WAF를 거친 요청은 위조 `X-Forwarded-For`를 붙여도 감사 로그 IP가 B이고 `Location`(HTTP→HTTPS, `/nope`, 스택 안 `https://nginx-waf:8443/nope`)이 `T31`까지와 같습니다. WAF가 아닌 컨테이너(`verify-postgres` 안 busybox `wget`)가 `dashboard-app:8080`에 `X-Forwarded-For`·`X-Forwarded-Proto: https`를 붙여 보내면 감사 로그 IP는 그 컨테이너 주소이고 HSTS가 없으며 `Location`은 `http://dashboard-app:8080/login`입니다.
- 검증 스택의 `dashboard-net`은 고정 서브넷(`10.203.49.0/24`)이라 같은 서브넷 네트워크가 남아 있으면 기동이 실패합니다. 스크립트는 기동 전에 그 서브넷을 쓰는 네트워크를 찾아 `zeekad-verify-*` 프로젝트면 내리고(`down -v`) 다른 네트워크면 이름을 알리고 멈춥니다. 스크립트는 성공·실패와 상관없이 끝날 때 자기 스택을 내립니다.
- E2E `[T61d]`·`[T61e]`(`T61`)는 `dashboard-app`·`nginx-waf`의 권한(PID 1의 `CapBnd`·`CapEff`가 0, `NoNewPrivs`가 1)과 상태 확인의 감사 줄을 봅니다. `nginx-waf`가 뜬 지 60초가 넘고 상태 확인이 여러 번 돈 뒤, 대조로 숫자 주소 `Host`의 `/healthz?probe=<표식>`을 한 번 보내 그 감사 줄이 남는 것을 보고, 그 표식 말고는 `/healthz` 감사 줄이 0건인지 봅니다. 구문만 확인했고 첫 실행은 통합 작업 `T57`입니다.
- E2E `[T52a]`~`[T52c]`(`T52`)는 중요 자산 관리자 API를 봅니다. `admin`의 추가(`POST`)·고치기(`PUT`)·지우기(`POST …/{id}/delete`)가 WAF를 지나 처리되고, 같은 주소 `409`·대역 주소 `400`, `analyst1`·`viewer1`의 같은 요청(유효 CSRF)은 앱의 `403`이며 자산 행이 그대로인지, 변경마다 감사 `CRITICAL_ASSET_CHANGE` 한 행인지 봅니다. 구문만 확인했고 첫 실행은 통합 작업 `T57`입니다.
- E2E는 `127.0.0.1`로 접속하므로 모든 요청에 CRS `920350`(숫자 IP Host, 3점)이 붙습니다. 실제 배포에서는 `WAF_SERVER_NAME`의 호스트명으로 접속하는 것을 권장합니다. 상태 확인은 `T61`부터 이름 `Host`를 보내 이 규칙에 걸리지 않습니다(1.2).
- 실행할 때만 난수 비밀번호를 만들어 `docker/verify/compose.verify.yml`을 띄웁니다. 검증이 끝나면 `docker compose down -v`로 임시 컨테이너와 볼륨을 지웁니다.
