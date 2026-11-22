# 포트폴리오 공개 배포 안내서 (Synology DS920+)

대시보드를 포트폴리오로 공개하는 절차다. 이 문서만 보고 처음부터 따라 할 수 있게 적었다.
`https://soc.<DDNS 이름>.synology.me`에서 공개 데모 계정 `demo`(읽기 전용 `VIEWER`, 마스킹 적용)로 로그인해 실제 `zeek_AD` 스냅샷 데이터를 보게 한다. 분석가 흐름은 체험 계정 `trial-analyst`(`ANALYST`, 마스킹 없음)로 직접 해 볼 수 있다. 바꾼 내용은 매시 정각에 앱 밖 운영 서비스가 되돌린다(`T33`).

- 역할 분담: **로컬 PC**(이미지·스냅샷 준비, 리허설) → **NAS**(SSH로 기동) → **DSM**(인증서·역방향 프록시 설정) → 공개 주소 확인.
- 처음에 "확인 필요"로 두었던 항목(DSM 메뉴·헤더 동작, `scp`, `docker compose` 등)은 NAS 배포(`T13`)에서 확인해 결과를 해당 절에 적었다.
- 기존 VMware 스택(`compose.yml`, `docs/deployment-guide.md`)과는 별개다. 두 파일을 병합하지 않는다.

## 1. 구성

```
방문자 ──HTTPS 443──> 공유기 ──> NAS DSM 역방향 프록시 (TLS 종료, 와일드카드 인증서, HSTS)
                                   │ Host: soc.<DDNS 이름>.synology.me
                                   │ X-Forwarded-Proto: https, X-Forwarded-For: <방문자 IP>
                                   ▼
                        127.0.0.1:18480 (NAS 루프백에만 묶임)
                                   │
  ┌────────────── Compose 프로젝트 zeekad-portfolio (네트워크 10.203.48.0/24 고정) ──────────────┐
  │ nginx-waf 주소 10.203.48.250 고정(T32), DSM 연결은 게이트웨이 10.203.48.1로 들어온다        │
  │ nginx-waf (ModSecurity CRS, 로그인 속도 제한) ─> dashboard-app ─> postgres (zeekad 스냅샷,     │
  │                                                     │              zeekad_dashboard)         │
  │                                                     └──────> api (zeek_AD 근거 API) ─┘        │
  └──────────────────────────────────────────────────────────────────────────────────────────┘
```

| 서비스 | 이미지(기본값) | 바깥 포트 | 메모리 상한 |
|---|---|---|---|
| `postgres` | `pgvector/pgvector:0.8.1-pg17` | 없음 | 1g |
| `api` | `zeekad-pipeline:dev` (`python scripts/run_api.py`) | 없음 | 1g |
| `dashboard-app` | `zeek-ad-dashboard-app:local` | 없음 | 1g |
| `nginx-waf` | `zeek-ad-dashboard-waf:local` | `127.0.0.1:18480` → 8080(HTTP) | 512m |
| `demo-seed`(도구, `--profile seed run`으로만 실행) | `zeekad-pipeline:dev` | 없음 | 256m |
| `sandbox-setup`(도구, `--profile seed run`으로만 실행, `T33`) | `pgvector/pgvector:0.8.1-pg17` | 없음 | 128m |
| `sandbox-reset`(상주, `T33`) | `pgvector/pgvector:0.8.1-pg17`(`psql`만) | 없음 | 64m |

리허설(로컬 PC)에서 측정한 실제 사용량은 네 서비스 합계 약 0.4GiB였다(`T12` 실행 기록, 저장소 밖 보관). 상한 합계 3.5GiB는 NAS 여유 메모리(약 17GB) 안이다.

### 1.1 보안 전제와 설정 요약

- **바깥에 여는 포트는 `nginx-waf` HTTP 하나뿐이고 NAS `127.0.0.1`에만 묶는다.** 그래서 이 포트에 접근할 수 있는 것은 같은 NAS의 DSM 역방향 프록시뿐이다. 아래 전달 헤더(`X-Forwarded-For`, `X-Forwarded-Proto`)를 믿는 근거가 이 전제다. 포트를 `0.0.0.0`이나 LAN 주소에 묶으면 이 전제가 깨진다.
- **클라이언트 IP**: nginx는 `X-Forwarded-For`에서 신뢰 범위(`127.0.0.1`, Docker 게이트웨이 `PORTFOLIO_GATEWAY_IP`) 밖의 가장 오른쪽 주소(DSM이 덧붙인 실제 접속 주소)를 클라이언트 IP로 쓴다(`real_ip_recursive on`, 포트폴리오 전용 http 문맥 설정). 앱에 넘기는 헤더는 `T14`부터 모든 스택이 같은 공유 규칙(WAF 이미지 템플릿 `includes/proxy_backend.conf.template`)을 쓴다: `X-Forwarded-For`는 그 주소 하나로 **덮어써서** 넘기고, 방문자가 붙인 `Forwarded`·`X-Forwarded-Host`·`X-Forwarded-Prefix`·`X-Forwarded-Ssl`은 지운다. 그래서 방문자가 헤더를 꾸며도 감사 로그 IP·속도 제한 키·리다이렉트 주소를 바꿀 수 없다. VMware 스택(`compose.yml`)은 `127.0.0.1`만 신뢰한다(`docs/deployment-guide.md` 1.2).
- **전달 헤더를 믿는 출처(`T32`)**: DSM이 `127.0.0.1:18480`으로 붙은 연결은 컨테이너 안에서 Docker 게이트웨이 주소(`PORTFOLIO_GATEWAY_IP`, 기본 `10.203.48.1`)에서 온 것으로 보인다. `nginx-waf`는 `127.0.0.1`과 이 주소에서 온 연결의 `X-Forwarded-For`·`X-Forwarded-Proto`만 믿는다(`set_real_ip_from`과 `X-Forwarded-Proto`·`Port` map의 출처 표시 `geo $realip_remote_addr`). `T31`까지는 스택 서브넷 전체를 믿어서 같은 네트워크의 다른 컨테이너(예: `api`)가 `nginx-waf:8080`에 `X-Forwarded-For`를 붙이면 그 값이 감사 로그 IP가 됐다. 앱은 `nginx-waf` 고정 주소(`PORTFOLIO_WAF_IP`, 기본 `10.203.48.250`)에서 온 연결의 전달 헤더만 믿는다(`DASHBOARD_TRUSTED_PROXIES`, 같은 변수). 그래서 다른 컨테이너가 `nginx-waf:8080`이나 `dashboard-app:8080`에 전달 헤더를 붙여 보내도 감사 로그 IP는 그 컨테이너 주소이고 `https`로 판정되지 않는다(리허설 `[T32]`).
  - `PORTFOLIO_SUBNET`을 바꾸면 `PORTFOLIO_WAF_IP`·`PORTFOLIO_GATEWAY_IP`도 그 서브넷 안으로 바꾼다. 게이트웨이 주소는 반영 전에 NAS에서 확인한다(3.8 `T32`).
  - 남은 위험: 같은 bridge에서 `NET_RAW` 권한으로 패킷 출처를 꾸미는 공격은 막지 못한다. 또 게이트웨이를 믿으므로 NAS 호스트의 로컬 프로세스와 host 네트워크 컨테이너는 `127.0.0.1:18480`으로 전달 헤더를 꾸밀 수 있다. 이것은 원래 전제(이 포트에는 DSM만 붙는다)와 같다. 공개 스택은 네트워크(ipam)를 다시 만들지 않으려고 동적 배정 범위를 따로 두지 않았다. 그래서 `nginx-waf`가 내려가 있는 동안 다른 컨테이너가 `.250`을 받으면 앱이 그 컨테이너를 믿는다(그때 `nginx-waf`는 주소 충돌로 뜨지 않아 장애로 드러난다). 네트워크를 다시 만들 일이 있으면 VMware 스택처럼 `ip_range`를 준다.
- **절대 URL**: 신뢰 출처(DSM)가 보낸 `X-Forwarded-Proto`가 `https`면 앱에 `https`/`443`을 넘긴다. 그래서 비인증 보호 경로의 `302 Location`이 `https://soc.<DDNS 이름>.synology.me/login`(내부 포트 없음)이 된다. HTTP 리스너는 HTTPS로 리다이렉트하지 않는다(TLS는 DSM이 끝낸다). 스택 내부 8443 리스너(DSM 헤더 없음)에서는 `https` + Host의 포트(`8443`)를 넘겨 리다이렉트가 실제로 열린 `https://nginx-waf:8443/...`을 가리킨다.
- **계정**: `demo`(VIEWER, 허용 캡처 `DEMO_CAPTURE_PATTERNS`, 비어 있으면 `cic17-*,syn1-*,lab-20261119`)와 체험용 분석가 `trial-analyst`(ANALYST, 허용 캡처는 `demo`와 같은 변수, `T33`)만 활성. `trial-analyst`는 분석가라 마스킹이 없다(공개 전 노출 확인 1.3). 실습망 캡처는 Kali 실행 결과 `lab-20261119`만 정확한 ID로 보인다. 시험 캡처 `lab-20261201`(가짜 패킷)·첫 VM 실행 `lab-20261118`처럼 스냅샷에 있는 나머지 캡처는 `demo`에게 보이지 않는다(DB에서는 지우지 않는다, 2026-11-21 결정). `viewer1`·`analyst1`·`analyst2`·`admin`은 서로 다른 비공개 무작위 비밀번호를 가진 채 비활성이다.
- **계정 잠금과 로그인 속도 제한(`T29`에서 바꿈)**: 모든 계정은 앱 기본대로 틀린 비밀번호 5번에 15분 잠긴다(`compose.portfolio.yml`이 `DASHBOARD_MAX_FAILED_ATTEMPTS="5"`로 고정하고 `.env`를 쓰지 않는다. `T12`~`T27`은 `PORTFOLIO_MAX_FAILED_ATTEMPTS=1000000`으로 모든 계정의 잠금을 사실상 껐었다. NAS `.env`에 그 줄이 남아 있어도 이제 쓰이지 않는다). 비밀번호를 공개한 `demo`·`trial-analyst`만 아래 잠금 제외로 빠진다. 비공개 ANALYST·ADMIN 계정이 남의 시도로 15분 잠길 수 있는 것은 받아들인다(방문자 화면은 공개 계정 둘). nginx는 `POST /api/auth/login`만 클라이언트 IP당 분당 10회 + 버스트 5로 제한하고 넘으면 `429`를 준다(`PORTFOLIO_LOGIN_RATE`, `PORTFOLIO_LOGIN_BURST`).
- **공유 계정 잠금 제외(`T29`, `T33`에서 넓힘)**: `compose.portfolio.yml`이 `DASHBOARD_LOCKOUT_EXEMPT_USERNAMES=demo,trial-analyst`(기본, `.env`의 같은 이름으로 바꿀 수 있음)를 넘긴다. 비밀번호를 공개한 공유 계정을 누군가 틀린 비밀번호로 잠가 다른 방문자를 막지 못하게 하려는 것이다. 앱은 로그인 때 DB 역할이 VIEWER 또는 ANALYST인 목록 계정만 잠금에서 빼고(실패 수·잠금을 바꾸지 않음), 실패 감사(`LOGIN_FAILURE`, `lockoutExempt: true`)는 그대로 남긴다. ADMIN은 목록에 있어도 잠긴다. 무작위 대입은 위 IP당 로그인 속도 제한이 막는다(값은 바꾸지 않았다). **운영 규칙: 목록에는 비밀번호를 공개한 공유 계정만 넣는다.** 실제 분석가처럼 비공개 비밀번호 계정을 넣으면 그 계정도 잠기지 않아 여러 IP에서 대입할 때 막을 것이 IP당 속도 제한뿐이다. 목록의 계정이 없거나 VIEWER·ANALYST가 아니면 앱이 시작할 때 경고 로그를 남긴다(이름만). 공개 데모에서는 로그인 실패를 일부러 만들어 시험하지 않는다(실패하면 방문자가 막힐 수 있다). 리허설 `[T29]`가 대신 확인한다.
- **기준 시각(`T23`)**: `dashboard-app`은 `DASHBOARD_TIME_ANCHOR=latest-data`(compose 기본, `.env`의 `PORTFOLIO_TIME_ANCHOR`로 바꿀 수 있음)로 뜬다. 데이터가 더 늘지 않는 고정 스냅샷이라 인시던트 큐의 "최근 24시간" 등을 `demo`가 볼 수 있는 캡처의 최신 탐지 작업 완료 시각에서 센다(숨긴 캡처의 시각은 섞이지 않는다). 모든 화면 맨 위에 "고정 스냅샷 · 기준 시각 …"이 보이고 새 인시던트 자동 갱신은 꺼진다. `T23`은 3.8로 `dashboard-app` 이미지와 `compose.portfolio.yml`을 바꿨다(`ID=t23`, `SVC=dashboard-app`, `FILES="compose.portfolio.yml"`).
- **센서 상태(`T24`)**: 현황판·운영 현황의 센서 상태 기준은 앱 기본값(마지막 채점이 기준 시각에서 15분 이내 정상, 1시간 이내 지연, 넘으면 중단)을 쓴다. 고정 스냅샷이라 기준 시각 기준으로 센다. `compose.portfolio.yml`은 이 값을 넘기지 않는다(`DASHBOARD_SENSOR_STALE_AFTER`·`DASHBOARD_SENSOR_DOWN_AFTER`, `docs/deployment-guide.md`).
- **착수 목표(`T25`)**: 앱 기본값(High 30분·Medium 4시간·Low 24시간, 실습망 신규 인시던트만)을 쓴다. 고정 스냅샷이라 경과·착수 지연·처리 시간 지표는 기준 시각 기준으로 센다. `compose.portfolio.yml`은 넘기지 않는다(`DASHBOARD_SLA_ACK_HIGH`·`DASHBOARD_SLA_ACK_MEDIUM`·`DASHBOARD_SLA_ACK_LOW`, `docs/deployment-guide.md`). 담당 기록(앱 DB `V2` 표)은 공개 데모에 지어 넣지 않으므로 처음에는 모두 "미배정"으로 보인다. 체험 계정이 지정한 담당은 매시 정각에 해제된다(1.3).
- **세션 쿠키**: `DASHBOARD_COOKIE_SECURE=true` 그대로다(`Secure`·`HttpOnly`·`SameSite=Lax`). 브라우저는 DSM과 HTTPS로 통신하므로 문제없다.
- **8443 리스너**: `nginx-waf`의 HTTPS 리스너(이미지 기본 자체 서명 인증서)는 스택 네트워크 안에서만 쓰인다(리허설 ZAP 대상). 바깥에 열지 않는다.
- **잔여 위험(고치지 않음)**: `dashboard_app` 계정은 관리용 `postgres` DB에도 접속할 수 있다(PostgreSQL 기본 `PUBLIC` CONNECT. 시드가 그 DB의 `pgcrypto`를 쓴다). 슈퍼유저가 아니고 `public` 스키마 CREATE 권한도 없다. `postgres` 컨테이너에는 바깥 포트가 없어 스택 네트워크 안의 컨테이너만 접속할 수 있다(`T13` 확인).

### 1.2 관련 파일

| 파일 | 내용 |
|---|---|
| `compose.portfolio.yml` | 포트폴리오 스택(Compose v2.20.1에서 동작하는 문법만 사용) |
| `.env.portfolio.example` | 환경 변수 목록(비밀값은 빈 값) |
| `docker/portfolio/initdb/01-roles-databases.sh` | 역할·DB·DB 수준 ACL 생성(zeek_AD `01-roles-databases.sh`와 같은 역할 집합) |
| `docker/portfolio/initdb/02-restore-snapshot.sh` | 스냅샷 SHA-256 확인 → `pg_restore --exit-on-error`(소유자·권한 포함) → 성공 표지 |
| `docker/portfolio/nginx/zeekad-portfolio-http.conf.template` | 포트폴리오 전용 nginx http 문맥 설정(DSM 뒤의 실제 IP·전달 Proto/Port·속도 제한). `compose.yml`에는 붙지 않는다. 방문자 전달 헤더 지우기는 공유 이미지 템플릿이 한다(`T14`) |
| `docker/portfolio/seed/seed_demo.py` | 계정 시드(멱등): `demo`, `trial-analyst`(`TRIAL_ANALYST_PASSWORD`가 비면 만들지 않음) |
| `docker/portfolio/sandbox/sandbox-setup.sh` | 체험 계정 초기화 설정(`T33`): 전용 역할·기준선·초기화 함수 둘, `--rebuild-baseline` |
| `docker/portfolio/sandbox/sandbox-reset.sh` | 체험 계정 초기화 서비스(`T33`): 매시 정각, `--once` |
| `scripts/portfolio-snapshot.ps1` | `zeekad` DB 스냅샷(로컬 PC 컨테이너 또는 `-SshHost`로 배포 VM)·매니페스트·비밀값 패턴 검사 |
| `scripts/portfolio-verify.ps1` | 로컬 PC 리허설(E2E [0]~[8], 재시드, [T33] 초기화(주기 1분), ZAP [9]). `-ExposureDir`를 주면 체험 계정 노출 확인 |

### 1.3 체험 계정과 매시 정각 초기화(`T33`)

- **무엇을 되돌리나**: 분석가 쓰기는 넷(상태 변경·담당 지정·인시던트 검토 결정·검토 목록 결정)이다. 파이프라인 DB(`zeekad`)는 쓰기 계정 `dashboard_rw`가 함수 둘(`dashboard.transition_incident`, `dashboard.decide_review`)만 실행해 바꾸므로 바뀌는 표가 `zeekad.incident_status`·`zeekad.incident_status_history`·`zeekad.analyst_review` 셋뿐이다. 이 셋을 스냅샷 직후 기준선(`sandbox_baseline` 스키마)과 기본키로 맞춘다. 기준선에 없는 행은 지운다. 없어진 행은 넣고 칸이 다른 행(모든 칸 비교)은 되돌린다. 앱 DB(`zeekad_dashboard`)의 담당은 해제만 하고 담당 이력에 해제 행(행위자 `sandbox-reset`, 사유 값 `manual`)을 덧붙인다. 감사 로그와 담당 이력(추가만 하는 기록)은 지우지 않는다.
- **어디서 하나**: 앱 밖 운영 서비스 `sandbox-reset`(상주, `psql`만)이 매시 정각(UTC·KST 모두 정각)에 `sandbox.reset_pipeline()` 다음 `sandbox.reset_assignments()`를 부르고 결과 한 줄을 남긴다. 시작할 때는 돌리지 않는다. 앱에는 데모 전용 동작(모드 플래그, 앱 안 예약 작업, 체험 계정 이름을 아는 코드, 배너)이 없다.
- **권한**: 두 함수는 `SECURITY DEFINER`(소유 `zeekad_owner`·`dashboard_app`)이고 `search_path`를 고정하며 모든 객체를 스키마로 한정한다. 접속 계정 `zeekad_sandbox_reset`은 두 DB `CONNECT`, 함수가 든 `sandbox` 스키마 `USAGE`, 두 함수 `EXECUTE`만 가진다. 표·기준선(`sandbox_baseline`)·`CREATE` 권한은 없다(기준선을 바꿀 수 있으면 실제 표를 고른 값으로 되돌릴 수 있다). `dashboard_rw` 권한은 바꾸지 않는다.
- **동시 쓰기**: `reset_pipeline()`은 처음에 세 표를 `SHARE ROW EXCLUSIVE`로 잠가 진행 중인 쓰기를 기다리고 새 쓰기를 막는다. 5초 안에 잠그지 못하면 아무것도 바꾸지 않고 오류로 끝내고 다음 정각에 다시 한다.
- **옛 기준선 거부**: 기준선에 표지(인시던트 수·탐지 작업 수·최대 `job_id`·세 표의 열 정의 해시)를 함께 둔다. 새 스냅샷을 올렸는데 기준선이 옛것이면 표지가 맞지 않아 초기화가 아무것도 바꾸지 않고 오류를 남긴다(3.10).
- **설정 도구 `sandbox-setup`**(`--profile seed`, 슈퍼유저로 접속): 전용 역할·두 스키마·기준선·두 함수를 만들고 권한을 점검한다. 멱등이다. 기준선은 처음과 `--rebuild-baseline`일 때만 만든다. 그때 체험 계정 이름이 세 표의 행위자(`updated_by`·`actor`·`analyst`)나 현재 담당자에 하나라도 있으면 멈춘다(방문자 변경이 기준선이 되는 것을 막는다. 새 스냅샷이 그 이름을 이미 쓰는 경우도 잡는다. 공개 스냅샷에는 zeek_AD 기록의 행위자 `demo-analyst`가 있어 체험 계정 이름을 `trial-analyst`로 정했다). 처음 만들 때는 담당자가 있는 담당 행이 0이어야 한다. 다시 만들 때는 `sandbox-reset`을 먼저 멈춘다(초기화 계정 접속이 있으면 멈춘다).
- **결정을 소비하는 주체 없음**: 공개 스택의 `api`는 `run_api.py` 하나뿐이고 `zeekad_api`에는 `zeekad` 표 쓰기 권한이 없다. 쓰기 권한이 있는 `zeekad_worker`는 NOLOGIN이고 워커가 없다. 그래서 검토 결정 뒤 재개·보고서·Slack 같은 후속 쓰기가 없다(리허설 `[T33f]`가 세 표 밖 `zeekad` 표 전부의 행 수·내용 해시를 쓰기 전·직후·2분 뒤에 비교한다).
- **쓰기 속도 제한**: nginx가 네 쓰기 경로의 `POST`만 클라이언트 IP당 분당 10회 + 버스트 5로 제한하고 넘으면 `429`를 준다(`PORTFOLIO_WRITE_RATE`, `PORTFOLIO_WRITE_BURST`, 로그인 제한과 다른 영역). 경로는 정규화된 `$uri`를 정규식으로 본다.
- **사유·메모 길이 상한**: 앱이 상태 변경 사유와 검토 메모를 500자(앞뒤 공백 뺀 코드 포인트)까지만 받는다(제품 기능, 모든 스택).
- **노출**: `trial-analyst`는 `demo`와 같은 캡처를 마스킹 없이 본다. 공개 전 리허설에서 `lab-20261119`의 모든 인시던트에서 화면이 부르는 API 응답을 두 계정으로 받아 비교하고(`scripts/portfolio-verify.ps1 -ExposureDir <저장소 밖 폴더>`), 드러나는 값의 종류를 운영자가 확인했다. 새 실습망 캡처를 공개할 때도 같은 확인을 한다(3.10).

## 2. 로컬 PC에서 준비

PowerShell에서 `<저장소 루트>`로 이동해 실행한다.

### 2.1 이미지 빌드

```powershell
docker build --pull -t zeek-ad-dashboard-app:local .
docker build --pull -t zeek-ad-dashboard-waf:local docker/nginx-waf
docker pull pgvector/pgvector:0.8.1-pg17
```

- 앱 이미지는 `--pull`로 최신 기반 이미지를 받고, 런타임 단계의 `apk upgrade`로 Alpine 패키지를 올린다.
- WAF 이미지의 기반(`owasp/modsecurity-crs`)은 Dockerfile에서 태그와 digest로 고정했다. `--pull`은 그 digest를 받아 올 뿐 새 기반을 가져오지 않는다. 기반 위에서는 `libxml2`만 고친 판(`2.13.9-r3` 이상)으로 올린다. 기반을 올리는 절차는 `docs/deployment-guide.md` 4.1 "WAF 기반 이미지 올리기"에 있다.

- `zeekad-pipeline:dev`(근거 API)는 `zeek_AD` 저장소에서 만든 이미지다. 로컬 PC에 있는 것을 그대로 쓴다. 다시 만들어야 하면 `zeek_AD` 저장소의 안내대로 `docker build -f deploy/pipeline/Dockerfile -t zeekad-pipeline:dev .`를 실행한다(바탕 이미지는 digest로 고정돼 있다).
- 로컬 PC와 NAS는 모두 `x86_64`라 이미지를 그대로 옮길 수 있다.

### 2.2 스냅샷 내보내기

```powershell
# 공개 데모 원본(T22부터): <배포 VM>(Ubuntu 24.04)의 zeek_AD DB. WSL의 ssh 설정(~/.ssh/config의 호스트 별칭)을 쓴다.
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/portfolio-snapshot.ps1 -SshHost <배포 VM>
# 로컬 PC Docker의 zeek_AD DB를 원본으로 쓸 때(T12~T21의 방식)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/portfolio-snapshot.ps1
```

- 원본은 `-SshHost`가 있으면 그 호스트(배포 VM), 없으면 로컬 PC의 `zeekad-postgres-1` 컨테이너다. 어느 쪽이든 컨테이너 안 로컬 소켓 인증(`psql`·`pg_dump -U postgres`)만 쓰며 `zeek_AD`의 `.env`·비밀번호를 읽지 않고 원본에 쓰지 않는다.
- VM 원본은 `wsl -d Ubuntu --exec bash -c "ssh <배포 VM> bash -s < <스크립트>"`로 보낸다. 원격 명령은 한 줄짜리 스크립트 파일(`build/portfolio/source-remote/NN.sh`)로 만들어 인용이 세 겹(PowerShell→WSL→ssh→원격 셸)으로 깨지는 것을 피한다. 보내는 명령은 `docker inspect`, `docker exec <pg> psql`(SELECT만), `pg_dump --version`, `pg_dump -Fc zeekad`(표준 출력), `pg_dumpall --globals-only --no-role-passwords`뿐이고 VM에 파일을 남기지 않는다. 덤프 바이트는 PowerShell을 거치지 않고 WSL bash가 바로 `/mnt/c/...` 파일에 쓴다. 보낸 명령 전체는 `build/portfolio/source-commands.txt`에 남는다. `zeekad` 밖의 DB(특히 VM 대시보드 앱 DB)는 덤프하지 않는다.
- 원본 `pg_dump`가 복원 이미지(`pgvector/pgvector:0.8.1-pg17`) 서버보다 높은 버전이면 멈춘다.
- 덤프 전후로 `dashboard.latest_incident_queue` 캡처별 건수를 센다. 파이프라인이 도는 중이라도 **공개할 캡처**(`-PublicCaptures`, 기본 `cic17-*,syn1-*,lab-20261119`)만 전후가 같으면 된다. 공개 캡처가 바뀌면 멈춘다. 그 밖의 캡처 변화는 `manifest.json`의 `nonPublicCountChanges`에 정보로 남는다.
- 결과(`build/portfolio/`, Git 제외): `zeekad.dump`(`pg_dump -Fc`), `zeekad.dump.sha256`, `manifest.json`(원본 `sourceHost`·`sourceTransport`, SHA-256, 내보낸 시각, 버전, 공개·숨김 캡처, 캡처별 건수, 캡처별 최신 작업 `captureLatestJobs`: 작업 ID·번들·사건 수·첫·마지막 사건 시각·`feedback_summary` `'all'` 행 수·전체 작업 목록. `latest_incident_queue`에서 한 캡처에 작업이 둘 이상이면 멈춘다), `source-globals.sql`(역할 비교용, 비밀번호 없음), `source-commands.txt`, `secret-scan.txt`(덤프·근거 API 이미지의 비밀값 패턴 위치·건수, 값은 남기지 않음).
- 새 스냅샷을 만들기 전에 이전 `build/portfolio/`를 `build/portfolio-pre-<작업 ID>/`로 옮겨 둔다(되돌리기용).
- `secret-scan.txt`에서 Slack 웹훅·토큰·API 키처럼 보이는 것이 새로 나오면 배포하지 말고 먼저 확인한다(지우지 않는다).

### 2.3 리허설(NAS와 같은 구성)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/portfolio-verify.ps1 -EvidenceDir build/portfolio-evidence/<작업 ID>
```

- 프로젝트 이름 `zeekad-portfolio-verify`로 같은 `compose.portfolio.yml`을 띄운다. 시드를 두 번 실행한 뒤 DSM을 흉내 낸 요청으로 E2E와 ZAP을 돌리고 `down -v`로 지운다. 비밀값은 실행마다 무작위로 만든다. 실패하면 종료 코드가 0이 아니다.
- 로컬 PC 메모리가 빠듯해 실행이 중단되면 다시 돌리지 말고 `docker compose -p zeekad-portfolio-verify -f compose.portfolio.yml down -v`로 정리한다.

### 2.4 옮길 파일 만들기

```powershell
New-Item -ItemType Directory -Force build/portfolio-images | Out-Null
# 순서가 NAS 3.3의 docker image inspect 인자 순서와 같아야 한다.
$images = [ordered]@{
  'zeek-ad-dashboard-app:local'  = 'zeek-ad-dashboard-app.tar'
  'zeek-ad-dashboard-waf:local'  = 'zeek-ad-dashboard-waf.tar'
  'zeekad-pipeline:dev'          = 'zeekad-pipeline.tar'
  'pgvector/pgvector:0.8.1-pg17' = 'pgvector-pg17.tar'
}
foreach ($tag in $images.Keys) {
  docker save -o "build/portfolio-images/$($images[$tag])" $tag
  # 다중 플랫폼 이미지(pgvector)는 받지 않은 플랫폼 때문에 실패할 수 있다. 그때만 amd64로 한정한다.
  if ($LASTEXITCODE -ne 0) { docker save --platform linux/amd64 -o "build/portfolio-images/$($images[$tag])" $tag }
  if ($LASTEXITCODE -ne 0) { throw "docker save failed: $tag" }
}
# NAS에서 sha256sum -c 로 확인할 목록(LF 줄바꿈)
$lines = foreach ($f in $images.Values) { "$((Get-FileHash -Algorithm SHA256 "build/portfolio-images/$f").Hash.ToLower())  $f" }
[IO.File]::WriteAllText("$PWD/build/portfolio-images/images.sha256", ($lines -join "`n") + "`n")
# 이미지 ID 대조 목록: 각 tar 안 manifest.json의 Config(이미지 설정 digest).
# 로컬 PC Docker Desktop은 containerd 이미지 저장소라 로컬 PC의 docker image inspect .Id(매니페스트·인덱스 digest)는
# NAS(Docker 24 기본 저장소)에서 docker load 뒤의 .Id(= 설정 digest)와 다르다. 그래서 tar 안의 Config digest로 비교한다.
$ids = foreach ($tag in $images.Keys) {
  $manifest = (tar -xOf "build/portfolio-images/$($images[$tag])" manifest.json | Out-String) | ConvertFrom-Json
  $cfg = @($manifest)[0].Config                        # 예: blobs/sha256/<hex> 또는 <hex>.json
  if ($cfg -notmatch '([0-9a-f]{64})') { throw "Config digest not found: $tag" }
  "sha256:$($Matches[1]) $tag"
}
# PowerShell의 > 는 UTF-16·CRLF로 써서 NAS diff가 항상 실패한다. LF UTF-8(BOM 없음)로 쓴다.
[IO.File]::WriteAllText("$PWD/build/portfolio-images/image-ids.txt", ($ids -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
Get-Content build/portfolio-images/image-ids.txt
```

- `zeekad-pipeline.tar`는 약 5GB다. `/volume1` 여유 공간(1.5TB)은 충분하다.
- 리허설(2.3)과 `docker save` 사이에 이미지를 다시 빌드하거나 받지 않는다. 그래야 리허설한 이미지가 NAS로 간다(로컬 PC 안의 동일성은 `docker image inspect --format '{{.Id}}'`를 리허설 전후·`docker save` 뒤에 기록해 비교한다).
- 이미지 `tar`와 스냅샷은 Git에 넣지 않는다(`build/`는 Git 제외 경로).

배포 묶음(NAS 폴더 `/volume1/docker/zeekad-portfolio`에 아래 구조로 둔다):

```
/volume1/docker/zeekad-portfolio/
├── compose.portfolio.yml
├── .env.portfolio.example        (복사해서 .env 작성)
├── docker/portfolio/initdb/*.sh   (LF 줄바꿈이어야 한다. 저장소의 .gitattributes가 *.sh를 LF로 고정한다)
├── docker/portfolio/nginx/*.conf.template
├── docker/portfolio/seed/seed_demo.py
├── snapshot/zeekad.dump, zeekad.dump.sha256, manifest.json
└── images/*.tar, images.sha256, image-ids.txt
```

## 3. NAS에서 배포 (SSH)

NAS: `ssh <NAS 사용자>@<NAS 주소>`(키 인증), Docker는 `/usr/local/bin/docker`(`<NAS 사용자>`는 `docker` 그룹이라 sudo 불필요). 아래 명령은 NAS 셸에서 실행한다.

### 3.1 사전 확인(기존 컨테이너를 건드리지 않는다)

```sh
export PATH=/usr/local/bin:$PATH
docker version --format '{{.Server.Version}}'; docker compose version   # Docker 24.0.2, Compose v2.20.1 예상
# 기존 컨테이너·네트워크 상태를 기록해 둔다(배포 뒤 같은지 비교).
mkdir -p ~/zeekad-portfolio-check
docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Ports}}' | sort > ~/zeekad-portfolio-check/containers-before.txt
for n in $(docker network ls -q); do docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' $n; done | sort | tee ~/zeekad-portfolio-check/networks-before.txt
docker image ls --format '{{.Repository}}:{{.Tag}} {{.ID}}' | sort > ~/zeekad-portfolio-check/images-before.txt
# 옮길 네 태그가 이미 있는지(아무것도 나오지 않는 것이 정상). 있으면 3.3 대조 전에 ID를 image-ids.txt와 비교하고,
# 다른 ID면 멈춘다(docker load가 기존 태그를 새 이미지로 옮겨 기존 컨테이너가 쓰던 이미지를 바꿀 수 있다).
grep -E '^(zeek-ad-dashboard-app:local|zeek-ad-dashboard-waf:local|zeekad-pipeline:dev|pgvector/pgvector:0\.8\.1-pg17) ' ~/zeekad-portfolio-check/images-before.txt || echo "no target tags"
# 포트 18480이 비어 있는지(아무것도 나오지 않아야 한다). 18080은 같은 NAS의 기존 포트폴리오 컨테이너가 쓴다.
netstat -tln 2>/dev/null | grep -E ':18480\b' || echo "18480 free"
# 배포 폴더를 sudo 없이 만들 수 있는지(/volume1/docker 쓰기 권한)
ls -ld /volume1/docker; test -w /volume1/docker && echo "volume1/docker writable"
free -m; df -h /volume1
```

로컬 PC(PowerShell)에서 기존 포트폴리오 응답을 기록해 둔다(배포·DSM 설정 뒤 같은지 비교). 공유기에 NAT 루프백이 없으면 로컬 PC에서 공개 IP로는 접속되지 않으므로 `--resolve`로 NAS의 DSM `443`에 직접 붙는다. 이 값은 `--resolve` 경로가 동작한다는 근거도 된다.

```powershell
curl.exe -s -o NUL -w "%{http_code}" --resolve <DDNS 이름>.synology.me:443:<NAS 주소> https://<DDNS 이름>.synology.me/
```

- **서브넷 겹침 확인**: `networks-before.txt`에 `10.203.48.0/24`와 겹치는 대역이 있으면 `.env`의 `PORTFOLIO_SUBNET`을 겹치지 않는 대역(예: `10.203.50.0/24`. `10.203.49.0/24`는 VMware 스택 `compose.yml`의 기본값이다)으로 바꾼다. 그때 `PORTFOLIO_WAF_IP`·`PORTFOLIO_GATEWAY_IP`도 그 대역 안으로 바꾼다(`T32`, 1.1).
- DS920+ DSM 7.3.2(Container Manager)에서는 `docker compose`(v2.20.1)가 동작한다(`T13` 확인). `docker-compose`로 바꿀 필요 없다.
- 이 절부터의 NAS 블록(`sh`)은 **NAS 셸 안에서** 실행한다(`ssh <NAS 사용자>@<NAS 주소>`로 들어가서 붙여 넣거나, 로컬 PC의 Git Bash에서 `ssh ... 'bash -s' <<'EOF' ... EOF`). 로컬 PC의 Windows PowerShell 5.1에서 `ssh <NAS> '<여러 명령>'`처럼 한 줄 인자로 넘기면 인자 안의 큰따옴표가 지워져(`printf "\n"` → `printf n`) 결과가 달라진다(`T13`에서 확인).

### 3.2 폴더와 파일 전송

NAS:

```sh
mkdir -p /volume1/docker/zeekad-portfolio/snapshot /volume1/docker/zeekad-portfolio/images /volume1/docker/zeekad-portfolio/docker
chmod 700 /volume1/docker/zeekad-portfolio
```

로컬 PC(PowerShell, 저장소 루트):

```powershell
$nas = "<NAS 사용자>@<NAS 주소>"; $dst = "/volume1/docker/zeekad-portfolio"
# DSM은 SFTP가 꺼져 있어 기본 scp(SFTP 모드)가 'subsystem request failed'로 실패한다. -O(기존 SCP 프로토콜)를 쓴다(T13 확인).
scp -O compose.portfolio.yml .env.portfolio.example "${nas}:${dst}/"
scp -O -r docker/portfolio "${nas}:${dst}/docker/"
scp -O build/portfolio/zeekad.dump build/portfolio/zeekad.dump.sha256 build/portfolio/manifest.json "${nas}:${dst}/snapshot/"
# PowerShell은 네이티브 명령 인자의 *.tar를 펼치지 않을 수 있으므로 파일 이름을 하나씩 적는다.
scp -O build/portfolio-images/zeek-ad-dashboard-app.tar build/portfolio-images/zeek-ad-dashboard-waf.tar build/portfolio-images/zeekad-pipeline.tar build/portfolio-images/pgvector-pg17.tar build/portfolio-images/images.sha256 build/portfolio-images/image-ids.txt "${nas}:${dst}/images/"
```

- PowerShell 5.1 파이프(`tar | ssh`, `docker save | ssh`)는 바이트를 문자열로 바꿔 깨뜨리므로 쓰지 않는다. 파일은 `scp`로만 보낸다.
- 작업 트리의 `.env.portfolio.example`·`compose.portfolio.yml`·`seed_demo.py`·nginx 템플릿은 Windows에서 CRLF로 체크아웃돼 그대로 전송된다(`*.sh`만 `.gitattributes`로 LF). Compose·nginx·`python`은 CRLF여도 동작한다. 다만 3.4의 `.env` 작성 스크립트는 줄 끝 `\r`을 떼야 한다(스크립트에 들어 있다).

NAS에서 스냅샷 권한과 무결성 확인:

```sh
cd /volume1/docker/zeekad-portfolio
# snapshot/은 chmod 700 이전에 만들어져 /volume1/docker의 Synology ACL을 상속받는다(NAS 사용자만 허용).
# 그러면 컨테이너 안 postgres(uid 999)가 덤프를 읽지 못해 복원이 'zeekad.dump ... is missing'으로 실패한다(T13에서 확인).
# 755/644로 바꾸면 Linux 권한 모드가 된다. 덤프는 공개 데모 데이터이고 상위 폴더가 700이라 다른 NAS 사용자는 들어올 수 없다.
chmod 755 snapshot && chmod 644 snapshot/*   # 컨테이너에서 읽히는지는 3.3 끝에서 확인한다
(cd snapshot && sha256sum -c zeekad.dump.sha256)
(cd images && sha256sum -c images.sha256)
ls -l docker/portfolio/initdb/*.sh && head -1 docker/portfolio/initdb/01-roles-databases.sh | od -c | head -2   # \r 이 없어야 한다
```

### 3.3 이미지 적재

```sh
cd /volume1/docker/zeekad-portfolio/images
for f in zeek-ad-dashboard-app.tar zeek-ad-dashboard-waf.tar zeekad-pipeline.tar pgvector-pg17.tar; do docker load -i "$f"; done
# image-ids.txt는 tar 안 manifest.json의 Config digest(2.4). Docker 24 기본 저장소에서는 이것이 적재 뒤 .Id다.
for t in zeek-ad-dashboard-app:local zeek-ad-dashboard-waf:local zeekad-pipeline:dev pgvector/pgvector:0.8.1-pg17; do
  printf '%s %s\n' "$(docker image inspect --format '{{.Id}}' "$t")" "$t"
done | diff - image-ids.txt && echo "image IDs match"
# 컨테이너 안 postgres(uid 999)가 스냅샷을 읽을 수 있는지(3.2의 권한 변경 확인). zeekad.dump: OK 가 나와야 한다
docker run --rm --network none --user 999:999 -v /volume1/docker/zeekad-portfolio/snapshot:/snapshot:ro --entrypoint sh pgvector/pgvector:0.8.1-pg17 -c 'cd /snapshot && sha256sum -c zeekad.dump.sha256'
```

이미지 적재가 끝나면 `images/*.tar`는 지워도 된다(롤백용으로 남겨도 된다).

### 3.4 `.env` 작성(비밀값 생성)

비밀값은 셸 변수와 내장 명령(`printf`)으로만 다룬다. `sed` 같은 외부 명령의 인자로 넘기면 실행 중 프로세스 목록에 보인다.

```sh
cd /volume1/docker/zeekad-portfolio
umask 077
gen() { tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32; }
while IFS= read -r line || [ -n "$line" ]; do
  line=${line%$'\r'}   # 작업 트리에서 CRLF로 전송된 예시 파일. 떼지 않으면 'KEY=' 패턴이 맞지 않아 비밀값이 하나도 채워지지 않는다
  case "$line" in
    POSTGRES_SUPERUSER_PASSWORD=|ZEEKAD_API_PASSWORD=|DASHBOARD_RO_PASSWORD=|DASHBOARD_RW_PASSWORD=|DASHBOARD_APP_PASSWORD=|\
    BOOTSTRAP_VIEWER1_PASSWORD=|BOOTSTRAP_ANALYST1_PASSWORD=|BOOTSTRAP_ANALYST2_PASSWORD=|BOOTSTRAP_ADMIN_PASSWORD=|\
    SANDBOX_RESET_DB_PASSWORD=)
      v=$(gen); printf '%s%s\n' "$line" "$v" ;;
    BOOTSTRAP_ADMIN_TOTP_SECRET=)
      v=$(tr -dc 'A-Z2-7' </dev/urandom | head -c 32); printf '%s%s\n' "$line" "$v" ;;
    PORTFOLIO_SERVER_NAME=*)
      printf '%s\n' 'PORTFOLIO_SERVER_NAME=soc.<DDNS 이름>.synology.me' ;;
    *) printf '%s\n' "$line" ;;
  esac
done < .env.portfolio.example > .env
unset v; chmod 600 .env
# 비어 있는 비밀값이 없어야 한다(DEMO_PASSWORD·TRIAL_ANALYST_PASSWORD만 남는다). 값은 출력하지 않는다.
grep -E '^[A-Z0-9_]*(PASSWORD|SECRET)=$' .env | cut -d= -f1
```

`DEMO_PASSWORD`는 로컬 PC에서 만들어 파일로 넣는다(값을 명령줄 인자·화면에 내지 않는다). **이 단계(파일 전송과 아래 'NAS:' 블록)는 운영자가 직접 한다.** 자동화 스크립트에는 `.env`를 읽거나 쓰는 일을 맡기지 않는다. 'NAS:' 블록은 NAS 셸 안에서 실행한다(3.1의 주의). 로컬 PC(PowerShell, 저장소 루트):

```powershell
# 영숫자 20자 무작위. build/는 Git 제외 경로다. 이 값을 포트폴리오 소개 글(README)에 옮겨 적는다.
$c = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'; $b = New-Object byte[] 20
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
[IO.File]::WriteAllText("$PWD/build/portfolio-secrets/demo-password.txt", (-join ($b | ForEach-Object { $c[$_ % $c.Length] })))   # 줄바꿈 없이
ssh <NAS 사용자>@<NAS 주소> 'umask 077; mkdir -p ~/zeekad-portfolio-check/tmp'
scp -O build/portfolio-secrets/demo-password.txt <NAS 사용자>@<NAS 주소>:zeekad-portfolio-check/tmp/demo-password.txt
```

NAS:

```sh
cd /volume1/docker/zeekad-portfolio
chmod 600 ~/zeekad-portfolio-check/tmp/demo-password.txt
umask 077
grep -v '^DEMO_PASSWORD=' .env > .env.new
{ printf 'DEMO_PASSWORD='; cat ~/zeekad-portfolio-check/tmp/demo-password.txt; printf '\n'; } >> .env.new
mv .env.new .env && chmod 600 .env
rm -f ~/zeekad-portfolio-check/tmp/demo-password.txt
grep -c '^DEMO_PASSWORD=.\{16,\}$' .env   # 1 (값은 출력하지 않는다)
grep -E '^[A-Z0-9_]*(PASSWORD|SECRET)=$' .env | cut -d= -f1   # 아무것도 나오지 않아야 한다
```

- `TRIAL_ANALYST_PASSWORD`(체험용 분석가)도 같은 방법으로 넣는다. 파일 이름만 `trial-analyst-password.txt`, 줄 이름만 `TRIAL_ANALYST_PASSWORD`로 바꾼다. 이미 운영 중인 `.env`에 `SANDBOX_RESET_DB_PASSWORD`가 없으면(T33 이전 `.env`) NAS에서 무작위로 넣는다: `umask 077; grep -q '^SANDBOX_RESET_DB_PASSWORD=.' .env || { grep -v '^SANDBOX_RESET_DB_PASSWORD=' .env > .env.new; v=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32); printf 'SANDBOX_RESET_DB_PASSWORD=%s\n' "$v" >> .env.new; unset v; mv .env.new .env; chmod 600 .env; }` 다음 `grep -c '^SANDBOX_RESET_DB_PASSWORD=.\{32\}$' .env`가 1인지 본다(값은 출력하지 않는다).
- `DEMO_PASSWORD`·`TRIAL_ANALYST_PASSWORD`는 포트폴리오 글에 공개할 값이다. 저장소·문서에는 적지 않는다. 나중에 바꾸려면 같은 방법으로 `.env`의 줄을 바꾸고 시드를 다시 실행한다(5절: `SET_PASSWORD` 하나만 한다).
- 다른 비밀값(DB 비밀번호, 비활성 계정 비밀번호, `BOOTSTRAP_ADMIN_TOTP_SECRET`)은 출력하거나 다른 곳에 옮겨 적지 않는다. 운영 중 필요한 것은 시드 재실행뿐이며 시드는 `.env`를 읽는다.
- 비밀값이 비어 있으면 기동되지 않는다: PostgreSQL 이미지가 빈 `POSTGRES_SUPERUSER_PASSWORD`로 초기화를 거부하고, `01-roles-databases.sh`가 빈 로그인 역할 비밀번호로 초기화를 멈춘다(그러면 `postgres`가 healthy가 되지 않아 `api`·`dashboard-app`·`nginx-waf`도 뜨지 않는다). 시드는 빈 `DEMO_PASSWORD`·부트스트랩 비밀번호·TOTP 시크릿이면 아무것도 하지 않고 끝난다. 부트스트랩 비밀번호가 빈 계정은 애초에 만들어지지 않는다.
- 부트스트랩 계정은 `users` 표가 빈 첫 기동 때만 만들어진다. 첫 기동 뒤에 `BOOTSTRAP_*` 값을 바꿔도 이미 있는 계정 비밀번호는 바뀌지 않는다(바꾸려면 3.9의 DB 볼륨 재생성. 이때 zeek_AD DB와 앱 DB가 둘 다 새로 만들어진다).

### 3.5 기동과 계정 시드

```sh
cd /volume1/docker/zeekad-portfolio
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env up -d --wait
docker compose -p zeekad-portfolio -f compose.portfolio.yml ps
docker compose -p zeekad-portfolio -f compose.portfolio.yml logs postgres | grep portfolio-restore   # "portfolio-restore: done" 확인, pg_restore 오류 없음
# 계정 시드: 첫 실행은 RESULT: CHANGED, 두 번째 실행은 RESULT: NO_CHANGES 이어야 한다.
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env --profile seed run --rm demo-seed
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env --profile seed run --rm demo-seed
# 체험 계정 초기화 설정(T33): 첫 실행은 "baseline created", 두 번째는 "baseline kept", 둘 다 RESULT: OK
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env --profile seed run --rm sandbox-setup
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env --profile seed run --rm sandbox-setup
# 한 번만 초기화: 방금 복원한 DB라 바뀐 행이 모두 0이어야 한다(OK pipeline[OK] ...(-0 +0 ~0) ...; assignments[OK] released=0)
docker compose -p zeekad-portfolio -f compose.portfolio.yml exec -T sandbox-reset bash /sandbox/sandbox-reset.sh --once
```

- 설정 전에는 `sandbox-reset`이 정각마다 `NOT_CONFIGURED…` 한 줄만 남긴다(오류가 아니다). 역할이 아직 없어 postgres 로그에 `password authentication failed for user "zeekad_sandbox_reset"`이 함께 남는다.
- 초기화 확인: `docker compose -p zeekad-portfolio -f compose.portfolio.yml logs --since 2h sandbox-reset`에 정각마다 `OK pipeline[OK] analyst_review(-지운 +넣은 ~되돌린) incident_status(…) incident_status_history(…); assignments[OK] released=… history+=…` 줄이 있고 `ERROR`가 없어야 한다.

- 첫 기동 때 `postgres`가 스냅샷을 복원한다(리허설에서 수십 초). 복원이 성공해야만 데이터 폴더에 표지 파일(`portfolio-restore.ok`)이 생기고 헬스체크가 통과한다. 복원이 실패하면 `postgres`가 healthy가 되지 않으므로 `down -v`로 지우고 원인을 고친 뒤 다시 올린다.
- `postgres`는 PostgreSQL 이미지 기본 설정 그대로 컨테이너 안 로컬 소켓에 `trust` 인증을 쓴다(`initdb: warning: enabling "trust" authentication for local connections`). 바깥 포트가 없어 NAS에서 `docker exec` 권한이 있는 사용자만 쓸 수 있다.

### 3.6 NAS 안에서 확인

```sh
H='Host: soc.<DDNS 이름>.synology.me'; P='X-Forwarded-Proto: https'
curl -s -o /dev/null -w '%{http_code}\n' -H "$H" -H "$P" http://127.0.0.1:18480/login          # 200
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' -H "$H" -H "$P" http://127.0.0.1:18480/   # 302 https://soc.<DDNS 이름>.synology.me/login
curl -s -o /dev/null -w '%{http_code}\n' -H "$H" -H "$P" 'http://127.0.0.1:18480/api/incidents?asset=%27%20OR%201%3D1--'   # 403 (WAF)
docker ps --filter label=com.docker.compose.project=zeekad-portfolio --format '{{.Names}} {{.Status}} {{.Ports}}'   # 포트는 127.0.0.1:18480->8080/tcp 하나
docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' | grep zeekad-portfolio
# 기존 컨테이너가 바뀌지 않았는지(새로 생긴 zeekad-portfolio-* 줄만 달라야 한다)
cd ~/zeekad-portfolio-check
# ID·이름·이미지·상태(running/exited)·포트를 비교한다(가동 시간은 비교하지 않는다).
docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Ports}}' | sort | grep -v zeekad-portfolio > containers-after.txt
grep -v zeekad-portfolio containers-before.txt | diff - containers-after.txt && echo "existing containers unchanged"
# 기존 네트워크가 바뀌지 않았는지(새로 생긴 zeekad-portfolio 네트워크만 달라야 한다)
for n in $(docker network ls -q); do docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' $n; done | sort | grep -v '^zeekad-portfolio' > networks-after.txt
grep -v '^zeekad-portfolio' networks-before.txt | diff - networks-after.txt && echo "existing networks unchanged"
```

로컬 PC(LAN)에서 직접 접근이 막혀 있는지: `curl.exe -m 5 http://<NAS 주소>:18480/login`이 연결 실패여야 한다.

### 3.7 중지·롤백

```sh
cd /volume1/docker/zeekad-portfolio
docker compose -p zeekad-portfolio -f compose.portfolio.yml stop              # 잠시 멈춤(데이터 유지)
docker compose -p zeekad-portfolio -f compose.portfolio.yml down              # 컨테이너 제거(DB 볼륨 유지)
docker compose -p zeekad-portfolio -f compose.portfolio.yml down -v           # 완전 제거(DB 볼륨까지)
docker image rm zeek-ad-dashboard-app:local zeek-ad-dashboard-waf:local zeekad-pipeline:dev   # 이미지까지 지울 때(pgvector는 다른 컨테이너가 쓰는지 먼저 확인)
```

- 완전 철거할 때는 DSM 역방향 프록시 규칙(4.2)도 지운다.
- 체험 계정만 닫을 때: `.env`의 `TRIAL_ANALYST_PASSWORD`를 비우고 시드를 다시 돌리면 `trial-analyst`가 비활성이 된다. `sandbox-reset`은 `stop`으로 멈춘다(`sandbox`·`sandbox_baseline` 스키마와 `zeekad_sandbox_reset` 역할은 남아도 해가 없다).
- 이미지를 이전 버전으로 되돌릴 때: 이전 `tar`를 `docker load` 한 뒤 `up -d --wait`(바뀐 서비스만 다시 만든다). 시드는 다시 할 필요가 없다.

### 3.8 이미지 갱신

새 이미지 `tar`를 옮겨 `docker load` → `docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env up -d --wait`. DB 볼륨은 유지되므로 계정·감사 로그가 그대로다.

#### 서비스 하나의 이미지 갱신(`dashboard-app` 또는 `nginx-waf`, T16 → T21 → T14 정리)

대시보드 코드만 바뀌었을 때는 앱 이미지 `zeek-ad-dashboard-app:local` 하나만, WAF 설정만 바뀌었을 때는 WAF 이미지 `zeek-ad-dashboard-waf:local` 하나만 옮기고 그 서비스만 다시 만든다. 5GB 파이프라인 `tar`는 다시 만들지 않는다. DB 볼륨·`.env`·다른 컨테이너는 그대로 둔다. `.env`는 읽거나 고치지 않고 `--env-file` 인자로만 넘긴다. 아래 명령은 서비스 이름 `SVC`와 이미지 이름 `IMG` 두 변수로 쓴다.

| `SVC` | `IMG` |
|---|---|
| `dashboard-app` | `zeek-ad-dashboard-app` |
| `nginx-waf` | `zeek-ad-dashboard-waf` |

규칙(T21·T14):

- **보존 이름은 `pre-<작업 ID>` 하나로 쓴다.** 작업 ID는 소문자로 쓴다(예: `T14` → `pre-t14`). 이미지는 `<IMG>:pre-<작업 ID>`, 교체한 파일은 같은 폴더의 `<파일>.pre-<작업 ID>`다. 아래 명령은 `ID`(예: `t14`) 변수로 이 이름을 만든다.
- **NAS 명령은 단계마다 실패하면 멈춘다**(`|| exit <번호>`). 멈추면 반복하지 말고 번호로 어느 단계인지 보고, 필요하면 아래 롤백을 한다.
- **compose·시드 같은 파일 교체**: 새 파일을 `images/<작업 ID>-files/`에 sha256 목록과 함께 먼저 올리고, NAS에서 원래 파일을 같은 폴더에 `*.pre-<작업 ID>`로 보존한 뒤(이미 있으면 덮지 않는다) sha256을 대조하고 바꾼다. 바꾼 뒤 `docker compose ... config --quiet`로 문법을 확인한다.
- **이미지 적재와 파일 교체를 모두 끝낸 뒤에 `up`을 한다**(1단계 → 2단계). 새 이미지와 옛 compose가 섞여 뜨는 구간을 만들지 않는다.
- **저장소에서 지운 파일은 NAS에서 지우지 않는다.** 되돌릴 때 쓰는 `*.pre-<작업 ID>` compose가 그 파일을 마운트할 수 있다(T14: `docker/portfolio/nginx/proxy_backend_extra_portfolio.conf.template`). 새 compose가 마운트하지 않으면 쓰이지 않는다.

로컬 PC(PowerShell, 저장소 루트). 2.1의 해당 이미지 빌드와 2.3 리허설을 먼저 한다:

```powershell
$ID = 't14'; $SVC = 'nginx-waf'; $IMG = 'zeek-ad-dashboard-waf'   # 앱이면 'dashboard-app', 'zeek-ad-dashboard-app'
New-Item -ItemType Directory -Force build/portfolio-images | Out-Null
docker save -o "build/portfolio-images/$IMG.tar" "${IMG}:local"
if ($LASTEXITCODE -ne 0) { throw "docker save failed" }
# 2.4와 같은 방식(LF UTF-8, tar 안 Config digest). 네 이미지 목록(images.sha256·image-ids.txt)을 덮어쓰지 않게 이름을 따로 쓴다.
$h = (Get-FileHash -Algorithm SHA256 "build/portfolio-images/$IMG.tar").Hash.ToLower()
[IO.File]::WriteAllText("$PWD/build/portfolio-images/$IMG-image.sha256", "$h  $IMG.tar`n", [Text.UTF8Encoding]::new($false))
$manifest = (tar -xOf "build/portfolio-images/$IMG.tar" manifest.json | Out-String) | ConvertFrom-Json
if (@($manifest)[0].Config -notmatch '([0-9a-f]{64})') { throw "Config digest not found" }
[IO.File]::WriteAllText("$PWD/build/portfolio-images/$IMG-image-id.txt", "sha256:$($Matches[1]) ${IMG}:local`n", [Text.UTF8Encoding]::new($false))
$nas = "<NAS 사용자>@<NAS 주소>"; $dst = "/volume1/docker/zeekad-portfolio"
scp -O "build/portfolio-images/$IMG.tar" "build/portfolio-images/$IMG-image.sha256" "build/portfolio-images/$IMG-image-id.txt" "${nas}:${dst}/images/"
if ($LASTEXITCODE -ne 0) { throw "scp image failed" }

# (파일 교체가 있을 때만) 바꿀 파일을 images/<ID>-files/에 sha256 목록과 함께 올린다. 경로는 저장소 기준 상대 경로, 올릴 때는 파일 이름만 쓴다.
$files = @('compose.portfolio.yml')   # 예: 시드가 바뀌었으면 'docker/portfolio/seed/seed_demo.py'도 넣는다
$stage = "build/portfolio-images/$ID-files"
New-Item -ItemType Directory -Force $stage | Out-Null
foreach ($f in $files) { Copy-Item $f $stage -Force }
$lines = $files | ForEach-Object { $n = Split-Path $_ -Leaf; "$((Get-FileHash -Algorithm SHA256 "$stage/$n").Hash.ToLower())  $n" }
[IO.File]::WriteAllText("$PWD/$stage/files.sha256", ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
ssh $nas "mkdir -p ${dst}/images/$ID-files"
scp -O (Get-ChildItem $stage).FullName "${nas}:${dst}/images/$ID-files/"
if ($LASTEXITCODE -ne 0) { throw "scp files failed" }
```

NAS(셸). 1단계(기록·보존·적재·파일 교체). `ID`·`SVC`·`IMG`와 `FILES`(저장소 기준 상대 경로, 파일 교체가 없으면 빈 값)를 먼저 정한다:

```sh
set -u
export PATH=$PATH:/usr/local/bin
ID=t14; SVC=nginx-waf; IMG=zeek-ad-dashboard-waf   # 앱이면 SVC=dashboard-app; IMG=zeek-ad-dashboard-app
FILES="compose.portfolio.yml"   # 예: "compose.portfolio.yml docker/portfolio/seed/seed_demo.py", 없으면 ""
cd /volume1/docker/zeekad-portfolio || exit 1
mkdir -p ~/zeekad-portfolio-check && C=~/zeekad-portfolio-check
# 1) 전 상태 기록
docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.CreatedAt}}' | sort > $C/$ID-containers-before.txt || exit 1
docker volume ls > $C/$ID-volumes-before.txt || exit 1
# 2) 롤백 준비: 지금 그 서비스가 쓰는 이미지 ID를 남기고 pre-<ID> 태그로 보존한다
CID=$(docker compose -p zeekad-portfolio -f compose.portfolio.yml ps -q $SVC < /dev/null) || exit 2
OLD=$(docker inspect --format '{{.Image}}' "$CID") || exit 2
echo "$OLD" > $C/$ID-old-$SVC-image-id.txt
docker tag "$OLD" $IMG:pre-$ID || exit 2
# 3) 무결성 확인 → 적재 → ID 대조
(cd images && sha256sum -c $IMG-image.sha256) || exit 3
docker load -i images/$IMG.tar || exit 4
printf '%s %s\n' "$(docker image inspect --format '{{.Id}}' $IMG:local)" $IMG:local | diff - images/$IMG-image-id.txt || exit 5
echo "$IMG image ID matches"
# 4) 파일 교체: 같은 폴더에 *.pre-<ID>로 보존(이미 있으면 덮지 않는다) → sha256 대조 → 교체 → compose 문법 확인
if [ -n "$FILES" ]; then
  (cd images/$ID-files && sha256sum -c files.sha256) || exit 6
  for f in $FILES; do
    [ -f "$f.pre-$ID" ] || cp -p "$f" "$f.pre-$ID" || exit 7
    cp "images/$ID-files/$(basename "$f")" "$f" || exit 8
    sha256sum "$f" "$f.pre-$ID"
  done
  docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env config --quiet < /dev/null || exit 9
fi
```

2단계(재생성·대조). 1단계가 끝까지 성공했을 때만 한다:

```sh
set -u
export PATH=$PATH:/usr/local/bin
ID=t14; SVC=nginx-waf; IMG=zeek-ad-dashboard-waf
cd /volume1/docker/zeekad-portfolio || exit 1
C=~/zeekad-portfolio-check
# 5) 그 서비스만 다시 만든다
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env up -d --wait --no-deps $SVC < /dev/null || exit 10
# 6) 후 상태 기록·비교: 그 서비스 줄만 달라야 하고 볼륨은 같아야 한다
docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.CreatedAt}}' | sort > $C/$ID-containers-after.txt || exit 11
docker volume ls > $C/$ID-volumes-after.txt || exit 11
grep -v -- "-$SVC-" $C/$ID-containers-before.txt > $C/$ID-others-before.txt
grep -v -- "-$SVC-" $C/$ID-containers-after.txt > $C/$ID-others-after.txt
diff $C/$ID-others-before.txt $C/$ID-others-after.txt || exit 12
echo "other containers unchanged"
diff $C/$ID-volumes-before.txt $C/$ID-volumes-after.txt || exit 13
echo "volumes unchanged"
docker image inspect --format '{{.Id}}' $IMG:local; docker inspect --format '{{.Image}}' "$(docker compose -p zeekad-portfolio -f compose.portfolio.yml ps -q $SVC < /dev/null)"   # 같아야 한다
# 7) 3.6 확인(WAF 경유)
H='Host: soc.<DDNS 이름>.synology.me'; P='X-Forwarded-Proto: https'
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$H" -H "$P" http://127.0.0.1:18480/login)
echo "login via nginx-waf: $CODE"
[ "$CODE" = "200" ] || exit 14
```

그 뒤 4.4의 공개 주소 확인을 한다.

**공개 주소(또는 7단계)가 502일 때**: `T14`부터 `nginx-waf`는 `dashboard-app` 이름을 요청 때 Docker 내장 DNS로 다시 해석하므로(`valid=10s`) 앱을 다시 만들어 IP가 바뀌어도 보통 생기지 않는다. 앱이 멈췄거나 막 다시 뜬 직후라면 10초쯤 기다려 한 번 더 확인한다. 그래도 502면 아래 대처를 한 번만 한다.

1. 같은 프로젝트의 `nginx-waf`만 다시 시작한다(다른 컨테이너·볼륨·`.env`는 건드리지 않는다):
   ```sh
   cd /volume1/docker/zeekad-portfolio || exit 1
   docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env restart nginx-waf < /dev/null || exit 15
   curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: soc.<DDNS 이름>.synology.me' -H 'X-Forwarded-Proto: https' http://127.0.0.1:18480/login
   ```
   재시작은 컨테이너를 다시 만들지 않으므로 6단계의 비교에서 `nginx-waf` 줄(ID·이미지·생성 시각)은 그대로다. 상태(`State`) 시각만 바뀐다.
2. 그래도 200이 아니면 반복하지 말고 아래 롤백으로 되돌린 뒤 멈추고 보고한다.

롤백(`--wait` 실패, 확인 실패, 502 대처 실패):

```sh
set -u
export PATH=$PATH:/usr/local/bin
ID=t14; SVC=nginx-waf; IMG=zeek-ad-dashboard-waf
FILES="compose.portfolio.yml"   # 1단계와 같은 값
NEED="docker/portfolio/nginx/proxy_backend_extra_portfolio.conf.template"   # 되돌릴 compose가 마운트하는 파일(T14). 없으면 ""
cd /volume1/docker/zeekad-portfolio || exit 1
# 0) 되돌릴 compose(*.pre-<ID>)가 마운트하는 파일이 있는지 먼저 확인한다(없으면 되돌린 compose가 뜨지 않는다)
for f in $NEED; do [ -f "$f" ] || { echo "missing $f"; exit 19; }; done
for f in $FILES; do [ -f "$f.pre-$ID" ] && cp -p "$f.pre-$ID" "$f"; done
docker tag $IMG:pre-$ID $IMG:local || exit 20
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env up -d --wait --no-deps $SVC < /dev/null || exit 21
docker image inspect --format '{{.Id}}' $IMG:local; cat ~/zeekad-portfolio-check/$ID-old-$SVC-image-id.txt   # 같아야 한다
```

- 확인이 끝나 더 필요 없으면 `docker image rm <IMG>:pre-<작업 ID>`로 보존 태그를 지운다(태그만 지워지고 다른 태그가 가리키는 이미지는 남는다). 보존 파일 `*.pre-<작업 ID>`는 다음 갱신 전까지 둔다.
- 앱 이미지가 바뀌어도 시드는 다시 할 필요가 없다(계정은 DB 볼륨에 있다). 단, 시드 스크립트(`docker/portfolio/seed/seed_demo.py`)의 목표 상태가 바뀐 갱신(예: T20 `demo` 허용 캡처 `*` → `cic17-*,syn1-*`. 데이터도 함께 바꾸는 T22 `cic17-*,syn1-*,lab-20261119`는 3.9)은 그 파일을 위 파일 교체로 옮기고(`.env`는 그대로. `DEMO_CAPTURE_PATTERNS`가 없으면 기본값이 쓰인다) 3.5의 시드를 두 번 실행한다. 첫 실행은 `RESULT: CHANGED`(`API UPDATE_USER demo`), 두 번째는 `RESULT: NO_CHANGES`여야 한다. 시드 파일이 바뀌지 않았으면 다시 돌리지 않는다.
- 스크립트로 실행할 때는 위 1·2단계를 스크립트 파일(`nas-step1.sh`·`nas-step2.sh`)로 저장한다. 스크립트를 표준 입력으로 bash에 넘기면(`echo <base64> | base64 -d | bash`, `ssh ... 'bash -s' < 파일`) `docker compose exec -T`·`run`이 남은 스크립트를 읽어 버려 뒤 단계가 실행되지 않은 채 exit 0으로 끝날 수 있다(T22에서 확인). 그래서 NAS의 확인 폴더에 파일로 풀고 표준 입력을 닫아 실행한다: `ssh ... "echo <base64> | base64 -d > ~/zeekad-portfolio-check/<ID>-step1.sh && bash ~/zeekad-portfolio-check/<ID>-step1.sh < /dev/null"`. 출력은 `build/portfolio-evidence/<작업 ID>/nas-update.txt`처럼 Git 제외 경로에 남긴다.

#### 앱 이미지와 compose·WAF 템플릿을 함께 바꾸는 갱신(`T32`)

`T32`는 앱 이미지 하나와 파일 둘(`compose.portfolio.yml`, `docker/portfolio/nginx/zeekad-portfolio-http.conf.template`)을 바꾼다. WAF 이미지는 그대로지만 `nginx-waf`도 고정 주소·신뢰 범위가 바뀌어 다시 만들어진다. 위 서비스 하나 절차에서 다음만 다르다.

- **반영 전 게이트웨이 확인**: NAS에서 `curl http://127.0.0.1:18480/?probe=<고유 표식>` 하나를 보내고 `docker logs --since 2m zeekad-portfolio-nginx-waf-1 2>&1 | grep -F <고유 표식>`으로 그 줄만 찾는다. 줄 맨 앞(접속 주소, `$realip_remote_addr`)이 `PORTFOLIO_GATEWAY_IP`(기본 `10.203.48.1`)여야 한다. 다르면 반영하지 않고 멈춘다. 같은 때 `docker network inspect zeekad-portfolio_portfolio-net`으로 `PORTFOLIO_WAF_IP`(기본 `10.203.48.250`)를 쓰는 컨테이너가 없는지 본다. 방문자 줄은 읽지 않는다.
- **1단계**: `SVC=dashboard-app`, `IMG=zeek-ad-dashboard-app`, `FILES="compose.portfolio.yml docker/portfolio/nginx/zeekad-portfolio-http.conf.template"`. 롤백용으로 `nginx-waf`가 쓰는 이미지 ID도 기록한다(바뀌지 않아야 한다). `.env`는 바꾸지 않는다(두 주소의 기본값이 NAS 서브넷과 맞다).
- **2단계**: `up -d --wait --no-deps dashboard-app nginx-waf`로 두 서비스를 함께 다시 만든다. 다른 컨테이너 비교에서 `-dashboard-app-`·`-nginx-waf-` 두 줄을 뺀다. 이어서 `nginx-waf` 주소가 `PORTFOLIO_WAF_IP`이고 앱 환경의 `DASHBOARD_TRUSTED_PROXIES`가 같은 값인지, `nginx-waf` 이미지 ID가 그대로인지 `docker inspect`로 본다.
- **롤백**: 두 파일을 `*.pre-t32`로 되돌리고 `zeek-ad-dashboard-app:pre-t32`를 `:local`로 다시 태그한 뒤 같은 두 서비스를 `up`한다. 옛 compose로 돌아가면 `nginx-waf` 주소는 다시 동적이 된다.
- 반영한 날의 실제 명령과 출력은 `T32` 작업 기록(저장소 밖)에 있다.

#### 체험 계정과 초기화 서비스를 더하는 갱신(`T33`)

`T33`은 앱 이미지 하나와 파일(`compose.portfolio.yml`, WAF 템플릿, 시드 스크립트, 새 폴더 `docker/portfolio/sandbox/`)을 바꾼다. `dashboard-app`·`nginx-waf`가 다시 만들어지고 `sandbox-reset`이 새로 뜬다. `postgres`·`api`·DB 볼륨은 그대로다.

- **운영자 단계 먼저**: `.env`에 `TRIAL_ANALYST_PASSWORD`와 `SANDBOX_RESET_DB_PASSWORD`를 넣는다(3.4). 자동화 도구는 `.env`를 읽거나 쓰지 않는다.
- **반영 전 확인**: 기준선을 만들 공개 DB가 스냅샷 직후 상태인지 본다. `zeekad.incident_status_history` 행 수가 스냅샷과 같고(공개 스냅샷은 6), 앱 DB의 담당자가 있는 담당 행이 0이다. 다르면 멈춘다.
- **1단계**: `SVC=dashboard-app`, `IMG=zeek-ad-dashboard-app`, `FILES="compose.portfolio.yml docker/portfolio/nginx/zeekad-portfolio-http.conf.template docker/portfolio/seed/seed_demo.py docker/portfolio/sandbox/sandbox-setup.sh docker/portfolio/sandbox/sandbox-reset.sh"`(새 폴더는 먼저 만든다).
- **2단계**: `up -d --wait --no-deps dashboard-app nginx-waf sandbox-reset` → `sandbox-setup`(기준선 = 지금 공개 DB) → `demo-seed` 두 번 → `sandbox-reset … --once`(바뀐 행 0).
- **롤백**: 파일을 `*.pre-t33`으로 되돌리고 `zeek-ad-dashboard-app:pre-t33`을 `:local`로 다시 태그한 뒤 `stop sandbox-reset`, 옛 시드로 `demo-seed`를 다시 돌려 `trial-analyst`를 비활성으로 만들고 `dashboard-app nginx-waf`를 `up`한다.

### 3.9 스냅샷(공개 데이터) 교체

스냅샷은 DB 볼륨이 빌 때만 복원된다(`02-restore-snapshot.sh`). 데이터를 바꾸려면 DB 볼륨을 지우고 다시 만든다. **DB 볼륨 하나에 zeek_AD DB(`zeekad`)와 앱 DB(`zeekad_dashboard`: 계정·감사 로그)가 함께 있으므로 둘 다 새로 만들어진다.** `zeekad`는 새 스냅샷으로, 앱 DB는 부트스트랩(첫 기동)과 시드로 다시 채운다. 지난 감사 로그(방문자 로그인 기록)는 새 DB에 없고 아래 3단계의 백업에만 남는다(받아들인다). 이 백업은 되돌리기용이다. 체험 계정 변경의 매시 정각 초기화(1.3)는 새 볼륨에서 다시 설정한다(아래 8c).

로컬 PC에서 먼저 한다: 2.2 스냅샷(VM 원본은 `-SshHost <배포 VM>`) → `secret-scan.txt` 확인 → 2.3 리허설(`-SnapshotDir build/portfolio`) 통과 → (실습망 등 처음 공개하는 데이터면) 공개 전 내용 확인. NAS에서는 `zeekad-portfolio` 프로젝트와 `/volume1/docker/zeekad-portfolio` 안에서만, sudo 없이, 아래 순서대로 하고 **단계마다 실패하면 멈추고 되돌린다.** `.env`는 읽거나 고치지 않는다(`DEMO_PASSWORD`는 그대로 쓰인다).

**표준 입력 주의(T22에서 확인)**: 아래 블록을 `echo <base64> | base64 -d | bash`나 `ssh ... 'bash -s' < 파일`처럼 **표준 입력으로 bash에 넘기면** `docker compose exec -T`·`run`이 남은 스크립트를 읽어 버린다. 그러면 그 뒤 줄(백업 권한·`down` 등)이 실행되지 않은 채 exit 0으로 끝난다. 블록은 NAS에 파일로 풀어 `bash <파일> < /dev/null`로 실행하고(또는 대화형 셸에 붙여 넣고), compose를 부르는 줄에는 아래처럼 `< /dev/null`을 붙인다.

```sh
export PATH=/usr/local/bin:$PATH
ID=<작업 ID 소문자, 예: t22>
cd /volume1/docker/zeekad-portfolio || exit 1
C="docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env"
# 1) 기록: 다른 프로젝트의 컨테이너·네트워크·볼륨, 앱 이미지 ID(3.1·3.6 방식)
mkdir -p ~/zeekad-portfolio-check
docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Ports}}' | grep -v 'zeekad-portfolio' | sort > ~/zeekad-portfolio-check/$ID-containers-before.txt
for n in $(docker network ls -q); do docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' $n; done | grep -v '^zeekad-portfolio' | sort > ~/zeekad-portfolio-check/$ID-networks-before.txt
docker volume ls --format '{{.Name}}' | grep -v '^zeekad-portfolio_' | sort > ~/zeekad-portfolio-check/$ID-volumes-before.txt
docker image inspect --format '{{.Id}}' zeek-ad-dashboard-app:local > ~/zeekad-portfolio-check/$ID-app-image-before.txt
# 2) 보존: 스냅샷 세 파일과 바뀌는 배포 파일을 *.pre-$ID로(이미 있으면 덮지 않는다)
# 0) 체험 계정 초기화 서비스를 먼저 멈춘다(T33)
$C stop sandbox-reset < /dev/null || exit 1
for f in snapshot/zeekad.dump snapshot/zeekad.dump.sha256 snapshot/manifest.json docker/portfolio/seed/seed_demo.py compose.portfolio.yml; do
  [ -e "$f.pre-$ID" ] || cp -p "$f" "$f.pre-$ID" || exit 2
done
# 3) 앱 DB 백업(NAS 안에만. 비밀번호 해시가 들어 있으므로 밖으로 옮기거나 내용을 출력하지 않는다)
mkdir -p backup && chmod 700 backup || exit 3
umask 077
$C exec -T postgres pg_dump -U postgres -Fc zeekad_dashboard < /dev/null > backup/app-pre-$ID.dump.partial || exit 3
mv -f backup/app-pre-$ID.dump.partial backup/app-pre-$ID.dump && chmod 600 backup/app-pre-$ID.dump && test -s backup/app-pre-$ID.dump || exit 3
$C exec -T postgres pg_restore --list < backup/app-pre-$ID.dump > /dev/null && echo "backup OK" || exit 3
# 4) 내리기(-v 없이)
$C down < /dev/null || exit 4
# 5) 이 프로젝트의 DB 볼륨 하나만 지운다(이름을 먼저 확인한다)
docker volume ls --format '{{.Name}}' | grep '^zeekad-portfolio_'      # zeekad-portfolio_pgdata 하나여야 한다
docker volume rm zeekad-portfolio_pgdata || exit 5
```

6) 로컬 PC에서 새 `zeekad.dump`·`zeekad.dump.sha256`·`manifest.json`과 바뀐 배포 파일을 `scp -O`로 보낸다(3.2). NAS에서 `(cd snapshot && sha256sum -c zeekad.dump.sha256)`가 `OK`인지 보고 `chmod 755 snapshot && chmod 644 snapshot/*`로 권한을 맞춘다(T13: 상속 ACL 때문에 컨테이너 postgres가 덤프를 못 읽는다).

```sh
# 7) 올리기(nginx-waf·sandbox-reset은 빼고): 빈 볼륨이라 01(역할·DB)·02(스냅샷 복원)가 다시 돈다. 공개 경로는 아직 열지 않는다
$C up -d --wait postgres api dashboard-app < /dev/null || exit 7
$C logs postgres < /dev/null | grep -E 'portfolio-restore|pg_restore: error'      # "portfolio-restore: done", 오류 줄 없음
# 8) 시드 두 번(시드는 dashboard-app에 직접 붙으므로 nginx-waf가 없어도 된다): 첫 실행 RESULT: CHANGED(demo 다시 생성), 두 번째 RESULT: NO_CHANGES
$C --profile seed run --rm demo-seed < /dev/null || exit 8
$C --profile seed run --rm demo-seed < /dev/null || exit 8
# 8a) 체험 계정 초기화 설정(T33): 새 스냅샷 직후 상태가 기준선이 된다. 스냅샷이 체험 계정 이름을 이미 행위자로 쓰면 여기서 멈춘다
$C --profile seed run --rm sandbox-setup < /dev/null || exit 8
# 8b) 시드가 끝난 뒤에 공개 경로(nginx-waf)와 초기화 서비스를 연다
$C up -d --wait nginx-waf sandbox-reset < /dev/null || exit 8
# 9) 대조: 다른 프로젝트의 컨테이너·네트워크·볼륨이 1)과 같고 앱 이미지가 그대로인지
docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Ports}}' | grep -v 'zeekad-portfolio' | sort | diff ~/zeekad-portfolio-check/$ID-containers-before.txt - && echo "containers same"
for n in $(docker network ls -q); do docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' $n; done | grep -v '^zeekad-portfolio' | sort | diff ~/zeekad-portfolio-check/$ID-networks-before.txt - && echo "networks same"
docker volume ls --format '{{.Name}}' | grep -v '^zeekad-portfolio_' | sort | diff ~/zeekad-portfolio-check/$ID-volumes-before.txt - && echo "volumes same"
docker image inspect --format '{{.Id}}' zeek-ad-dashboard-app:local | diff ~/zeekad-portfolio-check/$ID-app-image-before.txt - && echo "app image same"
```

- 앱 코드가 바뀌지 않았으면 앱 이미지는 교체하지 않는다(바뀌었으면 3.8을 먼저 따로 한다).
- 7과 8 사이에는 새 앱 DB의 부트스트랩 계정(`viewer1`·`analyst1`·`analyst2`·`admin`)이 활성이다(비공개 무작위 비밀번호, `admin`은 TOTP). `demo`는 아직 없다. 그래서 7에서는 `nginx-waf`를 띄우지 않고, 시드 두 번으로 그 계정들을 비활성으로 만든 뒤(8) `nginx-waf`를 띄운다(8b). 공개 경로에서 부트스트랩 계정이 활성인 틈이 없다(T22 때는 이 틈이 약 5분 있었다).
- 끝나면 3.6 확인과 4.4 공개 주소 확인을 한다. 공개 주소가 `502`면 3.8의 대처를 따른다.
- **되돌리기**(어느 단계든 실패 시) 다음 순서로 한 뒤 멈춰 원인을 본다. compose를 부르는 줄에는 모두 `< /dev/null`을 붙인다(위 표준 입력 주의):
  1. `$C down < /dev/null`
  2. 새로 생긴 DB 볼륨을 지운다(`docker volume rm zeekad-portfolio_pgdata`, 없으면 건너뛴다)
  3. `*.pre-$ID` 파일을 원래 이름으로 되돌린다(`for f in ...; do cp -p "$f.pre-$ID" "$f"; done`)
  4. `$C up -d --wait postgres api dashboard-app < /dev/null`(이전 스냅샷이 복원된다. 앱 DB를 되돌리기 전이므로 `nginx-waf`는 아직 띄우지 않는다)
  5. `$C stop dashboard-app < /dev/null`
  6. `$C exec -T postgres pg_restore -U postgres -d zeekad_dashboard --clean --if-exists < backup/app-pre-$ID.dump`
  7. `$C start dashboard-app < /dev/null`. 시드는 돌리지 않는다(`demo`가 백업에 있다).
  8. `$C up -d --wait nginx-waf < /dev/null`
  - 6이 실패하면 시드를 두 번 돌려 `demo`를 다시 만든 뒤 8을 한다. 이때 지난 감사 로그는 백업에만 남는다.
- 스크립트로 실행할 때는 단계를 스크립트 파일로 저장해 NAS의 `~/zeekad-portfolio-check/<작업 ID>-step-<단계>.sh`로 풀고 `bash <그 파일> < /dev/null`로 실행한다(표준 입력으로 넘기지 않는다). 출력은 `build/portfolio-evidence/<작업 ID>/nas-replace.txt`(시드는 `nas-seed.txt`)처럼 Git 제외 경로에 남긴다. 비밀값·쿠키·백업 내용은 출력하지 않는다.

### 3.10 새 실습망 캡처를 공개할 때(`T33`)

zeek_AD 실습망에 표적 VM이 늘어 새 캡처(정찰·무차별 대입·비커닝·느린 유출, 나중에 측면 이동)를 공개할 때의 순서다. 캡처 ID는 앱 코드·초기화 SQL에 없다(허용 캡처는 `DEMO_CAPTURE_PATTERNS` 한 곳).

1. 로컬 PC: 새 스냅샷(2.2) → `secret-scan.txt` 확인 → 리허설(2.3)을 `-ExposureDir <저장소 밖 폴더>`와 함께 돌린다(허용 캡처를 바꿨으면 리허설 셸에 같은 `DEMO_CAPTURE_PATTERNS`를 준다).
2. **분석가 노출 확인**: `exposure.md`(필드별 개수·값 형태)를 운영자가 본다. 필요하면 `exposure-values.txt`(실제 값, 커밋하지 않음)를 본다. 점검 항목: HTTP URI(쿼리 문자열의 토큰·계정), 인증 필드(사용자 이름, Kerberos·NTLM·SMB 계정), 호스트 이름(집 장비·개인 이름), 사설 대역(집 LAN `192.168.x`가 섞였는지), 공인 주소(집 공인 IP가 섞였는지), Slack 원문. 공개하면 안 되는 값이 있으면 그 캡처는 공개하지 않는다.
3. NAS: `sandbox-reset`을 멈춘다(`stop sandbox-reset`).
4. 3.9 순서로 스냅샷을 바꾼다(8a의 `sandbox-setup`이 새 볼륨에 기준선을 만든다). 볼륨을 다시 만들지 않고 데이터만 바꾸는 경우에는 `sandbox-setup --rebuild-baseline`으로 기준선을 다시 만든다(체험 계정 흔적이 있으면 멈추므로 먼저 `sandbox-reset … --once`).
5. 허용 캡처 변수(`DEMO_CAPTURE_PATTERNS`)를 바꿨으면 시드를 다시 돌린다(두 공개 계정에 같이 반영된다).
6. `sandbox-reset`을 다시 시작하고 다음 정각 로그(3.5)와 4.4를 확인한다.

## 4. DSM 설정

DSM 7.3 기준 메뉴 경로다. `T13`에서 이 절의 메뉴 경로와 값으로 설정해 확인했다.

### 4.1 하위 도메인 인증서

1. **제어판 > 보안 > 인증서 > 추가 > 새 인증서 추가 > Let's Encrypt에서 인증서 얻기**: 도메인 이름에 `soc.<DDNS 이름>.synology.me`를 넣어 발급한다(하위 도메인 전용 인증서).
   - DSM이 `*.<DDNS 이름>.synology.me` SAN을 "잘못된 도메인"으로 거부한 사례가 있다(`T13`). 하위 도메인 전용 인증서로 충분하다.
   - `T13` 발급 결과: `CN=soc.<DDNS 이름>.synology.me`, SAN `DNS:soc.<DDNS 이름>.synology.me`, Let's Encrypt `YE1`, 유효 90일(DSM이 자동 갱신).
2. `soc.<DDNS 이름>.synology.me`가 NAS 공인 IP로 풀리는지 확인한다: 로컬 PC에서 `nslookup soc.<DDNS 이름>.synology.me`. Synology DDNS의 와일드카드 레코드로 하위 도메인이 같은 IP를 가리킨다(`T13` 확인).

### 4.2 역방향 프록시 규칙

**제어판 > 로그인 포털 > 고급 > 역방향 프록시 > 생성**:

| 항목 | 값 |
|---|---|
| 설명 | `zeekad-soc` |
| 소스 프로토콜 / 호스트 이름 / 포트 | `HTTPS` / `soc.<DDNS 이름>.synology.me` / `443` |
| HSTS 활성화 | 켬 |
| 대상 프로토콜 / 호스트 이름 / 포트 | `HTTP` / `localhost` / `18480` (`.env`의 `PORTFOLIO_HTTP_PORT`) |

- **사용자 지정 헤더는 넣지 않는다.** `T13`에서 기본 규칙(사용자 지정 헤더 없음)이 넘기는 헤더를 `nginx-waf` ModSecurity 감사 로그로 확인했다: `Host`는 소스 호스트 이름, `X-Forwarded-For`는 방문자가 보낸 값 뒤에 실제 접속 IP를 **덧붙인다**(덮어쓰지 않음, 예: `203.0.113.9, <접속 IP>`), `X-Forwarded-Proto`는 방문자 값과 관계없이 `https`로 **덮어쓴다**, `X-Real-IP`는 실제 접속 IP다. nginx가 가장 오른쪽 비신뢰 주소를 쓰므로(1.1) 방문자가 앞부분을 꾸며도 감사 로그 IP·속도 제한 키·`Location`이 바뀌지 않는다. WebSocket 헤더는 필요 없다.
- `localhost`가 IPv6 `::1`로 풀려 연결되지 않으면 대상 호스트 이름을 `127.0.0.1`로 바꾼다(`T13`에서는 이 문제가 없었다).
- **인증서 연결**: **제어판 > 보안 > 인증서 > 설정**에서 서비스 `soc.<DDNS 이름>.synology.me`에 4.1의 인증서를 고른다.
- DSM은 HSTS를 켜면 `Strict-Transport-Security: max-age=15768000; includeSubdomains; preload`를 붙인다. 앱도 `max-age=31536000 ; includeSubDomains`를 보내므로 응답에 HSTS 헤더가 두 개 있다(동작 영향 없음). DSM 앞단은 `Server: nginx`(버전 없음)를 붙이며 이 스택에서 바꿀 수 없다.
- 공유기·모뎀 포트 포워딩과 기존 포트폴리오의 역방향 프록시 규칙은 바꾸지 않는다.

### 4.3 DSM이 실제로 보내는 헤더 확인(T13)

DSM 규칙을 만든 뒤 외부망(휴대전화 데이터 등)에서 `demo`로 한 번 로그인하고 NAS에서 감사 로그를 본다.

```sh
cd /volume1/docker/zeekad-portfolio
docker compose -p zeekad-portfolio -f compose.portfolio.yml exec -T postgres \
  psql -U postgres -d zeekad_dashboard -c "SELECT occurred_at, actor_username, client_ip FROM audit_logs WHERE action_type='LOGIN_SUCCESS' ORDER BY id DESC LIMIT 3"
```

- `occurred_at`은 UTC다. 외부망에서 로그인한 시각(한국 시간이면 9시간을 뺀다)으로 줄을 구분한다.
- `client_ip`가 방문자 공인 IP면 정상이다. `127.0.0.1`이나 스택 서브넷 게이트웨이(`10.203.48.1`)면 DSM이 `X-Forwarded-For`를 보내지 않는 것이다 → 4.2 규칙의 **사용자 지정 헤더 > 생성**에서 `X-Forwarded-For` = `$proxy_add_x_forwarded_for`, `X-Forwarded-Proto` = `$scheme`을 추가하고 다시 확인한다. 이 경우 속도 제한도 모든 방문자에게 하나의 키로 걸리므로 반드시 고친다(`T13`에서는 필요 없었다).
- `docker compose ... logs nginx-waf`: 접근 로그 줄의 마지막 칸은 받은 `X-Forwarded-For` 원문이다(DSM이 덧붙인 마지막 주소 = 방문자 IP). ModSecurity JSON 로그(`"client_ip"`)는 차단·오류 응답 등 관련 있는 요청만 남으므로 성공한 로그인(200)은 접근 로그로 본다.
- DSM이 넘기는 헤더를 직접 보려면 실패하는 로그인(401) 요청에 `X-E2E-Probe: <표지>` 헤더를 붙여 보내고, ModSecurity JSON 로그에서 그 표지가 있는 줄의 `request.headers`를 본다.

### 4.4 공개 주소 확인 체크리스트

외부망에서 `https://soc.<DDNS 이름>.synology.me`로 확인한다. 리허설에서 같은 항목을 로컬 PC로 확인한 증거는 `scripts/portfolio-verify.ps1`의 E2E 번호로 적었다.

**같은 LAN(로컬 PC)에서 확인할 때**: 공유기에 NAT 루프백이 없으면 로컬 PC에서 공인 IP로는 접속되지 않는다. 대신 `curl.exe --resolve soc.<DDNS 이름>.synology.me:443:<NAS 주소> https://soc.<DDNS 이름>.synology.me/...`로 NAS의 DSM `443`에 직접 붙는다(인증서·역방향 프록시·헤더는 공개 경로와 같다). 브라우저가 필요한 항목은 `curl.exe`의 인증서 검증 성공(`--insecure` 없이 종료 코드 0)과 `Set-Cookie` 속성으로 대신한다. 로컬 PC의 모든 요청은 같은 클라이언트 IP(로컬 PC의 LAN IP)라 로그인 요청 사이에 7초 정도 간격을 두지 않으면 속도 제한(`429`)에 걸린다. 공개 IP 접속 자체와 방문자 공인 IP 기록(4.3)은 외부망(휴대전화 데이터 등)에서만 확인할 수 있다.

- [ ] 브라우저 주소 표시줄에 인증서 경고가 없다(4.1 하위 도메인 인증서). `http://` 접속은 공유기가 `443`만 포워딩하므로 외부에서는 해당 없다.
- [ ] `demo` / 공개 비밀번호로 로그인되고(TOTP 없음) 조사 큐·사건 상세(근거 요약 칸 포함)·보고서·전송 판단·Slack 기록·운영 상태(`feedback_summary`)가 스냅샷 데이터로 보인다. 보이는 캡처(`snapshot/manifest.json`의 `publicCaptures`: `cic17-*` 4, `syn1-*` 4, `lab-20261119`) 건수가 매니페스트와 같고, `lab-20261119` 사건의 목록·상세·증적·AI 리포트가 보인다. 숨김 캡처(`hiddenCaptures`: `lab-20261201`, `lab-20261118` 등)는 캡처 목록에 없고, 직접 조회(목록 `captureId=<숨김 캡처>`·그 캡처의 사건 상세)는 `403`이다. 첫 화면(`/`)은 관제 현황판이다. (리허설 [2]·[3])
- [ ] IP는 뒤 두 옥텟이 가려져 보인다(`192.168.*.*`). (리허설 [3])
- [ ] `demo`로 상태 전이·검토 결정·`/api/admin/**`가 `403`이다(화면에 쓰기 버튼이 없거나 눌러도 거부). (리허설 [4])
- [ ] `trial-analyst` / 공개 비밀번호로 로그인되고 역할이 `ANALYST`, 허용 캡처가 `demo`와 같으며 숨긴 캡처 직접 조회가 `403`이다. 공개 데모에서는 쓰기(상태 변경·결정·담당)와 로그인 실패를 일부러 만들지 않는다(쓰기 흐름은 리허설 `[T33]`). (리허설 [T33a])
- [ ] 다음 정각 뒤 `logs --since 2h sandbox-reset`에 `OK` 줄이 있고 `ERROR`가 없다. (3.5, 리허설 [T33f])
- [ ] 추가만 하는 기록의 크기: `SELECT count(*) FROM audit_logs`와 `SELECT pg_size_pretty(pg_database_size('zeekad_dashboard'))`(NAS `exec -T postgres psql -U postgres -d zeekad_dashboard -Atc …`, 개수와 크기만)를 기록해 지난번과 비교한다. 체험 계정 사유·메모는 500자까지이고 쓰기는 IP당 분당 10회 + 버스트 5라, IP 하나가 하루에 늘릴 수 있는 감사 로그는 약 14,400행(행당 1KB 남짓, 약 15MB)이다. 크게 늘었으면 감사 로그 화면에서 행위자·IP 분포를 보고 판단한다.
- [ ] `viewer1`·`analyst1`·`analyst2`·`admin`은 로그인되지 않는다(비활성). (리허설 [5])
- [ ] `demo`에 틀린 비밀번호를 여러 번 넣어도 잠기지 않는다. 짧은 시간에 로그인을 많이 시도하면 `429`가 난다. (리허설 [6]·[7])
- [ ] 감사 로그의 로그인 IP가 실제 접속 IP다(4.3). (리허설 [7])
- [ ] `https://soc.<DDNS 이름>.synology.me/api/incidents?asset=%27%20OR%201%3D1--`가 `403`(WAF)이다. XSS(`?asset=%3Cscript%3E`)·경로 탐색(`?asset=../../etc/passwd`)도 `403`. (리허설 [8])
- [ ] 로그인 경로가 아닌 `POST /api/...`(예: `/api/incidents/101/rank/2/assignment`)에 인증 없이 `Content-Type: application/xml`로 깨진 XML 본문(`<a><b></a>`)을 보내면 `400`(WAF)이다. 이 요청은 로그인 실패를 만들지 않는다. 예: `curl.exe -s -o NUL -w "%{http_code}" -X POST -H "Content-Type: application/xml" --data-binary "<a><b></a>" "https://soc.<DDNS 이름>.synology.me/api/incidents/101/rank/2/assignment?probe=<고유 표식>"`. NAS에서 `docker logs --since 10m zeekad-portfolio-nginx-waf-1 2>&1 | grep -F <고유 표식>`으로 그 요청의 기록만 찾아 규칙 `200002`를 확인한다(방문자 IP가 든 다른 줄은 보지 않는다). ([T31])
- [ ] 전달 헤더 신뢰(`T32`): `docker inspect`로 `nginx-waf` 주소가 `PORTFOLIO_WAF_IP`(`10.203.48.250`)이고 `dashboard-app` 환경의 `DASHBOARD_TRUSTED_PROXIES`가 같은 값이다. 공개 HTTPS 주소로 보낸 표식 요청(`curl.exe --resolve …:443:<NAS 주소> "https://soc.<DDNS 이름>.synology.me/login?probe=<고유 표식>"`)의 WAF 로그 줄에서 클라이언트 IP(줄 끝 `X-Forwarded-For` 필드의 신뢰 범위 밖 가장 오른쪽 주소)가 스택 서브넷 주소가 아니다(주소는 적지 않고 "서브넷 안인가"만 적는다. NAS의 `127.0.0.1:18480`으로 바로 보내면 접속 주소가 게이트웨이라 이 확인이 되지 않는다). `demo` 로그인 뒤 반영 시각 이후 `LOGIN_SUCCESS` 행이 1 이상이고 그중 스택 서브넷 주소 행이 0이다(개수만 센다). NAS 안 `api` 컨테이너에서 `nginx-waf:8080/?probe=<고유 표식>`에 `X-Forwarded-For: 198.51.100.x`를 붙인 `GET`의 WAF 로그 접속 주소가 `api` 컨테이너 주소다(감사가 남지 않는 요청). (리허설 [T32])
- [ ] 응답 헤더에 `Strict-Transport-Security`(DSM HSTS), `Content-Security-Policy`(`script-src 'self'`, `style-src 'self'`, `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy`가 있고 `Server`에 버전이 없다(DSM 앞단이 `Server: nginx`를 붙인다. 4.2). 예: `curl.exe -sI https://soc.<DDNS 이름>.synology.me/login`. (리허설 [1], HSTS는 공개 주소에서만)
- [ ] 로그인 응답의 `ZEEKAD_SESSION` 쿠키가 `Secure; HttpOnly; SameSite=Lax`다(브라우저 개발자 도구 > 애플리케이션 > 쿠키). (리허설 [2])
- [ ] 로그아웃 상태에서 `https://soc.<DDNS 이름>.synology.me/`에 접속하면 `https://soc.<DDNS 이름>.synology.me/login`으로 간다(주소에 `:8080`·`:18480`·`http://`가 없다). (리허설 [1])
- [ ] LAN에서 `http://<NAS 주소>:18480/`로 직접 접근할 수 없다. NAS의 이 스택 포트는 `127.0.0.1:18480` 하나뿐이다. (3.6, 리허설 [0])
- [ ] 같은 NAS의 기존 컨테이너와 기존 포트폴리오 주소가 그대로 동작한다. (3.6)

## 5. 계정 시드의 직접 SQL 단계와 위험

시드(`docker/portfolio/seed/seed_demo.py`)는 먼저 `zeekad_dashboard`를 `dashboard_app`으로 읽어 현재 상태를 확인하고, 이미 목표 상태(`demo` 존재·`VIEWER`·허용 캡처 `DEMO_CAPTURE_PATTERNS`(비어 있으면 `cic17-*,syn1-*,lab-20261119`, 순서 무관)·표시 이름·활성·잠금 없음·`.env` 비밀번호와 일치, `TRIAL_ANALYST_PASSWORD`가 있으면 `trial-analyst`도 같은 조건(역할 `ANALYST`, 같은 허용 캡처), 다른 계정 모두 비활성)면 아무것도 바꾸지 않는다(`RESULT: NO_CHANGES`, 감사 로그 추가 없음). 바꿀 것이 있을 때만 바꾼다.

가능한 단계는 앱 관리자 API로 한다(`admin` 로그인 + `.env`의 `BOOTSTRAP_ADMIN_TOTP_SECRET`으로 계산한 TOTP 코드, 감사 로그 `USER_ADMIN_CHANGE`):
공개 계정 생성(`CREATE_USER`), 역할·허용 캡처·표시 이름 수정(`UPDATE_USER`), 활성화·다른 계정 비활성화(`TOGGLE_ENABLED`, 상태를 읽고 필요할 때만 호출), 잠금 해제(`UNLOCK_ACCOUNT`).

API로 할 수 없어 `zeekad_dashboard`에 직접 SQL을 쓰는 단계는 셋이다. 각 SQL은 같은 트랜잭션에서 감사 로그 한 줄(`actor_username=portfolio-seed`, `actor_role=SYSTEM`, `action_type=USER_ADMIN_CHANGE`, `detail_json`에 `operation`·`via: direct SQL`·이유)을 남긴다.

| 단계 | 이유 |
|---|---|
| `admin` 비활성화(`DISABLE`) | `UserAdminService.toggleEnabled`가 로그인한 자기 계정의 비활성화를 막는다 |
| 이미 있는 공개 계정(`demo`, `trial-analyst`)의 비밀번호 변경(`SET_PASSWORD`) | 비밀번호 변경 API가 없고 `createUser`는 이미 있는 아이디를 거부한다. 해시는 앱과 같은 BCrypt strength 12를 PostgreSQL `pgcrypto`(`crypt` + `gen_salt('bf', 12)`, 관리용 `postgres` DB에만 설치)로 만든다 |
| 관리자 API가 필요한데 `admin`이 비활성인 경우의 일시 활성화(`TEMP_ENABLE`) | API를 쓰려면 `admin` 로그인이 필요하다. API 단계를 마치면(실패해도) 곧바로 `DISABLE`로 다시 끈다 |

- 비밀번호·TOTP 시크릿은 환경 변수로만 받고(명령줄 인자로 넘기지 않음) 출력하지 않는다. 해시 계산·비교는 바인드 파라미터로 한다.
- **`admin` 일시 활성 구간의 위험**: 재시드가 API 단계를 해야 할 때(예: 다른 계정이 다시 활성화돼 있음)만 `admin`이 몇 초 동안 활성이 된다. 그동안 공개 주소에서 `admin` 로그인이 가능하지만 `admin`의 비밀번호는 비공개 무작위 값이고 TOTP 2단계 인증까지 필요하며, 로그인 시도는 속도 제한을 받는다. 처음 배포 때는 부트스트랩 직후라 `admin`이 이미 활성이므로 이 구간이 없다(시드가 끝나며 비활성화). 재시드를 피하려면 계정 상태를 손으로 바꾸지 않는다.
- `.env`의 `DEMO_PASSWORD`만 바꾼 경우 재시드는 SQL `SET_PASSWORD` 하나만 하고 `admin`을 켜지 않는다.

## 6. 문제 해결

| 증상 | 확인 |
|---|---|
| `postgres`가 healthy가 되지 않음 | `logs postgres`에서 `portfolio-init`·`portfolio-restore`·`ERROR` 줄. 빈 비밀번호, `sha256sum -c` 실패, `pg_restore` 오류 중 하나다. 고친 뒤 `down -v` → `up -d --wait` |
| 근거 칸이 "근거를 불러올 수 없음" | `exec dashboard-app wget -qO- http://api:8000/health`가 `{"status":"ok"}`인지, `logs api` |
| 로그인 후 바로 로그아웃되거나 CSRF 오류 | DSM이 HTTPS로 서비스하는지(쿠키가 `Secure`), 시스템 시간이 맞는지 |
| 모든 방문자가 `429`를 같이 받음 | 4.3: nginx가 실제 방문자 IP를 못 받고 있다(DSM `X-Forwarded-For` 확인) |
| `sandbox-reset` 로그에 `does not match the current snapshot` | 새 스냅샷인데 기준선이 옛것이다. `stop sandbox-reset` 뒤 `sandbox-setup --rebuild-baseline`(3.10의 4) |
| `sandbox-reset` 로그에 `lock timeout` | 그 정각에 쓰기가 5초 넘게 잠금을 잡았다. 아무것도 바뀌지 않았고 다음 정각에 다시 한다 |
| `302 Location`에 `http://`나 내부 포트가 붙음 | DSM이 `X-Forwarded-Proto: https`를 보내는지 확인(4.2 사용자 지정 헤더) |
