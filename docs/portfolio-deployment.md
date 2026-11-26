# 포트폴리오 공개 배포 안내서 (Synology NAS)

대시보드를 포트폴리오로 공개하는 절차다. 이 문서만 보고 처음부터 따라 할 수 있게 적었다.
`https://soc.<DDNS 이름>.synology.me`에서 공개 데모 계정 `demo`(읽기 전용 `VIEWER`, 마스킹 적용)로 로그인해 실제 `zeek_AD` 스냅샷 데이터를 보게 한다. 분석가 흐름은 체험 계정 `trial-analyst`(`ANALYST`, 마스킹 없음)로 직접 해 볼 수 있다. 바꾼 내용은 매시 정각에 앱 밖 운영 서비스가 되돌린다(`T33`).

탐지 파이프라인의 이름은 NBAD(Network Behavior Anomaly Detection, 저장소 `network-behavior-anomaly-detection`)다. 처음 이름 zeek_AD는 패키지·DB(`zeekad`)·컨테이너·설정 키에 그대로 남아 있고 이 문서의 본문도 그 이름을 쓴다.

- 역할 분담: **로컬 PC**(이미지·스냅샷 준비, 리허설) → **NAS**(SSH로 기동) → **DSM**(인증서·역방향 프록시 설정) → 공개 주소 확인.
- 처음에 "확인 필요"로 두었던 항목(DSM 메뉴·헤더 동작, `scp`, `docker compose` 등)은 NAS 배포(`T13`)에서 확인해 결과를 해당 절에 적었다.
- 기존 VMware 스택(`compose.yml`, `docs/deployment-guide.md`)과는 별개다. 두 파일을 병합하지 않는다.
- **배포 폴더**: NAS에서 이 스택의 파일을 두는 폴더를 이 문서에서는 `<배포 폴더>`라고 쓴다(운영 기기의 모델·판·경로·여유 자원은 문서에 적지 않는다. 실제 값은 저장소 밖 운영 기록에 있다). NAS 셸에서 처음에 한 번 `export DEPLOY_DIR=<배포 폴더>`(절대 경로)로 정하고 `test -d "$DEPLOY_DIR" && echo "DEPLOY_DIR ok"`로 확인한다. 명령은 `cd "$DEPLOY_DIR"`, 상위 폴더는 `"$(dirname "$DEPLOY_DIR")"`로 쓴다. `<배포 폴더>`를 명령 안에 그대로 넣으면 셸이 `<`·`>`를 리다이렉트로 읽는다. 단계를 스크립트 파일로 풀어 새 셸에서 실행할 때(3.8·3.9)는 그 파일 맨 앞에 같은 `DEPLOY_DIR=` 줄을 둔다. 로컬 PC의 `$dst`도 같은 경로다.

## 1. 구성

```
방문자 ──HTTPS 443──> 공유기 ──> NAS DSM 역방향 프록시 (TLS 종료, 와일드카드 인증서, HSTS)
                                   │ Host: soc.<DDNS 이름>.synology.me
                                   │ X-Forwarded-Proto: https, X-Forwarded-For: <방문자 IP>
                                   ▼
                        127.0.0.1:18480 (NAS 루프백에만 묶임)
                                   │
  Compose 프로젝트 zeekad-portfolio   네트워크 둘(T61)
  ┌ portfolio-net (10.203.48.0/24 고정) ─────────────────────────────────────────────────────
  │ nginx-waf 주소 10.203.48.250 고정(T32), DSM 연결은 게이트웨이 10.203.48.1로 들어온다
  │ nginx-waf (ModSecurity CRS, 속도 제한) ─> dashboard-app
  └──────────────────────────────────────────────│───────────────────────────────────────────
  ┌ portfolio-data (10.203.47.0/24, 내부 전용: 바깥 길 없음) ──│────────────────────────────────
  │                                             dashboard-app ─> postgres (zeekad 스냅샷, zeekad_dashboard)
  │                                                   └──────> api (zeek_AD 근거 API) ─> postgres
  │ sandbox-reset(상주)·sandbox-setup·demo-seed(도구) ─> postgres (demo-seed는 dashboard-app에도)
  └──────────────────────────────────────────────────────────────────────────────────────────
  nginx-waf는 portfolio-data에 붙지 않아 postgres·api에 닿지 않는다. 두 네트워크에 붙는 것은 dashboard-app뿐이다.
```

| 서비스 | 이미지(기본값) | 네트워크(`T61`) | 바깥 포트 | 메모리 상한 |
|---|---|---|---|---|
| `postgres` | `pgvector/pgvector:0.8.1-pg17` | `portfolio-data` | 없음 | 1g |
| `api` | `zeekad-pipeline:dev` (`python scripts/run_api.py`) | `portfolio-data` | 없음 | 1g |
| `dashboard-app` | `zeek-ad-dashboard-app:local` | `portfolio-net`, `portfolio-data` | 없음 | 1g |
| `nginx-waf` | `zeek-ad-dashboard-waf:local` | `portfolio-net` | `127.0.0.1:18480` → 8080(HTTP) | 512m |
| `demo-seed`(도구, `--profile seed run`으로만 실행) | `zeekad-pipeline:dev` | `portfolio-data` | 없음 | 256m |
| `sandbox-setup`(도구, `--profile seed run`으로만 실행, `T33`) | `pgvector/pgvector:0.8.1-pg17` | `portfolio-data` | 없음 | 128m |
| `sandbox-reset`(상주, `T33`) | `pgvector/pgvector:0.8.1-pg17`(`psql`만) | `portfolio-data` | 없음 | 64m |

리허설(로컬 PC)에서 측정한 실제 사용량은 네 서비스 합계 약 0.4GiB였다(`T12` 실행 기록, 저장소 밖 보관). 상한 합계는 3.5GiB다. 배포 전에 NAS의 여유 메모리가 이보다 넉넉한지 확인한다(3.1).

### 1.1 보안 전제와 설정 요약

- **바깥에 여는 포트는 `nginx-waf` HTTP 하나뿐이고 NAS `127.0.0.1`에만 묶는다.** 그래서 이 포트에 접근할 수 있는 것은 같은 NAS의 DSM 역방향 프록시뿐이다. 아래 전달 헤더(`X-Forwarded-For`, `X-Forwarded-Proto`)를 믿는 근거가 이 전제다. 포트를 `0.0.0.0`이나 LAN 주소에 묶으면 이 전제가 깨진다.
- **네트워크 둘(`T61`)**: 인터넷 요청을 받는 `nginx-waf`가 DB와 근거 API에 직접 닿지 못하게 스택 네트워크를 둘로 나눴다(`T60`까지는 일곱 서비스가 `portfolio-net` 하나에 붙었다).
  - `portfolio-net`(서브넷 `PORTFOLIO_SUBNET`, 기본 `10.203.48.0/24`): `nginx-waf`(고정 주소)와 `dashboard-app`만 붙는다. `nginx-waf`의 포트를 바깥에 열어야 해 내부 전용으로 만들 수 없다. 정의(이름·서브넷·주석)는 `T61` 전과 한 글자도 같다. NAS에 이미 있는 네트워크라 정의가 바뀌면 붙은 컨테이너를 모두 내리고 다시 만들어야 하고, 이름과 서브넷이 그대로여야 `T32`의 신뢰 값(WAF 주소, 게이트웨이)도 그대로다.
  - `portfolio-data`(`internal: true`, 서브넷 `PORTFOLIO_DATA_SUBNET`, 기본 `10.203.47.0/24`): `dashboard-app`·`postgres`·`api`와 초기화·시드 도구(`sandbox-setup`·`sandbox-reset`·`demo-seed`)가 붙는다. 내부 전용이라 호스트 밖으로 나가는 길(기본 경로)이 없고 포트를 열 수 없다. 고정 주소를 쓰는 서비스는 없다. 근거 API는 DB만 쓰므로 바깥 연결이 필요 없다.
  - 그래서 `nginx-waf`는 `postgres:5432`와 `api:8000`에 이름으로도 주소로도 닿지 않는다(Docker 내장 DNS는 같은 네트워크의 이름만 돌려준다). `nginx-waf`가 뚫려도 다음에 닿는 곳은 앱(`dashboard-app:8080`)뿐이다. 두 네트워크에 붙는 것은 앱 하나다. 바깥으로 나갈 길(기본 경로)은 `portfolio-net`에 붙는 `nginx-waf`와 앱에 남는다(WAF의 포트를 열어야 해서 `portfolio-net`은 내부 전용으로 만들 수 없다). 그래서 `nginx-waf`가 뚫리면 스택 안에서는 앱에만 닿지만 바깥으로 연결을 낼 수는 있다.
  - 남는 길: `api`·`sandbox-*`·`demo-seed`는 앱 `8080`에 직접 닿는다(앱이 `api`를 불러야 해 같은 네트워크에 있다). 그 연결의 전달 헤더는 앱이 믿지 않는다(`T32`, 리허설 `[T32d]`).
  - 셋으로 나누지 않았다. DB만 따로 떼면 `api`·앱·초기화 도구가 모두 두 네트워크에 붙어야 하고, 막으려는 길(WAF → DB·근거 API)은 둘로도 끊긴다.
  - 확인: 리허설 `[T61a]`(붙은 컨테이너, `Internal`, 기본 경로)·`[T61b]`(`nginx-waf` 안에서 TCP 연결 단계로 판정)·`[T61c]`(`api`에서 WAF로). NAS에 처음 반영할 때의 순서는 3.8의 `T61` 절이다.
- **컨테이너 권한(`T61`)**: 공개 스택의 모든 서비스가 capability 없이(`cap_drop: [ALL]`) 권한 상승 금지(`no-new-privileges`)로 돈다. `T60`까지는 `nginx-waf`에 `no-new-privileges`만 있었고 `postgres`에는 아무 설정이 없었다.
  - `nginx-waf`: 이미지가 `nginx` 계정으로 1024 위 포트(8080·8443)를 열어 capability가 필요 없다.
  - `postgres`: root로 시작하지 않는다(`user: postgres`, `sandbox-*`와 같은 꼴). 이미지의 진입 스크립트는 root가 아니면 데이터 폴더 소유자 바꾸기(`chown`)와 `gosu`를 건너뛴다. 데이터 폴더는 이미지가 `postgres` 소유로 만들어 두므로 새 볼륨과 옛 구성(root로 시작해 `gosu`로 내려감)이 만든 볼륨의 소유자가 같다. 새 볼륨은 리허설, 옛 볼륨은 갱신 리허설(3.8 `T61` 절)로 본다.
  - 고치기 전과 뒤는 `docker inspect`의 `Config.User`와 PID 1의 `/proc/1/status`(`CapBnd`, `NoNewPrivs`)로 가른다(리허설 `[T61d]`). 실행 중인 프로세스의 실효 권한(`CapEff`)은 고치기 전에도 0이었을 것이나(진입 스크립트가 `gosu`로 내려가고 WAF는 `USER nginx`) 권한 경계(`CapBnd`)가 남아 있었다.
  - `read_only`와 `tmpfs`는 `nginx-waf`·`postgres`에 걸지 않았다(`sandbox-*`에만 있다).
- **클라이언트 IP**: nginx는 `X-Forwarded-For`에서 신뢰 범위(`127.0.0.1`, Docker 게이트웨이 `PORTFOLIO_GATEWAY_IP`) 밖의 가장 오른쪽 주소(DSM이 덧붙인 실제 접속 주소)를 클라이언트 IP로 쓴다(`real_ip_recursive on`, 포트폴리오 전용 http 문맥 설정). 앱에 넘기는 헤더는 `T14`부터 모든 스택이 같은 공유 규칙(WAF 이미지 템플릿 `includes/proxy_backend.conf.template`)을 쓴다: `X-Forwarded-For`는 그 주소 하나로 **덮어써서** 넘기고, 방문자가 붙인 `Forwarded`·`X-Forwarded-Host`·`X-Forwarded-Prefix`·`X-Forwarded-Ssl`은 지운다. 그래서 방문자가 헤더를 꾸며도 감사 로그 IP·속도 제한 키·리다이렉트 주소를 바꿀 수 없다. VMware 스택(`compose.yml`)은 `127.0.0.1`만 신뢰한다(`docs/deployment-guide.md` 1.2).
- **전달 헤더를 믿는 출처(`T32`)**: DSM이 `127.0.0.1:18480`으로 붙은 연결은 컨테이너 안에서 Docker 게이트웨이 주소(`PORTFOLIO_GATEWAY_IP`, 기본 `10.203.48.1`)에서 온 것으로 보인다. `nginx-waf`는 `127.0.0.1`과 이 주소에서 온 연결의 `X-Forwarded-For`·`X-Forwarded-Proto`만 믿는다(`set_real_ip_from`과 `X-Forwarded-Proto`·`Port` map의 출처 표시 `geo $realip_remote_addr`). `T31`까지는 스택 서브넷 전체를 믿어서 같은 네트워크의 다른 컨테이너(예: `api`)가 `nginx-waf:8080`에 `X-Forwarded-For`를 붙이면 그 값이 감사 로그 IP가 됐다. 앱은 `nginx-waf` 고정 주소(`PORTFOLIO_WAF_IP`, 기본 `10.203.48.250`)에서 온 연결의 전달 헤더만 믿는다(`DASHBOARD_TRUSTED_PROXIES`, 같은 변수). 그래서 다른 컨테이너가 `nginx-waf:8080`이나 `dashboard-app:8080`에 전달 헤더를 붙여 보내도 감사 로그 IP는 그 컨테이너 주소이고 `https`로 판정되지 않는다(리허설 `[T32]`). `T61`부터 `nginx-waf:8080`에 닿는 다른 컨테이너는 `portfolio-net`에 새로 붙인 것뿐이다(앱 말고는 그 네트워크에 붙는 서비스가 없다). 리허설 `[T32c]`는 그 네트워크에 붙인 일회용 컨테이너로 본다.
  - `PORTFOLIO_SUBNET`을 바꾸면 `PORTFOLIO_WAF_IP`·`PORTFOLIO_GATEWAY_IP`도 그 서브넷 안으로 바꾼다. 게이트웨이 주소는 반영 전에 NAS에서 확인한다(3.8 `T32`). `PORTFOLIO_DATA_SUBNET`은 함께 바꿀 값이 없다.
  - 남은 위험: 같은 bridge에서 `NET_RAW` 권한으로 패킷 출처를 꾸미는 공격은 신뢰 목록으로 막지 못한다. `T61`부터 `nginx-waf`와 같은 네트워크에는 앱뿐이고 스택의 모든 컨테이너에 capability가 없어(`NET_RAW` 포함) 스택 안의 컨테이너는 이 공격을 할 수 없다. 호스트의 프로세스와 나중에 `portfolio-net`에 새로 붙인 컨테이너(`cap_drop` 없이 띄운 것)는 여전히 막지 못한다. 또 게이트웨이를 믿으므로 NAS 호스트의 로컬 프로세스와 host 네트워크 컨테이너는 `127.0.0.1:18480`으로 전달 헤더를 꾸밀 수 있다. 이것은 원래 전제(이 포트에는 DSM만 붙는다)와 같다. 공개 스택은 네트워크(ipam)를 다시 만들지 않으려고 동적 배정 범위를 따로 두지 않았다. 그래서 `nginx-waf`가 내려가 있는 동안 다른 컨테이너가 `.250`을 받으면 앱이 그 컨테이너를 믿는다(그때 `nginx-waf`는 주소 충돌로 뜨지 않아 장애로 드러난다). 네트워크를 다시 만들 일이 있으면 VMware 스택처럼 `ip_range`를 준다.
- **절대 URL**: 신뢰 출처(DSM)가 보낸 `X-Forwarded-Proto`가 `https`면 앱에 `https`/`443`을 넘긴다. 그래서 비인증 보호 경로의 `302 Location`이 `https://soc.<DDNS 이름>.synology.me/login`(내부 포트 없음)이 된다. HTTP 리스너는 HTTPS로 리다이렉트하지 않는다(TLS는 DSM이 끝낸다). 스택 내부 8443 리스너(DSM 헤더 없음)에서는 `https` + Host의 포트(`8443`)를 넘겨 리다이렉트가 실제로 열린 `https://nginx-waf:8443/...`을 가리킨다.
- **계정**: `demo`(VIEWER, 허용 캡처 `DEMO_CAPTURE_PATTERNS`, 비어 있으면 `cic17-*,syn1-*,lab-20261119,lab-20261122,lab-20261126`)와 체험용 분석가 `trial-analyst`(ANALYST, 허용 캡처는 `demo`와 같은 변수, `T33`)만 활성. `trial-analyst`는 분석가라 마스킹이 없다(공개 전 노출 확인 1.3). 실습망 캡처는 Kali 실행 결과 `lab-20261119`, Kali 공격 6종 + 타깃 VM `lab-20261122`(`T39`), 오탐 규칙 뒤 재실행 `lab-20261126`(`T66`)만 정확한 ID로 보인다. 시험 캡처 `lab-20261201`(가짜 패킷)·첫 VM 실행 `lab-20261118`·시험 뒤 유휴 구간 `lab-20261123`·규칙 전 유휴 날 `lab-20261124`·`lab-20261125`처럼 스냅샷에 있는 나머지 캡처는 `demo`에게 보이지 않는다(DB에서는 지우지 않는다, 2026-11-21·2026-11-23·2026-11-26 결정). `viewer1`·`analyst1`·`analyst2`·`admin`은 서로 다른 비공개 무작위 비밀번호를 가진 채 비활성이다. 시연 분석가 `demo-analyst`(ANALYST, 표시 이름 `시연 분석가`, 허용 캡처 `lab-20261119`·`lab-20261122`, `T54`)도 평소에는 비활성이다. 시드가 분석이 끝난 예시를 기록하는 몇 초 동안만 켜지고, 그 실행의 비밀번호는 무작위로 만들어 쓰고 버린다(1.4).
- **계정 잠금과 로그인 속도 제한(`T29`에서 바꿈)**: 모든 계정은 앱 기본대로 틀린 비밀번호 5번에 15분 잠긴다(`compose.portfolio.yml`이 `DASHBOARD_MAX_FAILED_ATTEMPTS="5"`로 고정하고 `.env`를 쓰지 않는다. `T12`~`T27`은 `PORTFOLIO_MAX_FAILED_ATTEMPTS=1000000`으로 모든 계정의 잠금을 사실상 껐었다. NAS `.env`에 그 줄이 남아 있어도 이제 쓰이지 않는다). 관리자는 TOTP 확인의 틀린 코드도 같은 횟수에 든다(`T60`). 비밀번호를 공개한 `demo`·`trial-analyst`만 아래 잠금 제외로 빠진다. 비공개 ANALYST·ADMIN 계정이 남의 시도로 15분 잠길 수 있는 것은 받아들인다(방문자 화면은 공개 계정 둘). nginx는 `POST /api/auth/login`과 관리자 TOTP 확인 `POST /api/auth/totp/verify`(`T60`)를 영역 하나로 묶어 클라이언트 IP당 분당 10회 + 버스트 5로 제한하고 넘으면 `429`를 준다(`PORTFOLIO_LOGIN_RATE`, `PORTFOLIO_LOGIN_BURST`). 관리자 로그인 한 번은 이 한도에서 두 건을 쓴다(로그인과 TOTP 확인). TOTP 등록 확인(`POST /api/auth/totp/setup`)은 세지 않는다. 리허설 `[T60]`이 인증 없는 요청으로 `429`를 본다(`admin`을 켜지 않는다).
- **조회 속도 제한(`T36`)**: nginx가 DSM에서 온 요청(공개 경로)의 `/api/` `GET`·`HEAD`를 클라이언트 IP당 분당 200회 + 버스트 30으로 제한하고 넘으면 `429`를 준다(`PORTFOLIO_READ_RATE`, `PORTFOLIO_READ_BURST`, 로그인·쓰기 제한과 다른 영역). 허용 밖 인시던트 조회 거부 감사(`ACCESS_DENIED_IDOR`)가 한 IP에서 쌓이는 속도를 묶으려는 것이다. `/api/auth/`(로그인 상태·안내 문구·CSRF)는 조회 거부 감사를 만들지 않아 세지 않는다. 그래서 한도에 걸린 동안에도 새로고침이 로그인 화면으로 바뀌지 않고 로그인할 수 있다. 정적 파일·화면 경로, 스택 안 8443 리스너와 다른 컨테이너에서 온 요청도 세지 않는다. 값은 빠른 사람 사용을 실제 화면으로 흉내 내 잰 최대치보다 분당 3배, 10초 2배 넘게 잡았다. 흉내는 5분 동안 현황판 60초마다 새로 고침, 큐 쪽 넘김 10번(3초 간격), 상세 이전·다음 20번(3초 간격), 운영 현황 두 번이고 `/api/` 요청은 1분 최대 65건, 10초 최대 14건이었다. 한도에 걸린 화면은 일반 오류와 다른 "요청이 잠시 제한됐습니다" 안내와 "다시 시도" 버튼을 보인다(`T41`, 로그인 화면도 같은 안내). 한도가 풀린 뒤 다시 시도나 새로고침 한 번으로 돌아온다. 현황판은 이미 보이던 같은 조건의 값을 지우지 않고 "최신 값이 아닙니다" 표시와 마지막 성공 시각을 붙인다. 실시간 배포의 현황판은 `429`·`5xx`·응답 없음 뒤에도 60초 자동 갱신을 이어 가서 한도가 풀리면 스스로 돌아온다(`401`·`403` 뒤에는 멈춘다). 공개 데모는 고정 스냅샷이라 자동 갱신이 원래 꺼져 있어 화면이 스스로 다시 부르지 않는다. 공인 IP 하나를 나눠 쓰는 방문자들(회사·학교 NAT)은 한도를 함께 쓴다.
- **공유 계정 잠금 제외(`T29`, `T33`에서 넓힘)**: `compose.portfolio.yml`이 `DASHBOARD_LOCKOUT_EXEMPT_USERNAMES=demo,trial-analyst`(기본, `.env`의 같은 이름으로 바꿀 수 있음)를 넘긴다. 비밀번호를 공개한 공유 계정을 누군가 틀린 비밀번호로 잠가 다른 방문자를 막지 못하게 하려는 것이다. 앱은 로그인 때 DB 역할이 VIEWER 또는 ANALYST인 목록 계정만 잠금에서 빼고(실패 수·잠금을 바꾸지 않음), 실패 감사(`LOGIN_FAILURE`, `lockoutExempt: true`)는 그대로 남긴다. ADMIN은 목록에 있어도 잠긴다. 무작위 대입은 위 IP당 로그인 속도 제한이 막는다(값은 바꾸지 않았다). **운영 규칙: 목록에는 비밀번호를 공개한 공유 계정만 넣는다.** 실제 분석가처럼 비공개 비밀번호 계정을 넣으면 그 계정도 잠기지 않아 여러 IP에서 대입할 때 막을 것이 IP당 속도 제한뿐이다. 목록의 계정이 없거나 VIEWER·ANALYST가 아니면 앱이 시작할 때 경고 로그를 남긴다(이름만). 공개 데모에서는 로그인 실패를 일부러 만들어 시험하지 않는다(실패하면 방문자가 막힐 수 있다). 리허설 `[T29]`가 대신 확인한다.
- **기준 시각(`T23`)**: `dashboard-app`은 `DASHBOARD_TIME_ANCHOR=latest-data`(compose 기본, `.env`의 `PORTFOLIO_TIME_ANCHOR`로 바꿀 수 있음)로 뜬다. 데이터가 더 늘지 않는 고정 스냅샷이라 인시던트 큐의 "최근 24시간" 등을 `demo`가 볼 수 있는 캡처의 최신 탐지 작업 완료 시각에서 센다(숨긴 캡처의 시각은 섞이지 않는다). 모든 화면 맨 위에 "고정 스냅샷 · 기준 시각 …"이 보이고 새 인시던트 자동 갱신은 꺼진다. `T23`은 3.8로 `dashboard-app` 이미지와 `compose.portfolio.yml`을 바꿨다(`ID=t23`, `SVC=dashboard-app`, `FILES="compose.portfolio.yml"`).
- **센서 상태(`T24`)**: 현황판·운영 현황의 센서 상태 기준은 앱 기본값(마지막 채점이 기준 시각에서 15분 이내 정상, 1시간 이내 지연, 넘으면 중단)을 쓴다. 고정 스냅샷이라 기준 시각 기준으로 센다. `compose.portfolio.yml`은 이 값을 넘기지 않는다(`DASHBOARD_SENSOR_STALE_AFTER`·`DASHBOARD_SENSOR_DOWN_AFTER`, `docs/deployment-guide.md`).
- **착수 목표(`T25`)**: 앱 기본값(High 30분·Medium 4시간·Low 24시간, 실습망 신규 인시던트만)을 쓴다. 고정 스냅샷이라 경과·착수 지연·처리 시간 지표는 기준 시각 기준으로 센다. `compose.portfolio.yml`은 넘기지 않는다(`DASHBOARD_SLA_ACK_HIGH`·`DASHBOARD_SLA_ACK_MEDIUM`·`DASHBOARD_SLA_ACK_LOW`, `docs/deployment-guide.md`). 담당 기록(앱 DB `V2` 표)은 공개 데모에 지어 넣지 않으므로 처음에는 모두 "미배정"으로 보인다. 체험 계정이 지정한 담당은 매시 정각에 해제된다(1.3).
- **세션 쿠키**: `DASHBOARD_COOKIE_SECURE=true` 그대로다(`Secure`·`HttpOnly`·`SameSite=Lax`). 브라우저는 DSM과 HTTPS로 통신하므로 문제없다.
- **8443 리스너**: `nginx-waf`의 HTTPS 리스너(이미지 기본 자체 서명 인증서)는 `portfolio-net` 안에서만 쓰인다(리허설 ZAP 대상). 바깥에 열지 않는다.
- **WAF 로그에 남기는 것(`T59`)**: `nginx-waf` 컨테이너 로그에는 두 가지 줄이 나간다.
  - 접근 로그는 모든 요청을 적는다: 연결 주소, 시각, 요청 줄(메서드·경로·쿼리), 응답 코드, 크기, Referer, User-Agent, 받은 `X-Forwarded-For` 원문. 쿠키와 본문은 적지 않는다.
  - ModSecurity 감사 로그(JSON 한 줄)는 `404`가 아닌 `4xx`와 `5xx` 응답, 그리고 규칙이 걸린 요청을 적는다. WAF 이미지가 부분을 `AHZ`로 줄여(`docker/nginx-waf/Dockerfile`의 `MODSEC_AUDIT_LOG_PARTS`) 접속 주소·시각·`unique_id`·메서드·요청 주소·응답 코드와 걸린 규칙의 메시지만 남긴다. 요청·응답의 헤더와 본문은 남기지 않는다.
  - 줄이기 전(기반 기본값 `ABIJDEFHZ`)에는 로그인 실패(`401`)·권한 거부(`403`)·충돌(`409`) 같은 응답마다 요청 헤더와 응답 헤더가 통째로 남아 세션 쿠키 `ZEEKAD_SESSION`, CSRF 토큰, 응답의 `Set-Cookie` 값이 컨테이너 로그에 들어갔다. 요청 본문(아이디·비밀번호)은 그때도 남지 않았다(`scripts/waf-audit-log-check.ps1`로 확인).
  - 남는 것: 걸린 규칙의 메시지에는 규칙이 잡은 요청의 일부가 그대로 들어간다(공격 꼴 글이 비밀번호 칸에 들어오면 그 글). 요청 주소의 쿼리(검색어, 호스트 주소 조건)는 두 줄 모두에 남는다. 차단된 요청의 User-Agent와 `X-Forwarded-For` 원문은 감사 줄에 없으므로 접근 로그에서 같은 시각·요청 주소의 줄로 찾는다.
  - 이 값은 compose에서 덮지 않는다(`MODSEC_AUDIT_LOG_PARTS`를 주면 이미지의 값을 덮는다. 정적 시험이 막는다).
  - 상태 확인(`T61`): compose와 WAF 이미지의 상태 확인은 `wget --header "Host: localhost" http://127.0.0.1:8080/healthz`다. `T60`까지는 `Host`가 숫자 주소(`127.0.0.1:8080`)라 CRS `920350`에 걸려 응답이 `200`인데도 10초마다 감사 줄이 하나씩 남았다. 접속 주소는 `127.0.0.1` 그대로다(`localhost` 이름으로 접속하면 IPv6로 풀릴 수 있다). WAF 규칙은 끄거나 예외를 두지 않았다. 바깥에서 숫자 주소 `Host`로 `/healthz`를 부르면 지금처럼 감사 줄이 남는다(리허설 `[T61e]`의 대조).
- **잔여 위험(고치지 않음)**: `dashboard_app` 계정은 관리용 `postgres` DB에도 접속할 수 있다(PostgreSQL 기본 `PUBLIC` CONNECT. 시드가 그 DB의 `pgcrypto`를 쓴다). 슈퍼유저가 아니고 `public` 스키마 CREATE 권한도 없다. `postgres` 컨테이너에는 바깥 포트가 없어 스택 네트워크 안의 컨테이너만 접속할 수 있다(`T13` 확인). `T61`부터는 `portfolio-data`의 컨테이너뿐이다(`nginx-waf`는 닿지 않는다).

### 1.2 관련 파일

| 파일 | 내용 |
|---|---|
| `compose.portfolio.yml` | 포트폴리오 스택(NAS의 Compose(옛 판)에서 `docker compose config`가 통과하는 문법만 사용). 네트워크 둘(`T61`) |
| `.env.portfolio.example` | 환경 변수 목록(비밀값은 빈 값). `PORTFOLIO_DATA_SUBNET`(`T61`, 데이터 네트워크 서브넷) |
| `docker/portfolio/initdb/01-roles-databases.sh` | 역할·DB·DB 수준 ACL 생성(zeek_AD `01-roles-databases.sh`와 같은 역할 집합) |
| `docker/portfolio/initdb/02-restore-snapshot.sh` | 스냅샷 SHA-256 확인 → `pg_restore --exit-on-error`(소유자·권한 포함) → 성공 표지 |
| `docker/portfolio/initdb/03-zeekad-functions.sh` | 스냅샷에 없는 zeek_AD 함수 넣기(`T53`): `dashboard.reopen_incident`라는 이름의 함수가 없을 때만 아래 사본을 `zeekad` DB에 한 트랜잭션으로 실행. 실패하면 복원 표지를 지우고 멈춤. 2026-11-26 스냅샷(`T66`)에는 함수가 있어 건너뛴다 |
| `docker/portfolio/initdb/zeekad-sql/018_incident_reopen.sql` | zeek_AD migration 018(종결한 사건 다시 열기)의 바이트 그대로 사본. 출처 commit과 sha256은 같은 폴더의 `SOURCE.md`. 하위 폴더라 이미지가 자동 실행하지 않는다 |
| `docker/portfolio/nginx/zeekad-portfolio-http.conf.template` | 포트폴리오 전용 nginx http 문맥 설정(DSM 뒤의 실제 IP·전달 Proto/Port·속도 제한·앱 HSTS 숨김). `compose.yml`에는 붙지 않는다. 방문자 전달 헤더 지우기는 공유 이미지 템플릿이 한다(`T14`) |
| `docker/portfolio/seed/seed_demo.py` | 계정 시드(멱등): `demo`, `trial-analyst`(`TRIAL_ANALYST_PASSWORD`가 비면 만들지 않음). 분석이 끝난 예시 셋을 시연 분석가 `demo-analyst`로 기록(`T54`, 1.4). 중요 자산 목록을 자료 파일과 같게 맞춤(`T52`, 1.5) |
| `docker/portfolio/seed/demo_examples.json` | 분석이 끝난 예시 셋의 자료(인시던트 ID·판정·착수 사유·대응 조치·종결 사유, `T54`). 시드가 읽는다(`SEED_EXAMPLES_FILE`, 기본 `/seed/demo_examples.json`) |
| `docker/portfolio/seed/critical_assets.json` | 공개 데모의 중요 자산 여섯 건(주소·이름·설명, `T52`). 시드가 읽는다(`SEED_ASSETS_FILE`, 기본 `/seed/critical_assets.json`) |
| `docker/portfolio/sandbox/sandbox-setup.sh` | 체험 계정 초기화 설정(`T33`): 전용 역할·기준선·초기화 함수 셋, `--rebuild-baseline`. 감사 로그 삭제 함수의 실행 권한(`T58`). 대응 조치 기준선 표식과 그 초기화 함수(`T56`) |
| `docker/portfolio/sandbox/sandbox-reset.sh` | 체험 계정 초기화 서비스(`T33`): 매시 정각, `--once`. 하루 한 번 보관 기한이 지난 감사 로그 삭제(`T58`). 매 주기 기준선 뒤에 덧붙은 대응 조치 기록 삭제(`T56`) |
| `scripts/portfolio-snapshot.ps1` | `zeekad` DB 스냅샷(로컬 PC 컨테이너 또는 `-SshHost`로 배포 VM)·매니페스트·비밀값 패턴 검사 |
| `scripts/portfolio-verify.ps1` | 로컬 PC 리허설(E2E [0]~[8], 재시드, [T54] 분석이 끝난 예시 셋, [T52a]~[T52d] 중요 자산, [T33] 초기화(주기 1분), [T61] 네트워크 둘·capability·상태 확인 감사 줄, ZAP [9]). `-ExposureDir`를 주면 체험 계정 노출 확인 |

### 1.3 체험 계정과 매시 정각 초기화(`T33`)

- **무엇을 되돌리나**: 분석가 쓰기는 여섯(상태 변경·담당 지정·인시던트 검토 결정·검토 목록 결정·대응 조치 기록·다시 열기)이다. 파이프라인 DB(`zeekad`)는 쓰기 계정 `dashboard_rw`가 함수 셋(`dashboard.transition_incident`, `dashboard.decide_review`, `dashboard.reopen_incident`(`T53`))만 실행해 바꾸므로 바뀌는 표가 `zeekad.incident_status`·`zeekad.incident_status_history`·`zeekad.analyst_review` 셋뿐이다(다시 열기는 앞의 두 표만 바꾼다. 방문자가 다시 연 건도 같은 방법으로 되돌아간다). 이 셋을 스냅샷 직후 기준선(`sandbox_baseline` 스키마)과 기본키로 맞춘다. 기준선에 없는 행은 지운다. 없어진 행은 넣고 칸이 다른 행(모든 칸 비교)은 되돌린다. 앱 DB(`zeekad_dashboard`)의 담당은 해제만 하고 담당 이력에 해제 행(행위자 `sandbox-reset`, 사유 값 `manual`)을 덧붙인다. 대응 조치 기록(`T56`, 방문자가 쓰는 자유 글이다)은 기준선 표식(설정할 때의 최대 `id`)보다 뒤에 덧붙은 행을 지운다. 그 기록을 남긴 감사 행(`INCIDENT_RESPONSE_ACTION`)은 그대로 둔다. 초기화는 감사 로그와 담당 이력(추가만 하는 기록)을 지우지 않는다. 감사 로그는 보관 기한(90일)이 지난 행만 같은 서비스가 하루 한 번 따로 지운다(아래 "감사 로그 보관 기한").
- **어디서 하나**: 앱 밖 운영 서비스 `sandbox-reset`(상주, `psql`만)이 매시 정각(UTC·KST 모두 정각)에 `sandbox.reset_pipeline()` 다음 `sandbox.reset_assignments()`와 `sandbox.reset_response_actions()`를 부르고 결과 한 줄을 남긴다. 시작할 때는 돌리지 않는다. 하루에 한 번은 이어서 감사 로그 삭제 함수도 부른다(`T58`, 아래). 앱에는 데모 전용 동작(모드 플래그, 앱 안 예약 작업, 체험 계정 이름을 아는 코드, 배너)이 없다.
- **권한**: 초기화 함수 셋은 `SECURITY DEFINER`(소유 `zeekad_owner`·`dashboard_app`)이고 `search_path`를 고정하며 모든 객체를 스키마로 한정한다. 접속 계정 `zeekad_sandbox_reset`은 두 DB `CONNECT`, 함수가 든 `sandbox` 스키마 `USAGE`, 초기화 함수 셋과 감사 로그 삭제 함수(`public.purge_expired_audit_logs(integer)`, `T58`)의 `EXECUTE`만 가진다. 표(감사 로그·대응 조치 기록·대응 조치 기준선 표식 포함)·기준선(`sandbox_baseline`)·`CREATE` 권한은 없다(기준선을 바꿀 수 있으면 실제 표를 고른 값으로 되돌릴 수 있다). `dashboard_rw` 권한은 바꾸지 않는다.
- **동시 쓰기**: `reset_pipeline()`은 처음에 세 표를 `SHARE ROW EXCLUSIVE`로 잠가 진행 중인 쓰기를 기다리고 새 쓰기를 막는다. 5초 안에 잠그지 못하면 아무것도 바꾸지 않고 오류로 끝내고 다음 정각에 다시 한다.
- **옛 기준선 거부**: 기준선에 표지(인시던트 수·탐지 작업 수·최대 `job_id`·세 표의 열 정의 해시)를 함께 둔다. 새 스냅샷을 올렸는데 기준선이 옛것이면 표지가 맞지 않아 초기화가 아무것도 바꾸지 않고 오류를 남긴다(3.10).
- **설정 도구 `sandbox-setup`**(`--profile seed`, 슈퍼유저로 접속): 전용 역할·두 스키마·기준선·초기화 함수 셋을 만들고 감사 로그 삭제 함수의 `EXECUTE`를 준 뒤 권한을 점검한다. 삭제 함수와 대응 조치 표는 앱이 만든 것이라(migration `V4`, `V5`) 앱이 그 migration을 적용하기 전이면 아무것도 바꾸지 않고 멈춘다. 멱등이다. 기준선은 처음과 `--rebuild-baseline`일 때만 만든다. 그때 체험 계정 이름이 세 표의 행위자(`updated_by`·`actor`·`analyst`)나 현재 담당자에 하나라도 있으면 멈춘다(방문자 변경이 기준선이 되는 것을 막는다. 새 스냅샷이 그 이름을 이미 쓰는 경우도 잡는다. 공개 스냅샷에는 zeek_AD 기록의 행위자 `demo-analyst`가 있어 체험 계정 이름을 `trial-analyst`로 정했다. `T54`부터는 같은 이름의 시연 분석가 계정이 예시 셋을 기록한다(1.4). 흔적 검사는 체험 계정 이름만 보므로 그 기록은 막지 않는다). 처음 만들 때는 담당자가 있는 담당 행이 0이어야 한다. 다시 만들 때는 `sandbox-reset`을 먼저 멈춘다(초기화 계정 접속이 있으면 멈춘다).
- **대응 조치 기준선 표식(`T56`)**: 표식은 앱 DB의 한 행짜리 표 `sandbox.response_action_baseline`(소유 `dashboard_app`)이고 값은 설정할 때 `incident_response_actions`의 최대 `id`다. zeek_AD 기준선과 따로 정한다. 표식이 없으면 만들고 `--rebuild-baseline`이면 다시 잡고 그 밖에는 그대로 둔다. 그래서 zeek_AD 기준선이 이미 있는 스택에 `sandbox-setup`을 다시 돌려도 표식이 생긴다. 표식을 만들거나 다시 잡을 때 체험 계정이 쓴 대응 조치 행이 하나라도 있으면 멈춘다(방문자가 쓴 글이 기준선이 되어 남는 것을 막는다). 그때는 그 행을 지우고 다시 돌린다(3.8의 `T56` 절). 초기화 함수는 표식이 없으면 0건으로 넘어가지 않고 오류를 낸다. 대응 조치 표의 트리거는 `UPDATE`·`TRUNCATE`를 늘 거부하고 `DELETE`는 초기화 함수가 트랜잭션 안에서 켠 표식(`dashboard.response_actions_reset`)이 있을 때만 통과시킨다. 이 표식은 실수 방지이고 권한 경계가 아니다(표 소유자는 직접 켤 수 있다). 권한 경계는 표 소유권이다.
- **결정을 소비하는 주체 없음**: 공개 스택의 `api`는 `run_api.py` 하나뿐이고 `zeekad_api`에는 `zeekad` 표 쓰기 권한이 없다. 쓰기 권한이 있는 `zeekad_worker`는 NOLOGIN이고 워커가 없다. 그래서 검토 결정 뒤 재개·보고서·Slack 같은 후속 쓰기가 없다(리허설 `[T33f]`가 세 표 밖 `zeekad` 표 전부의 행 수·내용 해시를 쓰기 전·직후·2분 뒤에 비교한다).
- **쓰기 속도 제한**: nginx가 여섯 쓰기 경로(대응 조치 기록·다시 열기 포함)의 `POST`만 클라이언트 IP당 분당 10회 + 버스트 5로 제한하고 넘으면 `429`를 준다(`PORTFOLIO_WRITE_RATE`, `PORTFOLIO_WRITE_BURST`, 로그인 제한과 다른 영역). 경로는 정규화된 `$uri`를 정규식으로 본다.
- **감사 로그 보관 기한(`T58`)**: 공개 데모는 방문자의 접속 기록(감사 로그의 계정·시각·접속 주소)을 90일 보관한다. 90일은 이 스택의 값이다. 앱의 기본값이 아니고 앱은 기한을 모른다(기한을 주지 않은 배포에서는 아무것도 지워지지 않는다, [`deployment-guide.md`](deployment-guide.md) 2.1).
  - **누가 지우나**: 앱이 아니라 `sandbox-reset`이 지운다. `compose.portfolio.yml`이 `SANDBOX_AUDIT_RETENTION_DAYS: "90"`을 고정 값으로 넘긴다(`.env` 변수가 아니다). 서비스는 하루에 한 번, 곧 서비스가 뜬 뒤 첫 주기와 UTC 날짜가 바뀐 뒤 첫 주기(KST 09:00 정각)에 앱 DB의 `public.purge_expired_audit_logs(90)`을 부른다. 그날 몫은 결과가 `OK`일 때만 쓴 것으로 친다. 실패했거나 아직 설정 전이면 다음 정각에 다시 부른다. `--once`는 늘 부른다.
  - **값**: 비우거나 `0`이면 지우지 않는다. 그 밖에는 정수 30~3650만 받고 아니면 서비스가 종료 코드 2로 끝나고 재시작을 되풀이한다(`restart: unless-stopped`).
  - **무엇이 지워지나**: `occurred_at`이 지금보다 90일 넘게 앞선 감사 행만 지워진다. 함수는 앱 migration `V4`의 것이고 30일보다 짧은 기한을 거부한다. 트리거는 30일 안의 행의 `DELETE`와 모든 `UPDATE`·`TRUNCATE`를 누가 시도하든 거부한다. 한 행이라도 지우면 그 사실이 감사 행 하나(`AUDIT_RETENTION_PURGE`, 행위자 `audit-retention`, 지운 수·기준 시각·기한)로 남고 감사 로그 화면에 "보관 기한 지난 기록 삭제"로 보인다. 이 행도 90일 뒤에 지워진다. 담당 이력(`incident_assignment_history`)에는 접속 주소가 없고 기한을 두지 않았다.
  - **로그**: 초기화 줄 끝에 감사 칸이 붙는다. `; audit[OK] purged=<지운 수> cutoff=<기준 시각 UTC>`, `; audit[SKIP]`(오늘 몫을 이미 씀), `; audit[OFF]`(기한 값 없음), `; audit[NOT_CONFIGURED] …`(함수가 없거나 실행 권한이 없음), `; audit[ERROR] …`. 감사 칸은 `ERROR`일 때만 줄 전체를 `ERROR`로 만든다.
  - **감사 로그 밖에 접속 주소가 남는 곳**: 컨테이너 로그와 되돌리기용 앱 DB 백업이다. `nginx-waf`의 접근 로그와 ModSecurity 기록은 컨테이너 로그로 나가고 접속 주소가 들어 있다. Docker는 로그를 기간으로 지우지 못하므로 모든 서비스에 크기 한도(`json-file`, 10MB 파일 5개, 컨테이너마다 50MB까지)를 걸었다. 요청이 적으면 90일보다 오래된 접근 줄이 남을 수 있고 컨테이너를 다시 만들면 그 컨테이너의 로그는 모두 사라진다. `T60`까지는 `nginx-waf`의 상태 확인이 10초마다 감사 줄을 남겨 한도가 며칠 만에 찼다(계산. 오래된 줄이 빨리 밀려나는 대신 차단 기록도 며칠 뒤에 사라졌다). `T61`부터 상태 확인은 감사 줄을 남기지 않아 `nginx-waf` 로그도 방문자 요청만큼만 천천히 찬다. 그래서 `nginx-waf`에서도 90일보다 오래된 줄이 남을 수 있다. 백업(`backup/app-pre-<ID>.dump`)에는 그 시점의 감사 로그가 통째로 들어 있어 배포 절차가 90일 넘은 백업을 지운다(3.9의 3a. 자동이 아니고 다음 배포 때다).
- **사유·메모 길이 상한**: 앱이 상태 변경 사유와 검토 메모를 500자(앞뒤 공백 뺀 코드 포인트)까지만 받는다(제품 기능, 모든 스택).
- **노출**: `trial-analyst`는 `demo`와 같은 캡처를 마스킹 없이 본다. 공개 전 리허설에서 `lab-20261119`(`T33`)와 `lab-20261122`(`T39`)의 모든 인시던트에서 화면이 부르는 API 응답을 두 계정으로 받아 비교하고(`scripts/portfolio-verify.ps1 -ExposureDir <저장소 밖 폴더>`, 대상 캡처는 스크립트의 `$exposureLabCapture`), 드러나는 값의 종류를 운영자가 확인했다. 새 실습망 캡처를 공개할 때도 같은 확인을 한다(3.10). `lab-20261126`(`T66`)은 스크립트의 대상 캡처를 그 캡처로 바꿨고, 두 계정 응답 비교는 `T57`의 리허설이 한다(`T66`은 복원 DB에서 SQL 수준의 내용 요약만 했다).

### 1.4 분석이 끝난 예시 셋(`T54`)

공개 데모의 인시던트는 거의 모두 신규·미배정이라 방문자가 "분석가가 근거를 보고 판정하고 조치를 기록한 모습"을 볼 수 없었다. 그래서 매시 초기화의 기준선에 분석이 끝난 예시 셋을 넣는다. 예시는 사실로만 만든다: 실제 증적과 실습 공격 기록(zeek_AD 공격 정답 `lab-attacks.v1.json`)에 맞는 글, 실제 앱 API를 거친 기록, 실제 기록 시각.

| | 인시던트(`docker/portfolio/seed/demo_examples.json`) | 판정 | 대응 조치 |
|---|---|---|---|
| A | `lab-20261122`, 10.10.0.50 조회하는 쪽, 16:25~16:40 UTC(SMB 공유 탐색. zeek_AD가 2026-11-26에 "측면 이동"에서 이름을 바꿨다) | 정탐 | 조치 없음(사유는 메모) |
| B | `lab-20261119`, 10.10.0.50 스캔하는 쪽, 03:45~03:55 UTC(빠른 스캔·서비스 스캔 1회차) | 정탐 | 조치 없음(사유는 메모) |
| C | `lab-20261122`, 10.10.0.20, 22:10~22:15 UTC(NetBIOS 데이터그램 브로드캐스트 한 건) | 오탐 | 없음 |

글(착수·종결 사유, 메모)은 자료 파일에만 둔다. 이 문서에 옮겨 적지 않는다(사용자 확인으로 바뀌면 자료 파일만 고친다).

- **누가 어떻게 기록하나**: 시드(`demo-seed`)가 시연 분석가 `demo-analyst`로 로그인해 앱 API로 착수 → (정탐이면) 대응 조치 → 담당 해제 → 종결을 기록한다. 착수 때 앱이 그 계정을 담당자로 자동 지정하고, 종결된 인시던트의 담당은 바꿀 수 없으므로(`409 INCIDENT_CLOSED`) 해제는 종결 앞이다. 그래서 상세의 '이력' 탭에는 담당 해제가 종결보다 먼저 보인다. zeek_AD 표·대응 조치 표·담당 표에는 SQL로 쓰지 않는다. 시각을 꾸미지 않는다(기록 시각은 시드를 돌린 시각이다).
- **판정 먼저, 쓰기는 나중**: 시드는 로그인 전에 DB 읽기만으로 예시마다 상태를 판정한다. zeekad 쪽(최신 큐의 작업 번호·순위, 상태·판정·마지막 변경자)은 앱과 같은 읽기 계정 `dashboard_ro`로 계약 뷰를 읽고(`demo-seed`에 `DASHBOARD_RO_PASSWORD`를 넘긴다. 새 비밀값이 아니다), 앱 DB 쪽(담당자, `demo-analyst`의 조치 수)은 `dashboard_app`으로 읽는다.

  | 지금 상태 | 시드가 하는 일 |
  |---|---|
  | 최신 큐에 그 인시던트가 없음(다른 스냅샷, ID 오타) | 건너뜀(`skipped`) |
  | 신규(상태 행 없음), 담당자 없음 | 착수 → (정탐이면) 조치 → 담당 해제 → 종결 |
  | 분석 중, 마지막 변경자 `demo-analyst`, 담당자가 `demo-analyst`이거나 없음 | 이어서: (정탐이고 그 계정의 조치가 0이면) 조치 → (담당자가 있으면) 해제 → 종결 |
  | 종결, 판정 일치, 마지막 변경자 `demo-analyst`, 담당자 없음, (정탐이면) 그 계정의 조치 1건 이상 | 그대로 둠(`kept`) |
  | 그 밖(신규인데 담당자 있음, 다른 사람이 착수·종결, 다른 판정, 종결인데 담당자가 남음, 정탐인데 조치 0) | 실패 |

  하나라도 실패면 아무것도 쓰지 않고(계정도 켜지 않고) 예시별 한 줄 이유와 함께 0이 아닌 코드로 끝난다. "종결인데 담당자가 남음"은 API로 풀 수 없다(3.9의 볼륨 재생성뿐). 결과는 로그 한 줄 `examples: applied=<기록> kept=<그대로> skipped=<건너뜀>`(건너뛴 ID 포함)이다. 글 본문과 비밀번호는 로그에 없다.
- **계정**: `demo-analyst`는 시드가 만든다(없을 때 관리자 API `createUser`). 예시를 기록해야 하는 실행마다 비밀번호를 무작위로 만들어 쓰고 버린다(출력·저장하지 않는다. `.env`에 없다). 이미 있는 계정의 비밀번호는 관리자 API로 바꿀 수 없어 공개 계정과 같은 SQL 해시 교체 + 감사 행으로 바꾼다(5절). 기록이 끝나면 관리자 API로 끄고, API 단계가 실패해도 `finally`에서 SQL로 끈다. 잠금 제외 목록에는 넣지 않는다. 할 일이 없으면(셋이 모두 `kept`·`skipped`이고 계정이 목표 상태) 로그인 없이 `RESULT: NO_CHANGES`다.
- **기준선**: 새로 만드는 스택은 시드 → `sandbox-setup` 순서라 예시가 기준선에 그대로 들어간다(zeek_AD 세 표의 사본에 예시의 상태 3행·이력 6행이 들고, 대응 조치 표식은 예시의 조치 두 행의 `id` 이상이다). 그래서 매시 초기화 뒤에도 예시의 상태·판정·이력과 조치 기록은 그대로이고, 방문자가 예시에 덧붙인 조치 기록과 상태 변경은 지워진다. 담당은 기준선이 없고 늘 해제된다(예시의 담당 행은 해제된 채 남는다). 이미 기준선이 있는 스택은 3.8의 `T54` 절로 넣는다.
- **한번 기준선에 들어가면 시드로 글을 고칠 수 없다**: 시드는 이미 종결된 예시를 그대로 둔다(`kept`). 종결 건은 다시 열 수 있지만(`T53`) 다시 열고 새 글로 다시 종결해도 앞선 종결의 사유·판정과 대응 조치 기록은 이력에 그대로 남는다(상태 이력과 대응 조치 기록은 지우지 않는다). 글을 바꾸려면 3.9의 볼륨 재생성뿐이고 그때 앱 DB(감사 로그·인시던트 번호)도 새로 만들어진다.
- **조회자에게 보이는 것**: 상태 변경 사유는 주소만 가려서 보인다(`10.10.*.*`). 대응 조치는 종류·기록자·시각만 보이고 메모는 내려가지 않는다. 기본 정렬에서 종결 건은 맨 뒤로 가므로 큐의 종결 필터(`/incidents?status=closed&period=all`)로 찾는다. 예시 A에는 옛 작업의 미결정 검토 때문에 큐의 "검토 대기" 표시가 남는다(에스컬레이션 목록에는 없다. 지금도 종결된 옛 시연 건에 같은 표시가 있다).
- **운영 현황에 주는 영향**: 기록 시각이 기준 시각(탐지 작업의 끝 시각) 뒤라 기간 7일 등에는 들지 않고 전체 기간에만 든다. 처리 시간(탐지부터 종결까지)은 며칠로 나온다. 예시는 기준 시각과 24시간 창을 옮기지 않는다. 판정이 10건 미만이라 "모델 판정"은 계속 "표본 부족"이다.
- **실습 공격 재현을 정탐으로 닫는 이유**: 탐지 품질의 되먹임에서는 재현한 공격을 맞힌 것이 정탐이다. 실제로 차단·격리하지 않았으므로 대응 조치는 "조치 없음"과 그 사유로 적었다. 글 끝의 "(시연)"과 행위자 `demo-analyst`는 스냅샷의 옛 시연 기록과 같은 관례다(`docs/ui-terminology.md`).

### 1.5 중요 자산(`T52`)

관리자가 등록한 중요 자산(IPv4 주소 하나·이름·설명)의 열린 인시던트는 자동 분류 우선순위가 한 단계 오른다(Low → Medium, Medium → High). 같은 우선순위 안에서는 중요 자산이 먼저 온다(규칙·관리자 화면·API는 `docs/deployment-guide.md`, 문구는 `docs/ui-terminology.md`). 공개 데모의 목록은 자료 파일 `docker/portfolio/seed/critical_assets.json`에 있고 시드가 관리자 API로 앱의 목록을 그 파일과 같게 맞춘다.

| 주소 | 이름 |
|---|---|
| `10.10.0.20`~`10.10.0.23` | 실습망 대상 서버(뒤 셋은 같은 서버의 별칭 주소) |
| `10.10.0.10` | 실습망 배포 서버 |
| `192.168.10.3` | 도메인 서버(CIC-IDS2017, DNS·Kerberos) |

- **목록을 정한 방법**: 공개 스냅샷에서 등록 앞뒤의 분포를 잰 뒤 사용자가 정했다(2026-11-26). 공개 데이터셋의 웹 서버(`192.168.10.50`)·Ubuntu 서버(`192.168.10.51`)까지 넣으면 전체 기간 High가 두 배를 넘어 뺐다.
- **시드가 하는 일**: 바꾸기 전에 파일을 검증한다(꼴, IPv4 하나의 정확한 꼴(범위·공백 없음), 중복 주소, 이름 1~100자·설명 300자 이하·제어 문자 없음, 200건 이하). 0건도 거부한다(빈 파일이나 깨진 파일이 목록 전부를 지우지 않게). 어긋나면 아무것도 바꾸지 않고(로그인도 하지 않고) 0이 아닌 코드로 끝난다. 판정은 로그인 전에 앱 DB 읽기(`dashboard_app`)로 하고, 자산만 달라도 관리자 단계를 돈다. 계정·예시·자산이 모두 같으면 지금처럼 로그인 없이 `RESULT: NO_CHANGES`다. 관리자 세션 안에서 `T54` 단계 뒤(로그아웃 앞)에 지우기 → 고치기 → 만들기 순서로 맞춘다(지우기가 먼저라 200건 상한에 걸리지 않는다). 주소를 바꾸는 API는 없어 주소가 바뀌면 지우고 만든다. 변경마다 감사 `CRITICAL_ASSET_CHANGE`가 남는다. 결과는 로그 한 줄 `critical-assets: created=<n> updated=<n> deleted=<n> kept=<n>`이다.
- **파일에 없는 자산은 지운다**: 관리자 화면에서 공개 데모에 손으로 더한 자산도 다음 시드가 지운다. 공개 데모의 목록은 파일로만 바꾼다.
- **앱 DB에 표가 없으면 멈춘다**: `critical_assets` 표(`V6`)가 없으면(`T52` 앞 앱 이미지) 아무것도 바꾸지 않고 0이 아닌 코드로 끝난다. 앱 이미지를 먼저 바꾼다(3.8의 `T52` 절).
- **조회자에게 보이는 것**: `demo`에게는 "중요 자산" 표지와 우선순위가 한 단계 올랐다는 사실만 보이고 자산 이름·설명은 내려가지 않는다. 다만 주소와 이름이 이 공개 저장소의 자료 파일에 함께 있으므로, 공개 데모에서 이름을 가리는 것은 규칙의 시연이다. 실제 운영에서는 자산을 관리자 화면으로만 등록한다.
- **매시 초기화와의 관계**: 중요 자산은 앱 DB의 표 하나이고 매시 초기화(`T33`)와 기준선은 이 표를 건드리지 않는다. 체험 분석가(`trial-analyst`)는 관리자 API를 쓸 수 없다(`403`).
- **운영 현황에 주는 영향**(`T52` 실측, 1.4의 예시 셋 기록 뒤): `demo`가 보는 전체 기간 High 151 → 241, Medium 671 → 748, Low 1,441 → 1,274, 24시간 High 76 → 85. 늘어난 High의 대부분(80건)은 도메인 서버다. 종결 건은 올리지 않는다(예시 C는 `10.10.0.20`이지만 종결이라 우선순위가 없다).

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
- 덤프 전후로 `dashboard.latest_incident_queue` 캡처별 건수를 센다. 파이프라인이 도는 중이라도 **공개할 캡처**(`-PublicCaptures`, 기본 `cic17-*,syn1-*,lab-20261119,lab-20261122,lab-20261126`. `lab-20261126`은 `T66`에서 더했다)만 전후가 같으면 된다. 공개 캡처가 바뀌면 멈춘다. 그 밖의 캡처 변화는 `manifest.json`의 `nonPublicCountChanges`에 정보로 남는다.
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
# NAS(Docker 기본 이미지 저장소)에서 docker load 뒤의 .Id(= 설정 digest)와 다르다. 그래서 tar 안의 Config digest로 비교한다.
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

- `zeekad-pipeline.tar`는 약 5GB다. 배포 폴더가 있는 볼륨의 여유 공간을 배포 전에 확인한다(3.1).
- 리허설(2.3)과 `docker save` 사이에 이미지를 다시 빌드하거나 받지 않는다. 그래야 리허설한 이미지가 NAS로 간다(로컬 PC 안의 동일성은 `docker image inspect --format '{{.Id}}'`를 리허설 전후·`docker save` 뒤에 기록해 비교한다).
- 이미지 `tar`와 스냅샷은 Git에 넣지 않는다(`build/`는 Git 제외 경로).

배포 묶음(NAS의 배포 폴더 `$DEPLOY_DIR`에 아래 구조로 둔다):

```
<배포 폴더>/
├── compose.portfolio.yml
├── .env.portfolio.example        (복사해서 .env 작성)
├── docker/portfolio/initdb/*.sh   (LF 줄바꿈이어야 한다. 저장소의 .gitattributes가 *.sh를 LF로 고정한다)
├── docker/portfolio/initdb/zeekad-sql/018_incident_reopen.sql, SOURCE.md   (T53. *.sql도 .gitattributes가 LF로 고정한다)
├── docker/portfolio/nginx/*.conf.template
├── docker/portfolio/seed/seed_demo.py
├── snapshot/zeekad.dump, zeekad.dump.sha256, manifest.json
└── images/*.tar, images.sha256, image-ids.txt
```

## 3. NAS에서 배포 (SSH)

NAS: `ssh <NAS 사용자>@<NAS 주소>`(키 인증), Docker는 `/usr/local/bin/docker`(`<NAS 사용자>`는 `docker` 그룹이라 sudo 불필요). 아래 명령은 NAS 셸에서 실행한다. 먼저 `export DEPLOY_DIR=<배포 폴더>`를 정한다(문서 머리).

### 3.1 사전 확인(기존 컨테이너를 건드리지 않는다)

```sh
export PATH=/usr/local/bin:$PATH
docker version --format '{{.Server.Version}}'; docker compose version   # 판을 운영 기록(저장소 밖)에 적어 둔다
# 기존 컨테이너·네트워크 상태를 기록해 둔다(배포 뒤 같은지 비교).
mkdir -p ~/zeekad-portfolio-check
docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Ports}}' | sort > ~/zeekad-portfolio-check/containers-before.txt
for n in $(docker network ls -q); do docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' $n; done | sort | tee ~/zeekad-portfolio-check/networks-before.txt
docker image ls --format '{{.Repository}}:{{.Tag}} {{.ID}}' | sort > ~/zeekad-portfolio-check/images-before.txt
# 옮길 네 태그가 이미 있는지(아무것도 나오지 않는 것이 정상). 있으면 3.3 대조 전에 ID를 image-ids.txt와 비교하고,
# 다른 ID면 멈춘다(docker load가 기존 태그를 새 이미지로 옮겨 기존 컨테이너가 쓰던 이미지를 바꿀 수 있다).
grep -E '^(zeek-ad-dashboard-app:local|zeek-ad-dashboard-waf:local|zeekad-pipeline:dev|pgvector/pgvector:0\.8\.1-pg17) ' ~/zeekad-portfolio-check/images-before.txt || echo "no target tags"
# 포트 18480이 비어 있는지(아무것도 나오지 않아야 한다). 같은 기기의 다른 서비스가 쓰는 포트와 겹치면 PORTFOLIO_HTTP_PORT를 바꾼다.
netstat -tln 2>/dev/null | grep -E ':18480\b' || echo "18480 free"
# 배포 폴더를 sudo 없이 만들 수 있는지(상위 폴더 쓰기 권한)
ls -ld "$(dirname "$DEPLOY_DIR")"; test -w "$(dirname "$DEPLOY_DIR")" && echo "parent folder writable"
# 여유 메모리(상한 합계 3.5GiB)와 배포 폴더가 있는 볼륨의 여유 공간(이미지 tar(파이프라인만 약 5GB)와 적재한 이미지, DB 볼륨)을 확인한다
free -m; df -h "$(dirname "$DEPLOY_DIR")"
```

로컬 PC(PowerShell)에서 같은 기기의 다른 서비스가 DSM `443`으로 내는 응답을 기록해 둔다(배포·DSM 설정 뒤 같은지 비교). 공유기에 NAT 루프백이 없으면 로컬 PC에서 공개 IP로는 접속되지 않으므로 `--resolve`로 NAS의 DSM `443`에 직접 붙는다. 이 값은 `--resolve` 경로가 동작한다는 근거도 된다.

```powershell
curl.exe -s -o NUL -w "%{http_code}" --resolve <DDNS 이름>.synology.me:443:<NAS 주소> https://<DDNS 이름>.synology.me/
```

- **서브넷 겹침 확인**: 스택은 서브넷 둘을 쓴다(`T61`). `networks-before.txt`에 `10.203.48.0/24`(`portfolio-net`)나 `10.203.47.0/24`(`portfolio-data`)와 겹치는 대역이 있으면 `.env`에서 바꾼다. `portfolio-net`은 `PORTFOLIO_SUBNET`을 겹치지 않는 대역(예: `10.203.50.0/24`. `10.203.49.0/24`는 VMware 스택 `compose.yml`의 기본값이다)으로 바꾸고 `PORTFOLIO_WAF_IP`·`PORTFOLIO_GATEWAY_IP`도 그 대역 안으로 바꾼다(`T32`, 1.1). `portfolio-data`는 `PORTFOLIO_DATA_SUBNET`만 바꾼다(고정 주소가 없다). 두 값끼리도 겹치면 안 된다.
- **내부 전용 네트워크**: 처음 배포할 때도 3.8 `T61` 절의 사전 확인(`docker network create --internal`을 만들었다 바로 지우기)으로 NAS의 Docker가 내부 전용 네트워크를 받는지 본다.
- NAS의 DSM 7(Container Manager)에서는 `docker compose`가 동작한다(`T13` 확인). `docker-compose`로 바꿀 필요 없다.
- 이 절부터의 NAS 블록(`sh`)은 **NAS 셸 안에서** 실행한다(`ssh <NAS 사용자>@<NAS 주소>`로 들어가서 붙여 넣거나, 로컬 PC의 Git Bash에서 `ssh ... 'bash -s' <<'EOF' ... EOF`). 로컬 PC의 Windows PowerShell 5.1에서 `ssh <NAS> '<여러 명령>'`처럼 한 줄 인자로 넘기면 인자 안의 큰따옴표가 지워져(`printf "\n"` → `printf n`) 결과가 달라진다(`T13`에서 확인).

### 3.2 폴더와 파일 전송

NAS:

```sh
mkdir -p "$DEPLOY_DIR/snapshot" "$DEPLOY_DIR/images" "$DEPLOY_DIR/docker"
chmod 700 "$DEPLOY_DIR"
```

로컬 PC(PowerShell, 저장소 루트):

```powershell
$nas = "<NAS 사용자>@<NAS 주소>"; $dst = '<배포 폴더>'   # NAS의 DEPLOY_DIR와 같은 절대 경로로 바꾼다
# DSM은 SFTP가 꺼져 있어 기본 scp(SFTP 모드)가 'subsystem request failed'로 실패한다. -O(기존 SCP 프로토콜)를 쓴다(T13 확인).
scp -O compose.portfolio.yml .env.portfolio.example "${nas}:${dst}/"
scp -O -r docker/portfolio "${nas}:${dst}/docker/"
scp -O build/portfolio/zeekad.dump build/portfolio/zeekad.dump.sha256 build/portfolio/manifest.json "${nas}:${dst}/snapshot/"
# PowerShell은 네이티브 명령 인자의 *.tar를 펼치지 않을 수 있으므로 파일 이름을 하나씩 적는다.
scp -O build/portfolio-images/zeek-ad-dashboard-app.tar build/portfolio-images/zeek-ad-dashboard-waf.tar build/portfolio-images/zeekad-pipeline.tar build/portfolio-images/pgvector-pg17.tar build/portfolio-images/images.sha256 build/portfolio-images/image-ids.txt "${nas}:${dst}/images/"
```

- PowerShell 5.1 파이프(`tar | ssh`, `docker save | ssh`)는 바이트를 문자열로 바꿔 깨뜨리므로 쓰지 않는다. 파일은 `scp`로만 보낸다.
- 작업 트리의 `.env.portfolio.example`·`compose.portfolio.yml`·`seed_demo.py`·nginx 템플릿은 Windows에서 CRLF로 체크아웃돼 그대로 전송된다(`*.sh`와 `initdb/zeekad-sql/*.sql`만 `.gitattributes`로 LF. 사본의 sha256은 LF 바이트 값이라 CRLF로 가면 대조가 맞지 않는다). Compose·nginx·`python`은 CRLF여도 동작한다. 다만 3.4의 `.env` 작성 스크립트는 줄 끝 `\r`을 떼야 한다(스크립트에 들어 있다).

NAS에서 스냅샷 권한과 무결성 확인:

```sh
cd "$DEPLOY_DIR"
# snapshot/은 chmod 700 이전에 만들어져 상위 공유 폴더의 Synology ACL을 상속받는다(NAS 사용자만 허용).
# 그러면 컨테이너 안 postgres(uid 999)가 덤프를 읽지 못해 복원이 'zeekad.dump ... is missing'으로 실패한다(T13에서 확인).
# 755/644로 바꾸면 Linux 권한 모드가 된다. 덤프는 공개 데모 데이터이고 상위 폴더가 700이라 다른 NAS 사용자는 들어올 수 없다.
chmod 755 snapshot && chmod 644 snapshot/*   # 컨테이너에서 읽히는지는 3.3 끝에서 확인한다
(cd snapshot && sha256sum -c zeekad.dump.sha256)
(cd images && sha256sum -c images.sha256)
ls -l docker/portfolio/initdb/*.sh && head -1 docker/portfolio/initdb/01-roles-databases.sh | od -c | head -2   # \r 이 없어야 한다
# T53: zeek_AD SQL 사본. sha256이 SOURCE.md의 값과 같고(줄 둘이 같은 값) \r 이 0개여야 한다
sha256sum docker/portfolio/initdb/zeekad-sql/018_incident_reopen.sql
grep 'sha256: ' docker/portfolio/initdb/zeekad-sql/SOURCE.md
grep -c $'\r' docker/portfolio/initdb/zeekad-sql/018_incident_reopen.sql   # 0
```

### 3.3 이미지 적재

```sh
cd "$DEPLOY_DIR/images"
for f in zeek-ad-dashboard-app.tar zeek-ad-dashboard-waf.tar zeekad-pipeline.tar pgvector-pg17.tar; do docker load -i "$f"; done
# image-ids.txt는 tar 안 manifest.json의 Config digest(2.4). NAS의 Docker 기본 이미지 저장소에서는 이것이 적재 뒤 .Id다.
for t in zeek-ad-dashboard-app:local zeek-ad-dashboard-waf:local zeekad-pipeline:dev pgvector/pgvector:0.8.1-pg17; do
  printf '%s %s\n' "$(docker image inspect --format '{{.Id}}' "$t")" "$t"
done | diff - image-ids.txt && echo "image IDs match"
# 컨테이너 안 postgres(uid 999)가 스냅샷을 읽을 수 있는지(3.2의 권한 변경 확인). zeekad.dump: OK 가 나와야 한다
docker run --rm --network none --user 999:999 -v "$DEPLOY_DIR/snapshot":/snapshot:ro --entrypoint sh pgvector/pgvector:0.8.1-pg17 -c 'cd /snapshot && sha256sum -c zeekad.dump.sha256'
```

이미지 적재가 끝나면 `images/*.tar`는 지워도 된다(롤백용으로 남겨도 된다).

### 3.4 `.env` 작성(비밀값 생성)

비밀값은 셸 변수와 내장 명령(`printf`)으로만 다룬다. `sed` 같은 외부 명령의 인자로 넘기면 실행 중 프로세스 목록에 보인다.

```sh
cd "$DEPLOY_DIR"
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
cd "$DEPLOY_DIR"
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
- `DEMO_PASSWORD`·`TRIAL_ANALYST_PASSWORD`는 공개 계정 둘(`demo`, `trial-analyst`)의 비밀번호라 README(포트폴리오 소개)에 공개한다. 공개하는 비밀값은 이 둘뿐이고 그 밖의 비밀값은 어디에도 적지 않는다(아래). 나중에 바꾸려면 같은 방법으로 `.env`의 줄을 바꾸고 시드를 다시 실행한다(5절: `SET_PASSWORD` 하나만 한다).
- 다른 비밀값(DB 비밀번호, 비활성 계정 비밀번호, `BOOTSTRAP_ADMIN_TOTP_SECRET`)은 출력하거나 다른 곳에 옮겨 적지 않는다. 운영 중 필요한 것은 시드 재실행뿐이며 시드는 `.env`를 읽는다.
- 비밀값이 비어 있으면 기동되지 않는다: PostgreSQL 이미지가 빈 `POSTGRES_SUPERUSER_PASSWORD`로 초기화를 거부하고, `01-roles-databases.sh`가 빈 로그인 역할 비밀번호로 초기화를 멈춘다(그러면 `postgres`가 healthy가 되지 않아 `api`·`dashboard-app`·`nginx-waf`도 뜨지 않는다). 시드는 빈 `DEMO_PASSWORD`·부트스트랩 비밀번호·TOTP 시크릿이면 아무것도 하지 않고 끝난다. 부트스트랩 비밀번호가 빈 계정은 애초에 만들어지지 않는다.
- 부트스트랩 계정은 `users` 표가 빈 첫 기동 때만 만들어진다. 첫 기동 뒤에 `BOOTSTRAP_*` 값을 바꿔도 이미 있는 계정 비밀번호는 바뀌지 않는다(바꾸려면 3.9의 DB 볼륨 재생성. 이때 zeek_AD DB와 앱 DB가 둘 다 새로 만들어진다).

### 3.5 기동과 계정 시드

```sh
cd "$DEPLOY_DIR"
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env up -d --wait
docker compose -p zeekad-portfolio -f compose.portfolio.yml ps
docker compose -p zeekad-portfolio -f compose.portfolio.yml logs postgres | grep portfolio-restore   # "portfolio-restore: done" 확인, pg_restore 오류 없음
# 계정 시드: 첫 실행은 RESULT: CHANGED, 두 번째 실행은 RESULT: NO_CHANGES 이어야 한다.
# 분석이 끝난 예시 셋(T54, 1.4): 첫 실행은 "examples: applied=3 kept=0 skipped=0", 두 번째는 "examples: applied=0 kept=3 skipped=0".
# skipped가 0이 아니면(스냅샷 착오나 ID 오타) sandbox-setup으로 넘어가지 않고 멈춘다.
# 중요 자산(T52, 1.5): 첫 실행은 "critical-assets: created=6 updated=0 deleted=0 kept=0", 두 번째는 "created=0 updated=0 deleted=0 kept=6".
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env --profile seed run --rm demo-seed
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env --profile seed run --rm demo-seed
# 체험 계정 초기화 설정(T33): 시드 뒤에 돌린다(예시 셋이 기준선에 들어간다). 첫 실행은 "baseline created", 두 번째는 "baseline kept", 둘 다 RESULT: OK
# 대응 조치 기준선 표식(T56)도 같다: 첫 실행은 "response action baseline created: max_id=2"(새 볼륨이면 예시의 조치 두 행), 두 번째는 "response action baseline kept"
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env --profile seed run --rm sandbox-setup
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env --profile seed run --rm sandbox-setup
# 한 번만 초기화: 방금 복원한 DB라 바뀐 행이 모두 0이어야 한다(OK pipeline[OK] ...(-0 +0 ~0) ...; assignments[OK] released=0 history+=0; responses[OK] removed=0; audit[...])
docker compose -p zeekad-portfolio -f compose.portfolio.yml exec -T sandbox-reset bash /sandbox/sandbox-reset.sh --once
```

- 설정 전에는 `sandbox-reset`이 정각마다 `NOT_CONFIGURED…` 한 줄만 남긴다(오류가 아니다). 역할이 아직 없어 postgres 로그에 `password authentication failed for user "zeekad_sandbox_reset"`이 함께 남는다.
- 초기화 확인: `docker compose -p zeekad-portfolio -f compose.portfolio.yml logs --since 2h sandbox-reset`에 정각마다 `OK pipeline[OK] analyst_review(-지운 +넣은 ~되돌린) incident_status(…) incident_status_history(…); assignments[OK] released=… history+=…; responses[OK] removed=…; audit[…]` 줄이 있고 `ERROR`가 없어야 한다. `responses` 칸은 그 주기에 지운 대응 조치 기록 수다(`T56`). 줄 끝의 감사 칸은 하루에 한 번 `audit[OK] purged=… cutoff=…`이고 나머지 정각은 `audit[SKIP]`이다(1.3).

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
# 이 스택의 네트워크 둘(T61): portfolio-net은 internal=false에 nginx-waf·dashboard-app만,
# portfolio-data는 internal=true에 postgres·api·dashboard-app·sandbox-reset만 붙어 있어야 한다(시드 도구는 실행 뒤 지워진다)
docker network inspect -f '{{.Name}} internal={{.Internal}} {{range .Containers}}{{.Name}} {{end}}' zeekad-portfolio_portfolio-net zeekad-portfolio_portfolio-data
```

로컬 PC(LAN)에서 직접 접근이 막혀 있는지: `curl.exe -m 5 http://<NAS 주소>:18480/login`이 연결 실패여야 한다.

### 3.7 중지·롤백

```sh
cd "$DEPLOY_DIR"
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
$nas = "<NAS 사용자>@<NAS 주소>"; $dst = '<배포 폴더>'   # 3.2와 같은 값(NAS의 DEPLOY_DIR)
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
cd "$DEPLOY_DIR" || exit 1
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
cd "$DEPLOY_DIR" || exit 1
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
   cd "$DEPLOY_DIR" || exit 1
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
cd "$DEPLOY_DIR" || exit 1
# 0) 되돌릴 compose(*.pre-<ID>)가 마운트하는 파일이 있는지 먼저 확인한다(없으면 되돌린 compose가 뜨지 않는다)
for f in $NEED; do [ -f "$f" ] || { echo "missing $f"; exit 19; }; done
for f in $FILES; do [ -f "$f.pre-$ID" ] && cp -p "$f.pre-$ID" "$f"; done
docker tag $IMG:pre-$ID $IMG:local || exit 20
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env up -d --wait --no-deps $SVC < /dev/null || exit 21
docker image inspect --format '{{.Id}}' $IMG:local; cat ~/zeekad-portfolio-check/$ID-old-$SVC-image-id.txt   # 같아야 한다
```

- 확인이 끝나 더 필요 없으면 `docker image rm <IMG>:pre-<작업 ID>`로 보존 태그를 지운다(태그만 지워지고 다른 태그가 가리키는 이미지는 남는다). 보존 파일 `*.pre-<작업 ID>`는 다음 갱신 전까지 둔다.
- 앱 이미지가 바뀌어도 시드는 다시 할 필요가 없다(계정은 DB 볼륨에 있다). 단, 시드 스크립트(`docker/portfolio/seed/seed_demo.py`)의 목표 상태가 바뀐 갱신(예: T20 `demo` 허용 캡처 `*` → `cic17-*,syn1-*`. 데이터도 함께 바꾸는 T22 `cic17-*,syn1-*,lab-20261119`는 3.9)은 그 파일을 위 파일 교체로 옮기고(`.env`는 그대로. `DEMO_CAPTURE_PATTERNS`가 없으면 기본값이 쓰인다) 3.5의 시드를 두 번 실행한다. 첫 실행은 `RESULT: CHANGED`(`API UPDATE_USER demo`), 두 번째는 `RESULT: NO_CHANGES`여야 한다. 시드 파일이 바뀌지 않았으면 다시 돌리지 않는다.
- 스크립트로 실행할 때는 위 1·2단계를 스크립트 파일(`nas-step1.sh`·`nas-step2.sh`)로 저장한다. 새 셸에서 실행되므로 파일 맨 앞에 `DEPLOY_DIR=<배포 폴더>` 줄을 둔다(문서 머리). 스크립트를 표준 입력으로 bash에 넘기면(`echo <base64> | base64 -d | bash`, `ssh ... 'bash -s' < 파일`) `docker compose exec -T`·`run`이 남은 스크립트를 읽어 버려 뒤 단계가 실행되지 않은 채 exit 0으로 끝날 수 있다(T22에서 확인). 그래서 NAS의 확인 폴더에 파일로 풀고 표준 입력을 닫아 실행한다: `ssh ... "echo <base64> | base64 -d > ~/zeekad-portfolio-check/<ID>-step1.sh && bash ~/zeekad-portfolio-check/<ID>-step1.sh < /dev/null"`. 출력은 `build/portfolio-evidence/<작업 ID>/nas-update.txt`처럼 Git 제외 경로에 남긴다.

#### 로그인 안내문과 링크를 바꾸는 갱신(`T50`)

로그인 안내문(`DASHBOARD_LOGIN_NOTICE`)과 그 아래 링크(`DASHBOARD_LOGIN_NOTICE_LINK_URL`, `DASHBOARD_LOGIN_NOTICE_LINK_LABEL`)는 앱 이미지가 아니라 `compose.portfolio.yml`의 `dashboard-app` 환경 값이다. 앱 이미지만 바꾸는 위 절차로는 안내문이 바뀌지 않는다. 안내문이나 링크 값이 바뀌면 NAS의 `compose.portfolio.yml`도 함께 바꾼다.

- **1단계**: `SVC=dashboard-app`, `IMG=zeek-ad-dashboard-app`, `FILES="compose.portfolio.yml"`. `.env`는 바꾸지 않는다(세 값은 compose 파일에 직접 적혀 있다).
- **2단계**: `up -d --wait --no-deps dashboard-app`. 링크 설정 둘은 `T50` 이후의 앱 이미지가 읽는다. 옛 이미지에 새 compose만 올리면 줄바꿈은 보이지만 링크는 보이지 않는다.
- **확인**: `curl`로 `GET /api/auth/login-notice`를 받아 `notice`가 네 줄이고 `link.url`이 compose 값과 같은지 본다. 링크 값이 앱의 검사(`https` 주소, 호스트 있음, `user@` 없음, 길이)에 걸리면 앱은 뜨고 `link`만 빠진다. 이때 `docker logs`의 시작 구간에 "로그인 안내 링크를 내리지 않습니다: <이유>" 경고가 한 줄 남는다.
- **롤백**: `compose.portfolio.yml`을 `*.pre-<ID>`로 되돌리고 `dashboard-app`을 다시 만든다.

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
- **반영 전 확인**: 기준선을 만들 공개 DB가 스냅샷 직후 상태인지 본다. `zeekad.incident_status_history` 행 수가 스냅샷과 같고(공개 스냅샷은 6. `T54` 뒤의 공개 기준선은 예시 셋의 이력 6행을 더해 12), 앱 DB의 담당자가 있는 담당 행이 0이다. 다르면 멈춘다.
- **1단계**: `SVC=dashboard-app`, `IMG=zeek-ad-dashboard-app`, `FILES="compose.portfolio.yml docker/portfolio/nginx/zeekad-portfolio-http.conf.template docker/portfolio/seed/seed_demo.py docker/portfolio/sandbox/sandbox-setup.sh docker/portfolio/sandbox/sandbox-reset.sh"`(새 폴더는 먼저 만든다).
- **2단계**: `up -d --wait --no-deps dashboard-app nginx-waf sandbox-reset` → `sandbox-setup`(기준선 = 지금 공개 DB) → `demo-seed` 두 번 → `sandbox-reset … --once`(바뀐 행 0).
- **롤백**: 파일을 `*.pre-t33`으로 되돌리고 `zeek-ad-dashboard-app:pre-t33`을 `:local`로 다시 태그한 뒤 `stop sandbox-reset`, 옛 시드로 `demo-seed`를 다시 돌려 `trial-analyst`를 비활성으로 만들고 `dashboard-app nginx-waf`를 `up`한다.

#### 조회 한도·HSTS·초기화 서비스 볼륨을 바꾸는 갱신(`T36`)

`T36`은 파일 둘(`compose.portfolio.yml`, `docker/portfolio/nginx/zeekad-portfolio-http.conf.template`)만 바꾼다. 이미지·`.env`·DB는 그대로다. `nginx-waf`와 `sandbox-reset`이 다시 만들어진다.

- **1단계**: 두 파일을 `images/t36-files/`에 sha256 목록과 함께 올려 대조하고 `*.pre-t36`으로 보존한 뒤 바꾼다. `config --quiet` 뒤 새 값(`ZEEKAD_READ_RATE`·`ZEEKAD_READ_BURST`, `sandbox-*`의 데이터 경로 tmpfs)만 `grep`으로 본다(설정 전체는 비밀값이 들어 있어 출력하지 않는다). 지금 `sandbox-reset`에 붙은 익명 볼륨 이름을 기록한다.
- **2단계**: `up -d --wait --no-deps nginx-waf`, 이어서 `up -d --no-deps --renew-anon-volumes sandbox-reset`. `--renew-anon-volumes`가 없으면 compose가 옛 컨테이너의 익명 볼륨을 새 컨테이너에 이어 붙이려 할 수 있다. 다른 컨테이너 비교에서 `-nginx-waf-`·`-sandbox-reset-` 두 줄을 빼고 두 이미지 ID가 그대로인지 본다. 새 `sandbox-reset`에 볼륨이 없고 실행 중인지 본다.
- **옛 익명 볼륨 지우기**: 기록한 볼륨이 매달렸고(`dangling`) 어느 컨테이너도 쓰지 않고 비었을 때만 그 이름 하나를 `docker volume rm`으로 지운다. 비었는지는 그 볼륨을 읽기 전용으로 붙인 일회용 컨테이너(`--network none --read-only --cap-drop ALL`, 같은 `pgvector` 이미지)에서 `find /v -mindepth 1 | wc -l`로 센다. 0이 아니면 지우지 않고 멈춘다. 뒤 상태는 볼륨 목록이 1단계에서 기록한 목록에서 지운 익명 볼륨 하나만 빠진 것이고(이 프로젝트 것은 `zeekad-portfolio_pgdata` 하나, 다른 볼륨은 앞에서 기록한 목록과 같다) `dangling` 0이다.
- **롤백**: 두 파일을 `*.pre-t36`으로 되돌리고 `nginx-waf`·`sandbox-reset`을 `up`한다. 옛 compose의 `sandbox-reset`은 새 익명 볼륨을 다시 만든다. 지운 옛 볼륨은 비어 있었으므로 되돌리지 않는다.
- 반영 뒤 4.4를 하고 다음 정각의 `sandbox-reset` 로그(3.5)를 본다.

#### 감사 로그 보관 기한·컨테이너 로그 한도를 넣는 갱신(`T58`)

`T58`은 앱 이미지 하나와 파일 셋(`compose.portfolio.yml`, `docker/portfolio/sandbox/sandbox-setup.sh`, `docker/portfolio/sandbox/sandbox-reset.sh`)을 바꾼다. `.env`와 스냅샷은 그대로다. NAS 반영은 통합 작업 `T57`이 한다. 아래는 그때 지킬 순서와 확인할 것이고 실제 명령과 값은 `T57`이 반영한 뒤 여기에 적는다.

- **순서가 있다**: ① 앱 이미지를 바꿔 `dashboard-app`을 다시 만든다(Flyway가 `V4`를 적용한다. `flyway_schema_history`에 버전 4가 성공으로 있는지 본다) → ② `sandbox-setup`을 다시 돌린다(초기화 계정에 삭제 함수의 `EXECUTE`를 준다. `RESULT: OK`와 `purge_public_execute=false`) → ③ compose 값(기한 90일, 로그 한도)이 걸리게 서비스를 다시 만든다. ①보다 ②를 먼저 하면 `sandbox-setup`이 `function public.purge_expired_audit_logs(integer) is missing`으로 멈춘다(아무것도 바꾸지 않는다).
- **`T61`과 한 번에 반영할 때**: 위 ①→②→③ 대신 아래 `T61` 절의 처음 전환 순서를 따른다(그 순서의 `up`이 ①과 ③을 한 번에 하고 이어서 ②를 한다. `dashboard-app` 하나만 `--no-deps`로 먼저 다시 만들지 않는다).
- **틈의 로그**: 새 `sandbox-reset.sh`가 ②보다 먼저 돌면 감사 칸이 `audit[NOT_CONFIGURED]`다. 줄 전체는 `ERROR`가 되지 않고 다음 정각에 다시 부른다.
- **로그 한도는 모든 서비스를 다시 만들어야 걸린다**: 로그 설정은 컨테이너를 만들 때 정해진다. `up -d`가 설정이 바뀐 서비스(전부)를 다시 만들므로 `postgres`도 잠깐 내려간다(DB 볼륨은 그대로다). 다시 만든 컨테이너의 옛 로그는 사라진다.
- **`T57`이 반영 전에 기록할 것**(이 문서를 쓸 때 NAS Container Manager의 기본 로그 드라이버는 확인하지 않았다): `docker info --format '{{.LoggingDriver}}'`와 컨테이너 하나의 `docker inspect --format '{{.HostConfig.LogConfig}}' zeekad-portfolio-nginx-waf-1`. 기본 드라이버가 `json-file`이 아니었다면 `json-file`로 바뀐 뒤 DSM Container Manager 화면의 로그 탭이 비는지 확인해 적는다(`docker logs`와 `docker compose logs`는 `json-file`에서 그대로 읽힌다).
- **반영 뒤 확인**: `sandbox-reset … --once`의 줄 끝이 `audit[OK] purged=<수> cutoff=<UTC>`다. 처음에는 90일 넘은 행이 한꺼번에 지워진다(지운 수를 기록한다). 서비스마다 `docker inspect --format '{{json .HostConfig.LogConfig}}'`가 `json-file`·`10m`·`5`다. 이어서 4.4를 한다.
- **되돌리기용 백업**: `backup/app-pre-*.dump` 가운데 90일 넘은 것을 지운다(3.9의 3a와 같은 명령). 처음 지우는 것은 `T57`의 NAS 단계다.
- **롤백**: 파일 셋을 `*.pre-t58`로 되돌리고 앞 앱 이미지를 `:local`로 다시 태그한 뒤 서비스를 `up`한다. 옛 `sandbox-reset.sh`는 삭제 함수를 부르지 않으므로 그 뒤로는 아무것도 지워지지 않는다. 앱 DB의 `V4`(좁힌 트리거, `TRUNCATE` 차단, 삭제 함수)를 그대로 둔 채 앞 앱 이미지가 뜨는지는 `T57`이 리허설에서 확인한다. 이미 지워진 감사 행은 되돌리지 않는다.

#### 대응 조치 기록을 넣는 갱신(`T56`)

`T56`은 앱 이미지 하나와 파일 셋(`docker/portfolio/sandbox/sandbox-setup.sh`, `docker/portfolio/sandbox/sandbox-reset.sh`, `docker/portfolio/nginx/zeekad-portfolio-http.conf.template`)을 바꾼다. `compose.portfolio.yml`, `.env`, 스냅샷은 그대로다. NAS 반영은 통합 작업 `T57`이 한다. 아래는 그때 지킬 순서와 확인할 것이다.

- **순서가 있다**: ① 앱 이미지를 바꿔 `dashboard-app`을 다시 만든다(Flyway가 `V5`를 적용한다. `flyway_schema_history`에 버전 5가 성공으로 있는지 본다) → ② `sandbox-setup`을 다시 돌린다(대응 조치 기준선 표식과 초기화 함수를 만든다. `response action baseline created: max_id=<수>`와 `RESULT: OK`) → ③ nginx 템플릿이 걸리게 `nginx-waf`를 다시 만든다(새 쓰기 경로의 속도 제한). ①보다 ②를 먼저 하면 `sandbox-setup`이 `table public.incident_response_actions is missing`으로 멈춘다(아무것도 바꾸지 않는다).
- **`T61`과 한 번에 반영할 때**: 위 ①→②→③ 대신 아래 `T61` 절의 처음 전환 순서를 따른다(그 순서의 `up`이 ①과 ③을 한 번에 하고 이어서 ②를 한다. `dashboard-app` 하나만 `--no-deps`로 먼저 다시 만들지 않는다).
- **틈의 로그**: 새 `sandbox-reset.sh`가 ②보다 먼저 돌면 그 줄의 대응 조치 칸이 `responses[NOT_CONFIGURED]`다. 줄 전체는 `ERROR`가 되지 않는다. ② 뒤의 첫 정각부터 `responses[OK] removed=<수>`다.
- **①과 ② 사이에 방문자가 대응 조치를 기록했을 때**: `sandbox-setup`이 `REFUSED: <수> response action rows recorded by 'trial-analyst' exist`로 멈춘다(그 글을 기준선으로 굳히지 않는다). 아래처럼 그 행을 지우고 다시 돌린다. 표의 트리거가 `DELETE`를 막으므로 트랜잭션 안에서만 표식을 켠다. 감사 로그의 기록은 남는다.

```bash
docker compose -p zeekad-portfolio -f compose.portfolio.yml exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d zeekad_dashboard \
  -c "BEGIN; SET LOCAL dashboard.response_actions_reset = 'on'; DELETE FROM public.incident_response_actions WHERE actor_username = 'trial-analyst'; COMMIT;"
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env --profile seed run --rm sandbox-setup
```

- **반영 뒤 확인**: `sandbox-reset … --once`의 줄에 `responses[OK] removed=0`이 있다. 공개 주소에서는 읽기만 한다(4.4, 공개 확인 `[T54a]`·`[T56a]`). 기록·초기화 흐름은 리허설 `[T56b]`·`[T56c]`가 본다. 같은 주소에서 로그인하지 않은 기록 요청을 잇달아 보내면 `429`가 나오는지 본다(앱이 거부하는 요청이라 기록이 생기지 않는다, 공개 확인 `[T56a]`).
- **롤백**: 파일 셋을 `*.pre-t56`로 되돌리고 앞 앱 이미지를 `:local`로 다시 태그한 뒤 서비스를 `up`한다. 옛 `sandbox-reset.sh`는 대응 조치 초기화 함수를 부르지 않는다. 앱 DB의 `V5`(표와 트리거), 기준선 표식, 초기화 함수는 그대로 남는다. `V5`를 둔 채 앞 앱 이미지가 뜨는지는 `T57`이 리허설에서 확인한다.

#### WAF 감사 로그의 부분을 줄이는 갱신(`T59`)

`T59`는 WAF 이미지 하나를 바꾼다(감사 로그의 부분 `AHZ`, 1.1). 값이 이미지에 있으므로 WAF 이미지를 다시 만들어 바꿔야 걸린다. `compose.portfolio.yml`은 주석 한 줄만 달라졌고 서비스 설정은 같다. NAS 반영은 통합 작업 `T57`이 한다.

- **절차**: 위 "서비스 하나의 이미지 갱신"을 `SVC=nginx-waf`, `IMG=zeek-ad-dashboard-waf`로 한다. 새 절차는 없다.
- **반영 뒤 확인**: 렌더된 설정의 값과 새 감사 줄을 본다.
  ```sh
  C="docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env"
  $C exec -T nginx-waf grep -n '^SecAuditLogParts' /etc/modsecurity.d/modsecurity.conf < /dev/null   # SecAuditLogParts AHZ
  $C logs --no-log-prefix --since 5m nginx-waf < /dev/null | grep -c '"headers":{'                    # 0
  ```
  이어서 4.4를 한다.
- **롤백**: 옛 WAF 이미지(`zeek-ad-dashboard-waf:pre-<작업 ID>`)로 되돌리면 요청 헤더와 응답 헤더 기록이 다시 켜진다. 세션 쿠키·CSRF 토큰·`Set-Cookie` 값이 컨테이너 로그에 다시 남으므로 되돌린 채 두지 않는다.
- **이미 쌓인 로그**(`T57`이 NAS에서 확인한 뒤 확정할 문장): 반영 전의 `nginx-waf` 컨테이너 로그에는 옛 감사 줄(쿠키 값 포함)이 들어 있다. 로그 드라이버가 `json-file`이면 서비스를 다시 만들 때 옛 컨테이너의 로그가 함께 사라진다. NAS의 드라이버는 이 문서를 쓸 때 확인하지 않았다. `docker inspect --format '{{.HostConfig.LogConfig.Type}}' zeekad-portfolio-nginx-waf-1`로 확인한다. `json-file`이 아니면 옛 로그가 남는 곳과 지우는 방법을 여기에 적는다. 옛 줄에 남은 세션 쿠키 값은 그 세션이 끝나면(유휴 30분, 절대 8시간) 쓸 수 없다.

#### 네트워크를 나누고 capability를 빼는 갱신(`T61`)

`T61`은 `compose.portfolio.yml`(네트워크 둘, 모든 서비스의 `cap_drop`·`no-new-privileges`, `postgres`의 `user: postgres`, 상태 확인의 `Host`)과 WAF 이미지(`HEALTHCHECK`의 `Host` 한 줄)를 바꾼다. 공개 스택에서는 compose의 상태 확인이 이미지의 `HEALTHCHECK`를 덮으므로 WAF 이미지는 다른 작업(`T59`)의 WAF 이미지와 함께 옮기면 된다. `.env`는 바꾸지 않는다(`PORTFOLIO_DATA_SUBNET`이 없으면 기본값 `10.203.47.0/24`를 쓴다. 겹치면 3.1처럼 넣는다). 새 네트워크 `zeekad-portfolio_portfolio-data`가 생기고 상주 다섯이 모두 다시 만들어진다(`postgres`도 잠깐 내려간다. DB 볼륨은 그대로다). `portfolio-net`은 정의가 같아 있는 것을 그대로 쓴다. NAS 반영은 통합 작업 `T57`이 한다. 아래 순서와 확인은 로컬 PC의 갱신 리허설(지금 NAS에 떠 있는 구성 → 이 구성, 같은 DB 볼륨, `down` 없이)로 맞춰 본다(결과는 [보안 검증 보고서](security-verification-report.md)의 검증 표). 로컬 Docker와 NAS는 Compose 판이 달라서 옛 Compose의 동작과 NAS의 Docker가 내부 전용 네트워크를 받는지는 아래 사전 확인으로 본다.

로컬 PC에서 먼저 서비스 하나 절차의 PowerShell 블록으로 올린다(`$ID = 't61'`, `$SVC = 'nginx-waf'`, `$IMG = 'zeek-ad-dashboard-waf'`, `$files = @('compose.portfolio.yml')`. WAF 이미지를 이번에 옮기지 않으면 이미지 `tar` 부분은 건너뛴다).

**반영 전 확인**(NAS 셸):

```sh
export PATH=$PATH:/usr/local/bin
cd "$DEPLOY_DIR" || exit 1
C="docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env"
mkdir -p ~/zeekad-portfolio-check && K=~/zeekad-portfolio-check
# 1) NAS의 Docker가 내부 전용 네트워크를 받는지와 그 서브넷이 비었는지: 같은 서브넷(PORTFOLIO_DATA_SUBNET을 바꿨으면 그 값)으로 만들었다 바로 지운다.
#    실패 메시지에 overlaps가 있으면 서브넷 겹침(3.1), 그 밖이면 내부 전용 네트워크 문제(아래 "internal이 문제를 일으킬 때")다
docker network create --internal --subnet 10.203.47.0/24 zeekad-t61-precheck && docker network rm zeekad-t61-precheck
# 2) 새 compose의 문법: 올린 파일(1단계의 images/t61-files/)을 배포 폴더 기준으로 교체 전에 본다
docker compose --project-directory "$DEPLOY_DIR" -p zeekad-portfolio -f images/t61-files/compose.portfolio.yml --env-file .env config --quiet < /dev/null && echo "config OK"
# 3) 전 상태 기록: portfolio-net의 ID·만든 시각·게이트웨이, WAF 주소, DB 볼륨, 행 수(개수만), 다른 프로젝트의 컨테이너
docker network inspect -f '{{.Id}} {{.Created}} {{range .IPAM.Config}}{{.Gateway}}{{end}}' zeekad-portfolio_portfolio-net | tee $K/t61-net-before.txt
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' zeekad-portfolio-nginx-waf-1 | tee $K/t61-waf-ip-before.txt
docker volume inspect -f '{{.Name}} {{.CreatedAt}}' zeekad-portfolio_pgdata | tee $K/t61-volume-before.txt
{ $C exec -T postgres psql -U postgres -d zeekad_dashboard -Atc "SELECT count(*) FROM users" < /dev/null
  $C exec -T postgres psql -U postgres -d zeekad -Atc "SELECT count(*) FROM dashboard.latest_incident_queue" < /dev/null; } | tee $K/t61-rows-before.txt
docker ps -a --format '{{.Names}}' | grep -v zeekad-portfolio | sort > $K/t61-others-before.txt
```

**1단계**: 위 "서비스 하나의 이미지 갱신" 1단계를 `ID=t61`, `SVC=nginx-waf`, `IMG=zeek-ad-dashboard-waf`, `FILES="compose.portfolio.yml"`로 한다(WAF 이미지를 이번에 옮기지 않으면 3)의 적재와 대조를 건너뛰고 2)의 보존 태그와 4)의 파일 교체만 한다). 1단계의 4)가 교체 뒤 `config --quiet`를 한 번 더 본다.

**2단계(처음 전환, `down` 없이)**: 서비스 하나 절차의 2단계(`--no-deps $SVC`) 대신 아래 순서로 한다: `stop sandbox-reset` → `up -d --wait postgres api dashboard-app nginx-waf` → `sandbox-setup` → `up -d --wait sandbox-reset` → `sandbox-reset --once`.

```sh
set -u
export PATH=$PATH:/usr/local/bin
cd "$DEPLOY_DIR" || exit 1
C="docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env"
# 5) 초기화 서비스를 먼저 멈춘다(전환 중에 돌지 않게)
$C stop sandbox-reset < /dev/null || exit 10
# 6) 상주 넷을 새 구성으로: portfolio-data가 생기고 네 서비스가 다시 만들어진다(portfolio-net은 있는 것을 그대로 쓴다)
$C up -d --wait postgres api dashboard-app nginx-waf < /dev/null || exit 11
# 7) 초기화 설정(멱등): RESULT: OK. T58·T56과 함께 반영하면 여기서 새 함수의 실행 권한과 대응 조치 표식을 만든다
$C --profile seed run --rm sandbox-setup < /dev/null || exit 12
# 8) 초기화 서비스를 새 구성으로 올리고 한 번 돌린다: 줄에 ERROR가 없어야 한다
$C up -d --wait sandbox-reset < /dev/null || exit 13
$C exec -T sandbox-reset bash /sandbox/sandbox-reset.sh --once < /dev/null || exit 14
```

- **하지 않을 것**: 새 compose로 서비스 하나만 `--no-deps`로 먼저 올리지 않는다(예: `up -d --no-deps dashboard-app`). 그러면 `portfolio-data`는 생기지만 옛 `postgres`가 그 네트워크에 없어 새 구성으로 뜬 `sandbox-*`와 `api`가 `postgres` 이름을 찾지 못한다. `T58`·`T56` 절의 "① 앱 → ② `sandbox-setup` → ③ 다시 만들기"는 이 작업과 한 번에 반영할 때 이 순서로 바뀐다(두 절에 적었다). 전환이 끝난 뒤의 갱신은 지금처럼 서비스 하나 절차를 쓴다.

**확인**(갱신 리허설과 같은 단언. 이어서 4.4의 공개 주소 로그인을 한다):

```sh
cd "$DEPLOY_DIR" || exit 1
C="docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env"; K=~/zeekad-portfolio-check
# 9) 다섯 컨테이너: postgres·api·dashboard-app·nginx-waf healthy, sandbox-reset 실행 중. 이 프로젝트의 다른(고아) 컨테이너는 없다
docker ps -a --filter label=com.docker.compose.project=zeekad-portfolio --format '{{.Names}} {{.Status}}'
# 10) DB 볼륨·행 수·portfolio-net(ID·만든 시각·게이트웨이)·WAF 주소가 반영 전과 같다. portfolio-net의 ID가 같으면 다시 만들어지지 않은 것이다
docker volume inspect -f '{{.Name}} {{.CreatedAt}}' zeekad-portfolio_pgdata | diff $K/t61-volume-before.txt - && echo "volume same"
{ $C exec -T postgres psql -U postgres -d zeekad_dashboard -Atc "SELECT count(*) FROM users" < /dev/null
  $C exec -T postgres psql -U postgres -d zeekad -Atc "SELECT count(*) FROM dashboard.latest_incident_queue" < /dev/null; } | diff $K/t61-rows-before.txt - && echo "rows same"
docker network inspect -f '{{.Id}} {{.Created}} {{range .IPAM.Config}}{{.Gateway}}{{end}}' zeekad-portfolio_portfolio-net | diff $K/t61-net-before.txt - && echo "portfolio-net same"
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' zeekad-portfolio-nginx-waf-1 | diff $K/t61-waf-ip-before.txt - && echo "WAF address same"
# 11) 네트워크 둘과 붙은 컨테이너(3.6과 같다), 내부 전용 네트워크에만 붙은 컨테이너의 기본 경로(앞 셋 0, dashboard-app 1)
docker network inspect -f '{{.Name}} internal={{.Internal}} {{range .Containers}}{{.Name}} {{end}}' zeekad-portfolio_portfolio-net zeekad-portfolio_portfolio-data
for s in postgres api sandbox-reset dashboard-app; do printf '%s default routes: ' $s; $C exec -T $s cat /proc/net/route < /dev/null | awk '$2=="00000000"' | wc -l; done
# 12) nginx-waf에서 DB·근거 API에 TCP 연결이 되지 않고(no connection) 앱에는 된다(open). 연결만 보고 데이터는 보내지 않는다
for t in "api 8000" "postgres 5432" "dashboard-app 8080"; do printf '%s: ' "$t"; $C exec -T nginx-waf timeout 5 nc -z -w 3 $t < /dev/null && echo open || echo "no connection"; done
# 13) api에서 nginx-waf에 닿지 않고(error) 앱에는 닿는다(connected)
$C exec -T api python -c 'import socket
for h in ("nginx-waf", "dashboard-app"):
    try:
        socket.create_connection((h, 8080), timeout=3).close(); print(h, "connected")
    except Exception as e:
        print(h, "error", type(e).__name__)' < /dev/null
# 14) 권한: 상주 다섯 PID 1의 CapBnd 0000000000000000, NoNewPrivs 1. postgres는 root로 시작하지 않는다(Config.User postgres)
for s in postgres api dashboard-app nginx-waf sandbox-reset; do printf '%s ' $s; $C exec -T $s grep -E '^(CapBnd|NoNewPrivs)' /proc/1/status < /dev/null | tr '\n' ' '; echo; done
docker inspect -f '{{.Config.User}}' zeekad-portfolio-postgres-1
# 15) 앱 -> 근거 API("status":"ok"), DSM 흉내 요청의 로그인 화면(200)
$C exec -T dashboard-app wget -qO- http://api:8000/health < /dev/null; echo
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: soc.<DDNS 이름>.synology.me' -H 'X-Forwarded-Proto: https' http://127.0.0.1:18480/login
# 16) 다른 프로젝트의 컨테이너가 반영 전과 같다
docker ps -a --format '{{.Names}}' | grep -v zeekad-portfolio | sort | diff $K/t61-others-before.txt - && echo "other containers same"
```

- 1분쯤 뒤 상태 확인의 감사 줄이 없는지 본다: `$C logs --no-log-prefix --since 2m nginx-waf < /dev/null | grep -c '"uri":"/healthz'`가 `0`이다(방문자가 숫자 주소 `Host`로 `/healthz`를 부르면 그 줄은 남는다). 방문자 줄은 출력하지 않고 개수만 본다.
- 시드(`demo-seed`)는 다시 돌리지 않아도 된다(계정은 DB 볼륨에 있다).

**되돌리기**(옛 compose와 옛 WAF 이미지로):

```sh
set -u
export PATH=$PATH:/usr/local/bin
cd "$DEPLOY_DIR" || exit 1
C="docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env"
cp -p compose.portfolio.yml.pre-t61 compose.portfolio.yml || exit 20
docker tag zeek-ad-dashboard-waf:pre-t61 zeek-ad-dashboard-waf:local || exit 21   # WAF 이미지를 옮기지 않았으면 건너뛴다
$C up -d --wait < /dev/null || exit 22
# 옛 compose에는 없는 네트워크라 남는다. 붙은 컨테이너가 없어야 지워진다
docker network rm zeekad-portfolio_portfolio-data || exit 23
```

- 위 9)·10)으로 healthy와 행 수가 반영 전과 같은지 본다. 함께 바꾼 앱 이미지가 있으면 그 갱신 절의 롤백을 따른다. 앱 DB에 적용된 새 migration은 되돌리지 않는다(옛 앱 이미지가 그 DB에서 뜨는지는 리허설에서 본다).

**`internal`이 NAS에서 문제를 일으킬 때**:

- 사전 확인 1)이 서브넷 겹침이 아닌 까닭으로 실패하면(NAS의 Docker가 내부 전용 네트워크를 받지 않는다) 처음부터 `portfolio-data`의 `internal: true` 줄을 뺀 파일로 반영한다. 그러면 `postgres`·`api`·초기화 도구에 바깥 길(기본 경로)이 남는다. `nginx-waf`와 DB·근거 API를 갈라 놓는 효과는 그대로다. 뺀 것과 그 까닭을 운영 기록에 적는다.
- 이미 만든 뒤라면 compose에서 그 줄만 빼고 `up`해도 듣지 않는다(NAS의 옛 Compose는 있는 네트워크를 정의와 견주지 않고 그대로 쓴다. 새 Compose는 정의가 다르면 다시 만들자고 멈춘다. 어느 쪽이든 붙은 컨테이너가 있으면 바꿀 수 없다. 서브넷을 바꿀 때도 같다). 그 네트워크에 붙은 서비스를 멈추고 네트워크를 지운 뒤 다시 올린다: `$C stop sandbox-reset dashboard-app api postgres` → `docker network rm zeekad-portfolio_portfolio-data` → `$C up -d --wait --force-recreate postgres api dashboard-app sandbox-reset`. 그동안 `nginx-waf`는 `502`를 낸다. 이 경로는 로컬에서 돌려 보지 않았다.

#### 분석이 끝난 예시 셋을 넣는 갱신(`T54`)

`T54`는 파일 셋(`docker/portfolio/seed/seed_demo.py`, 새 파일 `docker/portfolio/seed/demo_examples.json`, `compose.portfolio.yml`의 `demo-seed` 환경 값 한 줄)을 바꾼다. 앱 이미지·WAF 이미지·`.env`·스냅샷은 그대로다. 새로 만드는 스택(3.5, 3.9)은 시드 → `sandbox-setup` 순서라 따로 할 일이 없다. 아래는 **기준선이 이미 있는 스택(지금 NAS)** 에 넣는 순서다. NAS 반영은 통합 작업 `T57`이 한다.

- **앞 조건**: `T56`(앱 `V5`와 대응 조치 API)이 NAS에 반영된 뒤다(정탐 종결에 조치 기록이 필요하다). **예시 글(`demo_examples.json`)의 사용자 확인이 끝난 뒤다**(기준선에 들어가면 고칠 수 없다, 아래).
- **순서**: 공개 경로를 잠시 닫아 방문자가 끼어들지 못하게 한 채, 방문자 흔적을 지우고 예시를 기록한 뒤 기준선을 다시 만든다.
  ```sh
  export PATH=$PATH:/usr/local/bin
  cd "$DEPLOY_DIR" || exit 1
  C="docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env"
  $C stop nginx-waf < /dev/null                                              # 공개 경로를 닫는다(4.4의 공개 주소는 이 동안 502)
  $C exec -T sandbox-reset bash /sandbox/sandbox-reset.sh --once < /dev/null   # 방문자 흔적을 지운다(OK 줄)
  $C stop sandbox-reset < /dev/null
  $C --profile seed run --rm demo-seed < /dev/null                           # examples: applied=3 kept=0 skipped=0, RESULT: CHANGED
  $C --profile seed run --rm demo-seed < /dev/null                           # examples: applied=0 kept=3 skipped=0, RESULT: NO_CHANGES
  $C --profile seed run --rm sandbox-setup --rebuild-baseline < /dev/null    # baseline rebuilt, response action baseline rebuilt, RESULT: OK
  $C up -d --wait sandbox-reset nginx-waf < /dev/null
  ```
  파일 교체(`seed_demo.py`·`demo_examples.json`·`compose.portfolio.yml`을 `*.pre-t54`로 보존한 뒤 바꾸고 `config -q`)는 이 순서 앞에 한다(3.8의 "서비스 하나의 이미지 갱신" 4단계와 같은 방식. 다시 만들 서비스는 없다).
- **확인**: 시드 로그가 `skipped=0`이고 `applied + kept = 3`이다(ID 오타나 스냅샷 착오를 드러낸다). `sandbox-setup` 로그의 기준선 행 수가 앞보다 상태 3·이력 6 많다. 다음 정각 뒤 `logs sandbox-reset`의 줄이 `OK`이고, `demo`로 `/incidents?status=closed&period=all`에 예시 셋이 보인다(4.4).
- **다시 해야 할 때**(시드가 실패했거나 `--rebuild-baseline`이 `REFUSED`일 때): 시드의 실패 이유(예시별 한 줄)를 먼저 본다. `--once`는 **옛 기준선**으로 되돌리므로 시드가 넣은 예시도 지운다(상태·이력, 옛 표식보다 뒤의 조치 기록). 그래서 "다시"는 `--once`(서비스가 멈춰 있으면 `$C run --rm sandbox-reset --once`) → 시드 → `--rebuild-baseline` 전체다. "종결인데 담당자가 남음"으로 실패하면 API로 풀 수 없다(아래 볼륨 재생성).
- **`T61`(네트워크 분리)과 한 번에 반영할 때**: 위 `T61` 절의 2단계 순서에서 `sandbox-setup` 앞에 시드(두 번)를 넣고 `sandbox-setup`에 `--rebuild-baseline`을 준다(기준선이 이미 있다). 공개 경로를 닫은 채 하려면 이렇게 잇는다: `stop nginx-waf` → `exec … sandbox-reset.sh --once`(옛 구성에서 방문자 흔적 지우기) → `stop sandbox-reset` → `up -d --wait postgres api dashboard-app`(`nginx-waf`는 아직) → 시드 두 번 → `sandbox-setup --rebuild-baseline` → `up -d --wait sandbox-reset nginx-waf` → `sandbox-reset --once`. 새 구성에서 시드(`demo-seed`)는 `portfolio-data`에 붙고 두 네트워크에 붙은 `dashboard-app`에 닿는다.
- **기준선에 들어간 뒤에는 시드로 글을 고칠 수 없다**: 시드는 이미 종결된 예시를 그대로 둔다. 다시 열기(`T53`)로 열고 다시 종결해도 앞선 종결의 사유·판정과 대응 조치 기록은 이력에 남는다(지우지 않는다). 글을 바꾸려면 3.9의 볼륨 재생성뿐이고, 그때 앱 DB(감사 로그·인시던트 번호)도 새로 만들어진다(번호는 같은 스냅샷이면 같게 다시 매겨진다).
- **롤백**: 파일 셋을 `*.pre-t54`로 되돌려도 기준선에 들어간 예시는 남는다(옛 시드는 예시를 읽지 않고 `demo-analyst`를 다른 비공개 계정처럼 비활성으로 둔다). 예시를 빼려면 3.9의 볼륨 재생성이다.

#### 종결 건 다시 열기를 넣는 갱신(`T53`)

`T53`은 앱 이미지 하나와 파일 넷(`docker/portfolio/nginx/zeekad-portfolio-http.conf.template`, `docker/portfolio/initdb/03-zeekad-functions.sh`, `docker/portfolio/initdb/zeekad-sql/018_incident_reopen.sql`, 같은 폴더의 `SOURCE.md`)을 바꾸고 `zeekad` DB에 함수 하나(`dashboard.reopen_incident`, zeek_AD migration 018)를 더한다. `compose.portfolio.yml`, `.env`, 스냅샷, `sandbox-setup.sh`·`sandbox-reset.sh`는 그대로다. NAS 반영은 통합 작업 `T57`이 한다. 아래는 그때의 순서와 확인이다.

- **이미 볼륨이 있는 스택은 initdb가 돌지 않는다.** 셋째 스크립트(`03-zeekad-functions.sh`)는 볼륨을 새로 만들 때만 돈다(3.9). 지금 NAS의 DB에는 사본을 한 번 손으로 실행한다(아래). zeek_AD가 "스냅샷 복원 DB에는 이 파일 하나만 실행하면 된다(다시 실행해도 결과가 같다)"고 적었다. `CREATE OR REPLACE`·`ALTER … OWNER`·`REVOKE`·`GRANT`라 두 번 실행해도 같다.
- **순서는 상관없다.** 앱 이미지를 먼저 바꾸면 함수를 넣기 전까지 다시 열기 요청이 `501`(`REOPEN_UNAVAILABLE`, "이 환경의 탐지 DB에는 다시 열기 기능이 아직 없습니다.")일 뿐이고 다른 기능은 그대로다. 함수를 먼저 넣어도 옛 앱은 부르지 않는다. 초기화(`reset_pipeline()`)는 상태·이력 표를 기준선과 맞추므로 다시 연 건도 되돌리고, 기준선 표지는 함수를 보지 않아 `sandbox-setup`을 다시 돌릴 필요가 없다.
- **파일 옮기기**: 서비스 하나 절차의 PowerShell 블록으로 올린다(`$ID = 't53'`, `$SVC = 'dashboard-app'`, `$IMG = 'zeek-ad-dashboard-app'`, `$files = @('docker/portfolio/nginx/zeekad-portfolio-http.conf.template', 'docker/portfolio/initdb/03-zeekad-functions.sh', 'docker/portfolio/initdb/zeekad-sql/018_incident_reopen.sql', 'docker/portfolio/initdb/zeekad-sql/SOURCE.md')`). 4)의 교체에서 `zeekad-sql/` 폴더가 없으면 먼저 만든다(`mkdir -p docker/portfolio/initdb/zeekad-sql`). 교체 뒤 3.2 끝의 확인(sha256이 `SOURCE.md`와 같고 `\r` 0개)을 한다. 이어서 같은 절차의 5)로 `dashboard-app`을, 템플릿이 걸리게 `nginx-waf`를 다시 만든다(`$C up -d --wait --no-deps nginx-waf`).

**함수 넣기**(NAS 셸. `postgres` 컨테이너 안에서 슈퍼유저로. 사본은 initdb 폴더 마운트로 컨테이너 안 `/docker-entrypoint-initdb.d/zeekad-sql/`에 보인다):

```sh
set -u
export PATH=$PATH:/usr/local/bin
cd "$DEPLOY_DIR" || exit 1
C="docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env"
Q="$C exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d zeekad -At"
# 1) 지금 있는지(0이면 넣는다. 1 이상이면 새 스냅샷에 이미 있으므로 넣지 않고 아래 3)만 본다)
$Q -c "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'dashboard' AND p.proname = 'reopen_incident'" < /dev/null
# 2) 컨테이너 안 사본의 sha256이 SOURCE.md의 값과 같은지 보고 한 트랜잭션으로 실행한다
$C exec -T postgres sha256sum /docker-entrypoint-initdb.d/zeekad-sql/018_incident_reopen.sql < /dev/null
$C exec -T postgres psql -v ON_ERROR_STOP=1 --single-transaction -U postgres -d zeekad -f /docker-entrypoint-initdb.d/zeekad-sql/018_incident_reopen.sql < /dev/null || exit 2
# 3) 확인: 하나, 소유 zeekad_owner, SECURITY DEFINER, 실행 권한은 dashboard_rw뿐(PUBLIC·초기화 계정 불가)
$Q -c "SELECT p.oid::regprocedure || ' owner=' || pg_get_userbyid(p.proowner) || ' secdef=' || p.prosecdef || ' acl=' || p.proacl::text || ' reset_exec=' || has_function_privilege('zeekad_sandbox_reset', p.oid, 'EXECUTE') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'dashboard' AND p.proname = 'reopen_incident'" < /dev/null
#    -> dashboard.reopen_incident(bigint,text,text,text,text) owner=zeekad_owner secdef=true acl={zeekad_owner=X/zeekad_owner,dashboard_rw=X/zeekad_owner} reset_exec=false
# 4) dashboard_rw가 실행할 수 있는 함수(권한 목록에 명시된 것)가 정확히 셋
$Q -c "SELECT n.nspname || '.' || p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE a.grantee = 'dashboard_rw'::regrole AND a.privilege_type = 'EXECUTE' ORDER BY 1" < /dev/null
#    -> dashboard.decide_review / dashboard.reopen_incident / dashboard.transition_incident
# 5) 초기화 계정으로는 부를 수 없다(permission denied). 비밀번호는 컨테이너 환경에서 읽고 출력하지 않는다
$C exec -T sandbox-reset sh -c 'PGPASSWORD="$SANDBOX_RESET_DB_PASSWORD" psql -h postgres -U zeekad_sandbox_reset -d zeekad -c "SELECT dashboard.reopen_incident(1, NULL, NULL, NULL, NULL)"' < /dev/null 2>&1 | grep -c 'permission denied'   # 1
```

- 5)의 `sandbox-reset` 컨테이너 환경 변수 이름은 compose의 값(`SANDBOX_RESET_DB_PASSWORD`)과 같은지 반영 때 확인한다. 이 블록은 로컬 리허설에서 같은 SQL로 본다(`T53`의 실제 대상 확인. 결과는 [보안 검증 보고서](security-verification-report.md)).
- **반영 뒤 확인**: `trial-analyst`로 종결 건 하나를 다시 열면 분석 중으로 바뀌고 이력에 "종결 → 분석 중 · 다시 열림"이 보인다. 다음 정각 뒤 그 건이 원래 종결 상태로 돌아왔는지 본다(`[T53d]`와 같다). `demo`에는 다시 열기 폼이 없다. 같은 주소에서 다시 열기 요청을 잇달아 보내면 `429`다. 이어서 4.4를 한다.
- **되돌리기**: 함수만 빼려면 `$Q -c "DROP FUNCTION dashboard.reopen_incident(bigint, text, text, text, text)"`. 그러면 앱의 다시 열기는 `501`로 돌아가고 다른 기능은 그대로다. 이미 다시 연 건의 상태와 이력은 그대로 남는다(다음 정각 초기화가 기준선으로 되돌린다). 앱 이미지와 파일은 서비스 하나 절차의 롤백(`*.pre-t53`)을 따른다. 옛 `03-zeekad-functions.sh`가 없던 상태로 돌아가도 이미 만든 볼륨에는 영향이 없다.

#### 중요 자산을 넣는 갱신(`T52`)

`T52`는 앱 이미지 하나(`V6`: 앱 DB의 `critical_assets` 표, 관리자 API와 화면 `/admin/critical-assets`, 우선순위 규칙)와 시드 파일 둘(`docker/portfolio/seed/seed_demo.py`, 새 파일 `docker/portfolio/seed/critical_assets.json`)을 바꾼다. WAF 이미지·`compose.portfolio.yml`·`.env`·스냅샷은 그대로다. NAS 반영은 통합 작업 `T57`이 한다.

- **순서가 있다**: ① 앱 이미지를 바꿔 `dashboard-app`을 다시 만든다(위 "서비스 하나의 이미지 갱신". Flyway가 `V6`를 적용한다. `flyway_schema_history`에 버전 6이 성공으로 있는지 본다) → ② 시드 파일 둘을 `*.pre-t52`로 보존하고 바꾼다 → ③ 시드를 두 번 돌린다(첫 번째 `critical-assets: created=6 updated=0 deleted=0 kept=0`과 `RESULT: CHANGED`, 두 번째 `kept=6`과 `RESULT: NO_CHANGES`). ①보다 ③을 먼저 하면 시드가 `app database has no critical_assets table`로 멈춘다(아무것도 바꾸지 않는다).
- **공개 경로를 닫지 않아도 된다**: 자산 단계는 앱 DB의 자산 표만 바꾸고 zeek_AD 표·기준선과 상관없다. 기준선(`sandbox-setup --rebuild-baseline`)도 다시 만들지 않는다. `admin`이 몇 초 켜지는 것은 다른 재시드와 같다(5절).
- **`T54`와 한 번에 반영할 때**: 위 `T54` 절의 순서에서 시드 두 번이 자산도 맞춘다(앱 이미지를 그 순서 앞에 바꾼다). 시드 로그에 `examples:` 줄과 `critical-assets:` 줄이 함께 있다.
- **반영 뒤 확인**: 4.4의 `T52` 항목.
- **롤백**: 시드 파일 둘을 `*.pre-t52`로 되돌리고 앞 앱 이미지를 `:local`로 다시 태그한 뒤 `dashboard-app`을 `up`한다. 우선순위는 옛 규칙으로 돌아간다. 앱 DB의 `V6` 표와 자산 행은 남는다(앞 앱 이미지는 그 표를 읽지 않는다. `V6`를 둔 채 앞 앱 이미지가 뜨는 것은 `T52` 확인에서 두 이미지를 같은 DB에 함께 띄워 봤다). 시드 파일을 새것으로 둔 채 앱만 되돌리면, 자산이 파일과 다를 때 시드가 앞 앱 이미지에 없는 자산 API를 부르다 실패한다.

### 3.9 스냅샷(공개 데이터) 교체

스냅샷은 DB 볼륨이 빌 때만 복원된다(`02-restore-snapshot.sh`). 데이터를 바꾸려면 DB 볼륨을 지우고 다시 만든다. **DB 볼륨 하나에 zeek_AD DB(`zeekad`)와 앱 DB(`zeekad_dashboard`: 계정·감사 로그)가 함께 있으므로 둘 다 새로 만들어진다.** `zeekad`는 새 스냅샷으로, 앱 DB는 부트스트랩(첫 기동)과 시드로 다시 채운다. 지난 감사 로그(방문자 로그인 기록)는 새 DB에 없고 아래 3단계의 백업에만 남는다. 이 백업은 되돌리기용이고 그 시점의 감사 로그가 통째로 들어 있으므로 감사 로그와 같은 기한을 둔다: 90일 넘은 백업은 배포 절차가 지운다(아래 3a. 자동이 아니라 다음 배포 때 지우므로 배포가 뜸하면 90일보다 오래 남는다). 체험 계정 변경의 매시 정각 초기화(1.3)는 새 볼륨에서 다시 설정한다(아래 8c).

로컬 PC에서 먼저 한다: 2.2 스냅샷(VM 원본은 `-SshHost <배포 VM>`) → `secret-scan.txt` 확인 → 2.3 리허설(`-SnapshotDir build/portfolio`) 통과 → (실습망 등 처음 공개하는 데이터면) 공개 전 내용 확인. NAS에서는 `zeekad-portfolio` 프로젝트와 배포 폴더(`$DEPLOY_DIR`) 안에서만, sudo 없이, 아래 순서대로 하고 **단계마다 실패하면 멈추고 되돌린다.** `.env`는 읽거나 고치지 않는다(`DEMO_PASSWORD`는 그대로 쓰인다).

**표준 입력 주의(T22에서 확인)**: 아래 블록을 `echo <base64> | base64 -d | bash`나 `ssh ... 'bash -s' < 파일`처럼 **표준 입력으로 bash에 넘기면** `docker compose exec -T`·`run`이 남은 스크립트를 읽어 버린다. 그러면 그 뒤 줄(백업 권한·`down` 등)이 실행되지 않은 채 exit 0으로 끝난다. 블록은 NAS에 파일로 풀어 `bash <파일> < /dev/null`로 실행하고(또는 대화형 셸에 붙여 넣고), compose를 부르는 줄에는 아래처럼 `< /dev/null`을 붙인다.

```sh
export PATH=/usr/local/bin:$PATH
ID=<작업 ID 소문자, 예: t22>
cd "$DEPLOY_DIR" || exit 1
C="docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env"
# 0) 체험 계정 초기화 서비스를 먼저 멈춘다(T33)
$C stop sandbox-reset < /dev/null || exit 1
# 1) 기록: 다른 프로젝트의 컨테이너·네트워크·볼륨, 앱 이미지 ID(3.1·3.6 방식)
mkdir -p ~/zeekad-portfolio-check
docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Ports}}' | grep -v 'zeekad-portfolio' | sort > ~/zeekad-portfolio-check/$ID-containers-before.txt
for n in $(docker network ls -q); do docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' $n; done | grep -v '^zeekad-portfolio' | sort > ~/zeekad-portfolio-check/$ID-networks-before.txt
docker volume ls --format '{{.Name}}' | grep -v '^zeekad-portfolio_' | sort > ~/zeekad-portfolio-check/$ID-volumes-before.txt
docker image inspect --format '{{.Id}}' zeek-ad-dashboard-app:local > ~/zeekad-portfolio-check/$ID-app-image-before.txt
# 2) 보존: 스냅샷 세 파일과 바뀌는 배포 파일을 *.pre-$ID로(이미 있으면 덮지 않는다)
for f in snapshot/zeekad.dump snapshot/zeekad.dump.sha256 snapshot/manifest.json docker/portfolio/seed/seed_demo.py docker/portfolio/seed/demo_examples.json compose.portfolio.yml docker/portfolio/initdb/02-restore-snapshot.sh; do
  [ -e "$f.pre-$ID" ] || cp -p "$f" "$f.pre-$ID" || exit 2
done
# 3) 앱 DB 백업(NAS 안에만. 비밀번호 해시가 들어 있으므로 밖으로 옮기거나 내용을 출력하지 않는다)
mkdir -p backup && chmod 700 backup || exit 3
umask 077
$C exec -T postgres pg_dump -U postgres -Fc zeekad_dashboard < /dev/null > backup/app-pre-$ID.dump.partial || exit 3
mv -f backup/app-pre-$ID.dump.partial backup/app-pre-$ID.dump && chmod 600 backup/app-pre-$ID.dump && test -s backup/app-pre-$ID.dump || exit 3
$C exec -T postgres pg_restore --list < backup/app-pre-$ID.dump > /dev/null && echo "backup OK" || exit 3
# 3a) 90일 넘은 되돌리기용 백업을 지운다(T58: 백업에도 감사 로그가 들어 있다). 지울 파일을 먼저 보고(이름만) 지운 뒤 0인지 확인한다.
#     -mtime +89 = 만든 지 90일(24시간 단위)이 넘은 파일. 방금 만든 app-pre-$ID.dump는 해당하지 않는다
find backup -maxdepth 1 -type f -name 'app-pre-*.dump' -mtime +89
find backup -maxdepth 1 -type f -name 'app-pre-*.dump' -mtime +89 -exec rm -f {} \;
test "$(find backup -maxdepth 1 -type f -name 'app-pre-*.dump' -mtime +89 | wc -l)" -eq 0 && echo "old backups: 0" || exit 3
# 4) 내리기(-v 없이)
$C down < /dev/null || exit 4
# 5) 이 프로젝트의 DB 볼륨 하나만 지운다(이름을 먼저 확인한다)
docker volume ls --format '{{.Name}}' | grep '^zeekad-portfolio_'      # zeekad-portfolio_pgdata 하나여야 한다
docker volume rm zeekad-portfolio_pgdata || exit 5
```

6) 로컬 PC에서 새 `zeekad.dump`·`zeekad.dump.sha256`·`manifest.json`과 바뀐 배포 파일을 `scp -O`로 보낸다(3.2). NAS에서 `(cd snapshot && sha256sum -c zeekad.dump.sha256)`가 `OK`인지 보고 `chmod 755 snapshot && chmod 644 snapshot/*`로 권한을 맞춘다(T13: 상속 ACL 때문에 컨테이너 postgres가 덤프를 못 읽는다).

```sh
# 7) 올리기(nginx-waf·sandbox-reset은 빼고): 빈 볼륨이라 01(역할·DB)·02(스냅샷 복원)·03(스냅샷에 없는 zeek_AD 함수, T53)이 다시 돈다. 공개 경로는 아직 열지 않는다
$C up -d --wait postgres api dashboard-app < /dev/null || exit 7
$C logs postgres < /dev/null | grep -E 'portfolio-restore|pg_restore: error|portfolio-functions'   # "portfolio-restore: done", 오류 줄 없음
#    03은 "dashboard.reopen_incident created" 또는 (새 스냅샷에 이미 있으면) "already exists ... skipping" 한 줄. 실패하면 표지를 지워 healthy가 되지 않는다
# 8) 시드 두 번(시드는 dashboard-app에 직접 붙으므로 nginx-waf가 없어도 된다): 첫 실행 RESULT: CHANGED(demo 다시 생성), 두 번째 RESULT: NO_CHANGES
#    T54: 첫 실행이 분석이 끝난 예시 셋을 기록한다(examples: applied=3 kept=0 skipped=0). 새 스냅샷에 그 인시던트가 없으면 skipped로 남는다(1.4)
$C --profile seed run --rm demo-seed < /dev/null || exit 8
$C --profile seed run --rm demo-seed < /dev/null || exit 8
# 8a) 체험 계정 초기화 설정(T33): 새 스냅샷 + 시드가 기록한 예시 셋이 기준선이 된다. 스냅샷이 체험 계정 이름을 이미 행위자로 쓰면 여기서 멈춘다
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
- 셋째 스크립트(`T53`)는 함수 이름만 본다. 새 스냅샷이 zeek_AD의 새 판 `reopen_incident`를 이미 담고 있으면 옛 사본을 실행하지 않는다. 사본이 더 쓰이지 않게 되면 `zeekad-sql/`의 사본과 `03-zeekad-functions.sh`를 지우는 것은 다음 작업에서 정한다.
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
- 스크립트로 실행할 때는 단계를 스크립트 파일로 저장해 NAS의 `~/zeekad-portfolio-check/<작업 ID>-step-<단계>.sh`로 풀고 `bash <그 파일> < /dev/null`로 실행한다(표준 입력으로 넘기지 않는다). 파일 맨 앞에 `DEPLOY_DIR=<배포 폴더>` 줄을 둔다(문서 머리). 출력은 `build/portfolio-evidence/<작업 ID>/nas-replace.txt`(시드는 `nas-seed.txt`)처럼 Git 제외 경로에 남긴다. 비밀값·쿠키·백업 내용은 출력하지 않는다.

### 3.10 새 실습망 캡처를 공개할 때(`T33`, `T39`)

zeek_AD 실습망의 새 공격 시험 캡처를 공개할 때의 순서다. 타깃 VM을 둔 뒤의 공격 시험 캡처 `lab-20261122`(공격 6종: 느린 스캔·비커닝·분할 유출·SMB 공유 탐색·SSH 무차별 대입·DNS 터널)를 `T39`에서 이 순서로 공개했다. 허용 캡처는 `DEMO_CAPTURE_PATTERNS`(비어 있으면 시드 기본값) 한 곳이다. 앱 코드에서 캡처 ID가 있는 곳은 캡처 표시 이름 사전(`frontend/src/utils/labels.ts` `LAB_CAPTURE_NOTES`, zeek_AD 표의 글) 하나뿐이고 권한에는 쓰이지 않는다. 초기화 SQL에는 없다.

1. 로컬 PC: 새 스냅샷(2.2) → `secret-scan.txt` 확인 → 리허설(2.3)을 `-ExposureDir <저장소 밖 폴더>`와 함께 돌린다(허용 캡처를 바꿨으면 리허설 셸에 같은 `DEMO_CAPTURE_PATTERNS`를 준다).
2. **분석가 노출 확인**: `exposure.md`(필드별 개수·값 형태)를 운영자가 본다. 필요하면 `exposure-values.txt`(실제 값, 커밋하지 않음)를 본다. 점검 항목: HTTP URI(쿼리 문자열의 토큰·계정), 인증 필드(사용자 이름, Kerberos·NTLM·SMB 계정), 호스트 이름(집 장비·개인 이름), 사설 대역(집 LAN `192.168.x`가 섞였는지), 공인 주소(집 공인 IP가 섞였는지), Slack 원문. 공개하면 안 되는 값이 있으면 그 캡처는 공개하지 않는다.
3. NAS: `sandbox-reset`을 멈춘다(`stop sandbox-reset`).
4. 3.9 순서로 스냅샷을 바꾼다(8a의 `sandbox-setup`이 새 볼륨에 기준선을 만든다). 볼륨을 다시 만들지 않고 데이터만 바꾸는 경우에는 `sandbox-setup --rebuild-baseline`으로 기준선을 다시 만든다(체험 계정 흔적이 있으면 멈추므로 먼저 `sandbox-reset … --once`).
5. 허용 캡처 변수(`DEMO_CAPTURE_PATTERNS`)를 바꿨으면 시드를 다시 돌린다(두 공개 계정에 같이 반영된다).
6. `sandbox-reset`을 다시 시작하고 다음 정각 로그(3.5)와 4.4를 확인한다.

`T39`(`lab-20261122` 공개, `lab-20261123` 숨김)에서 더한 것:
- **공개 전 내용 목록**: 노출 확인(`exposure.md`)은 두 계정의 차이만 보인다. 조회자에게도 그대로 보이는 도메인·URI·계정 이름·사용자 에이전트는 따로 본다. 같은 덤프를 일회용 컨테이너(`--network none`)에 복원해 새 캡처의 `dashboard` 뷰 행에서 도메인·IPv6·실습망 밖 IPv4·계정·호스트·사람 기록·Slack 채널과 버튼 URL 호스트를 뽑고, 리허설의 `demo` 응답 원문(`-ExposureDir` 아래 `demo-responses/`, 커밋하지 않음)에서도 같은 종류를 본다. 개인 도메인·실명·집 네트워크 주소·실제 서비스 계정처럼 보이는 것이 있으면 공개하지 않는다.
- **옛 캡처 그대로인지**: 옛 스냅샷과 새 스냅샷을 각각 일회용 컨테이너에 복원해 옛 캡처의 `latest_incident_queue`(캡처·`incident_id`·탐지 시각·순위·작업 ID) 개수와 내용 해시가 같은지 본다. 다르면(zeek_AD가 옛 캡처를 다시 채점) 인시던트 번호와 공개된 링크가 달라지므로 멈춘다.
- **인시던트 번호 유지**: 3.9는 앱 DB도 새로 만들어 번호를 처음부터 다시 매긴다(탐지 시각 = 그 인시던트가 처음 나온 성공 작업의 완료 시각 → 캡처 → `incident_id` 순). 새 캡처의 작업이 옛 작업보다 늦게 끝났으면 옛 번호는 그대로이고 새 캡처는 그 뒤 번호를 받는다. 교체 전에 공개 앱 DB의 `incident_refs`를 `BEGIN READ ONLY`로 번호와 `sha256(incident_id)`만 내보내고(주소가 든 `incident_id` 원문은 내보내지 않는다), 리허설에 `-ExpectedRefsFile <그 파일>`로 주면 `[T39c]`가 최신 큐에 있는 옛 인시던트의 번호가 모두 같은지 본다. NAS 교체 직전(3.9의 0) 뒤 4) 전)에 한 번 더 내보내 공개 확인에서 견준다.
- **스레드 부모**: 공개 인시던트의 Slack 행 부모(`zeekad_thread_parent`)가 숨김 캡처에 있으면 숨김 캡처의 인시던트 ID가 조회자에게 보인다. 리허설 `[T39b]`가 0인지 본다(`lab-20261123`의 부모는 `lab-20261122`에 있어 반대 방향이다).
- **복원 뒤 통계**: `02-restore-snapshot.sh`가 복원 끝에 `zeekad` DB를 `ANALYZE`한다(복원 직후 행 수 추정이 어긋나 큐가 느려진 일, `T35`). 3.9 2)의 보존 목록에 이 파일을 넣었다.

`T66`(`lab-20261126` 공개, `lab-20261124`·`lab-20261125` 숨김, 2026-11-26 사용자 결정)에서 한 것:
- **왜**: 리뷰어가 데모 화면에서 브로드캐스트 한 건이 High 경보가 된 사건(`lab-20261122`)을 지적했다. 탐지 저장소가 브로드캐스트뿐인 창을 조사 큐에서 빼는 규칙(설계 결정 DD-021)을 배포 VM에 넣고 같은 공격 둘(비커닝, 분할 유출)을 다시 돌린 캡처가 `lab-20261126`이다. 고친 뒤의 모습을 같은 화면에서 보이려고 배포 VM에서 스냅샷을 새로 떴다. `lab-20261122`의 그 사건은 "규칙 전의 오탐 사례"로 그대로 둔다.
- **스냅샷**: `-PublicCaptures` 기본값에 `lab-20261126`을 더해(2.2) 떴고 옛 스냅샷은 `build/portfolio-pre-t66/`에 옮겨 뒀다. 새 스냅샷에는 zeek_AD가 배포 VM에 적용한 `dashboard.reopen_incident`가 있어 셋째 initdb 스크립트는 건너뛴다(`zeekad-sql/` 사본과 그 스크립트를 지우는 것은 다음 작업).
- **복원 DB에서 SQL로 본 것**(일회용 컨테이너, `--network none`, 포트 없음): `reopen_incident`와 `dashboard_rw`의 실행 권한, 새 캡처 최신 큐의 사건이 탐지 저장소 2026-11-26 전달 글 9절의 표와 같은지, 그 캡처의 작업이 모두 성공으로 끝났는지, 공개 인시던트의 스레드 부모가 숨김 캡처에 없는지(`[T39b]`와 같은 질의), 24시간 기본 화면에 들 수(기준 시각 = 공개 캡처 성공 작업의 마지막 완료 시각, 앱과 같은 식). 옛 공개 캡처 열 개의 큐는 위 "옛 캡처 그대로인지" 방법으로 같음을 봤다.
- **순위 숫자를 쓰지 않는 사건**: 새 캡처의 최신 큐에는 모델 점수가 같아 파이프라인이 작업마다 다른 순서로 놓는 사건 넷이 있다(같은 점수 안의 순서가 정해져 있지 않다. 설계자가 탐지 저장소에 알린다). 이 넷의 순위 숫자는 문서·README·화면 글·시험에 쓰지 않는다. 사건 ID·시간 창과 분할 유출 보내는 쪽이 맨 위라는 것은 쓸 수 있다.
- **기본 화면이 바뀐다**: 기준 시각이 `lab-20261126`의 마지막 작업 완료 시각으로 옮겨 가서 24시간 기본 화면에는 그 캡처의 사건만 보인다. 앞선 숫자(1.5의 24시간 수 등)는 옛 스냅샷의 값이다.
- **`T57`·`T65`로 넘긴 것**: 리허설(새 스냅샷, `-ExposureDir`의 대상은 `$exposureLabCapture` = `lab-20261126`), 인시던트 번호(`[T39c]`), 수와 그림은 `T57`, NAS 반영(3.9, 시드 파일 교체)은 `T65`다. 공개 전 내용은 복원 DB의 SQL 수준 요약(값 없이 필드별 개수·꼴)과 `T57`의 노출 확인을 합쳐 사용자가 확인한다.
- **`.env.portfolio.example`의 주석 예시**는 옛 목록 그대로다(이 작업에서 고치지 않았다). NAS `.env`의 `DEMO_CAPTURE_PATTERNS`가 비어 있으면 새 시드 기본값이 쓰이고, 값을 적어 두었으면 `lab-20261126`을 더해야 한다.

## 4. DSM 설정

DSM 7 기준 메뉴 경로다. `T13`에서 이 절의 메뉴 경로와 값으로 설정해 확인했다.

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

- **사용자 지정 헤더는 넣지 않는다.** `T13`에서 기본 규칙(사용자 지정 헤더 없음)이 넘기는 헤더를 `nginx-waf` ModSecurity 감사 로그로 확인했다: `Host`는 소스 호스트 이름, `X-Forwarded-For`는 방문자가 보낸 값 뒤에 실제 접속 IP를 **덧붙인다**(덮어쓰지 않음, 예: `203.0.113.9, <접속 IP>`), `X-Forwarded-Proto`는 방문자 값과 관계없이 `https`로 **덮어쓴다**, `X-Real-IP`는 실제 접속 IP다. nginx가 가장 오른쪽 비신뢰 주소를 쓰므로(1.1) 방문자가 앞부분을 꾸며도 감사 로그 IP·속도 제한 키·`Location`이 바뀌지 않는다. WebSocket 헤더는 필요 없다. `T13` 때는 감사 줄에 요청 헤더가 통째로 들어 있어 이렇게 볼 수 있었다. `T59`부터 WAF는 감사 줄에 요청 헤더를 남기지 않아 같은 방법은 쓸 수 없다. 지금은 4.3의 접근 로그 줄로 `X-Forwarded-For`만 본다.
- `localhost`가 IPv6 `::1`로 풀려 연결되지 않으면 대상 호스트 이름을 `127.0.0.1`로 바꾼다(`T13`에서는 이 문제가 없었다).
- **인증서 연결**: **제어판 > 보안 > 인증서 > 설정**에서 서비스 `soc.<DDNS 이름>.synology.me`에 4.1의 인증서를 고른다.
- DSM은 HSTS를 켜면 `Strict-Transport-Security: max-age=15768000; includeSubdomains; preload`를 붙인다. 앱도 `max-age=31536000 ; includeSubDomains`를 보내지만 `T36`부터 공개 WAF가 앱의 HSTS를 내보내지 않는다(`proxy_hide_header`). 그래서 공개 응답에는 DSM 값 하나만 있다(`T35`까지는 두 개였고 동작 영향은 없었다). 스택 안 8443 리스너(ZAP 대상)는 자기 HSTS 하나를 그대로 붙인다. DSM 앞단은 `Server: nginx`(버전 없음)를 붙이며 이 스택에서 바꿀 수 없다.
- 공유기·모뎀 포트 포워딩과 같은 기기의 다른 서비스의 역방향 프록시 규칙은 바꾸지 않는다.

### 4.3 DSM이 실제로 보내는 헤더 확인(T13)

DSM 규칙을 만든 뒤 외부망(휴대전화 데이터 등)에서 `demo`로 한 번 로그인하고 NAS에서 감사 로그를 본다.

```sh
cd "$DEPLOY_DIR"
docker compose -p zeekad-portfolio -f compose.portfolio.yml exec -T postgres \
  psql -U postgres -d zeekad_dashboard -c "SELECT occurred_at, actor_username, client_ip FROM audit_logs WHERE action_type='LOGIN_SUCCESS' ORDER BY id DESC LIMIT 3"
```

- `occurred_at`은 UTC다. 외부망에서 로그인한 시각(한국 시간이면 9시간을 뺀다)으로 줄을 구분한다.
- `client_ip`가 방문자 공인 IP면 정상이다. `127.0.0.1`이나 `portfolio-net` 게이트웨이(`10.203.48.1`)면 DSM이 `X-Forwarded-For`를 보내지 않는 것이다 → 4.2 규칙의 **사용자 지정 헤더 > 생성**에서 `X-Forwarded-For` = `$proxy_add_x_forwarded_for`, `X-Forwarded-Proto` = `$scheme`을 추가하고 다시 확인한다. 이 경우 속도 제한도 모든 방문자에게 하나의 키로 걸리므로 반드시 고친다(`T13`에서는 필요 없었다).
- `docker compose ... logs nginx-waf`: 접근 로그 줄의 마지막 칸은 받은 `X-Forwarded-For` 원문이다(DSM이 덧붙인 마지막 주소 = 방문자 IP). ModSecurity JSON 로그(`"client_ip"`)는 차단·오류 응답 등 관련 있는 요청만 남으므로 성공한 로그인(200)은 접근 로그로 본다.
- DSM이 넘기는 `X-Forwarded-For`를 직접 보려면 요청 주소에 표지를 붙여 보낸다(예: 외부망에서 `https://soc.<DDNS 이름>.synology.me/login?probe=<표지>`). `docker compose ... logs --no-log-prefix nginx-waf`에서 `{`로 시작하지 않고 `probe=<표지>`가 든 접근 로그 줄을 찾는다.
  - 줄의 꼴(기반 이미지의 `log_format main`): `<연결 주소> - - [시각] "<메서드> <요청 주소> HTTP/1.1" <응답 코드> <크기> "<Referer>" "<User-Agent>" "<받은 X-Forwarded-For 원문>"`.
  - 첫 칸은 WAF에 붙은 연결의 주소다(DSM 경로면 게이트웨이 `10.203.48.1`). 방문자 주소는 마지막 칸의 가장 오른쪽 값이다.
  - `Host`·`X-Forwarded-Proto`·`X-Real-IP`는 접근 로그 서식에 없다. `T59`부터 ModSecurity 감사 줄은 요청 헤더를 남기지 않으므로(1.1) `T13` 때처럼 감사 줄의 `request.headers`로 볼 수 없다. 이 셋을 다시 봐야 하면 공개 스택의 감사 부분을 넓히지 말고(세션 쿠키가 로그에 남는다) 다른 방법을 따로 정한다.

### 4.4 공개 주소 확인 체크리스트

외부망에서 `https://soc.<DDNS 이름>.synology.me`로 확인한다. 리허설에서 같은 항목을 로컬 PC로 확인한 증거는 `scripts/portfolio-verify.ps1`의 E2E 번호로 적었다.

**같은 LAN(로컬 PC)에서 확인할 때**: 공유기에 NAT 루프백이 없으면 로컬 PC에서 공인 IP로는 접속되지 않는다. 대신 `curl.exe --resolve soc.<DDNS 이름>.synology.me:443:<NAS 주소> https://soc.<DDNS 이름>.synology.me/...`로 NAS의 DSM `443`에 직접 붙는다(인증서·역방향 프록시·헤더는 공개 경로와 같다). 브라우저가 필요한 항목은 `curl.exe`의 인증서 검증 성공(`--insecure` 없이 종료 코드 0)과 `Set-Cookie` 속성으로 대신한다. 로컬 PC의 모든 요청은 같은 클라이언트 IP(로컬 PC의 LAN IP)라 로그인 요청 사이에 7초 정도 간격을 두지 않으면 속도 제한(`429`)에 걸린다. 공개 IP 접속 자체와 방문자 공인 IP 기록(4.3)은 외부망(휴대전화 데이터 등)에서만 확인할 수 있다.

- [ ] 브라우저 주소 표시줄에 인증서 경고가 없다(4.1 하위 도메인 인증서). `http://` 접속은 공유기가 `443`만 포워딩하므로 외부에서는 해당 없다.
- [ ] `demo` / 공개 비밀번호로 로그인되고(TOTP 없음) 조사 큐·사건 상세(근거 요약 칸 포함)·보고서·전송 판단·Slack 기록·운영 상태(`feedback_summary`)가 스냅샷 데이터로 보인다. 보이는 캡처(`snapshot/manifest.json`의 `publicCaptures`: `cic17-*` 4, `syn1-*` 4, `lab-20261119`, `lab-20261122`, `lab-20261126`(`T66`)) 건수가 매니페스트와 같고, 세 실습망 캡처 사건의 목록·상세·증적·AI 리포트가 보인다. `lab-20261122` 상세의 Slack 탭에 스레드 답글과 "채널에도 표시" 표지가 보인다(리허설 [T39a]). 숨김 캡처(`hiddenCaptures`: `lab-20261201`, `lab-20261118`, `lab-20261123`, `lab-20261124`, `lab-20261125`)는 캡처 목록에 없고, 직접 조회(목록 `captureId=<숨김 캡처>`·그 캡처의 사건 상세)는 `403`이다. 첫 화면(`/`)은 관제 현황판이다. 숨김 캡처 ID는 현황판·운영 현황·검토 목록 응답에도 없다. 최신 큐에 있던 인시던트의 번호(`/incidents/<번호>`)는 교체 전과 같다. (리허설 [2]·[3]·[T39])
- [ ] IP는 뒤 두 옥텟이 가려져 보인다(`192.168.*.*`). (리허설 [3])
- [ ] `demo`로 상태 전이·검토 결정·`/api/admin/**`가 `403`이다(화면에 쓰기 버튼이 없거나 눌러도 거부). 종결 건의 다시 열기도 `403`이고 화면에 다시 열기 폼이 없다. (리허설 [4]·[T53c])
- [ ] `trial-analyst` / 공개 비밀번호로 로그인되고 역할이 `ANALYST`, 허용 캡처가 `demo`와 같으며 숨긴 캡처 직접 조회가 `403`이다. 공개 데모에서는 쓰기(상태 변경·결정·담당)와 로그인 실패를 일부러 만들지 않는다(쓰기 흐름은 리허설 `[T33]`). (리허설 [T33a])
- [ ] 다음 정각 뒤 `logs --since 2h sandbox-reset`에 `OK` 줄이 있고 `ERROR`가 없다. (3.5, 리허설 [T33f])
- [ ] 분석이 끝난 예시 셋(`T54`): 시드 로그가 `skipped=0`이고 `applied + kept = 3`이다. `demo`로 `/incidents?status=closed&period=all`에 셋이 보이고, 예시 A 상세가 종결·정탐이며 사유의 주소가 가려져 있고(`10.10.*.*`) 대응 조치는 종류·기록자·시각만 보인다(메모 없음). 다음 정각 뒤에도 그대로다. `demo-analyst`가 비활성이다(NAS `exec -T postgres psql -U postgres -d zeekad_dashboard -Atc "SELECT enabled FROM users WHERE username = 'demo-analyst'"`가 `f`. 로그인 실패를 일부러 만들지 않는다). (1.4, 리허설 [T54a]~[T54d])
- [ ] 중요 자산(`T52`): 두 번째 시드 실행의 로그가 `critical-assets: created=0 updated=0 deleted=0 kept=6`이다. NAS `exec -T postgres psql -U postgres -d zeekad_dashboard -Atc "SELECT host_ip FROM critical_assets ORDER BY host_ip"`가 자료 파일의 여섯 주소다. `demo`로 큐에서 `10.10.*.*`·`192.168.*.*` 행 일부에 "중요 자산" 표지가 보이고 그 툴팁·응답에 자산 이름이 없다(큐 응답의 `criticalAssetName`이 모두 `null`). `demo`로 `/api/admin/critical-assets`가 `403`이다. (1.5, 리허설 [T52a]~[T52d])
- [ ] 초기화 줄 끝에 감사 칸(`audit[…]`)이 있고 보관 기한을 반영한 뒤 `audit[OK] purged=… cutoff=…` 줄이 한 번 이상 있다. `audit[NOT_CONFIGURED]`가 이어지면 `sandbox-setup`을 다시 돌린다(실행 권한). 90일 넘은 감사 행이 없다: `SELECT count(*) FROM audit_logs WHERE occurred_at < now() - interval '91 days'`가 `0`(개수만 본다). (1.3, 리허설 [T58b]·[T58c])
- [ ] 컨테이너 로그 한도가 걸려 있다: `docker inspect --format '{{json .HostConfig.LogConfig}}' <컨테이너>`가 서비스마다 `json-file`, `max-size` `10m`, `max-file` `5`다. (리허설 [T58a])
- [ ] 감사 로그·담당 이력의 크기: `SELECT count(*) FROM audit_logs`와 `SELECT pg_size_pretty(pg_database_size('zeekad_dashboard'))`(NAS `exec -T postgres psql -U postgres -d zeekad_dashboard -Atc …`, 개수와 크기만)를 기록해 지난번과 비교한다. 체험 계정 사유·메모는 500자까지이고 쓰기는 IP당 분당 10회 + 버스트 5다. 그래서 IP 하나가 쓰기로 하루에 늘릴 수 있는 감사 로그는 약 14,400~28,800행이다(분당 10회 × 1,440분. 조사 시작 때 자동 담당 기록이 한 행 더 붙는다). 상태 변경 기록에는 사유 전문이 들어가서 한글 500자(UTF-8 약 1.5KB)면 행당 약 2KB다. 자동 담당 기록은 사유가 없어 수백 바이트라 하루 약 30MB 안팎이다. 허용 밖 인시던트 조회 거부(`ACCESS_DENIED_IDOR`)도 조회 1번에 감사 1행을 남긴다(행당 인덱스 포함 약 300바이트, 리허설 `[T36b]`). 이 증가는 `T33` 전부터 `demo`로도 열려 있었고 `T35`까지는 상한이 없었다. `T36`부터 조회 한도(IP당 분당 200회 + 버스트 30)가 묶어 IP 하나가 조회 거부로 하루에 늘릴 수 있는 감사 로그는 약 288,000행(약 86MB)이다. 이것은 IP별 상한이고 전체 상한이 아니다(방문자가 IP를 바꾸면 더 늘릴 수 있다). 인증 없는 조회는 감사 행을 만들지 않는다. 크게 늘었으면 감사 로그 화면에서 행위자·IP 분포를 보고 판단한다. `T58`부터 감사 로그는 90일이 지나면 하루 한 번 지워지므로 위 증가는 90일치까지 쌓인다(담당 이력은 기한이 없다). PostgreSQL은 지운 자리를 autovacuum 뒤에 다시 쓰므로 DB 크기 값은 지운 날 바로 줄지 않는다. 컨테이너 로그는 컨테이너마다 50MB(10MB 파일 5개)가 한도다. 기간이 아니라 크기 한도라 요청이 적으면 90일보다 오래된 접근 줄이 남을 수 있고 컨테이너를 다시 만들면 사라진다. `T61`부터 `nginx-waf`의 상태 확인이 감사 줄을 남기지 않아 `nginx-waf` 로그도 방문자 요청만큼만 찬다(`T60`까지는 상태 확인 줄이 한도를 며칠 만에 채웠다).
- [ ] 조회 한도: 인증 없는 `/api/` `GET`(예: `/api/dashboard/overview?period=24h`)을 이 PC에서 240건(분당 200 + 버스트 30 + 10)까지만 몰아 보내 `429`가 한 번 이상 나오고, 그동안 `/api/auth/csrf`는 `200`, 60초 뒤 다시 `401`이다. 이 확인 밖에서는 `/api/` 조회 사이에 0.4초 넘게 간격을 둔다. (리허설 [T36b])
- [ ] `viewer1`·`analyst1`·`analyst2`·`admin`은 로그인되지 않는다(비활성). (리허설 [5])
- [ ] `demo`에 틀린 비밀번호를 여러 번 넣어도 잠기지 않는다. 짧은 시간에 로그인을 많이 시도하면 `429`가 난다. (리허설 [6]·[7])
- [ ] 감사 로그의 로그인 IP가 실제 접속 IP다(4.3). (리허설 [7])
- [ ] `https://soc.<DDNS 이름>.synology.me/api/incidents?asset=%27%20OR%201%3D1--`가 `403`(WAF)이다. XSS(`?asset=%3Cscript%3E`)·경로 탐색(`?asset=../../etc/passwd`)도 `403`. (리허설 [8])
- [ ] 로그인 경로가 아닌 `POST /api/...`(예: `/api/incidents/101/rank/2/assignment`)에 인증 없이 `Content-Type: application/xml`로 깨진 XML 본문(`<a><b></a>`)을 보내면 `400`(WAF)이다. 이 요청은 로그인 실패를 만들지 않는다. 예: `curl.exe -s -o NUL -w "%{http_code}" -X POST -H "Content-Type: application/xml" --data-binary "<a><b></a>" "https://soc.<DDNS 이름>.synology.me/api/incidents/101/rank/2/assignment?probe=<고유 표식>"`. NAS에서 `docker logs --since 10m zeekad-portfolio-nginx-waf-1 2>&1 | grep -F <고유 표식>`으로 그 요청의 기록만 찾아 규칙 `200002`를 확인한다(방문자 IP가 든 다른 줄은 보지 않는다). ([T31])
- [ ] 전달 헤더 신뢰(`T32`): `docker inspect`로 `nginx-waf` 주소가 `PORTFOLIO_WAF_IP`(`10.203.48.250`)이고 `dashboard-app` 환경의 `DASHBOARD_TRUSTED_PROXIES`가 같은 값이다. 공개 HTTPS 주소로 보낸 표식 요청(`curl.exe --resolve …:443:<NAS 주소> "https://soc.<DDNS 이름>.synology.me/login?probe=<고유 표식>"`)의 WAF 로그 줄에서 클라이언트 IP(줄 끝 `X-Forwarded-For` 필드의 신뢰 범위 밖 가장 오른쪽 주소)가 스택 두 서브넷의 주소가 아니다(주소는 적지 않고 "서브넷 안인가"만 적는다. NAS의 `127.0.0.1:18480`으로 바로 보내면 접속 주소가 게이트웨이라 이 확인이 되지 않는다). `demo` 로그인 뒤 반영 시각 이후 `demo`의 `LOGIN_SUCCESS` 행이 1 이상이고 그중 스택 두 서브넷(`PORTFOLIO_SUBNET`·`PORTFOLIO_DATA_SUBNET`, `T61`) 주소 행이 0이다(개수만 센다). 그 사이에 시드를 돌렸다면 시드의 관리자 로그인(`admin`)은 `portfolio-data` 주소로 찍히는 것이 정상이라 세지 않는다. `T61`부터 `api` 컨테이너에서는 `nginx-waf`에 닿지 않는다(아래 `T61` 항목). 같은 네트워크의 다른 컨테이너가 보낸 전달 헤더를 볼 때는 `portfolio-net`에 붙인 일회용 컨테이너(`docker run --rm --network zeekad-portfolio_portfolio-net --cap-drop ALL --security-opt no-new-privileges:true …`)에서 `nginx-waf:8080/?probe=<고유 표식>`에 `X-Forwarded-For: 198.51.100.x`를 붙인 `GET`을 보내고 WAF 로그 접속 주소가 그 컨테이너 주소인지 본다(감사가 남지 않는 요청). (리허설 [T32])
- [ ] 다시 열기(`T53`): `zeekad` DB에 `dashboard.reopen_incident`가 하나 있고 소유 `zeekad_owner`, 실행 권한은 `dashboard_rw`뿐이며 `dashboard_rw`가 실행할 수 있는 함수가 셋이다(3.8 `T53` 절의 3)·4)). 공개 데모에서는 다시 열기를 일부러 만들지 않는다(쓰기 흐름은 리허설 `[T53b]`). (리허설 [T53a])
- [ ] 네트워크 둘·권한·상태 확인(`T61`): 3.8 `T61` 절의 확인 9)~16)이 기대대로다. 곧 `portfolio-net`에는 `nginx-waf`·`dashboard-app`만, 내부 전용 `portfolio-data`에는 `postgres`·`api`·`dashboard-app`·`sandbox-reset`만 붙어 있다. `nginx-waf`에서 `api:8000`·`postgres:5432`에 TCP 연결이 되지 않고 `dashboard-app:8080`에는 된다. `api`에서 `nginx-waf:8080`에 닿지 않는다. 상주 다섯 PID 1의 `CapBnd`가 0, `NoNewPrivs`가 1이고 `postgres`의 `Config.User`가 `postgres`다. `nginx-waf` 로그에 최근 2분의 `/healthz` 감사 줄이 0이다(개수만). (리허설 [T61a]~[T61e])
- [ ] 응답 헤더에 `Strict-Transport-Security`가 DSM 값 하나(`max-age=15768000; includeSubdomains; preload`, `T36`)이고 `Content-Security-Policy`(`script-src 'self'`, `style-src 'self'`, `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy`가 있고 `Server`에 버전이 없다(DSM 앞단이 `Server: nginx`를 붙인다. 4.2). 예: `curl.exe -sI https://soc.<DDNS 이름>.synology.me/login`. (리허설 [1]·[T36c]. 리허설의 WAF 응답에는 HSTS가 없고 공개 주소에서 DSM이 붙인다)
- [ ] 로그인 응답의 `ZEEKAD_SESSION` 쿠키가 `Secure; HttpOnly; SameSite=Lax`다(브라우저 개발자 도구 > 애플리케이션 > 쿠키). (리허설 [2])
- [ ] 로그아웃 상태에서 `https://soc.<DDNS 이름>.synology.me/`에 접속하면 `https://soc.<DDNS 이름>.synology.me/login`으로 간다(주소에 `:8080`·`:18480`·`http://`가 없다). (리허설 [1])
- [ ] LAN에서 `http://<NAS 주소>:18480/`로 직접 접근할 수 없다. NAS의 이 스택 포트는 `127.0.0.1:18480` 하나뿐이다. (3.6, 리허설 [0])
- [ ] 같은 기기의 다른 서비스(기존 컨테이너와 DSM `443`의 기존 주소)가 그대로 동작한다. 다른 프로젝트의 컨테이너·네트워크 목록이 앞에서 기록한 목록과 같다. (3.6)

## 5. 계정 시드의 직접 SQL 단계와 위험

시드(`docker/portfolio/seed/seed_demo.py`)는 먼저 `zeekad_dashboard`를 `dashboard_app`으로 읽어 현재 상태를 확인하고, 이미 목표 상태(`demo` 존재·`VIEWER`·허용 캡처 `DEMO_CAPTURE_PATTERNS`(비어 있으면 `cic17-*,syn1-*,lab-20261119,lab-20261122,lab-20261126`, 순서 무관)·표시 이름·활성·잠금 없음·`.env` 비밀번호와 일치, `TRIAL_ANALYST_PASSWORD`가 있으면 `trial-analyst`도 같은 조건(역할 `ANALYST`, 같은 허용 캡처), `demo-analyst` 존재·`ANALYST`·표시 이름·허용 캡처 `lab-20261119,lab-20261122`(`T54`), 다른 계정 모두 비활성, 분석이 끝난 예시 셋이 모두 `kept`·`skipped`(1.4), 중요 자산 목록이 자료 파일과 같음(`T52`, 1.5))면 아무것도 바꾸지 않는다(`RESULT: NO_CHANGES`, 감사 로그 추가 없음, 로그인 없음). 바꿀 것이 있을 때만 바꾼다. 예시 판정은 로그인 전에 DB 읽기만으로 하고, 어긋난 예시가 하나라도 있으면 아무것도 바꾸지 않고 실패한다(zeekad는 읽기 전용 계정 `dashboard_ro`로 읽는다).

가능한 단계는 앱 관리자 API로 한다(`admin` 로그인 + `.env`의 `BOOTSTRAP_ADMIN_TOTP_SECRET`으로 계산한 TOTP 코드, 감사 로그 `USER_ADMIN_CHANGE`):
공개 계정 생성(`CREATE_USER`), 역할·허용 캡처·표시 이름 수정(`UPDATE_USER`), 활성화·다른 계정 비활성화(`TOGGLE_ENABLED`, 상태를 읽고 필요할 때만 호출), 잠금 해제(`UNLOCK_ACCOUNT`). `demo-analyst`의 생성·수정·켜기·끄기도 같은 API다(`T54`). 중요 자산 맞추기(`T52`)는 관리자 자산 API다(목록 `GET`, 만들기 `POST /api/admin/critical-assets`, 고치기 `PUT …/{id}`, 지우기 `POST …/{id}/delete`, 감사 `CRITICAL_ASSET_CHANGE`). 예시 기록(착수·대응 조치·담당 해제·종결)은 관리자가 아니라 `demo-analyst` 세션이 분석가 API로 한다. 관리자 로그인은 한 실행에 한 번이다(TOTP 실패가 실패 횟수에 든다, `T60`).

한 관리자 세션 안의 순서: 공개 계정 맞추기 → `demo-analyst` 만들기(없을 때) 또는 SQL 비밀번호 교체 뒤 켜기(예시를 기록할 때만) → `demo-analyst` 세션으로 예시 기록 → `demo-analyst` 끄기 → 공개 계정이 아닌 활성 계정 끄기 → 중요 자산 맞추기(`T52`) → 로그아웃.

API로 할 수 없어 `zeekad_dashboard`에 직접 SQL을 쓰는 단계는 넷이다. 모두 `users` 표만 바꾸고, 각 SQL은 같은 트랜잭션에서 감사 로그 한 줄(`actor_username=portfolio-seed`, `actor_role=SYSTEM`, `action_type=USER_ADMIN_CHANGE`, `detail_json`에 `operation`·`via: direct SQL`·이유)을 남긴다. zeek_AD 표·대응 조치 표·담당 표에는 SQL로 쓰지 않는다(정적 시험 `t54SeedRecordsExamplesOnlyThroughTheAppApiAndKeepsNoNewSecret`).

| 단계 | 이유 |
|---|---|
| `admin` 비활성화(`DISABLE`) | `UserAdminService.toggleEnabled`가 로그인한 자기 계정의 비활성화를 막는다 |
| 이미 있는 공개 계정(`demo`, `trial-analyst`)과 `demo-analyst`의 비밀번호 변경(`SET_PASSWORD`) | 비밀번호 변경 API가 없고 `createUser`는 이미 있는 아이디를 거부한다. 해시는 앱과 같은 BCrypt strength 12를 PostgreSQL `pgcrypto`(`crypt` + `gen_salt('bf', 12)`, 관리용 `postgres` DB에만 설치)로 만든다. `demo-analyst`는 예시를 기록할 때만, 그 실행의 무작위 값으로 바꾼다(`T54`) |
| 관리자 API가 필요한데 `admin`이 비활성인 경우의 일시 활성화(`TEMP_ENABLE`) | API를 쓰려면 `admin` 로그인이 필요하다. API 단계를 마치면(실패해도) 곧바로 `DISABLE`로 다시 끈다 |
| API 단계가 실패했을 때 켜진 채 남은 `demo-analyst`의 비활성화(`DISABLE`, `T54`) | 관리자 세션이 깨졌을 수 있다. `finally`에서 `admin`과 같은 방식으로 끈다 |

- 비밀번호·TOTP 시크릿은 환경 변수로만 받고(명령줄 인자로 넘기지 않음) 출력하지 않는다. 해시 계산·비교는 바인드 파라미터로 한다.
- **`admin` 일시 활성 구간의 위험**: 재시드가 API 단계를 해야 할 때(예: 다른 계정이 다시 활성화돼 있음)만 `admin`이 몇 초 동안 활성이 된다. 그동안 공개 주소에서 `admin` 로그인이 가능하지만 `admin`의 비밀번호는 비공개 무작위 값이고 TOTP 2단계 인증까지 필요하며, 로그인 시도와 TOTP 확인은 속도 제한을 받는다. TOTP 확인의 틀린 코드는 실패 횟수에 들어 5번에 계정이 잠긴다(`T60`). 처음 배포 때는 부트스트랩 직후라 `admin`이 이미 활성이므로 이 구간이 없다(시드가 끝나며 비활성화). 재시드를 피하려면 계정 상태를 손으로 바꾸지 않는다.
- `.env`의 `DEMO_PASSWORD`만 바꾼 경우 재시드는 SQL `SET_PASSWORD` 하나만 하고 `admin`을 켜지 않는다.
- **`demo-analyst` 활성 구간의 위험(`T54`)**: 예시를 기록하는 실행에서만 몇 초 동안 켜진다. 비밀번호는 그 실행이 만든 무작위 값이고 출력·저장하지 않으므로 아무도 모른다. 잠금 제외가 아니어서 대입은 5번에 잠기고 로그인 속도 제한도 받는다. 기록 순서에서 공개 경로(`nginx-waf`)를 닫아 두는 것은 방문자가 예시에 끼어드는 것을 막기 위해서다(3.8의 `T54` 절). 강제 종료(`SIGKILL`, 컨테이너 강제 삭제)로 `finally`가 돌지 못하면 켜진 채 남는다. 그래도 비밀번호는 아무도 모르고, 다음 시드 실행의 기존 단계(공개 계정이 아닌 활성 계정 끄기)가 끈다. 매시 초기화는 계정을 끄지 않는다.

## 6. 문제 해결

| 증상 | 확인 |
|---|---|
| `postgres`가 healthy가 되지 않음 | `logs postgres`에서 `portfolio-init`·`portfolio-restore`·`ERROR` 줄. 빈 비밀번호, `sha256sum -c` 실패, `pg_restore` 오류 중 하나다. 고친 뒤 `down -v` → `up -d --wait` |
| 근거 칸이 "근거를 불러올 수 없음" | `exec dashboard-app wget -qO- http://api:8000/health`가 `{"status":"ok"}`인지, `logs api` |
| 로그인 후 바로 로그아웃되거나 CSRF 오류 | DSM이 HTTPS로 서비스하는지(쿠키가 `Secure`), 시스템 시간이 맞는지 |
| 모든 방문자가 `429`를 같이 받음 | 4.3: nginx가 실제 방문자 IP를 못 받고 있다(DSM `X-Forwarded-For` 확인) |
| `sandbox-reset` 로그에 `does not match the current snapshot` | 새 스냅샷인데 기준선이 옛것이다. 그동안 담당 해제는 계속되고 상태·결정은 되돌지 않는다. `stop sandbox-reset` 뒤 `sandbox-setup --rebuild-baseline`(3.10의 4) |
| `sandbox-reset` 로그에 `lock timeout` | 그 정각에 쓰기가 5초 넘게 잠금을 잡았다. 아무것도 바뀌지 않았고 다음 정각에 다시 한다 |
| `302 Location`에 `http://`나 내부 포트가 붙음 | DSM이 `X-Forwarded-Proto: https`를 보내는지 확인(4.2 사용자 지정 헤더) |
| `up`이 `Pool overlaps with other one on this address space`나 `could not find an available, non-overlapping IPv4 address pool`로 실패 | 스택 서브넷 둘(`T61`) 가운데 하나가 기존 네트워크와 겹친다. `.env`의 `PORTFOLIO_SUBNET`(그때는 `PORTFOLIO_WAF_IP`·`PORTFOLIO_GATEWAY_IP`도) 또는 `PORTFOLIO_DATA_SUBNET`을 겹치지 않는 대역으로 바꾼다(3.1) |
| `api`·`sandbox-reset`·`sandbox-setup`·`demo-seed`가 `postgres` 이름을 찾지 못함(`could not translate host name "postgres"`, `Name or service not known`) | `T61` 전환 중에 새 compose로 서비스 하나만 `--no-deps`로 올려 옛 `postgres`가 `portfolio-data`에 없다. 3.8 `T61` 절의 2단계 순서대로 `postgres`부터 함께 `up`한다 |
| `nginx-waf`에서 `api`·`postgres`에 닿는다(3.8 `T61` 절 확인 12) | `nginx-waf`가 `portfolio-data`에 붙어 있거나 옛 compose로 떠 있다. 3.6의 네트워크 확인으로 붙은 컨테이너를 보고 새 compose로 `nginx-waf`를 다시 만든다 |
| 내부 전용 네트워크를 만들지 못함, 또는 그 줄을 바꿔도 반영되지 않음 | 3.8 `T61` 절의 "`internal`이 NAS에서 문제를 일으킬 때" |
| `T61` 뒤 `postgres`가 healthy가 되지 않고 로그에 `Permission denied`·`must be owned by` | DB 볼륨의 데이터 폴더가 `postgres`(uid 999) 소유가 아니다(이미지가 만든 볼륨이 아니다). 3.8 `T61` 절의 되돌리기로 옛 compose로 돌리고 원인을 본다 |
