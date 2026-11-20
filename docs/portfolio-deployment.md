# 포트폴리오 공개 배포 안내서 (Synology DS920+)

이 문서는 대시보드를 포트폴리오로 공개하는 절차다. 작업자와 사용자는 이 문서만 보고 따라 할 수 있어야 한다.
`https://soc.<DDNS 이름>.synology.me`에서 공개 데모 계정 `demo`(읽기 전용 `VIEWER`, 마스킹 적용)로 로그인해 실제 `zeek_AD` 스냅샷 데이터를 보게 한다.

- 역할 분담: **이 PC**(이미지·스냅샷 준비, 리허설) → **NAS**(작업자가 SSH로 기동) → **DSM**(사용자가 인증서·역방향 프록시 설정) → 공개 주소 확인.
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

리허설(이 PC)에서 측정한 실제 사용량은 네 서비스 합계 약 0.4GiB였다(`handoff/T12/evidence/compose-stats.txt`). 상한 합계 3.5GiB는 NAS 여유 메모리(약 17GB) 안이다.

### 1.1 보안 전제와 설정 요약

- **바깥에 여는 포트는 `nginx-waf` HTTP 하나뿐이고 NAS `127.0.0.1`에만 묶는다.** 그래서 이 포트에 접근할 수 있는 것은 같은 NAS의 DSM 역방향 프록시뿐이다. 아래 전달 헤더(`X-Forwarded-For`, `X-Forwarded-Proto`)를 믿는 근거가 이 전제다. 포트를 `0.0.0.0`이나 LAN 주소에 묶으면 이 전제가 깨진다.
- **클라이언트 IP**: nginx는 `X-Forwarded-For`에서 신뢰 범위(`127.0.0.1`, 스택 서브넷 `PORTFOLIO_SUBNET`) 밖의 가장 오른쪽 주소(DSM이 덧붙인 실제 접속 주소)를 클라이언트 IP로 쓴다(`real_ip_recursive on`). 앱에는 `X-Forwarded-For`를 그 주소 하나로 **덮어써서** 넘기고, 방문자가 붙인 `Forwarded`·`X-Forwarded-Host`·`X-Forwarded-Prefix`·`X-Forwarded-Ssl`은 지운다. 그래서 방문자가 헤더를 꾸며도 감사 로그 IP·속도 제한 키·리다이렉트 주소를 바꿀 수 없다.
- **절대 URL**: 들어온 `X-Forwarded-Proto`가 `https`면 앱에 `https`/`443`을 넘긴다. 그래서 비인증 보호 경로의 `302 Location`이 `https://soc.<DDNS 이름>.synology.me/login`(내부 포트 없음)이 된다. HTTP 리스너는 HTTPS로 리다이렉트하지 않는다(TLS는 DSM이 끝낸다). 스택 내부 8443 리스너(DSM 헤더 없음)에서는 `https` + Host의 포트(`8443`)를 넘겨 리다이렉트가 실제로 열린 `https://nginx-waf:8443/...`을 가리킨다.
- **계정**: `demo`(VIEWER, 허용 캡처 `*`)만 활성. `viewer1`·`analyst1`·`analyst2`·`admin`은 서로 다른 비공개 무작위 비밀번호를 가진 채 비활성이다.
- **로그인 잠금 대신 속도 제한**: 공개 비밀번호 계정은 계정 잠금이 보호 효과 없이 남이 데모를 막는 수단이 되므로 `DASHBOARD_MAX_FAILED_ATTEMPTS=1000000`으로 사실상 끈다(`0`이나 작은 값은 오히려 첫 실패에 잠근다). 대신 nginx가 `POST /api/auth/login`만 클라이언트 IP당 분당 10회 + 버스트 5로 제한하고 넘으면 `429`를 준다(`PORTFOLIO_LOGIN_RATE`, `PORTFOLIO_LOGIN_BURST`).
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
| `docker/portfolio/nginx/*.conf.template` | 포트폴리오 전용 nginx 설정(실제 IP·전달 헤더·속도 제한). `compose.yml`에는 붙지 않는다 |
| `docker/portfolio/seed/seed_demo.py` | 계정 시드(멱등) |
| `scripts/portfolio-snapshot.ps1` | 이 PC에서 `zeekad` DB 스냅샷·매니페스트·비밀값 패턴 검사 |
| `scripts/portfolio-verify.ps1` | 이 PC 리허설(E2E [0]~[8], 재시드, ZAP [9]) |

## 2. 이 PC에서 준비

PowerShell에서 저장소 루트(`C:\Users\pgils\src\zeek_ad_dashboard`)로 이동해 실행한다.

### 2.1 이미지 빌드(최신 기반 이미지로)

```powershell
docker build --pull -t zeek-ad-dashboard-app:local .
docker build --pull -t zeek-ad-dashboard-waf:local docker/nginx-waf
docker pull pgvector/pgvector:0.8.1-pg17
```

- `zeekad-pipeline:dev`(근거 API)는 `zeek_AD` 저장소에서 만든 이미지다. 이 PC에 있는 것을 그대로 쓴다. 다시 만들어야 하면 `zeek_AD` 저장소(WSL `~/src/zeek_AD`)의 안내대로 `docker build -f deploy/pipeline/Dockerfile -t zeekad-pipeline:dev .`를 실행한다(바탕 이미지는 digest로 고정돼 있다).
- 이 PC와 NAS는 모두 `x86_64`라 이미지를 그대로 옮길 수 있다.

### 2.2 스냅샷 내보내기

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/portfolio-snapshot.ps1
```

- 원본은 이 PC의 `zeekad-postgres-1` 컨테이너(`zeek_AD` 운영 DB)다. 컨테이너 안 로컬 소켓 인증(`pg_dump -U postgres`)만 쓰며 `zeek_AD`의 `.env`·비밀번호를 읽지 않고 원본에 쓰지 않는다.
- 결과(`build/portfolio/`, Git 제외): `zeekad.dump`(`pg_dump -Fc`), `zeekad.dump.sha256`, `manifest.json`(SHA-256, 내보낸 시각, 캡처별 `dashboard.latest_incident_queue` 건수 — 덤프 전후로 세어 같을 때만 기록), `source-globals.sql`(역할 비교용, 비밀번호 없음), `secret-scan.txt`(덤프·근거 API 이미지의 비밀값 패턴 위치·건수, 값은 남기지 않음).
- `secret-scan.txt`에서 Slack 웹훅·토큰·API 키처럼 보이는 것이 새로 나오면 배포하지 말고 먼저 확인한다(지우지 않는다).

### 2.3 리허설(NAS와 같은 구성)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/portfolio-verify.ps1 -EvidenceDir handoff/<작업 ID>/evidence
```

- 프로젝트 이름 `zeekad-portfolio-verify`로 같은 `compose.portfolio.yml`을 띄우고, 시드를 두 번 실행한 뒤 DSM을 흉내 낸 요청으로 E2E와 ZAP을 돌리고 `down -v`로 지운다. 비밀값은 실행마다 무작위로 만든다. 실패하면 종료 코드가 0이 아니다.
- 이 PC 메모리가 빠듯해 실행이 중단되면 다시 돌리지 말고 `docker compose -p zeekad-portfolio-verify -f compose.portfolio.yml down -v`로 정리한다.

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
# 이 PC Docker Desktop은 containerd 이미지 저장소라 이 PC의 docker image inspect .Id(매니페스트·인덱스 digest)는
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
- 리허설(2.3)과 `docker save` 사이에 이미지를 다시 빌드하거나 받지 않는다. 그래야 리허설한 이미지가 NAS로 간다(이 PC 안의 동일성은 `docker image inspect --format '{{.Id}}'`를 리허설 전후·`docker save` 뒤에 기록해 비교한다).
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

## 3. NAS에서 배포 (작업자, SSH)

NAS: `ssh psdev93@192.168.50.146`(키 인증), Docker는 `/usr/local/bin/docker`(`psdev93`은 `docker` 그룹이라 sudo 불필요). 아래 명령은 NAS 셸에서 실행한다.

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
# 포트 18480이 비어 있는지(아무것도 나오지 않아야 한다). 18080은 nexus-portal이 쓴다.
netstat -tln 2>/dev/null | grep -E ':18480\b' || echo "18480 free"
# 배포 폴더를 sudo 없이 만들 수 있는지(/volume1/docker 쓰기 권한)
ls -ld /volume1/docker; test -w /volume1/docker && echo "volume1/docker writable"
free -m; df -h /volume1
```

이 PC(PowerShell)에서 기존 포트폴리오 응답을 기록해 둔다(배포·DSM 설정 뒤 같은지 비교). 공유기에 NAT 루프백이 없으면 이 PC에서 공개 IP로는 접속되지 않으므로 `--resolve`로 NAS의 DSM `443`에 직접 붙는다. 이 값은 `--resolve` 경로가 동작한다는 근거도 된다.

```powershell
curl.exe -s -o NUL -w "%{http_code}" --resolve <DDNS 이름>.synology.me:443:192.168.50.146 https://<DDNS 이름>.synology.me/
```

- **서브넷 겹침 확인**: `networks-before.txt`에 `10.203.48.0/24`와 겹치는 대역이 있으면 `.env`의 `PORTFOLIO_SUBNET`을 겹치지 않는 대역(예: `10.203.49.0/24`)으로 바꾼다. 이 값 하나가 Compose 네트워크와 nginx 신뢰 범위를 함께 바꾼다.
- DS920+ DSM 7.3.2(Container Manager)에서는 `docker compose`(v2.20.1)가 동작한다(`T13` 확인). `docker-compose`로 바꿀 필요 없다.
- 이 절부터의 NAS 블록(`sh`)은 **NAS 셸 안에서** 실행한다(`ssh psdev93@192.168.50.146`로 들어가서 붙여 넣거나, 이 PC의 Git Bash에서 `ssh ... 'bash -s' <<'EOF' ... EOF`). 이 PC의 Windows PowerShell 5.1에서 `ssh <NAS> '<여러 명령>'`처럼 한 줄 인자로 넘기면 인자 안의 큰따옴표가 지워져(`printf "\n"` → `printf n`) 결과가 달라진다(`T13`에서 겪음).

### 3.2 폴더와 파일 전송

NAS:

```sh
mkdir -p /volume1/docker/zeekad-portfolio/snapshot /volume1/docker/zeekad-portfolio/images /volume1/docker/zeekad-portfolio/docker
chmod 700 /volume1/docker/zeekad-portfolio
```

이 PC(PowerShell, 저장소 루트):

```powershell
$nas = "psdev93@192.168.50.146"; $dst = "/volume1/docker/zeekad-portfolio"
# DSM은 SFTP가 꺼져 있어 기본 scp(SFTP 모드)가 'subsystem request failed'로 실패한다. -O(기존 SCP 프로토콜)를 쓴다(T13 확인).
scp -O compose.portfolio.yml .env.portfolio.example "${nas}:${dst}/"
scp -O -r docker/portfolio "${nas}:${dst}/docker/"
scp -O build/portfolio/zeekad.dump build/portfolio/zeekad.dump.sha256 build/portfolio/manifest.json "${nas}:${dst}/snapshot/"
# PowerShell은 네이티브 명령 인자의 *.tar를 펼치지 않을 수 있으므로 파일 이름을 하나씩 적는다.
scp -O build/portfolio-images/zeek-ad-dashboard-app.tar build/portfolio-images/zeek-ad-dashboard-waf.tar build/portfolio-images/zeekad-pipeline.tar build/portfolio-images/pgvector-pg17.tar build/portfolio-images/images.sha256 build/portfolio-images/image-ids.txt "${nas}:${dst}/images/"
```

- PowerShell 5.1 파이프(`tar | ssh`, `docker save | ssh`)는 바이트를 문자열로 바꿔 깨뜨리므로 쓰지 않는다. 파일은 `scp`로만 보낸다.
- 작업 트리의 `.env.portfolio.example`·`compose.portfolio.yml`·`seed_demo.py`·nginx 템플릿은 Windows에서 CRLF로 체크아웃돼 그대로 전송된다(`*.sh`만 `.gitattributes`로 LF). Compose·nginx·`python`은 CRLF여도 동작하지만, 3.4의 `.env` 작성 스크립트는 줄 끝 `\r`을 떼야 한다(스크립트에 들어 있다).

NAS에서 스냅샷 권한과 무결성 확인:

```sh
cd /volume1/docker/zeekad-portfolio
# snapshot/은 chmod 700 이전에 만들어져 /volume1/docker의 Synology ACL을 상속받는다(psdev93만 허용).
# 그러면 컨테이너 안 postgres(uid 999)가 덤프를 읽지 못해 복원이 'zeekad.dump ... is missing'으로 실패한다(T13에서 겪음).
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
    BOOTSTRAP_VIEWER1_PASSWORD=|BOOTSTRAP_ANALYST1_PASSWORD=|BOOTSTRAP_ANALYST2_PASSWORD=|BOOTSTRAP_ADMIN_PASSWORD=)
      v=$(gen); printf '%s%s\n' "$line" "$v" ;;
    BOOTSTRAP_ADMIN_TOTP_SECRET=)
      v=$(tr -dc 'A-Z2-7' </dev/urandom | head -c 32); printf '%s%s\n' "$line" "$v" ;;
    PORTFOLIO_SERVER_NAME=*)
      printf '%s\n' 'PORTFOLIO_SERVER_NAME=soc.<DDNS 이름>.synology.me' ;;
    *) printf '%s\n' "$line" ;;
  esac
done < .env.portfolio.example > .env
unset v; chmod 600 .env
# 비어 있는 비밀값이 없어야 한다(DEMO_PASSWORD만 남는다). 값은 출력하지 않는다.
grep -E '^[A-Z0-9_]*(PASSWORD|SECRET)=$' .env | cut -d= -f1
```

`DEMO_PASSWORD`는 이 PC에서 만들어 파일로 넣는다(값을 명령줄 인자·화면에 내지 않는다). **이 단계(파일 전송과 아래 'NAS:' 블록)는 사용자가 한다.** 에이전트 세션은 `.env`를 읽거나 쓰는 명령이 이 PC의 guard 훅에 막힌다(`T13`). 'NAS:' 블록은 NAS 셸 안에서 실행한다(3.1의 주의). 이 PC(PowerShell, 저장소 루트):

```powershell
# 영숫자 20자 무작위. handoff/<작업 ID>/는 Git 제외 경로다. 사용자가 이 값을 포트폴리오 글에 옮겨 적는다.
$c = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'; $b = New-Object byte[] 20
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
[IO.File]::WriteAllText("$PWD/handoff/<작업 ID>/demo-password.txt", (-join ($b | ForEach-Object { $c[$_ % $c.Length] })))   # 줄바꿈 없이
ssh psdev93@192.168.50.146 'umask 077; mkdir -p ~/zeekad-portfolio-check/tmp'
scp -O handoff/<작업 ID>/demo-password.txt psdev93@192.168.50.146:zeekad-portfolio-check/tmp/demo-password.txt
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

- `DEMO_PASSWORD`는 포트폴리오 글에 공개할 값이다. 저장소·문서에는 적지 않는다. 나중에 바꾸려면 같은 방법으로 `.env`의 줄을 바꾸고 시드를 다시 실행한다(5절: `SET_PASSWORD` 하나만 한다).
- 다른 비밀값(DB 비밀번호, 비활성 계정 비밀번호, `BOOTSTRAP_ADMIN_TOTP_SECRET`)은 출력하거나 다른 곳에 옮겨 적지 않는다. 운영 중 필요한 것은 시드 재실행뿐이며 시드는 `.env`를 읽는다.
- 비밀값이 비어 있으면 기동되지 않는다: PostgreSQL 이미지가 빈 `POSTGRES_SUPERUSER_PASSWORD`로 초기화를 거부하고, `01-roles-databases.sh`가 빈 로그인 역할 비밀번호로 초기화를 멈춘다(그러면 `postgres`가 healthy가 되지 않아 `api`·`dashboard-app`·`nginx-waf`도 뜨지 않는다). 시드는 빈 `DEMO_PASSWORD`·부트스트랩 비밀번호·TOTP 시크릿이면 아무것도 하지 않고 끝난다. 부트스트랩 비밀번호가 빈 계정은 애초에 만들어지지 않는다.
- 부트스트랩 계정은 `users` 표가 빈 첫 기동 때만 만들어진다. 첫 기동 뒤에 `BOOTSTRAP_*` 값을 바꿔도 이미 있는 계정 비밀번호는 바뀌지 않는다(바꾸려면 3.9의 초기화 재배포).

### 3.5 기동과 계정 시드

```sh
cd /volume1/docker/zeekad-portfolio
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env up -d --wait
docker compose -p zeekad-portfolio -f compose.portfolio.yml ps
docker compose -p zeekad-portfolio -f compose.portfolio.yml logs postgres | grep portfolio-restore   # "portfolio-restore: done" 확인, pg_restore 오류 없음
# 계정 시드: 첫 실행은 RESULT: CHANGED, 두 번째 실행은 RESULT: NO_CHANGES 이어야 한다.
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env --profile seed run --rm demo-seed
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env --profile seed run --rm demo-seed
```

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

이 PC(LAN)에서 직접 접근이 막혀 있는지: `curl.exe -m 5 http://192.168.50.146:18480/login`이 연결 실패여야 한다.

### 3.7 중지·롤백

```sh
cd /volume1/docker/zeekad-portfolio
docker compose -p zeekad-portfolio -f compose.portfolio.yml stop              # 잠시 멈춤(데이터 유지)
docker compose -p zeekad-portfolio -f compose.portfolio.yml down              # 컨테이너 제거(DB 볼륨 유지)
docker compose -p zeekad-portfolio -f compose.portfolio.yml down -v           # 완전 제거(DB 볼륨까지)
docker image rm zeek-ad-dashboard-app:local zeek-ad-dashboard-waf:local zeekad-pipeline:dev   # 이미지까지 지울 때(pgvector는 다른 컨테이너가 쓰는지 먼저 확인)
```

- 완전 철거할 때는 DSM 역방향 프록시 규칙(4.2)도 지운다(사용자).
- 이미지를 이전 버전으로 되돌릴 때: 이전 `tar`를 `docker load` 한 뒤 `up -d --wait`(바뀐 서비스만 다시 만든다). 시드는 다시 할 필요가 없다.

### 3.8 이미지 갱신

새 이미지 `tar`를 옮겨 `docker load` → `docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env up -d --wait`. DB 볼륨은 유지되므로 계정·감사 로그가 그대로다.

#### 앱 이미지만 갱신(`dashboard-app` 하나, T16)

대시보드 코드만 바뀌었을 때는 `zeek-ad-dashboard-app:local` 하나만 옮기고 `dashboard-app`만 다시 만든다. 5GB 파이프라인 `tar`는 다시 만들지 않는다. DB 볼륨·`.env`·다른 컨테이너는 그대로 둔다.

이 PC(PowerShell, 저장소 루트). 2.1의 앱 이미지 빌드와 2.3 리허설을 먼저 한다:

```powershell
New-Item -ItemType Directory -Force build/portfolio-images | Out-Null
docker save -o build/portfolio-images/zeek-ad-dashboard-app.tar zeek-ad-dashboard-app:local
if ($LASTEXITCODE -ne 0) { throw "docker save failed" }
# 2.4와 같은 방식(LF UTF-8, tar 안 Config digest). 네 이미지 목록(images.sha256·image-ids.txt)을 덮어쓰지 않게 이름을 따로 쓴다.
$h = (Get-FileHash -Algorithm SHA256 build/portfolio-images/zeek-ad-dashboard-app.tar).Hash.ToLower()
[IO.File]::WriteAllText("$PWD/build/portfolio-images/app-image.sha256", "$h  zeek-ad-dashboard-app.tar`n", [Text.UTF8Encoding]::new($false))
$manifest = (tar -xOf build/portfolio-images/zeek-ad-dashboard-app.tar manifest.json | Out-String) | ConvertFrom-Json
if (@($manifest)[0].Config -notmatch '([0-9a-f]{64})') { throw "Config digest not found" }
[IO.File]::WriteAllText("$PWD/build/portfolio-images/app-image-id.txt", "sha256:$($Matches[1]) zeek-ad-dashboard-app:local`n", [Text.UTF8Encoding]::new($false))
$nas = "psdev93@192.168.50.146"; $dst = "/volume1/docker/zeekad-portfolio"
scp -O build/portfolio-images/zeek-ad-dashboard-app.tar build/portfolio-images/app-image.sha256 build/portfolio-images/app-image-id.txt "${nas}:${dst}/images/"
```

NAS(셸):

```sh
cd /volume1/docker/zeekad-portfolio
mkdir -p ~/zeekad-portfolio-check && C=~/zeekad-portfolio-check
# 1) 전 상태 기록
docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.CreatedAt}}' | sort > $C/app-update-containers-before.txt
docker volume ls > $C/app-update-volumes-before.txt
# 2) 롤백 준비: 지금 dashboard-app이 쓰는 이미지 ID를 남기고 태그로 보존한다
APP=$(docker compose -p zeekad-portfolio -f compose.portfolio.yml ps -q dashboard-app)
OLD=$(docker inspect --format '{{.Image}}' "$APP"); echo "$OLD" > $C/app-update-old-image-id.txt
docker tag "$OLD" zeek-ad-dashboard-app:pre-update
# 3) 무결성 확인 → 적재 → ID 대조
(cd images && sha256sum -c app-image.sha256)
docker load -i images/zeek-ad-dashboard-app.tar
printf '%s %s\n' "$(docker image inspect --format '{{.Id}}' zeek-ad-dashboard-app:local)" zeek-ad-dashboard-app:local | diff - images/app-image-id.txt && echo "app image ID matches"
# 4) dashboard-app만 다시 만든다
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env up -d --wait --no-deps dashboard-app
# 5) 후 상태 기록·비교: dashboard-app 줄만 달라야 하고 볼륨은 같아야 한다
docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.CreatedAt}}' | sort > $C/app-update-containers-after.txt
docker volume ls > $C/app-update-volumes-after.txt
grep -v dashboard-app $C/app-update-containers-before.txt > $C/app-update-others-before.txt
grep -v dashboard-app $C/app-update-containers-after.txt > $C/app-update-others-after.txt
diff $C/app-update-others-before.txt $C/app-update-others-after.txt && echo "other containers unchanged"
diff $C/app-update-volumes-before.txt $C/app-update-volumes-after.txt && echo "volumes unchanged"
```

그 뒤 3.6의 `curl` 확인(`/login` 200)과 4.4의 공개 주소 확인을 한다. `nginx-waf`는 다시 만들지 않으므로, 확인에서 502가 나오면 반복하지 말고 멈춰 원인을 본다.

롤백(`--wait` 실패 또는 확인 실패):

```sh
cd /volume1/docker/zeekad-portfolio
docker tag zeek-ad-dashboard-app:pre-update zeek-ad-dashboard-app:local
docker compose -p zeekad-portfolio -f compose.portfolio.yml --env-file .env up -d --wait --no-deps dashboard-app
docker image inspect --format '{{.Id}}' zeek-ad-dashboard-app:local; cat ~/zeekad-portfolio-check/app-update-old-image-id.txt   # 같아야 한다
```

- 보존 태그 이름은 갱신 작업마다 정한다(T16은 `zeek-ad-dashboard-app:pre-t16`). 확인이 끝나 더 필요 없으면 `docker image rm zeek-ad-dashboard-app:pre-<작업>`으로 지운다(태그만 지워지고 다른 태그가 가리키는 이미지는 남는다).
- 앱 이미지가 바뀌어도 시드는 다시 할 필요가 없다(계정은 DB 볼륨에 있다).

### 3.9 스냅샷 갱신

스냅샷은 DB를 처음 만들 때만 복원된다. 데이터를 새로 바꾸려면 DB 볼륨을 지우고 다시 만든다. 이때 `zeekad_dashboard`(계정·감사 로그)도 새로 만들어진다(공개 데모 데이터는 읽기 전용이라 주기적 리셋은 두지 않는다).

1. 이 PC: `scripts/portfolio-snapshot.ps1` → `secret-scan.txt` 확인 → (권장) `scripts/portfolio-verify.ps1` 리허설.
2. 새 `zeekad.dump`, `zeekad.dump.sha256`, `manifest.json`을 NAS `snapshot/`에 덮어쓰고 `sha256sum -c`.
3. 감사 로그를 남겨 둘 필요가 있으면 먼저 백업한다: `docker compose -p zeekad-portfolio -f compose.portfolio.yml exec -T postgres pg_dump -U postgres -Fc zeekad_dashboard > ~/zeekad_dashboard-$(date +%Y%m%d).dump`.
4. `down -v` → `up -d --wait` → 시드 두 번(3.5) → 3.6 확인.

## 4. DSM 설정 (사용자)

DSM 7.3 기준 메뉴 경로다. `T13`에서 사용자가 이 절의 메뉴 경로와 값 그대로 설정했다.

### 4.1 하위 도메인 인증서

1. **제어판 > 보안 > 인증서 > 추가 > 새 인증서 추가 > Let's Encrypt에서 인증서 얻기**: 도메인 이름에 `soc.<DDNS 이름>.synology.me`를 넣어 발급한다(하위 도메인 전용 인증서).
   - DSM이 `*.<DDNS 이름>.synology.me` SAN을 "잘못된 도메인"으로 거부한 사례가 있다(`T13`). 하위 도메인 전용 인증서로 충분하다.
   - `T13` 발급 결과: `CN=soc.<DDNS 이름>.synology.me`, SAN `DNS:soc.<DDNS 이름>.synology.me`, Let's Encrypt `YE1`, 유효 90일(DSM이 자동 갱신).
2. `soc.<DDNS 이름>.synology.me`가 NAS 공인 IP로 풀리는지 확인한다: 이 PC에서 `nslookup soc.<DDNS 이름>.synology.me`. Synology DDNS의 와일드카드 레코드로 하위 도메인이 같은 IP를 가리킨다(`T13` 확인).

### 4.2 역방향 프록시 규칙

**제어판 > 로그인 포털 > 고급 > 역방향 프록시 > 생성**:

| 항목 | 값 |
|---|---|
| 설명 | `zeekad-soc` |
| 소스 프로토콜 / 호스트 이름 / 포트 | `HTTPS` / `soc.<DDNS 이름>.synology.me` / `443` |
| HSTS 활성화 | 켬 |
| 대상 프로토콜 / 호스트 이름 / 포트 | `HTTP` / `localhost` / `18480` (`.env`의 `PORTFOLIO_HTTP_PORT`) |

- **사용자 지정 헤더는 넣지 않는다.** `T13`에서 기본 규칙(사용자 지정 헤더 없음)이 넘기는 헤더를 `nginx-waf` ModSecurity 감사 로그로 확인했다: `Host`는 소스 호스트 이름, `X-Forwarded-For`는 방문자가 보낸 값 뒤에 실제 접속 IP를 **덧붙인다**(덮어쓰지 않음, 예: `203.0.113.9, 192.168.50.207`), `X-Forwarded-Proto`는 방문자 값과 관계없이 `https`로 **덮어쓴다**, `X-Real-IP`는 실제 접속 IP다. nginx가 가장 오른쪽 비신뢰 주소를 쓰므로(1.1) 방문자가 앞부분을 꾸며도 감사 로그 IP·속도 제한 키·`Location`이 바뀌지 않는다. WebSocket 헤더는 필요 없다.
- `localhost`가 IPv6 `::1`로 풀려 연결되지 않으면 대상 호스트 이름을 `127.0.0.1`로 바꾼다(`T13`에서는 이 문제가 없었다).
- **인증서 연결**: **제어판 > 보안 > 인증서 > 설정**에서 서비스 `soc.<DDNS 이름>.synology.me`에 4.1의 인증서를 고른다.
- DSM은 HSTS를 켜면 `Strict-Transport-Security: max-age=15768000; includeSubdomains; preload`를 붙인다. 앱도 `max-age=31536000 ; includeSubDomains`를 보내므로 응답에 HSTS 헤더가 두 개 있다(동작 영향 없음). DSM 앞단은 `Server: nginx`(버전 없음)를 붙이며 이 스택에서 바꿀 수 없다.
- 공유기·모뎀 포트 포워딩과 기존 포트폴리오(`nexus-portal`)의 역방향 프록시 규칙은 바꾸지 않는다.

### 4.3 DSM이 실제로 보내는 헤더 확인(T13, 작업자)

DSM 규칙을 만든 뒤 외부망(휴대전화 데이터 등)에서 `demo`로 한 번 로그인하고 NAS에서 감사 로그를 본다.

```sh
cd /volume1/docker/zeekad-portfolio
docker compose -p zeekad-portfolio -f compose.portfolio.yml exec -T postgres \
  psql -U postgres -d zeekad_dashboard -c "SELECT occurred_at, actor_username, client_ip FROM audit_logs WHERE action_type='LOGIN_SUCCESS' ORDER BY id DESC LIMIT 3"
```

- `occurred_at`은 UTC다. 사용자가 알려 준 로그인 시각(한국 시간이면 9시간을 뺀다)으로 줄을 구분한다.
- `client_ip`가 방문자 공인 IP면 정상이다. `127.0.0.1`이나 스택 서브넷 게이트웨이(`10.203.48.1`)면 DSM이 `X-Forwarded-For`를 보내지 않는 것이다 → 4.2 규칙의 **사용자 지정 헤더 > 생성**에서 `X-Forwarded-For` = `$proxy_add_x_forwarded_for`, `X-Forwarded-Proto` = `$scheme`을 추가하고 다시 확인한다. 이 경우 속도 제한도 모든 방문자에게 하나의 키로 걸리므로 반드시 고친다(`T13`에서는 필요 없었다).
- `docker compose ... logs nginx-waf`: 접근 로그 줄의 마지막 칸은 받은 `X-Forwarded-For` 원문이다(DSM이 덧붙인 마지막 주소 = 방문자 IP). ModSecurity JSON 로그(`"client_ip"`)는 차단·오류 응답 등 관련 있는 요청만 남으므로 성공한 로그인(200)은 접근 로그로 본다.
- DSM이 넘기는 헤더를 직접 보려면 실패하는 로그인(401) 요청에 `X-E2E-Probe: <표지>` 헤더를 붙여 보내고, ModSecurity JSON 로그에서 그 표지가 있는 줄의 `request.headers`를 본다.

### 4.4 공개 주소 확인 체크리스트(SPEC '완료 기준' 6)

외부망에서 `https://soc.<DDNS 이름>.synology.me`로 확인한다. 리허설에서 같은 항목을 이 PC로 확인한 증거는 `scripts/portfolio-verify.ps1`의 E2E 번호로 적었다.

**같은 LAN(이 PC)에서 확인할 때**: 공유기에 NAT 루프백이 없으면 이 PC에서 공인 IP로는 접속되지 않는다. 대신 `curl.exe --resolve soc.<DDNS 이름>.synology.me:443:192.168.50.146 https://soc.<DDNS 이름>.synology.me/...`로 NAS의 DSM `443`에 직접 붙는다(인증서·역방향 프록시·헤더는 공개 경로와 같다). 브라우저가 필요한 항목은 `curl.exe`의 인증서 검증 성공(`--insecure` 없이 종료 코드 0)과 `Set-Cookie` 속성으로 대신한다. 이 PC의 모든 요청은 같은 클라이언트 IP(이 PC LAN IP)라 로그인 요청 사이에 7초 정도 간격을 두지 않으면 속도 제한(`429`)에 걸린다. 공개 IP 접속 자체와 방문자 공인 IP 기록(4.3)은 외부망(휴대전화 데이터 등)에서만 확인할 수 있다.

- [ ] 브라우저 주소 표시줄에 인증서 경고가 없다(4.1 하위 도메인 인증서). `http://` 접속은 공유기가 `443`만 포워딩하므로 외부에서는 해당 없다.
- [ ] `demo` / 공개 비밀번호로 로그인되고(TOTP 없음) 조사 큐·사건 상세(근거 요약 칸 포함)·보고서·전송 판단·Slack 기록·운영 상태(`feedback_summary`)가 스냅샷 데이터로 보인다. 캡처 9개(`cic17-*` 4, `syn1-*` 4, `lab-20261201`) 건수가 `snapshot/manifest.json`과 같다. (리허설 [2]·[3])
- [ ] IP는 뒤 두 옥텟이 가려져 보인다(`192.168.*.*`). (리허설 [3])
- [ ] `demo`로 상태 전이·검토 결정·`/api/admin/**`가 `403`이다(화면에 쓰기 버튼이 없거나 눌러도 거부). (리허설 [4])
- [ ] `viewer1`·`analyst1`·`analyst2`·`admin`은 로그인되지 않는다(비활성). (리허설 [5])
- [ ] `demo`에 틀린 비밀번호를 여러 번 넣어도 잠기지 않는다. 짧은 시간에 로그인을 많이 시도하면 `429`가 난다. (리허설 [6]·[7])
- [ ] 감사 로그의 로그인 IP가 실제 접속 IP다(4.3). (리허설 [7])
- [ ] `https://soc.<DDNS 이름>.synology.me/api/incidents?asset=%27%20OR%201%3D1--`가 `403`(WAF)이다. XSS(`?asset=%3Cscript%3E`)·경로 탐색(`?asset=../../etc/passwd`)도 `403`. (리허설 [8])
- [ ] 응답 헤더에 `Strict-Transport-Security`(DSM HSTS), `Content-Security-Policy`(`script-src 'self'`, `style-src 'self'`, `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy`가 있고 `Server`에 버전이 없다(DSM 앞단이 `Server: nginx`를 붙인다. 4.2). 예: `curl.exe -sI https://soc.<DDNS 이름>.synology.me/login`. (리허설 [1], HSTS는 공개 주소에서만)
- [ ] 로그인 응답의 `ZEEKAD_SESSION` 쿠키가 `Secure; HttpOnly; SameSite=Lax`다(브라우저 개발자 도구 > 애플리케이션 > 쿠키). (리허설 [2])
- [ ] 로그아웃 상태에서 `https://soc.<DDNS 이름>.synology.me/`에 접속하면 `https://soc.<DDNS 이름>.synology.me/login`으로 간다(주소에 `:8080`·`:18480`·`http://`가 없다). (리허설 [1])
- [ ] LAN에서 `http://192.168.50.146:18480/`로 직접 접근할 수 없다. NAS의 이 스택 포트는 `127.0.0.1:18480` 하나뿐이다. (3.6, 리허설 [0])
- [ ] 같은 NAS의 기존 컨테이너(`nexus-portal` 등)와 기존 포트폴리오 주소가 그대로 동작한다. (3.6)

## 5. 계정 시드의 직접 SQL 단계와 위험

시드(`docker/portfolio/seed/seed_demo.py`)는 먼저 `zeekad_dashboard`를 `dashboard_app`으로 읽어 현재 상태를 확인하고, 이미 목표 상태(`demo` 존재·`VIEWER`·허용 캡처 `*`·표시 이름·활성·잠금 없음·`.env` 비밀번호와 일치, 다른 계정 모두 비활성)면 아무것도 바꾸지 않는다(`RESULT: NO_CHANGES`, 감사 로그 추가 없음). 바꿀 것이 있을 때만 바꾼다.

가능한 단계는 앱 관리자 API로 한다(`admin` 로그인 + `.env`의 `BOOTSTRAP_ADMIN_TOTP_SECRET`으로 계산한 TOTP 코드, 감사 로그 `USER_ADMIN_CHANGE`):
`demo` 생성(`CREATE_USER`), 역할·허용 캡처·표시 이름 수정(`UPDATE_USER`), 활성화·다른 계정 비활성화(`TOGGLE_ENABLED`, 상태를 읽고 필요할 때만 호출), 잠금 해제(`UNLOCK_ACCOUNT`).

API로 할 수 없어 `zeekad_dashboard`에 직접 SQL을 쓰는 단계는 셋이다. 각 SQL은 같은 트랜잭션에서 감사 로그 한 줄(`actor_username=portfolio-seed`, `actor_role=SYSTEM`, `action_type=USER_ADMIN_CHANGE`, `detail_json`에 `operation`·`via: direct SQL`·이유)을 남긴다.

| 단계 | 이유 |
|---|---|
| `admin` 비활성화(`DISABLE`) | `UserAdminService.toggleEnabled`가 로그인한 자기 계정의 비활성화를 막는다 |
| 이미 있는 `demo`의 비밀번호 변경(`SET_PASSWORD`) | 비밀번호 변경 API가 없고 `createUser`는 이미 있는 아이디를 거부한다. 해시는 앱과 같은 BCrypt strength 12를 PostgreSQL `pgcrypto`(`crypt` + `gen_salt('bf', 12)`, 관리용 `postgres` DB에만 설치)로 만든다 |
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
| `302 Location`에 `http://`나 내부 포트가 붙음 | DSM이 `X-Forwarded-Proto: https`를 보내는지 확인(4.2 사용자 지정 헤더) |
