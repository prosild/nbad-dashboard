# zeek_ad_dashboard 보안 검증 보고서

`zeek_ad_dashboard`의 보안 검증을 실제로 돌린 결과와 조치, 남은 위험을 적습니다. 대상은 멀티스테이지 컨테이너 빌드, 앞단 Nginx + ModSecurity(OWASP CRS) WAF, React SPA와 JSON REST API(`/api/**`)를 PostgreSQL 17에 붙여 돌린 E2E, CycloneDX SBOM, Trivy 취약점·설정 스캔, OWASP ZAP 베이스라인 스캔입니다.

## 최근 검증

주요 변경 뒤 아래 검증을 다시 돌립니다. 가장 최근 E2E 실행은 `T49`(2026-11-26, commit `712f173`)입니다. 그 뒤의 변경(`T50`~`T63`)을 포함한 E2E는 통합 작업 `T57`이 돌립니다. 신뢰하지 않는 글자열의 처리(`T63`)는 아래 7절에 적었습니다. 공개 스택 리허설과 NAS 전환 예행은 `T61`(2026-11-26, 로컬 Docker)에서 다시 돌렸습니다(아래 `T61` 두 줄). 공개 주소 확인은 `T49` 앱 이미지 교체(2026-11-26) 뒤 결과입니다. 실행 기록 원본은 저장소 밖에 보관합니다.

| 검증 | 다시 돌리는 방법 | 결과 |
|---|---|---|
| 프론트엔드 타입 검사·Vitest·빌드, Gradle `check`(단위·통합·정적 보안 시험) | `npm --prefix frontend run typecheck`, `run test`, `run build`, `.\gradlew.bat check --rerun-tasks --no-daemon` | 모두 통과(Gradle 시험 271개, Vitest 481개, `T49`. `T44`~`T46`·`T45b`가 더한 인시던트 목록 `hostIp`·`attack` 조건, 묶음 표지, 호스트 위험도, 같은 호스트 인시던트, 조회자 관측 계정 가리기, 현황판 위협 패널 시험과 호스트 위험도·운영 현황 수집원 선택 목록 글 시험, 일곱 화면의 제목 아래에 설명 문장이 없다는 시험, 인시던트 상세의 조치 패널이 머리말과 한 상자 안에 있다는 시험 포함) |
| VMware 구성 E2E(PostgreSQL 17 + WAF + SPA/JSON API, 역할별 권한·IDOR·마스킹·감사 로그) + OWASP ZAP 베이스라인 | `scripts/security-scan.ps1` | 종료 코드 `0`, `T44`~`T46`·`T45b` 기능 `[21]`(인시던트 목록 `hostIp`·`attack` 건수, 묶음 표지, 호스트 위험도 `/api/hosts`, 같은 호스트 인시던트, 현황판 새 집계가 독립 SQL과 같은 조건의 목록 건수와 같음. 조회자가 온전한 주소로 물으면 있는 호스트와 없는 호스트가 같은 `200`·0건. 조회자 응답에 온전한 IPv4와 계정 원문 없음. `*`가 든 호스트 조건과 공백이 든 ATT&CK 조건이 WAF를 지남. 허용 밖 `403`과 IDOR 감사, 형식 오류 `400`), 알림 묶음(허용 캡처 밖 구성원 제외·허용 밖 묶음 머리 식별자 숨김·`thread` 조건 `403`과 IDOR 감사·형식 오류 `400`) `[20]`, 사유·메모 길이 상한 `[17]`·사용자 지정 기간 `[18]`·AI 리포트 근거 새 칸의 조회자 IPv4 마스킹(객체 키 포함) `[19]`·Slack 알림 기록(`text`·`blocks`)의 조회자 IPv4 마스킹 `[4b]` 포함, ZAP High `0`·Medium `0`·Low `0`(허용 예외 `XSRF-TOKEN` 제외)·Informational `4` |
| 공개 스택 리허설(스냅샷 복원, 시드, E2E `[0]`~`[8]`·`[T33]`(체험 계정 초기화, 주기 1분)·`[T25]`·`[T27]`·`[T29]`·`[T32]`·`[T36]`(익명 볼륨·조회 한도·HSTS·빠른 사람 사용 흉내)·`[T39]`(새 캡처 상세의 스레드 표시 칸·조회자 IPv4 마스킹, 숨김 캡처 부모 0, 옛 사건 번호 유지, 숨김 캡처 ID 노출 0)·`[T40]`(알림 묶음 11개의 목록 수와 상세 묶음 칸 = 독립 SQL, 숨김 캡처 구성원 14건 제외, 숨김 캡처 번호 `403`, 응답 시간)·`[T47]`(실제 스냅샷에서 `demo`·`trial-analyst`로 인시던트 목록 `hostIp`·`attack` 건수, 묶음 표지, 호스트 위험도, 같은 호스트 인시던트, 현황판 새 집계 = 독립 SQL·목록 건수, 조회자 응답의 온전한 IPv4·계정 원문·숨김 캡처 ID `0`, 공개 캡처의 IPv6 호스트 주소 `0`건, 전체 기간 인시던트 목록 중앙값 앞 이미지 412ms·새 이미지 396ms), ZAP) | `scripts/portfolio-verify.ps1` | 통과, ZAP High `0`·Medium `0`·Low `0`·Informational `4` |
| 공개 주소 확인(`demo` 로그인·마스킹·허용 캡처·숨김 캡처 `403`·보안 헤더·쿠키 속성 등) | [`docs/portfolio-deployment.md`](portfolio-deployment.md) 4.4 체크리스트(WAF 차단·깨진 XML 본문 `400`·전달 헤더 신뢰 포함) | PASS `250`, FAIL `0`. `[10f]` 전체 기간 인시던트 목록 응답 최댓값은 980ms입니다(기준 1초, `T48` 1,009ms). 반영 뒤 정각 초기화는 OK입니다. 확인 항목: 배포된 화면의 CSS에 인시던트 상세 조치 패널의 새 위치 규칙이 있고 옛 고정 값은 `0`건 `[T49]`(따로 돌린 브라우저 확인 13항목도 통과: 공개 주소의 상세 화면에서 조치 패널이 폭 1280·1600px, 스크롤 세 위치 모두 머리말 아래 24px에 붙음), 배포 화면 번들에 없앤 화면 제목 아래 설명 문장 일곱이 `0`건 `[T48]`, `T44`~`T46`·`T45b` 기능 `[T47]`(배포 화면 번들의 새 화면 글, `demo`·`trial-analyst`로 인시던트 목록 `hostIp`·`attack` 건수·묶음 표지·호스트 위험도·같은 호스트 인시던트·현황판 새 집계 = NAS 독립 SQL과 같은 조건의 목록 건수, `*`가 든 호스트 조건과 공백이 든 ATT&CK 조건이 WAF를 지남, 조회자 응답의 온전한 IPv4·계정 원문·숨김 캡처 ID `0`, 호스트 위험도·같은 호스트 인시던트·현황판·운영 현황 응답 최댓값 681ms), 배포 화면 번들의 "전체 기간" 링크·템플릿 리포트 문구와 `demo` 현황판 24시간에서 가져온 데이터 8개가 기간 안 0건·마지막 탐지 기간 밖이고 그 캡처의 전체 기간 목록이 1건 이상 `[T43]`, 배포 화면 번들의 조치 막힘 이유·운영 현황 "불러오지 못했습니다" 문구 `[T42]`, 요청 제한·최신 아님 안내 문구 `[T41]`, 알림 묶음 11개의 목록 수·`lab-20261122` 상세 88건의 묶음 칸 = 독립 SQL, 숨김 캡처 번호 `403`, 조회자 IPv4 `0`, 응답 시간 `[T40]`, 사용자 지정 기간 `[T34]`, 이전·다음 이동 = 목록 순서·응답 시간 `[T35]`, HSTS 하나·조회 한도·볼륨·초기화 `[T36]`, 리포트 있는 상세 112건의 근거 새 칸·조회자 IPv4 `0`·응답 시간 `[T37]`, Slack 기록 있는 상세 153건의 알림 기록 조회자 IPv4 `0` `[T38]`, `lab-20261122` 상세 88건 전부 200·조회자 IPv4 `0`·스레드 답글 117·채널 재알림 21, 옛 인시던트 번호 2,192건 그대로 `[T39]` |
| 감사 로그 보관 기한의 SQL을 PostgreSQL에서 직접(`T58`. Gradle 시험은 H2라 이 SQL을 보지 못합니다) | `scripts/audit-retention-check.ps1`(일회용 PostgreSQL 컨테이너에 `V1`~`V4`를 앱 계정으로 적용하고 저장소의 `sandbox-setup.sh`·`sandbox-reset.sh`를 그대로 실행) | 2026-11-26, PostgreSQL 17.8: SQL 단언 59건, 설정 도구와 초기화 서비스 24건, 하루 한 번 판정 47건 모두 통과. E2E `[8b]`와 리허설 `[T58a]`~`[T58c]`는 스크립트에 넣었고 실행 결과는 다음 통합 검증 때 적습니다 |
| WAF 감사 로그에 남는 값을 일회용 컨테이너에서 직접(`T59`) | `scripts/waf-audit-log-check.ps1`(저장소의 WAF 이미지와 대역 서버를 전용 Docker 네트워크에 띄우고 표식을 쿠키·헤더·본문·응답에 실어 보낸 뒤 컨테이너 전체 출력에서 셈) | 2026-11-26, libmodsecurity 3.0.17 + CRS 4.30.0: 고친 뒤 단언 35개 모두 통과(표식 여섯 모두 0번). 고치기 전 이미지는 7개 실패(세션 쿠키·CSRF 토큰·`Set-Cookie`·`text/html` 응답 본문이 감사 줄에 남음). 6절. E2E `[23]`과 리허설 `[8b]`는 스크립트에 넣었고 실행 결과는 다음 통합 검증 때 적습니다 |
| 관리자 TOTP 확인의 실패 제한(`T60`) | `.\gradlew.bat test --tests "*T60TotpFailureLimitIntegrationTest"`(H2), Vitest `t60TotpLock.test.tsx` | 2026-11-26: 통합 시험 16건 통과(틀린 코드마다 `400`과 감사, 5번째에서 `423`·잠금·세션 종료, 잠금 전에 로그인해 둔 다른 세션의 맞는 코드도 `423`, 동시에 보낸 틀린 코드 20건 가운데 판정받은 것 5건과 잠금 감사 1건, 비밀번호 재로그인으로 횟수가 되돌아가지 않음, 잠금이 만료된 뒤에는 1부터). 화면 시험 3건 통과. 이 SQL은 PostgreSQL에서 아직 돌리지 않았습니다. E2E `[T60a]`~`[T60f]`와 리허설 `[T60]`은 스크립트에 넣었고 실행 결과는 다음 통합 검증 때 적습니다 |
| 종결 건 다시 열기(`T53`) | `.\gradlew.bat test --tests "*T53*"`(H2 대역과 쓰기 매퍼 대역), Vitest `t53Reopen.test.tsx`. 실제 대상: 작업 기록의 확인 도구(저장소 밖)로 실제 스냅샷 + zeek_AD migration 018, 검증 스택 대역 | 2026-11-26: 통합·단위 시험 20건, 화면 시험 13건 통과(성공·거부 경우, 동시 두 번 가운데 하나만 성공, 다시 연 뒤의 담당·정탐 재종결·처리 시간·판정 집계·우선순위, 함수가 없거나 권한이 없을 때 `501`이고 DB 문구 없음). 실제 대상 확인(로컬 Docker, commit `ac4fe82`로 빌드한 앱 이미지): 2026-11-23 스냅샷 + zeek_AD migration 018에서 27개 통과(새 볼륨의 셋째 initdb 스크립트가 함수를 만듦, 소유 `zeekad_owner`·실행 권한은 `dashboard_rw`뿐·`dashboard_rw`가 실행할 수 있는 함수 셋, 다시 실행하면 건너뜀, 사본 sha256 = zeek_AD 파일, 체험 분석가의 다시 열기 `200`·틀린 판정 `409`·조회자 `403`·다시 종결, 초기화 한 번 뒤 기준선, 함수를 지우면 `501` `REOPEN_UNAVAILABLE`이고 원인은 서버 로그에만, 깨진 사본이면 초기화가 멈추고 다시 시작해도 healthy가 되지 않음). 검증 스택 대역(`postgres:17-alpine`, 일회용)은 계약의 경우 30개 통과. E2E `[T53a]`~`[T53e]`와 리허설 `[T53a]`~`[T53d]`는 스크립트에 넣었고 실행 결과는 다음 통합 검증 때 적습니다 |
| 공개 스택 리허설의 네트워크 둘·컨테이너 권한·상태 확인 감사 줄(`T61`) | `scripts/portfolio-verify.ps1`의 `[T61a]`(붙은 컨테이너·`Internal`·기본 경로)·`[T61b]`(`nginx-waf` 안에서 `api:8000`·`postgres:5432`에 이름과 주소로 TCP 연결 안 됨, 대조 `dashboard-app:8080` 연결)·`[T61c]`(`api`에서 WAF로 연결 안 됨)·`[T61d]`(상주 다섯 PID 1의 `CapBnd` 0·`NoNewPrivs` 1, `postgres` `Config.User`)·`[T61e]`(상태 확인 감사 줄 0, 대조로 숫자 주소 `Host` 표식 줄은 남음). `portfolio-net` 일회용 컨테이너로 옮긴 `[T32c]`·`[T36b]`, ZAP `[9]` | 통과(2026-11-26, 로컬 Docker, 이미지는 commit `56ecb86`으로 빌드). `[T61a]`~`[T61e]`, `[T32a]`~`[T32d]`, `[T36b]`, ZAP `[9]`(High·Medium·Low 0, 허용 예외 10010 `XSRF-TOKEN`만) 모두 통과. `nginx-waf`에서 `api`·`postgres`는 이름을 찾지 못하고(`bad address`, 또는 이름 찾기가 5초 상한에 걸림) `portfolio-data` 주소로는 연결 시간 초과, 대조 `dashboard-app:8080`은 연결됨. `api`에서 WAF는 이름 찾기 실패·`Network is unreachable`. 상주 다섯 모두 `CapBnd`·`CapEff` 0, `NoNewPrivs` 1이고 `postgres`는 `postgres` 계정으로 시작. 상태 확인 감사 줄 0(뜬 지 70초, 상태 확인 5번), 대조로 보낸 숫자 주소 `Host` 표식 줄은 1(`920350`). 고치기 전 구성(지금 NAS와 같은 판)에서는 같은 확인이 실패: WAF에서 `api:8000`·`postgres:5432` 연결됨, `postgres`·`nginx-waf`의 `CapBnd` `00000000a80425fb`, 상태 확인 감사 줄 70초에 7줄 |
| NAS 전환 예행(갱신 리허설, `T61`): 지금 NAS에 떠 있는 구성 → 이 구성을 같은 DB 볼륨 위에서 `down` 없이 넘기고 되돌리기 | 작업 기록의 갱신 리허설 도구(저장소 밖, 로컬 Docker. NAS와 Compose 판이 다르다). 순서와 단언은 [`docs/portfolio-deployment.md`](portfolio-deployment.md) 3.8 `T61` 절(다섯 컨테이너 healthy, DB 볼륨·행 수 그대로, `portfolio-net`의 ID·만든 시각·게이트웨이와 WAF 주소 그대로, `portfolio-data` 생성·`Internal`, 되돌린 뒤 `portfolio-data` 지우기) | 통과(2026-11-26, 로컬 Docker Compose v5.6.0. NAS의 옛 Compose가 아님). 37개 확인 통과. 옛 구성(`09310ce`의 compose: NAS에 반영한 파일과 sha256 같음, 앱 `t49`)에 시드·초기화 설정을 한 뒤 넘김: `portfolio-net`의 ID·만든 시각·게이트웨이와 WAF 주소 그대로, DB 볼륨 그대로, 옛 표 32개의 행 수 같음(앱 DB에 새 migration `V4`·`V5` 기록과 새 표 둘만 더해짐), `postgres`가 옛 구성이 만든 볼륨에서 `postgres` 계정·capability 없이 healthy, 고아 컨테이너 0, 앱 → 근거 API와 DSM 흉내 로그인 화면 `200`. 되돌리기: 옛 앱이 `V5`까지 적용된 DB에서 뜨고(Flyway 경고만) 행 수가 같으며 `portfolio-data`를 지울 수 있음. 다른 프로젝트의 컨테이너·볼륨·네트워크는 앞뒤 같음 |
| 분석이 끝난 예시 셋을 시드가 앱 API로 기록(`T54`) | 정적 시험 `t54SeedRecordsExamplesOnlyThroughTheAppApiAndKeepsNoNewSecret`(Gradle `check`). 일회용 공개 스택 일부(`postgres`·`api`·`dashboard-app` + 실제 공개 스냅샷)에서 시드·`sandbox-setup`·`sandbox-reset --once`·조회자 상세를 보는 집중 확인 | 정적 시험 통과: 시드가 SQL로 쓰는 표는 `users`와 감사 행뿐이고(zeek_AD 표·대응 조치·담당 표에 쓰는 SQL 없음), 로그에 비밀번호·예시 글이 없고, 자료 파일의 ID 꼴·판정이 맞고, `demo-seed`에 더한 값은 읽기 계정 하나다. 집중 확인(2026-11-26, 새 볼륨 두 번): 시드 전 신규·담당 없음, 시드 1차가 셋을 기록(이력 순서 착수 → 자동 담당 → (정탐) 조치 → 해제 → 종결, 담당자 있는 행 0, `demo-analyst` 비활성), 2차는 로그인 없이 `NO_CHANGES`, 기준선 = 시드 전 + 상태 3·이력 6, 체험 계정이 다른 건을 착수하고 예시에 조치를 덧붙여도 한 번의 초기화로 되돌아가고 예시는 그대로, 조회자 응답에 온전한 IPv4와 조치 메모 없음, 어긋난 상태면 아무것도 바꾸지 않고 실패, 없는 ID는 건너뜀 — 단언 30개 모두 통과. 첫 실행에서 시드가 실제 스냅샷의 계약 뷰(인시던트 × 작업마다 한 행, 상태가 없으면 `open`)를 상태 행으로 읽어 신규 건을 실패로 판정한 결함을 찾아 고쳤습니다(검증용 스키마의 뷰는 상태 행만 내서 시험이 잡지 못했다). 리허설 `[T54]`·`[T54a]`~`[T54d]`는 스크립트에 넣었고 실행 결과는 다음 통합 검증 때 적습니다 |

Trivy는 의존성이나 Dockerfile이 바뀔 때 돌립니다. 마지막 실행은 `T49`(2026-11-26, E2E 안)이고 결과는 `T31`(2026-11-22) 때와 같습니다.

| 스캔 대상 | CRITICAL | HIGH | MEDIUM | 내용 |
|---|---:|---:|---:|---|
| SBOM(`bom.json`) | 2 | 0 | 0 | `spring-webmvc` 2건(아래 4.3의 1) |
| `frontend/package-lock.json`, Dockerfile 2개 | 0 | 0 | 0 | 오설정 0건 |
| 앱 이미지 OS / `app.jar` | 0 / 2 | 0 / 0 | 0 / 1 | `spring-webmvc` 2건, `ognl` 1건(4.3의 1·2) |
| WAF 이미지 | 0 | 0 | 0 | 0건. 직전 실행(`T25`)의 `libxml2` `CVE-2026-86144` HIGH 1건은 고정 기반 위에서 `libxml2`만 `2.13.9-r3`으로 올려 해소했습니다. 상류 최신 기반 이미지에도 취약한 `2.13.9-r2`가 들어 있어 다시 빌드만으로는 해소되지 않았습니다([`docs/deployment-guide.md`](deployment-guide.md) 4.1) |

## 처음 정리한 검증 (`T10`, 2026-11-20)

아래 1~5절은 `T10`에서 처음 정리한 검증입니다. 그 뒤 화면 경로 GET·HEAD는 비인증이어도 SPA 셸 `200`을 주도록 바뀌었습니다(`T27`, [`docs/deployment-guide.md`](deployment-guide.md) 1.3). 3절 표의 "비인증 보호 경로 `302`"는 그때의 결과입니다.

- 실행: `scripts/security-scan.ps1` (commit `e565082`, 2026-11-20 11:17~11:23 KST, 종료 코드 `0`, 실행 기록 `security-scan-run-4.txt`는 저장소 밖 보관)
- 실행 전 `docker compose -f compose.yml -f docker/verify/compose.verify.yml build --pull --no-cache`로 이미지 빌드 캐시를 비웠습니다(아래 4.1 참고).

---

## 1. 검증 환경 및 실행 명령

| 항목 | 실행 명령 | 비고 |
|---|---|---|
| 프론트엔드 타입·테스트·빌드 | `npm --prefix frontend run typecheck`, `run test`, `run build` | Vitest, Vite 프로덕션 번들 |
| 정적 검사·단위/통합 테스트 | `.\gradlew.bat check --rerun-tasks --no-daemon` | MyBatis `#{}` 전용, 보안 헤더, RBAC/IDOR, JSON API·SPA 보안 계약, Docker/WAF 정적 검증 |
| CycloneDX SBOM 생성 | `.\gradlew.bat cyclonedxBom` | `build/reports/bom.json`, `build/reports/bom.xml` 생성 |
| Docker Compose 유효성 | `docker compose -f compose.yml -f docker/verify/compose.verify.yml config -q` | 검증 오버라이드 포함 |
| 통합 보안 검증 스크립트 | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/security-scan.ps1 -EvidenceDir "build/security-evidence"` | SBOM → 이미지 빌드 → Trivy(SBOM/FS/이미지) → PG17 + WAF + SPA/JSON API E2E → OWASP ZAP 일괄 실행 후 `down -v` 정리 |

> [!NOTE]
> 대용량 원본 스캔 리포트(`trivy-*.json`, `zap-baseline.html/json`, `bom.json/xml`)는 `.gitignore`에 등록된 `security-reports/` 경로에 생성되며 Git 저장소에는 포함하지 않습니다.

---

## 2. 빌드·정적 보안·컨테이너 격리 검증

1. **멀티스테이지 `Dockerfile`** (`frontend` `node:24-alpine` → `builder` `eclipse-temurin:17-jdk-alpine` → 런타임 `eclipse-temurin:17-jre-alpine`):
   - Windows에서 만든 `frontend/package-lock.json`으로 Alpine(musl)에서 `npm ci`가 그대로 성공했습니다(lock 파일 재생성 없음).
   - `StaticSecurityAndConfigTest`가 Node 빌드 단계(`npm ci`, `npm run build`, `--omit=dev` 미사용), `COPY --from=frontend ... ./frontend/dist`, 마지막 `FROM eclipse-temurin:17-jre-alpine`, 마지막 단계의 `node`·`npm` 부재, `.dockerignore`의 `frontend/node_modules`·`frontend/dist`, `compose.yml` `ALLOWED_METHODS`(`PUT` 포함, `DELETE`·`PATCH` 미포함)와 WAF 완화값(`DetectionOnly`, 엔진 `off`, `PARANOIA` 0) 부재를 확인합니다.
2. **프로덕션 `bootJar`·런타임 이미지 확인** (E2E [0], 실행 중인 `dashboard-app` 컨테이너):
   - `unzip -l /app/app.jar`: H2·`application-test.yml` 없음(`NO_H2_OR_TEST_YML`), `BOOT-INF/classes/static/index.html`과 `BOOT-INF/classes/static/assets/*.js`·`*.css` 있음.
   - `uid=100 user=appuser`(non-root), `node`·`npm`·`node_modules` 없음, `javac` 없음(JRE), 이미지 `JAVA_VERSION=jdk-17.0.21+9`, `NODE_VERSION` 없음.
3. **네트워크·권한 격리**:
   - `dashboard-app`은 `expose: ["8080"]`만 선언하고 호스트 포트를 직접 열지 않습니다. `nginx-waf`는 `nginx`(non-root)로 실행되며 TLS 인증서를 런타임에 생성하므로 이미지와 Git에 개인키가 남지 않습니다.

---

## 3. PostgreSQL 17 + Nginx ModSecurity WAF + SPA/JSON API 실측 E2E 검증

`compose.yml` + `docker/verify/compose.verify.yml`(`postgres:17-alpine`) 기동 후 외부 HTTPS(`https://127.0.0.1:18443`) 및 HTTP(`http://127.0.0.1:18080`)로 실측했습니다(실행 기록 `waf-e2e-verification.txt`, 저장소 밖 보관). 로그인은 `GET /api/auth/csrf`로 받은 `XSRF-TOKEN`을 `X-XSRF-TOKEN` 헤더에 넣은 JSON `POST /api/auth/login`으로 합니다. 응답은 JSON 필드로 판정합니다. 쓰기 요청마다 curl 쿠키 파일의 최신 토큰을 읽습니다.

| 검증 항목 | 요청/대상 | 실측 결과 |
|---|---|---|
| [0] 이미지·jar | `dashboard-app` 컨테이너 | 위 2.2와 같음 |
| [1] HTTP → HTTPS | `GET http://127.0.0.1:18080/login` | `301`, `Location: https://127.0.0.1:18443/login` |
| [1] SPA 셸·보안 헤더 | 비인증 `GET /login` | `200`, `<div id="root"></div>`·`src="/assets/...js"`, CSP `script-src 'self'; style-src 'self'; ... frame-ancestors 'none'`(`unsafe-inline`·`unsafe-eval` 없음), `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Strict-Transport-Security`, `Server: nginx`·와일드카드 CORS 없음 |
| [1] 비인증 보호 경로 | `GET /`, `GET /incidents/101/rank/1` | 모두 `302`, `Location: https://127.0.0.1:18443/login` |
| [1] 정적 자산 | `index.html`이 가리키는 `/assets/index-*.js`, `/assets/index-*.css` | 비인증 `200`, `text/javascript`·`text/css`, `nosniff` |
| [1] 운영 화면 고정 문구 | 배포된 JS 번들 | `분석가 결론 집계`, `놓친 공격(재현율)`, `전체 (all)` 있음, `정확도` 없음 (판정 방식은 아래 주석) |
| [2] `/api/**` 비폴백 | 비인증 `GET /api/incidents`, `GET /api/does-not-exist/e2e` / `viewer1` 세션 `GET /api/does-not-exist/e2e` | `401` JSON `UNAUTHENTICATED` / `404` JSON `NOT_FOUND`, 어느 경우도 `index.html` 아님 |
| [3] WAF 쿼리 SQLi | `GET /api/incidents?asset=' OR 1=1--` | `403`(nginx HTML, 앱 JSON 아님), 감사 로그 규칙 `942100`, `949110` |
| [3] WAF 쿼리 XSS | `GET /api/incidents?asset=<script>alert(1)</script>` | `403`, 규칙 `941100`, `941110`, `941160`, `941390`, `949110` |
| [3] WAF 쿼리 경로 탐색 | `GET /api/incidents?asset=../../etc/passwd` | `403`, 규칙 `930100`, `930110`, `930120`, `932160`, `949110` (참고: URI `/../../etc/passwd`는 Nginx `400`) |
| [3] WAF JSON 본문 SQLi·XSS | 유효한 `XSRF-TOKEN` 쿠키 + `X-XSRF-TOKEN` 헤더의 `POST /api/auth/login` (`username`에 페이로드) | 둘 다 `403`, 규칙 `942100`·`949110` / `941100`·`941110`·`941160`·`941390`·`949110`. 같은 토큰의 정상 본문은 앱까지 도달해 `401` `INVALID_CREDENTIALS` |
| [3] Actuator 비노출 | `GET /actuator/health`, `/actuator/env` | 둘 다 `403` |
| [4] `viewer1`(`cic17-*`) | 로그인·조회·쓰기 | `ZEEKAD_SESSION` `Secure; HttpOnly; SameSite=Lax`. `cic17-wed` 큐·상세 `hostIp` `192.168.*.*`(본문에 `192.168.10.50` 없음). `101/rank/1` Slack `threadRoleLabel` `머리 알림`·`머리 사건 후속 답글`, `replyBroadcast=true` 1건, 스레드 묶음 1개. `101/rank/2` `스레드 답글`의 `threadParent`도 마스킹. `201/rank/1` `403`. `/api/operations` `feedbackSummaries`는 `cic17-wed`만, `allModel` 행 `precisionSummaryText` `정밀도 0.00, 결론 1/3 (33.3%)`, 본문에 `syn1-tue`·`lab-20261118`·`lab-fusion-v2`·`정확도` 없음. 상태 전이·`/api/reviews/decide`·상세 `review-decision`·`GET /api/admin/users` 모두 `403` |
| [5] `analyst1`(`cic17-*`) | 조회·전이·검토 결정 | `syn1-tue`·`lab-20261118` 큐 및 `job 201` 검토 결정 `403`. `101/rank/1` 원문 `192.168.10.50`. `open → investigating` 전이 `200` 후 `currentStatus=investigating`. `101/rank/2` `confirm` `200` 후 `analystReview.reviewAction=confirm`, `resumeStatusLabel=반영 중`. 같은 사건 중복 결정은 `409` JSON `CONFLICT`(PostgreSQL `22023`, 메시지에 새로고침 안내). `/api/operations` `cic17-wed`만 |
| [6] `admin`(`*`) TOTP·v2.1 | TOTP 전후 | 1차 로그인 `nextRoute=/login/totp`, TOTP 전 `GET /api/incidents` `403` `TOTP_VERIFICATION_REQUIRED`, `POST /api/auth/totp/verify` `200`. `lab-20261118` 큐 `selectedJob=502`(`captureJobs`에 `501`), rank 2 `zeekadReportJobId=501`·검토 대기, rank 1 보고서 없음(`502/rank/1` `report.present=false`, `10.20.0.25`). `502/rank/2` `windowRatioLabel` `5 / 6`, `currentStatus=investigating`(이력 `실습망 초기 조사 시작`) → `closed`(`true_positive`) 전이 `200` 후 이력 작업 `501`+`502` |
| [6] `admin` 운영 집계·fusion/3·검토 | `/api/operations`, `602/rank/1`, `/api/reviews` | `bundles`에 `zeekad-fusion/3`, `feedbackSummaries` 4개 캡처 전부·`all` 행, `정밀도 1.00, 결론 1/2 (50.0%)`·`정밀도 1.00, 결론 1/1 (100.0%)`, `정확도` 없음. `602/rank/1` `zeekad-fusion/3`, 보고 작업 `602`, `eventEnd` `2026-11-19T01:45:00Z`(45분 사건), Slack `jobId 601`. `dismiss` `200` 후 `lab-fusion-v2` 검토 목록: 해당 사건 `dismiss`(작업 `602` 한 건), `반영 중`·`반영 실패(운영자 확인)` 표시, 작업 `601` 중복 요청 없음 |
| [6] `PUT` WAF 통과 | `PUT /api/admin/users/3` (`analyst2`, `GET` 결과의 `role`·`capturePatterns` 그대로, `displayName`만 변경) | `200`, `/api/admin/audit-logs`에 `USER_ADMIN_CHANGE`(`UPDATE_USER`, `analyst2`) 기록 |
| [6] SPA 셸(인증) | TOTP를 마친 `admin`의 `GET /`, `/incidents/101/rank/1`, `/admin/users` | 모두 `200`, SPA 셸 표지 있음 |
| [7] 서버 쪽 세션 무효화 | 로그아웃 전 `ZEEKAD_SESSION` 값 저장 → `POST /api/auth/logout` → 그 값만으로 `GET /api/incidents` | 로그아웃 `200`, 재사용 `401` `UNAUTHENTICATED` |
| [8] 감사 로그 불변(`T58`부터: 보관 기한 안의 기록은 수정·삭제 불가) | `UPDATE audit_logs SET action_type = 'TAMPERED' ...` | `ERROR: audit_logs is append-only: UPDATE is forbidden` |
| 공통 | 모든 응답 본문 63건 | `정확도` 문구 0건 |

> [!NOTE]
> **판정 방식(2026-11-20 결정):** `분석가 결론 집계`, `놓친 공격(재현율)`, `전체 (all)`은 데이터가 아니라 SPA 화면에 고정된 문구이므로 배포된 JS 번들 안에 있는지로 판정합니다. 데이터 쪽은 `/api/operations` JSON의 `feedbackSummaries`·`allModel`·`precisionSummaryText` 필드로 판정합니다.
>
> **WAF 차단 판정:** 상태 코드만 보지 않습니다. 응답 본문이 앱의 `ApiErrorResponse` JSON(`code`)이 아니고 요청 주소에 붙인 `probe=<표식>`으로 찾은 `nginx-waf` ModSecurity 감사 로그에 `is_interrupted=true`, `http_code=403`, 규칙 ID가 있어야 통과입니다. E2E는 `127.0.0.1`로 접속하므로 모든 요청에 `920350`(숫자 IP Host, 3점)이 함께 기록됩니다. 각 공격은 그 규칙 하나만으로 임계값 `5` 이상(예: `942100` 단독 5점)입니다. `T58`까지는 요청마다 붙인 `X-E2E-Probe` 헤더로 감사 줄을 찾았습니다. `T59`부터 감사 줄에 요청 헤더가 없어 요청 주소의 표식으로 찾습니다(6절).
>
> **WAF 예외:** 추가하지 않았습니다(`modsecurity-override.conf.template` 변경 없음). 시험 중 본문 없는 `POST /api/auth/logout`이 `403`을 받았습니다. curl `-X POST`만 쓰면 `Content-Length`가 빠져 `920180`(+ `920350`)에 걸린 것이었습니다. 브라우저 `fetch`처럼 `Content-Length: 0`을 보내게 스크립트를 고친 뒤로는 `200`입니다.

---

## 4. CycloneDX SBOM 및 Trivy 스캔 결과

### 4.1 조치 내역
1. **Java 의존성 CVE 조치 (`build.gradle`, T07)**: Spring Boot `3.5.3` 기본 의존성 기준 `bom.json` `82`건 / `app.jar` `83`건이었습니다. Spring Boot `3.5.16`과 하위 라이브러리를 패치 버전으로 올려 각각 `2`건 / `3`건으로 줄였습니다.
2. **OS 패키지 (`Dockerfile` `apk upgrade --no-cache`)**: 이번 검증의 첫 전체 실행(run-3)에서 앱 이미지 Alpine OS가 `18`건(MEDIUM 15 · UNKNOWN 3: `openssl`·`libssl3`·`libcrypto3` `3.5.9-r0` → `3.5.9-r1`, `gnutls` `3.8.13-r0` → `3.8.14-r0`)이었습니다. `RUN apk upgrade` 레이어를 빌드 캐시에서 다시 써서 그 뒤 패치가 들어가지 않은 것이 원인이었습니다. `build --pull --no-cache`로 다시 빌드하자 `0`건이 되었습니다. 같은 재빌드로 WAF 기반 이미지가 `nginx 1.30.7`로 갱신되어 WAF 이미지 OS `24`건(CRITICAL 4 · HIGH 2 · MEDIUM 18)도 `0`건이 되었습니다. 배포·재검증 전에는 캐시 없이 다시 빌드합니다(`docs/deployment-guide.md` 4.1).
3. **Dockerfile 정적 점검**: Trivy FS 오설정 `0`건(앱 `Dockerfile`은 `USER appuser`·`HEALTHCHECK`, WAF `Dockerfile`은 `USER nginx`·`HEALTHCHECK`).

### 4.2 최종 Trivy 스캔 요약 (run-4, 실행 기록 `trivy-summary.txt`)

| 스캔 대상 | 유형 | CRITICAL | HIGH | MEDIUM | LOW | 비고 |
|---|---|---:|---:|---:|---:|---|
| `build/reports/bom.json` (`trivy sbom`) | Java SBOM | 2 | 0 | 0 | 0 | `spring-webmvc` 2건 |
| `frontend/package-lock.json` (`trivy fs`) | npm | 0 | 0 | 0 | 0 | FS 스캔 대상에 포함됨(`frontend/node_modules`·`frontend/dist`는 `--skip-dirs`로 제외) |
| `Dockerfile`, `docker/nginx-waf/Dockerfile` (`trivy fs`) | 오설정 / 비밀값 | 0 | 0 | 0 | 0 | 오설정 0건, 비밀값 노출 0건 |
| `zeek-ad-dashboard-app:local` | Alpine 3.24.4 OS | 0 | 0 | 0 | 0 | run-3 18건 → 캐시 없는 재빌드로 0건 |
| `zeek-ad-dashboard-app:local` | `app/app.jar` | 2 | 0 | 1 | 0 | `spring-webmvc` 2건, `ognl` 1건 |
| `zeek-ad-dashboard-waf:local` | Alpine 3.24.4 OS (`nginx 1.30.7`) | 0 | 0 | 0 | 0 | run-3 24건 → 기반 이미지 갱신으로 0건 |

### 4.3 잔여 위험 및 수용 근거
1. **`org.springframework:spring-webmvc 6.2.19`** (`CVE-2026-47884`, `CVE-2026-47890`, CRITICAL, `7.0.9`에서 수정):
   - Spring Framework `7.0.9`(Spring Boot `4.x` 세대) 메이저 업그레이드가 필요한 항목입니다.
   - `CVE-2026-47884`는 `XsltView` 경로 제한 우회, `CVE-2026-47890`은 SSE(Server-Sent Events) 뷰 스트림 손상 취약점입니다. 지금 구조는 서버 뷰 렌더링을 하지 않습니다(Thymeleaf 제거, T08). 백엔드는 `@RestController`의 Jackson JSON 응답과, SPA 화면 경로를 정적 `index.html`로 넘기는 `forward:`만 씁니다. `XsltView`·`SseEmitter`·SSE 뷰를 쓰는 코드가 없어 해당 경로가 노출되지 않습니다. Spring Boot 4.x로 옮길 때 해소합니다.
2. **`ognl:ognl 3.4.4`** (`CVE-2026-113730`, MEDIUM, `3.4.13`에서 수정):
   - `mybatis-3.5.19.jar` 내부에 shaded(`org.apache.ibatis.ognl`) 형태로 들어 있는 라이브러리입니다. 이 앱은 MyBatis 정적 XML 매퍼(`#{}` 바인딩만, `${}` 0건)만 쓰고 사용자 입력을 OGNL 표현식으로 평가하지 않습니다. 그래서 직접 악용할 경로가 없습니다.
3. **OWASP ZAP Low `10010` Cookie No HttpOnly Flag** (`XSRF-TOKEN`만, 2026-11-20 결정, [판단 기록](design-decisions.md)):
   - SPA는 이중 제출(double-submit) CSRF 방식이어서 JS가 `XSRF-TOKEN` 쿠키를 읽어 `X-XSRF-TOKEN` 헤더로 보내야 합니다. HttpOnly를 붙이면 모든 쓰기 요청이 실패합니다.
   - 이 쿠키는 세션 자격 증명이 아닙니다. 탈취돼도 그것만으로 세션을 쓸 수 없습니다. 세션 쿠키 `ZEEKAD_SESSION`은 `Secure; HttpOnly; SameSite=Lax`입니다(E2E [4]에서 확인).
   - CSP `script-src 'self'`(인라인 스크립트 금지)로 쿠키를 읽을 수 있는 XSS 경로를 줄였습니다. `XSRF-TOKEN`도 `Secure; SameSite=Lax`입니다.
   - 스크립트는 모든 인스턴스의 param이 정확히 `XSRF-TOKEN`인 `10010`만 허용합니다. 다른 쿠키가 섞인 `10010`이나 그 밖의 Low·Medium·High가 하나라도 있으면 실패합니다(ZAP 설정으로 `10010`을 끄지 않음). 로컬 시험 결과: 원본 통과, 다른 쿠키 혼입·다른 Low 추가·`10010` Medium 변경·param 대소문자 차이는 모두 실패.
4. **전달 헤더 출처 위조**(`T32`에서 줄임, [판단 기록](design-decisions.md)):
   - `T32` 전에는 앱이 전달 헤더를 연결 출처와 상관없이 믿었고 공개 스택 WAF는 스택 서브넷 전체를 믿었습니다. 같은 Docker 네트워크의 다른 컨테이너가 탈취되면 감사 로그 IP를 꾸밀 수 있었습니다.
   - 지금은 앱이 WAF 고정 주소에서 온 연결의 전달 헤더만 믿고, 공개 스택 WAF는 `127.0.0.1`과 Docker 게이트웨이(DSM 경로)만 믿습니다. 다른 컨테이너가 앱이나 WAF에 직접 보낸 `X-Forwarded-For`·`X-Forwarded-Proto`는 무시됩니다(E2E `[16]`, 리허설 `[T32]`).
   - 남은 것: 같은 bridge 네트워크에서 `NET_RAW` 권한으로 패킷 출처 주소를 꾸미는 공격은 신뢰 목록으로 막지 못합니다. `T61`부터 공개 스택은 `nginx-waf`와 같은 네트워크(`portfolio-net`)에 앱만 두고 모든 컨테이너에서 capability(`NET_RAW` 포함)를 뺐습니다. 그래서 스택 안의 컨테이너는 이 공격을 할 수 없고, 남은 것은 호스트의 프로세스와 나중에 `portfolio-net`에 새로 붙인 컨테이너(capability를 빼지 않고 띄운 것)입니다(9). VMware 구성은 두 서비스에서 capability를 뺐지만 같은 네트워크에 붙는 탐지 파이프라인(NBAD) 서비스의 권한은 이 저장소가 정하지 않습니다. 공개 스택은 게이트웨이를 믿으므로 NAS 호스트의 로컬 프로세스와 host 네트워크 컨테이너는 `127.0.0.1:18480`으로 전달 헤더를 꾸밀 수 있습니다. 이것은 "이 포트에는 DSM만 붙는다"는 원래 전제와 같습니다.
5. **공개 체험 분석가 계정 `trial-analyst`**(`T33`, [판단 기록](design-decisions.md)):
   - 방문자가 바꾼 상태·결정·담당은 매시 정각에 앱 밖 서비스가 스냅샷 직후 기준선으로 되돌립니다(파이프라인 표 셋, 담당 해제). 전용 DB 계정은 초기화 함수 셋과 보관 기한이 지난 감사 로그를 지우는 함수 하나(`T58`)만 실행할 수 있고 표·기준선·`CREATE` 권한이 없습니다(리허설 `[T33c]`에서 거부 시도 확인).
   - 공유 상태: 모든 방문자가 같은 계정과 같은 데이터를 씁니다. 한 방문자가 바꾼 상태·판정과 적은 사유·메모가 다음 정각까지 최대 1시간 다른 방문자에게 보입니다. 사유·메모는 500자까지이고 화면은 일반 텍스트로만 그립니다(HTML 해석·링크 변환 없음).
   - 판정 통계(분석가 결론 집계·처리 시간)가 방문자 판정에 따라 그 시간 동안 흔들립니다.
   - 정각 사이에 스크립트로 상태를 바꾸는 낙서는 쓰기 경로 IP당 속도 제한(분당 10회 + 버스트 5)까지만 막습니다. 여러 IP를 쓰면 더 많이 바꿀 수 있지만 다음 정각에 되돌아갑니다.
   - 감사 로그는 보관 기한(90일, `T58`) 동안 방문자 글로 커지고 담당 이력은 기한 없이 커집니다. IP 하나가 쓰기 한도(분당 10회)로 하루에 늘릴 수 있는 감사 로그는 약 14,400~28,800행입니다(조사 시작 때 자동 담당 기록이 한 행 더 붙습니다). 상태 변경 기록에는 사유 전문이 들어가서 한글 500자(UTF-8 약 1.5KB)면 행당 약 2KB입니다. 자동 담당 기록은 사유가 없어 수백 바이트라 하루 약 30MB 안팎입니다. 허용 밖 인시던트 조회 거부(`ACCESS_DENIED_IDOR`)도 조회 1번에 감사 1행(인덱스 포함 약 300바이트)을 남깁니다. 이 경로는 `T33` 전부터 `demo`로도 열려 있었고 `T35`까지는 조회 요청에 한도가 없었습니다. `T36`부터 공개 WAF가 `/api/` 조회를 IP당 분당 200회 + 버스트 30으로 묶어 IP 하나가 조회 거부로 하루에 늘릴 수 있는 감사 로그는 약 288,000행(약 86MB)입니다. IP별 상한이라 방문자가 IP를 바꾸면 더 늘릴 수 있습니다(리허설 `[T36b]`). 공개 주소 확인 때 행 수와 앱 DB 크기를 기록해 비교합니다([`docs/portfolio-deployment.md`](portfolio-deployment.md) 4.4).
   - 파이프라인 DB와 앱 DB는 따로 초기화됩니다. 두 초기화 사이(밀리초)에 들어온 쓰기는 "분석 중인데 담당 없음" 같은 어긋남을 다음 정각까지 남길 수 있습니다.
   - 새 스냅샷을 올렸는데 기준선을 다시 만들지 않으면 파이프라인 초기화는 거부되고 담당 해제만 계속됩니다. 그동안 상태·결정은 되돌지 않고 정각마다 `ERROR` 줄이 남습니다.
   - 체험 계정은 분석가라 실습망 캡처의 IP를 마스킹 없이 봅니다. 공개 전에 드러나는 값의 종류(실습망 사설 주소·외부 공인 주소와 그 주소가 든 문장)를 운영자가 확인했습니다. 새 실습망 캡처를 공개할 때도 같은 확인을 합니다.
6. **감사 로그 보관 기한**(`T58`, 공개 데모 90일):
   - 바뀐 것: 감사 로그는 여전히 추가만 하지만 보관 기한이 지난 행은 전용 DB 함수가 지웁니다. 트리거는 `UPDATE`와 `TRUNCATE`를 늘 거부하고 `DELETE`는 표식이 켜져 있고 행이 30일보다 오래됐을 때만 통과시킵니다. 30일은 SQL에 있는 바닥값이라 설정이나 함수 인자로 줄일 수 없습니다. 함수는 지운 사실을 감사 행 하나로 남깁니다. PostgreSQL에서 직접 확인했습니다(`scripts/audit-retention-check.ps1`).
   - 표 소유자인 앱 계정(`dashboard_app`)은 트리거를 끌 수 있습니다. `T58` 전에도 같았습니다. 앱 코드에는 감사 로그를 고치거나 지우는 문장이 없지만(정적 시험) 앱 DB 계정이 넘어가면 기록을 지울 수 있습니다. 표 소유 계정과 앱 접속 계정을 나누면 줄어드는 위험이고 지금은 나누지 않았습니다.
   - 표식(`dashboard.audit_retention_purge`)은 권한 경계가 아니라 실수 방지입니다. 사용자 정의 설정은 어느 역할이든 세션에서 켤 수 있습니다. 표에 `DELETE` 권한이 있는 계정(소유자)은 표식을 켜고 30일 지난 행을 함수 없이 지울 수 있고 그때는 삭제 기록 행이 남지 않습니다. 권한 경계는 표 권한과 바닥값입니다. 초기화 계정은 표 권한이 없어 함수로만 지울 수 있습니다. 그 계정이 넘어가면 기한을 30일로 줘서 30일 지난 행까지 지울 수 있습니다.
   - 삭제 기록 행도 감사 행이라 기한 뒤에 지워집니다. 90일보다 앞서 무엇이 언제 지워졌는지는 DB에 남지 않습니다.
   - 컨테이너 로그(`nginx-waf` 접근 로그와 ModSecurity 기록의 접속 주소)는 기간이 아니라 크기로만 제한합니다(컨테이너마다 50MB). 요청이 적으면 90일보다 오래된 줄이 남습니다. `T60`까지는 `nginx-waf`의 상태 확인 요청이 감사 줄을 남겨 한도를 며칠 만에 채웠습니다(계산, 6.4의 6). `T61`에서 상태 확인이 그 줄을 남기지 않게 고쳐 `nginx-waf` 로그도 방문자 요청만큼만 차고, 그래서 `nginx-waf`에서도 90일보다 오래된 줄이 남을 수 있습니다.
   - 되돌리기용 앱 DB 백업(`backup/app-pre-<ID>.dump`)에는 그 시점의 감사 로그가 들어 있습니다. 90일 넘은 백업은 배포 절차가 지우지만 자동이 아니라 다음 배포 때라서 그때까지 남습니다.
   - 이 SQL의 시험은 Gradle `check`에 들어 있지 않습니다(H2는 이 트리거와 함수를 쓰지 않습니다). migration이나 초기화 스크립트를 고치면 `scripts/audit-retention-check.ps1`을 따로 돌려야 합니다.
7. **WAF 감사 로그에 남는 값**(`T59`): 감사 줄에서 요청·응답의 헤더와 본문을 뺐습니다. 남은 것(규칙 메시지에 찍히는 요청의 일부, 요청 주소, 차단 요청의 헤더를 접근 로그에서 찾아야 하는 것, 이미 쌓인 로그)은 6.4에 적었습니다.
8. **관리자 TOTP 확인의 실패 제한**(`T60`):
   - 찾은 것: 관리자 2단계 인증의 코드 확인(`POST /api/auth/totp/verify`)은 코드가 틀려도 `400`만 돌려주고 횟수를 세지 않았습니다. 실패가 감사 로그에 남지 않았고 공개 스택의 속도 제한에도 이 경로가 없었습니다. 관리자 비밀번호를 아는 사람은 6자리 코드를 제한 없이 넣어 볼 수 있었습니다. 지원 서류를 저장소와 대조한 검토에서 나온 지적입니다.
   - 고친 것: 틀린 코드를 비밀번호 실패와 같은 횟수(`users.failed_attempts`)에 더하고 감사 `TOTP_FAILURE`(행위자, 접속 IP)로 남깁니다. 한도(기본 5회)에 닿으면 계정을 15분 잠그고 그 세션을 끝냅니다. 서버는 코드를 보기 전에 조건부 `UPDATE` 한 문장으로 시도 하나를 차지합니다. 잠겨 있거나 한도에 닿아 있으면 코드를 보지 않고 `423`을 줍니다. 그래서 요청을 동시에 여러 개 보내도 판정받는 수가 한도를 넘지 않습니다. 잠금 전에 비밀번호 로그인만 해 둔 다른 세션도 잠긴 뒤에는 코드를 넣어 볼 수 없습니다. 관리자는 비밀번호가 맞아도 횟수가 되돌아가지 않고 TOTP 확인(처음이면 등록 완료)까지 성공해야 되돌아갑니다. 비밀번호 실패 경로는 읽은 값에 1을 더해 덮어쓰던 것을 같은 원자 증가로 바꿨습니다(비밀번호를 비교하는 사이에 들어온 TOTP 실패분을 지우지 않습니다). 공개 스택은 이 경로를 로그인 속도 제한(IP당 분당 10회 + 버스트 5)에 넣었습니다.
   - 남은 시도: 계정 하나에 15분마다 5번이므로 하루 480번까지 넣어 볼 수 있습니다. 한 번에 맞을 확률은 100만분의 3입니다(서버가 지금 창과 앞뒤 한 창씩, 세 창의 코드를 받습니다). 하루로는 약 0.14%입니다(480 × 3 ÷ 1,000,000). 매일 한도까지 1년을 이어 가면 약 41%입니다(1 - (1 - 0.000003)^175,200). 이 시도는 관리자 비밀번호를 이미 아는 사람만 할 수 있고 시도마다 `TOTP_FAILURE`, 잠금마다 `ACCOUNT_LOCKED` 감사가 남습니다(하루 한도까지 넣으면 잠금 감사 96건).
   - 관리자 계정은 원래 아이디만 알아도 틀린 비밀번호 5번으로 15분 잠글 수 있습니다(잠금 제외 목록은 조회자와 분석가에만 적용됩니다). `T60` 전과 같고 이 작업이 잠금 수단을 새로 만든 것은 아닙니다. 공개 데모의 관리자는 비활성이라 해당이 없습니다(비활성 검사가 잠금 검사보다 앞입니다). 관리자가 하나뿐인 배포는 15분 뒤 풀리기를 기다리거나 DB에서 풉니다.
   - 관리자 로그인 전에 쌓인 비밀번호 실패(남이 넣은 것 포함)는 TOTP 확인이 성공할 때까지 남습니다. 전에는 비밀번호가 맞으면 지워졌습니다.
   - 잠금은 요청한 세션만 끝냅니다. 같은 계정으로 이미 TOTP 확인을 마친 다른 세션은 그대로 남습니다(세션 목록을 두지 않습니다. 비밀번호 잠금도 같습니다). 확인을 마친 세션이 이 경로를 다시 부르면 횟수를 세지 않고 실패 감사도 남기지 않습니다.
   - TOTP 코드는 허용 창(약 90초) 안에서 다시 쓸 수 있습니다. 쓴 코드를 기록하지 않습니다.
   - TOTP 등록 전인 관리자(새로 만든 관리자, TOTP를 초기화한 관리자)는 비밀번호만으로 등록 화면에서 비밀키를 받습니다. 등록 확인의 틀린 코드는 세지 않고 속도 제한에도 넣지 않았습니다.
   - VMware 구성(`compose.yml`)에는 속도 제한이 없습니다. 계정 잠금만 시도 수를 묶습니다.
   - 비밀번호 확인은 `T60` 전처럼 판정(BCrypt 비교) 뒤에 횟수를 올립니다. 틀린 비밀번호를 동시에 여러 개 보내면 한도보다 많이 판정받을 수 있습니다. 횟수는 빠짐없이 오르고 한도에서 잠깁니다. 공개 스택은 속도 제한이 한 IP의 시도 수를 묶습니다.
   - 한도에 닿은 다섯 번째 시도가 판정을 받는 사이에 다른 요청이 오면 그 요청이 계정을 먼저 잠급니다. 다섯 번째 코드가 맞았다면 잠금은 바로 풀리지만 `ACCOUNT_LOCKED` 감사 한 건은 남습니다. 이렇게 한 까닭은 한도에 닿았는데 잠금이 없는 행(시도를 차지한 뒤 잠그기 전에 프로세스가 죽은 경우, 한도 설정을 낮춘 경우)이 풀리지 않는 상태로 남지 않게 하려는 것입니다.
   - 조건부 `UPDATE` 두 문장은 H2(통합 시험)에서만 돌렸습니다. PostgreSQL에서는 E2E `[T60]`의 첫 실행이 두 문장과 차례로 보낸 요청의 결과를 확인합니다. 동시 요청은 H2 시험으로만 확인했습니다.
9. **공개 스택의 네트워크와 컨테이너 권한**(`T61`):
   - 찾은 것: 공개 스택의 일곱 서비스가 Docker 네트워크 하나에 붙어 있어 인터넷 요청을 받는 `nginx-waf`가 DB(`postgres:5432`)와 근거 API(`api:8000`)에 직접 닿을 수 있었습니다. `nginx-waf`에는 권한 상승 금지만 있고 capability가 남아 있었고 `postgres`에는 권한 설정이 없었습니다(root로 시작해 진입 스크립트가 일반 계정으로 내려갑니다). VMware 구성의 두 서비스에도 권한 설정이 없었습니다. 외부 검토의 지적입니다.
   - 고친 것: 네트워크를 둘로 나눴습니다. `portfolio-net`에는 `nginx-waf`와 앱만 두고(정의는 그대로) 새 내부 전용 네트워크 `portfolio-data`에 앱·DB·근거 API·초기화와 시드 도구를 둡니다. 두 네트워크에 붙는 것은 앱뿐입니다. 공개 스택의 모든 서비스와 VMware 구성의 두 서비스가 `cap_drop: [ALL]`과 `no-new-privileges`로 돌고 `postgres`는 root로 시작하지 않습니다(`user: postgres`). 리허설 `[T61a]`~`[T61d]`가 붙은 컨테이너·`Internal`·기본 경로, `nginx-waf`에서 DB·근거 API로의 TCP 연결(연결 단계로 판정), `api`에서 WAF로의 연결, PID 1의 `CapBnd`·`NoNewPrivs`를 봅니다. 고치기 전 구성에서 같은 확인이 실패하는 것도 잽니다(결과는 위 검증 표).
   - 남은 것: `api`·초기화·시드 도구는 앱 `8080`에 직접 닿습니다(앱이 `api`를 불러야 해 같은 네트워크입니다). 그 연결의 전달 헤더는 앱이 믿지 않습니다(4). `portfolio-net`은 WAF 포트를 열어야 해서 내부 전용으로 만들 수 없으므로 `nginx-waf`와 앱에는 바깥으로 나갈 길(기본 경로)이 남습니다. `nginx-waf`가 뚫리면 스택 안에서는 앱에만 닿지만 바깥으로 연결을 낼 수는 있습니다. 호스트의 프로세스와 나중에 `portfolio-net`에 새로 붙인 컨테이너는 막지 못합니다. `nginx-waf`와 `postgres`에는 읽기 전용 루트 파일 시스템(`read_only`)을 걸지 않았습니다.
   - 로컬에서 확인할 수 없는 것: 로컬 Docker와 NAS는 Compose 판이 다릅니다. NAS의 옛 Compose가 이미 있는 `portfolio-net`을 다시 만들지 않고 쓰는지, NAS의 Docker가 내부 전용 네트워크를 받는지는 NAS 반영 때 사전 확인으로 봅니다([`docs/portfolio-deployment.md`](portfolio-deployment.md) 3.8 `T61` 절). 이미 만든 내부 전용 네트워크는 compose의 줄을 바꿔도 다시 만들어지지 않습니다.
10. **종결 건 다시 열기**(`T53`):
   - 바뀐 것: 대시보드 쓰기 계정(`dashboard_rw`)이 실행할 수 있는 zeek_AD 함수가 둘에서 셋이 됐습니다(`dashboard.reopen_incident`, 소유 `zeekad_owner`, `SECURITY DEFINER`, 실행 권한은 `dashboard_rw`뿐). 함수가 바꾸는 표는 상태 변경과 같은 두 표(상태, 상태 이력)라 공개 데모의 정각 초기화가 그대로 되돌립니다. 새 감사 유형은 없습니다(상태 변경 유형에 `operation: reopen`).
   - 오래된 화면: 다시 열기 요청은 화면이 보던 판정을 늘 보내고 함수가 지금 판정과 글자 그대로 견줍니다. 다른 사람이 그사이 다시 열어 다른 판정으로 종결했으면 거부됩니다(`409`). 거부 문장은 고정이라 "이미 분석 중"인지 "판정이 다름"인지 화면이 가르지 않습니다(새로고침하면 보입니다).
   - 오류 문구: `409`·`501`은 고정 문장이고 DB 메시지(지금 상태·판정 코드, 함수 이름, 권한 오류)를 내보내지 않습니다. 원인은 서버 로그에만 남습니다.
   - 함수가 없을 때: 앱은 `42883`(함수 없음)·`42501`(권한 없음)을 기능 없음(`501`)으로 봅니다. 그래서 쓰기 매퍼의 인자 이름이 함수와 어긋나도 `501`로 보입니다. 실제 함수로 한 성공 확인(실제 대상 확인, 리허설 `[T53b]`)이 이것을 막습니다.
   - 사본: 공개 스택은 zeek_AD migration 파일의 사본(`docker/portfolio/initdb/zeekad-sql/`, sha256을 정적 시험이 대조)을 볼륨을 처음 만들 때 실행합니다. 스냅샷에 그 이름의 함수가 이미 있으면 건너뛰므로 zeek_AD가 함수를 고쳐 새 스냅샷에 담으면 사본은 쓰이지 않습니다. 반대로 함수가 없는 새 스냅샷에서는 이 사본이 그대로 들어갑니다(zeek_AD 쪽이 바뀌었으면 사본을 다시 옮겨야 합니다).
   - 지표: 분석 중 기록 없이 종결된 건(파이프라인이 닫은 건)을 다시 열면 다시 연 시각이 착수 시각이 되어 착수 시간(MTTA)에 큰 값이 들어갈 수 있습니다. 다시 연 건의 처리 시간(MTTR)은 마지막 종결 기준입니다. 공개 데모에서는 방문자가 다시 연 건 때문에 판정 집계·처리 시간이 다음 정각까지 흔들립니다(5와 같다).
   - 조회자: 상세 응답의 `canReopen`은 조회자에게 늘 `false`이고 다시 열기 요청은 `403`입니다. 조회자에게 새로 내려가는 값은 이 불리언 하나입니다.
11. **중요 자산과 조회자 마스킹**(`T52`):
   - 바뀐 것: 관리자가 등록한 중요 자산(IPv4 주소 하나)이 호스트인 미종결 인시던트는 우선순위가 한 단계 올라갑니다. 응답에 `assetCritical`(중요 자산 여부)·`priorityBase`(올리기 전 우선순위)·`criticalAssetName`(자산 이름)이 더해졌습니다. 조회자에게 `criticalAssetName`은 늘 `null`이고 자산 설명은 어떤 역할의 인시던트 응답에도 없습니다(관리자 API에만 있습니다). 주소·호스트 이름·계정의 가림 규칙은 그대로입니다. 관리자 API의 지우기는 `POST …/{id}/delete`라 WAF 허용 메서드는 그대로이고 변경은 감사 `CRITICAL_ASSET_CHANGE`로 같은 트랜잭션에 남습니다.
   - 조회자가 받는 표지가 드러내는 것: 표지만으로는 주소를 알 수 없습니다. 다만 가린 대역 안에 중요 자산이 하나뿐이면 표지가 참인 인시던트는 모두 그 한 호스트의 것이라 조회자가 그 호스트의 인시던트를 묶고 셀 수 있습니다. 호스트 위험도가 대역으로 묶어 막으려던 "원문 호스트 단위의 수"가 그 호스트에 한해 드러납니다. 표지를 빼도 `priority`와 `priorityBase`의 차이(Low·Medium에서 올린 경우)로 같은 것이 드러나므로 우선순위를 올리는 한 딸려 나오는 정보로 보고 받아들였습니다.
   - 공개 데모의 자산 목록: 공개 데모는 시드가 저장소의 자료 파일(`docker/portfolio/seed/critical_assets.json`)대로 자산을 맞추므로 자산의 주소와 이름이 공개 저장소에 함께 실립니다. 그래서 조회자에게 이름을 내리지 않는 규칙은 공개 데모에서는 통제를 보여 주는 시연이고 이름을 숨기지 못합니다(분석가 체험 계정도 공개돼 있습니다). 실제 운영에서는 그 파일이 저장소에 있지 않고 관리자 화면으로만 등록합니다.
   - 자산은 주소로만 맞춥니다(캡처를 가리지 않습니다). 가져온 데이터셋과 실습망의 주소가 겹치면 같이 올라갑니다. 지금 공개 자료에서는 겹치지 않습니다(`192.168.10.x`와 `10.10.0.x`).

---

## 5. OWASP ZAP 베이스라인 스캔 결과 (`zap-baseline.py`)

기동된 `https://nginx-waf:8443/` 대상(`--network <compose_net>`)으로 `ghcr.io/zaproxy/zaproxy:stable zap-baseline.py`를 실행했습니다. ZAP은 정보성 경고만 있어도 종료 코드가 `2`라서 스크립트는 종료 코드 대신 `zap-baseline.json`의 위험 등급별 경고 수로 판정합니다(exit `1`/`3`은 계속 실패).

- **최종 스캔 (run-4, 실행 기록 `zap-baseline-summary.md`)**: `ZAP_EXIT_CODE=2`
  - **High**: `0`
  - **Medium**: `0`
  - **Low**: `0` (허용 예외 제외. `ALLOWED: 10010 XSRF-TOKEN (instances=3)`: `/`, `/robots.txt`, `/sitemap.xml`의 `Set-Cookie: XSRF-TOKEN`)
  - **Informational**: `3` (`Modern Web Application [10109]`: SPA라서, `Non-Storable Content [10049]`: `Cache-Control: no-store` 정책, `Session Management Response Identified [10112]`)
  - **PASS**: `64`건 (`FAIL-NEW: 0`)
- 참고: T07(Thymeleaf SSR)에서는 `XSRF-TOKEN` 쿠키가 없어 Low `0`이었습니다. COOP/COEP/CORP·`Permissions-Policy` 헤더(T07 조치)는 그대로 있습니다.

---

## 6. WAF 감사 로그에 남는 값 (`T59`, 2026-11-26)

로그인 화면의 안내문은 "접속 IP와 요청 주소는 웹 방화벽 로그에도 남습니다"라고 말합니다. 그보다 민감한 값이 WAF 컨테이너 로그에 남는지 확인했고, 남는 값을 찾아 줄였습니다.

### 6.1 확인 방법

- `scripts/waf-audit-log-check.ps1`이 저장소의 WAF 이미지와 대역 서버(경로에 따라 `200`·`401`·`403`·`404`·`409`·`500`으로 답하고 `Set-Cookie`를 붙이는 작은 서버)를 전용 Docker 네트워크에 띄웁니다. 실행마다 무작위로 만든 표식 여섯을 요청의 쿠키·헤더·본문과 응답의 `Set-Cookie`·본문에 싣고, WAF 컨테이너의 전체 출력(stdout + stderr)에서 표식이 몇 번 나오는지 셉니다. 줄 종류와 상관없이 전체에서 셉니다.
- WAF의 환경 값은 공개 스택(`compose.portfolio.yml`)과 같게 줍니다. nginx, ModSecurity, CRS는 실제 것이고 앱과 실제 계정은 쓰지 않습니다. 표식은 비밀값이 아니며 결과 파일에는 표식의 이름과 개수만 적습니다.
- 근거를 나눠 적습니다. 공개 스택의 감사 줄에 요청 헤더가 통째로 들어 있었다는 것은 문서 근거입니다(`T13`이 NAS에서 DSM이 넘기는 헤더를 감사 줄로 확인했습니다. [`docs/portfolio-deployment.md`](portfolio-deployment.md) 4.2). 쿠키 값이 실제로 들어간다는 것은 이 재현 환경에서 확인했습니다. 공개 스택의 로그 원문은 열어 보지 않았습니다.
- 보지 않은 것: 속도 제한 `429` 경로(포트폴리오용 http 문맥 설정을 붙이지 않았습니다). 감사 로그의 부분 설정은 응답 코드와 무관하게 전역으로 걸립니다.
- 시험한 요청은 로그인 꼴(쿠키 + `X-XSRF-TOKEN` 헤더 + JSON 본문)뿐입니다. 비밀값이 본문에 든 다른 요청(관리자의 사용자 생성·수정, TOTP 등록·확인의 `400`·`409`)도 같은 전역 설정으로 덮이지만 따로 보내 보지 않았습니다.

### 6.2 찾은 것

고치기 전 WAF 이미지는 기반 이미지의 기본값 `SecAuditLogParts ABIJDEFHZ`를 썼습니다. 감사 줄은 `404`가 아닌 `4xx`와 `5xx` 응답, 그리고 규칙이 걸린 요청에 한 줄씩 나갑니다. `200`과 `404` 응답(규칙이 걸리지 않은 것)에는 감사 줄이 없었습니다.

| 값 | 고치기 전 감사 줄 | 센 결과 |
|---|---|---|
| 세션 쿠키 `ZEEKAD_SESSION`(요청 `Cookie` 헤더) | 남음 | 쿠키를 실은 감사 대상 요청 6건(`401` 2건, `403`·`409`·`500`, CRS 차단 `403`)에서 6번 |
| CSRF 토큰(요청 `Cookie`의 `XSRF-TOKEN`과 `X-XSRF-TOKEN` 헤더) | 남음 | 같은 6건에서 12번(요청마다 두 번) |
| 요청 본문(JSON의 아이디와 비밀번호) | 남지 않음 | 0번. CRS가 막은 요청에서도 0번 |
| 응답의 `Set-Cookie` | 남음 | 대역 서버가 답한 5건에서 5번(WAF가 막은 `403`은 WAF의 응답이라 `Set-Cookie`가 없습니다) |
| 응답 본문, `application/json` | 남지 않음 | 4건에서 0번 |
| 응답 본문, `text/html` | 남음 | 1건에서 1번(ModSecurity가 본문을 읽는 종류가 `text/plain text/html text/xml`입니다) |
| 접근 로그 줄, nginx 오류 로그 | 표식 없음 | 여섯 표식 모두 0번 |

- 앱의 API 응답은 JSON이라 응답 본문은 남지 않았을 것입니다. 요청 본문이 남지 않은 것은 기본값에 `C`가 없어서입니다(`I`는 있지만 JSON 본문을 적지 않았습니다).
- 컨테이너 로그를 읽을 수 있는 사람(호스트 관리자)은 로그인 실패·권한 거부·충돌 응답이 날 때마다 그 요청의 세션 쿠키 값을 로그에서 얻을 수 있었습니다. 세션은 유휴 30분, 절대 8시간까지 유효합니다.
- 실행 결과: 고치기 전 이미지에서 단언 35개 가운데 7개가 실패했습니다(부분 설정 2, 감사 줄의 `headers`·`body` 키 1, 표식 4).

### 6.3 고친 것

- WAF 이미지가 감사 로그의 부분을 `AHZ`로 줄입니다(`docker/nginx-waf/Dockerfile`의 `ENV MODSEC_AUDIT_LOG_PARTS=AHZ`). 기반 이미지의 `modsecurity.conf.template`이 이 환경 값을 `SecAuditLogParts`로 옮깁니다. 환경 값을 바꿔 띄우면 렌더된 값이 바뀌는 것과 띄운 컨테이너의 `/etc/modsecurity.d/modsecurity.conf`에 `SecAuditLogParts AHZ`가 있는 것을 확인했습니다. 읽히는 규칙 파일에 요청마다 부분을 바꾸는 `ctl:auditLogParts`는 없습니다.
- 남기는 것: 접속 주소, 시각, `unique_id`, `is_interrupted`, 메서드, 요청 주소, 응답 코드, 걸린 규칙의 메시지(`ruleId`, `data` 등). 빼는 것: 요청 헤더, 요청 본문, 응답 헤더, 응답 본문. 헤더 일부만 가릴 수는 없어 요청 헤더를 통째로 뺐습니다. 이 기반의 libmodsecurity 3.0.17은 값을 가리는 동작(`sanitiseRequestHeader`, `sanitiseResponseHeader`, `sanitiseArg`, `sanitiseMatched`)을 넣으면 설정 검사에서 `is not yet supported`로 거부합니다.
- 고친 뒤 결과: 표식 여섯이 컨테이너 전체 출력에 0번입니다. 감사 대상 응답마다 감사 줄이 있고 접속 주소·요청 주소·응답 코드가 있습니다. CRS 차단 줄에는 `is_interrupted`·`unique_id`·`ruleId`·메시지의 `data`가 있습니다. 접근 로그 줄은 그대로입니다. 단언 35개가 모두 통과했습니다.
- 설정은 이미지 한 곳에 있습니다. compose 파일에서 `MODSEC_AUDIT_LOG_PARTS`를 주면 이미지의 값을 덮으므로 정적 시험(`StaticSecurityAndConfigTest`)이 compose 파일과 저장소 템플릿에 그 값이 없는지 봅니다.
- E2E와 리허설 스크립트: WAF 감사 줄을 찾는 표식을 `X-E2E-Probe` 헤더에서 요청 주소의 `probe=<표식>`으로 옮겼습니다. "그 요청의 차단 줄 0건"을 보는 단언(`[12a]`·`[15b]`·`[21c]`·`[22f]`)은 표식을 못 찾아도 0건이 되므로 그 표식이 든 로그 줄이 있다는 단언을 함께 넣었습니다. 실제 스택에서 표식 비밀번호·세션 쿠키 값·CSRF 토큰 값이 WAF 로그 전체에 0번인지 보는 단언도 넣었습니다(E2E `[23]`, 리허설 `[8b]`). 두 스크립트는 구문만 확인했고 실행 결과는 다음 통합 검증 때 적습니다.

### 6.4 남은 위험

1. **규칙 메시지에 찍히는 요청의 일부**: 걸린 규칙의 메시지에는 규칙이 잡은 값이 그대로 들어갑니다. 공격 꼴 글을 JSON 본문의 `password` 칸에 넣어 보낸 요청의 감사 줄에는 `Matched Data: s&1c found within ARGS:json.password: ' OR 1=1--`가 남았습니다. nginx 오류 로그에도 차단 줄이 나갑니다(이 시험에서는 점수 초과 규칙 `949110`의 줄이었고 `data`는 비어 있었습니다). 공격 내용은 관제에 필요해서 줄이지 않았습니다. 정상 비밀번호가 CRS 규칙에 걸리는 꼴이면 그 값도 같은 자리에 남습니다.
2. **요청 주소**: 접근 로그 줄과 감사 줄에 쿼리 문자열까지 남습니다. 앱은 요청 주소에 비밀값을 싣지 않습니다. 컨트롤러의 요청 파라미터는 기간·필터·정렬·쪽 값이고 화면은 CSRF 토큰을 헤더로만 보냅니다. 서버는 `_csrf` 요청 파라미터도 받지만 앱은 그렇게 보내지 않습니다. 검색어와 호스트 주소 조건 같은 필터 값은 남습니다.
3. **차단 요청의 헤더는 접근 로그에서 찾아야 함**: 감사 줄에서 요청 헤더가 빠져 차단된 요청의 User-Agent·`Host`·`Content-Type`·받은 `X-Forwarded-For` 원문은 감사 줄에 없습니다. User-Agent와 `X-Forwarded-For` 원문은 접근 로그 줄에 있고 시각·요청 주소로 찾아 잇습니다. 두 줄을 잇는 공통 ID는 없습니다. `Host`는 감사 줄의 `hostname`에 포트를 뺀 이름으로 남고 `Content-Type`은 어느 줄에도 남지 않습니다.
4. **이미 쌓인 로그**: 반영 전의 `nginx-waf` 컨테이너 로그에는 옛 감사 줄이 들어 있습니다. 컨테이너를 다시 만들 때 함께 사라지는지는 로그 드라이버에 달려 있고 NAS에서는 아직 확인하지 않았습니다([`docs/portfolio-deployment.md`](portfolio-deployment.md) 3.8).
5. **되돌리면 다시 켜짐**: 값이 이미지에 있으므로 옛 WAF 이미지로 되돌리면 헤더 기록이 다시 켜집니다. 재현 시험은 Docker가 필요해 Gradle `check`에 넣지 않았습니다. WAF `Dockerfile`이나 기반 이미지를 바꾸면 `scripts/waf-audit-log-check.ps1`을 따로 돌려야 합니다.
6. **상태 확인 요청의 감사 줄**(따로 찾은 것, `T61`에서 고침): compose의 상태 확인(`wget http://127.0.0.1:8080/healthz`, 10초마다)은 `Host`가 숫자 주소라 CRS 규칙 `920350`이 걸렸습니다. 응답이 `200`인데도 감사 줄이 10초마다 하나씩 나갔습니다(공개 스택과 같은 compose로 띄운 로컬 리허설 스택에서 10분에 60줄). 줄 하나는 감사 부분을 줄이기 전 약 1.5KB, 줄인 뒤 약 1.2KB입니다. 이 줄만으로 하루 약 10MB가 쌓여 `nginx-waf`의 로그 한도 50MB는 약 4일 치로 계산됐습니다(줄 크기 × 빈도에 `json-file`이 붙이는 양을 더한 계산이고 디스크에서 재지 않았습니다). 그래서 접속 주소가 든 줄이 오래 남지 않는 대신 차단 기록도 며칠 뒤에 밀려났습니다. `T61`부터 세 곳(두 compose의 `healthcheck`, WAF 이미지의 `HEALTHCHECK`)의 상태 확인이 `--header "Host: localhost"`로 이름 `Host`를 보냅니다. 접속 주소는 `127.0.0.1` 그대로이고 WAF 규칙은 끄거나 예외를 두지 않았습니다. 바깥에서 숫자 주소 `Host`로 `/healthz`를 부르면 지금처럼 감사 줄이 남습니다. 리허설 `[T61e]`가 컨테이너가 뜬 지 60초가 넘은 뒤 표식 요청 말고 `/healthz` 감사 줄이 0건인지와, 대조로 숫자 주소 `Host`의 표식 요청 줄이 남는지 봅니다(E2E `[T61e]`도 같고 첫 실행은 `T57`). `scripts/waf-audit-log-check.ps1`의 준비 확인은 지금도 숫자 주소 `Host`로 `/healthz`를 부르므로 그 도구의 출력에는 이 줄이 남습니다.

---

## 7. 신뢰하지 않는 입력의 처리 (`T63`, 2026-11-26)

호스트 이름과 계정 이름은 네트워크에 접속하는 쪽이 정하고, 탐지 파이프라인은 관측한 그대로 넘깁니다(HTML·마크다운·Slack 표기, 제어·방향 전환 문자, 4,000자까지). LLM 보고서의 글도 사람이 쓴 글이 아닙니다. 탐지 파이프라인이 인젝션 시험에 쓴 공격 문장 16종(지시 덮어쓰기, 판정 조작, JSON·역할·채팅 템플릿 표지, 제어·방향 전환 문자, 4,039자, Slack 표기 등)을 그대로 옮겨 서버 응답을 시험했습니다. 화면 쪽(칸 폭, 내보내기, "AI 작성" 표지, ATT&CK 후보 접기)은 짝 작업 `T64`가 다룹니다.

### 7.1 위협과 고치기 전 상태

- HTML 주입은 이미 막혀 있었습니다(React 글자 노드, 엄격한 CSP, 시험). 남은 것은 보이지 않는 문자(방향 전환 U+202E로 이름을 거꾸로 보이게 하기, 폭 없는 문자로 다른 이름을 같은 이름처럼 보이게 하기, 주소의 옥텟 사이에 끼워 조회자 가림을 비키기), 제어 문자(서버 로그 줄 위조), 길이 제한이 없는 값(표 깨기), 숨은 문자·전각 글자로 찾을 수 없게 된 이름, 감사 로그 검색의 와일드카드였습니다.
- 고치기 전 코드로 새 시험을 돌린 결과: 조회자에게 `10.0<U+200B>.0.1`이 가려지지 않았고(화면에는 주소로 보인다), `<U+202E>admin`은 `<U+202E>***`, 서러게이트 쌍으로 시작하는 계정은 짝 없는 반쪽이 남았습니다. 응답의 키·글자 값 1,767개가 아래 정책을 벗어났습니다(최종 판 시험 기준). 감사 로그 행위자 열에 반쪽 서러게이트가 저장됐고, 행위자 검색어의 `%`가 와일드카드였습니다. 검토 결정 요청의 `incidentId`에 줄바꿈을 넣으면 서버 로그에 가짜 줄이 생겼습니다. 숨은 문자·전각 글자를 끼운 호스트 이름은 보이는 글자로 검색되지 않았습니다.

### 7.2 처리

- **글자 정책 한 곳**(`UntrustedText`): 숨은 문자는 제어 문자(Cc. 여러 줄 칸에서는 `\n`·`\t`를 뺀다), 서식 문자(Cf), 줄·문단 구분자, `Default_Ignorable_Code_Point`(Unicode 15.0 `DerivedCoreProperties.txt`의 범위. 한글 채움 문자, 변형 선택자 등), 짝 없는 서러게이트, 한 글자에 3개를 넘게 이어 붙은 결합 문자의 넘는 몫입니다. 여러 줄 칸의 `\r\n`은 `\n`이 됩니다.
- **역할별**: 분석가·관리자에게는 숨은 문자를 그 자리에 `[U+202E]` 같은 표지로 보입니다(이름에 그런 문자가 있다는 것 자체가 공격의 단서라 지우지 않는다). 조회자에게는 지우고 끝에 ` [보이지 않는 문자 N개 제거]`를 붙입니다(표지는 없다).
- **길이 상한**(코드 포인트): 이름 256(호스트·계정·표시 이름, 감사 로그 행위자, `T52` 중요 자산 이름), 글 4,000(LLM 보고서 글, 오류·사유, 사람이 쓴 글, `T52` 중요 자산 설명, Slack 페이로드의 글자 잎), 그 밖의 모든 글자 값 1,000. 넘으면 `…(N자 생략)`을 붙입니다. 표지 한가운데나 서러게이트 쌍을 가르지 않습니다. 식별자(인시던트·캡처·번들 ID, 호스트 주소, 모델 이름, ATT&CK ID, 열거값, 사실 ID, 가명표의 키 등 닫힌 목록)는 바꾸지 않습니다.
- **조회자 가림 순서**(가리는 쪽으로만 바꿨다): 주소가 들 수 있는 글은 `maskIps(strip(maskIps(raw)))`입니다. 원문에서 한 번 가리고, 숨은 문자를 지우고, 다시 가립니다. 지우기만 먼저 하면 `10.0.0.1<U+200B>.5`가 다섯 마디 숫자열이 되어 가림을 비키므로 원문 가림을 먼저 둡니다. 계정 이름은 숨은 문자를 지운 값의 첫 글자 + `***`이고 첫 글자가 BMP 밖이면 `***`입니다. 숨은 문자가 없는 값은 전과 같습니다(기존 가림 시험을 고치지 않고 통과).
- **적용 자리**: 조회자 처리는 가림 단계(`MaskingService`)에서 합니다. 분석가 표지와 모든 역할의 상한은 검색·정렬·묶음이 원문으로 끝난 뒤 응답 직전의 서비스 층 구성요소(`ResponseTextGuard`)가 응답 JSON의 경로 규칙(`ResponseTextCatalog`)으로 적용합니다. 칸 이름·형·순서는 그대로이고(분석가 큐 행처럼 같은 키가 두 번 나오는 응답도 그대로) DTO에 새 칸이 생기면 기본 "값" 정책을 거칩니다. 전역 Jackson 모듈은 쓰지 않아 감사 로그 저장은 원문 그대로입니다.
- **글 안의 JSON**(Slack `payloadJson`, 운영 현황 `slackSummaries[].slackPayload`, 감사 로그 `detail`): 직렬화된 글이 아니라 푼 나무의 잎(키와 값)에 적용한 뒤 다시 직렬화합니다. Jackson은 제어 문자를 `\u0000` 꼴로 적어 직렬화된 글에서는 숨은 문자가 보이지 않고, 화면이 `JSON.parse`로 되살리기 때문입니다. 직렬화된 글은 자르지 않습니다(자르면 JSON이 깨져 화면이 본문을 통째로 잃는다). 바뀐 잎이 없으면 원래 글을 그대로 둡니다.
- **검색**: 인시던트 목록의 `asset`(목록·옛 목록 API·새 건수·이웃)과 호스트 위험도의 `q`는 검색어와 비교 대상에 같은 정규화(숨은 문자 제거 → NFKC → 소문자)를 적용합니다. 비교 대상은 분석가는 원문(자르기 전), 조회자는 가린 값(제거 표시 글은 뺀다)입니다. 앞뒤 공백을 뺀 검색어가 UTF-16 100단위를 넘으면 `400 INVALID_REQUEST`, 숨은 문자만 넣은 검색어는 조건이 없는 것으로 봅니다.
- **감사 로그**: 저장하는 값은 원문입니다(증거). 열 자르기(행위자 100, 캡처 128, 인시던트 255)는 UTF-16 단위 상한 이하이고 서러게이트 쌍을 가르지 않습니다(걸치면 그 쌍을 버린다. H2는 UTF-16 단위로, PostgreSQL은 문자로 세므로 두 DB 모두 들어간다). 행위자 검색어는 100단위 상한이고 `LIKE … ESCAPE '\'`에 검색어의 `\`·`%`·`_`를 이스케이프합니다(H2·PostgreSQL 같은 문장). 관리자 화면의 응답에는 위 정책(표지)을 적용합니다.
- **서버 로그**: 검토 결정의 SQL 오류 때 찍던 요청 본문의 `incidentId`와 사용자 이름, 상태 전이·다시 열기(`T53`)의 사용자 이름을 표지로 찍습니다(줄바꿈이 `[U+000A]`가 되어 로그 줄을 만들지 못한다).
- 로그인 안내 링크 검사(`LoginNoticeController`)는 지금 문자 집합 그대로입니다.

### 7.3 시험

모의 환경(H2 + MockMvc + 근거 API를 흉내 내는 로컬 HTTP 서버)에서 돌립니다. 고치기 전 코드에서 새 시험 15개 가운데 13개가 실패했습니다(식별자 시험과 분석가에게 같은 객체를 돌려주는 시험만 통과).

- `T63UntrustedTextIntegrationTest`(모든 응답의 모든 글자 값): 공격 문장 16종과 보이지 않는 글자(한글 채움 문자, 결합 문자 연속, 이모지 ZWJ·변형 선택자, 태그 문자, 줄 구분자, 짝 없는 서러게이트)를 호스트 이름, 관측 계정 세 칸, `extraAttributes`, 보고서 글 칸·사실·구조 값·검증 문제, 근거의 글자 잎과 키, Slack 페이로드, 상태 이력 사유, 대응 조치 메모, 표시 이름, 감사 로그(로그인 실패 이름, 허용 밖 캡처 요청 값)에 넣습니다. 큐(목록·이웃·새 건수), 옛 목록 API, 상세 18건, 같은 호스트 인시던트, 호스트 위험도, 현황판, 운영 현황, 에스컬레이션 목록을 분석가·조회자로, 감사 로그를 관리자로 받아 스트리밍 파서로 모든 키와 글자 값을 훑습니다(글 안의 JSON은 풀어서). 판정은 숨은 문자 없음, 칸 종류별 상한, 분석가 쪽 표지·조회자 쪽 표지 없음과 제거 표시, 조회자 응답에 가려지지 않은 IPv4 없음, 식별자는 분석가에게 원문·조회자에게 지금 가림 그대로입니다.
- `T52` 중요 자산: 이름·설명(관리자가 넣고 제어 문자는 받지 않지만 방향 전환 같은 서식 문자는 받는다)은 큐·상세·호스트 위험도·같은 호스트 인시던트의 `criticalAssetName`(분석가·관리자만, 조회자는 `null`)과 관리자 API `/api/admin/critical-assets`의 응답에서 위 정책을 거칩니다. "모든 응답" 시험의 자료에 서식 문자와 공격 문장을 넣은 이름·설명을 더했습니다.
- `T63ViewerMaskingGapIntegrationTest`: T63 전부터 있던 가림 누락 넷(옛 목록 API의 작업 둘, 상세의 작업, ATT&CK 후보 이름·전술)이 조회자에게 가려지고 분석가에게는 원문인지 봅니다.
- `MaskingServiceT63Test`: 원문 가림이 잡는 반례 둘(`10.0.0.1<U+200B>.5`, `7.<U+200B>10.0.0.1`), 쪼갠 주소, `<U+202E>admin` → `a***`, BMP 밖 글자로 시작하는 계정 → `***`, 지운 뒤 Map 키가 겹칠 때의 지금 동작.
- `T63SearchAuditLogIntegrationTest`: 숨은 문자·전각 글자를 낀 이름이 네 경로와 호스트 위험도에서 보이는 글자로 찾힘(분석가·조회자), `asset` 101 UTF-16 단위는 `400`, 숨은 문자만인 검색어는 조건 없음, 감사 로그 검색의 `%`·`_`·`\`가 글자 그대로, 101단위는 `400`, 서러게이트 쌍이 100·128번째 자리에 걸치는 값의 저장, 서버 로그 줄 위조.
- 단위 시험: `UntrustedTextTest`, `ResponseTextGuardTest`(깨끗한 응답은 바이트까지 그대로이고 겹친 키도 그대로), `ResponseTextCatalogTest`(식별자로 뺀 칸이 닫힌 목록의 종류에만 든다).
- E2E `[T63]`(`scripts/security-scan.ps1`): 검증 스택 DB에 숨은 문자를 낀 이름, 쪼갠 주소, 4,039자 이름, 11번 문장(PostgreSQL이 받지 않는 NUL은 뺐다)을 넣고 분석가·조회자로 큐·상세를 받아 숨은 문자 없음, 표지·제거 표시, 상한, 쪼갠 주소의 가림을 봅니다. 구문만 확인했고 첫 실행은 `T57`입니다.
- 길이 조사: 공개 스냅샷의 응답 표본(조회자 응답, `T39` 판)의 글자 값 약 5만 3천 개와 키를 재 보니 상한을 넘는 값이 없었습니다(이름 최대 34자, 값 최대 91자, 글 최대 472자). 계정 이름은 가려져 있어 잴 수 없었고 분석가 응답으로 다시 재는 일은 `T57`에 넘겼습니다. 탐지 파이프라인의 실측은 보고서 문자열 최대 304자, 응답 전체 2,597자입니다.

### 7.4 남은 위험

1. **혼동 문자**: 키릴 `а` 같은 비슷한 글자는 맞추지 않습니다. NFKC는 전각·호환 문자만 맞춥니다.
2. **가리지 않는 주소 꼴**: 전각 숫자로 쓴 주소와 `::ffff:` 꼴의 IPv6 주소는 조회자에게 가려지지 않습니다(지금과 같다. IPv6 가림은 열린 질문).
3. **표지 위조**: 이름에 글자 그대로 `[U+202E]`나 제거 표시·생략 표시 글을 넣으면 진짜와 구별되지 않습니다. 값 끝에 생략 표시 글을 넣으면 그 글 길이(10~16자)만큼 상한을 넘길 수 있습니다. 둘 다 공격자가 쓴 글이고 넘치는 양이 정해져 있어 해는 작습니다.
4. **이모지**: 이모지 ZWJ 열(U+200D)과 변형 선택자(U+FE0F)도 표지로 바뀝니다. 이름 칸에서는 받아들입니다.
5. **복사·검색**: 분석가가 이름을 복사하면 표지가 든 글이 복사됩니다(원래 바이트는 근거 원문에 있다). 분석가 검색은 화면에서 잘려 안 보이는 256자 뒤에서도 맞습니다.
6. **감사 로그 원문**: 감사 로그에 저장되는 값은 원문입니다(증거). DB를 직접 읽으면 숨은 문자가 그대로 있습니다.
7. **처리 안 된 예외의 로그**: `GlobalExceptionHandler`는 처리 안 된 예외를 메시지와 스택으로 찍습니다. 예외 메시지에 입력 값이 들 수 있습니다(고치지 않았다).
8. **키 겹침**: 조회자에게서 숨은 문자를 지워 Map 키가 겹치면 값 하나를 잃습니다(근거 Map은 뒤의 값이 앞을 덮고, 사실의 구조 값은 통째로 빠진다). 새는 쪽은 아닙니다.
9. **이 처리 밖의 응답**: 로그인한 사용자 자신의 정보(`/api/auth/me`)와 관리자 사용자 관리 응답(`/api/admin/users`)은 응답 직전 처리를 거치지 않습니다. 둘 다 관리자가 정한 표시 이름이고, 사용자 관리는 편집 화면이 받은 값을 그대로 다시 저장합니다. 오류 응답의 문구는 서버가 정한 고정 글입니다. 관리자 중요 자산 화면은 처리 안에 있어, 관리자가 표지가 든 이름을 고치지 않고 다시 저장하면 표지 글(`[U+202E]` 등)이 그대로 저장됩니다(숨은 문자가 보이는 글로 바뀌는 쪽이다).
10. **T63 전부터 있던 가림 누락(이 작업에서 고침)**: 옛 목록 API의 작업(`selectedJob`, `captureJobs[]`)과 상세의 `detail.job`은 조회자에게 작업 오류 글의 주소를 가리지 않았고(현황판·운영 현황의 같은 칸은 가렸다), 상세의 ATT&CK 후보 이름·전술(`detail.report.attackCandidates[].name`·`tactics[]`)도 조회자 가림을 거치지 않았습니다(현황판의 같은 후보 이름은 가렸다). 가리는 쪽으로만 바뀌는 변경이라 설계자가 정해 이 작업에서 고쳤습니다: 작업은 기존 `maskScoringJob`, 후보 이름·전술은 현황판과 같은 조회자 가림입니다. ATT&CK ID는 식별자라 그대로이고 분석가 응답은 바뀌지 않습니다(`T63ViewerMaskingGapIntegrationTest`, 고치기 전 3개 모두 실패). 이 칸들은 이제 "모든 응답" 시험의 "조회자 응답에 가려지지 않은 IPv4 없음" 판정에서도 빠지지 않습니다.
11. **E2E 미실행**: `[T63]`은 Docker를 쓰지 않는 작업이라 돌리지 않았습니다. WAF의 응답 검사 규칙이 공격 문장이 든 응답에 걸리는지도 첫 실행에서 봅니다.
