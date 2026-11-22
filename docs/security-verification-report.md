# zeek_ad_dashboard 보안 검증 보고서

`zeek_ad_dashboard`의 보안 검증을 실제로 돌린 결과와 조치, 남은 위험을 적습니다. 대상은 멀티스테이지 컨테이너 빌드, 앞단 Nginx + ModSecurity(OWASP CRS) WAF, React SPA와 JSON REST API(`/api/**`)를 PostgreSQL 17에 붙여 돌린 E2E, CycloneDX SBOM, Trivy 취약점·설정 스캔, OWASP ZAP 베이스라인 스캔입니다.

## 최근 검증

주요 변경 뒤 아래 검증을 다시 돌립니다. 가장 최근 실행은 `T31`(2026-11-22, commit `4d8674a`)입니다. 실행 기록 원본은 저장소 밖에 보관합니다.

| 검증 | 다시 돌리는 방법 | 결과 |
|---|---|---|
| 프론트엔드 타입 검사·Vitest·빌드, Gradle `check`(단위·통합·정적 보안 시험) | `npm --prefix frontend run typecheck`, `run test`, `run build`, `.\gradlew.bat check --rerun-tasks --no-daemon` | 통과 |
| VMware 구성 E2E(PostgreSQL 17 + WAF + SPA/JSON API, 역할별 권한·IDOR·마스킹·감사 로그) + OWASP ZAP 베이스라인 | `scripts/security-scan.ps1` (WAF Dockerfile이 바뀌어 Trivy 포함) | 종료 코드 `0`, XML 본문 경로 `[15]` 포함, ZAP High `0`·Medium `0`·Low `0`(허용 예외 `XSRF-TOKEN` 제외)·Informational `4` |
| 공개 스택 리허설(스냅샷 복원, 시드, E2E `[0]`~`[8]`·`[T25]`·`[T27]`·`[T29]`, ZAP) | `scripts/portfolio-verify.ps1` | 통과, ZAP High `0`·Medium `0`·Low `0`·Informational `4` |
| 공개 주소 확인(`demo` 로그인·마스킹·허용 캡처·숨김 캡처 `403`·속도 제한 등) | [`docs/portfolio-deployment.md`](portfolio-deployment.md) 4.4 체크리스트 | PASS `124`, FAIL `0` |

Trivy는 의존성이나 Dockerfile이 바뀔 때만 돌립니다. 마지막 실행은 `T31`(2026-11-22)입니다.

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
| [8] 감사 로그 불변 | `UPDATE audit_logs SET action_type = 'TAMPERED' ...` | `ERROR: audit_logs is append-only: UPDATE is forbidden` |
| 공통 | 모든 응답 본문 63건 | `정확도` 문구 0건 |

> [!NOTE]
> **판정 방식(2026-11-20 결정):** `분석가 결론 집계`, `놓친 공격(재현율)`, `전체 (all)`은 데이터가 아니라 SPA 화면에 고정된 문구이므로 배포된 JS 번들 안에 있는지로 판정합니다. 데이터 쪽은 `/api/operations` JSON의 `feedbackSummaries`·`allModel`·`precisionSummaryText` 필드로 판정합니다.
>
> **WAF 차단 판정:** 상태 코드만 보지 않습니다. 응답 본문이 앱의 `ApiErrorResponse` JSON(`code`)이 아니고 요청마다 붙인 `X-E2E-Probe` 헤더로 찾은 `nginx-waf` ModSecurity 감사 로그에 `is_interrupted=true`, `http_code=403`, 규칙 ID가 있어야 통과입니다. E2E는 `127.0.0.1`로 접속하므로 모든 요청에 `920350`(숫자 IP Host, 3점)이 함께 기록됩니다. 각 공격은 그 규칙 하나만으로 임계값 `5` 이상(예: `942100` 단독 5점)입니다.
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
