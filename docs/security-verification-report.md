# zeek_ad_dashboard 보안 검증 보고서

이 문서는 `zeek_ad_dashboard`의 컨테이너 구성, 앞단 Nginx + ModSecurity(OWASP CRS) WAF, 실제 PostgreSQL 17 연동 E2E 동작, CycloneDX SBOM, Trivy 취약점/설정 스캔, OWASP ZAP 베이스라인 스캔의 **실제 실행 결과와 조치 내역, 잔여 위험**을 기록합니다.

---

## 1. 검증 환경 및 실행 명령

| 항목 | 실행 명령 | 비고 |
|---|---|---|
| 정적 검사·단위/통합 테스트 | `.\gradlew.bat check --rerun-tasks --no-daemon` | MyBatis `#{}` 전용, 보안 헤더, RBAC/IDOR, v2.1·migration 014~017(`slack_deliveries` `incident_id` 단독/스레드, `decide_review`, `zeekad-fusion/3`, `feedback_summary` 결론 집계), Docker/WAF·코드 중립성 정적 검증 |
| CycloneDX SBOM 생성 | `.\gradlew.bat cyclonedxBom --no-daemon` | `build/reports/bom.json`, `build/reports/bom.xml` 생성 |
| Docker Compose 유효성 | `docker compose config -q` 및 `docker compose -f compose.yml -f docker/verify/compose.verify.yml config -q` | VMware 통합 운영 기본값(`http://api:8000`) 및 검증 오버라이드 검증 |
| 통합 보안 검증 스크립트 | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/security-scan.ps1 -EvidenceDir "handoff/T07/evidence"` | SBOM → 이미지 빌드 → Trivy → PG17+WAF E2E(v2.1 + migration 014~017 포함) → OWASP ZAP 일괄 실행 후 `down -v` 정리 |

> [!NOTE]
> 대용량 원본 스캔 리포트(`trivy-*.json`, `zap-baseline.html/json`, `bom.json/xml`)는 `.gitignore`에 등록된 `security-reports/` 경로에 생성되며 Git 저장소에는 포함하지 않습니다.

---

## 2. 빌드·정적 보안·컨테이너 격리 검증

1. **`.\gradlew.bat check --rerun-tasks --no-daemon`**: 종료 코드 `0` (전체 단위·통합 테스트 통과).
   - `StaticSecurityAndConfigTest`: MyBatis XML/인터페이스 `${}` 치환 `0`건, `ZeekadReadMapper`의 `findRawFeedbackSummaries`·`dashboard.feedback_summary` 포함 및 `operations/index.html` 내 `"정확도"` 미포함, PostgreSQL `audit_logs` 불변 트리거 DDL, `application.yml` 평문 비밀번호 `0`건, `Dockerfile`/`.dockerignore`/`compose.yml`/`.env.example`/`docker/nginx-waf/` 필수 파일 및 평문 비밀번호·TLS 개인키 `0`건, `.gitignore` 제외 규칙, `build.gradle`의 `h2` `testImplementation` 격리를 모두 확인했습니다.
2. **프로덕션 `bootJar` 격리 확인**:
   - 실행 중인 `dashboard-app` 컨테이너 내부에서 `unzip -l /app/app.jar | grep -E 'h2-|application-test\.yml'`을 실행한 결과 `NO_H2_OR_TEST_YML`로 확인되었습니다.
3. **네트워크·권한 격리**:
   - `compose.yml`의 `dashboard-app`은 `expose: ["8080"]`만 선언하고 호스트 포트를 직접 열지 않으며, `appuser`(non-root)로 실행됩니다.
   - `nginx-waf`는 `nginx`(non-root)로 실행되며 컨테이너 기동 시 `/docker-entrypoint.d/10-generate-certificate.sh`가 자체 서명 TLS 인증서를 런타임 동적 생성하므로 이미지와 Git에 개인키가 남지 않습니다.

---

## 3. PostgreSQL 17 + Nginx ModSecurity WAF 실측 E2E 검증

`compose.yml` + `docker/verify/compose.verify.yml`(`postgres:17-alpine`) 기동 후 외부 HTTPS(`https://127.0.0.1:18443`) 및 HTTP(`http://127.0.0.1:18080`) 엔드포인트로 실측했습니다.

| 검증 항목 | 요청/대상 | 실측 결과 |
|---|---|---|
| HTTP → HTTPS 리다이렉트 | `GET http://127.0.0.1:18080/login` | `301 Moved Permanently` (`Location: https://127.0.0.1:18443/login`) |
| 로그인 화면 및 보안 헤더 | `GET https://127.0.0.1:18443/login` | `200 OK`, `Content-Security-Policy` (`frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Strict-Transport-Security`, `COOP/COEP/CORP`, `Permissions-Policy` 확인. `Server` 헤더 및 와일드카드 CORS 헤더 미노출 |
| 세션 쿠키 속성 | `POST /login` (`viewer1`) | `Set-Cookie: ZEEKAD_SESSION=...; Path=/; Secure; HttpOnly; SameSite=Lax` |
| WAF SQLi 차단 | `GET /incidents?asset=' OR 1=1--` | `403 Forbidden` (ModSecurity CRS 차단) |
| WAF XSS 차단 | `GET /incidents?asset=<script>alert(1)</script>` | `403 Forbidden` (ModSecurity CRS 차단) |
| WAF 경로 탐색 차단 | `GET /incidents?asset=../../etc/passwd` / `GET /../../etc/passwd` | 쿼리 경로 탐색 `403 Forbidden` (URI `/../../etc/passwd`는 Nginx `400 Bad Request` 거부) |
| Actuator 비노출 | `GET /actuator/health`, `GET /actuator/env` | 모두 앞단 Nginx `location ^~ /actuator`에서 `403 Forbidden` 차단 |
| `VIEWER` 마스킹·IDOR·전이·검토 결정 차단 | `viewer1`(`cic17-*`) | `cic17-wed` 큐/상세 `200 OK`, IP 마스킹(`192.168.*.*`), Slack 스레드 묶음(`머리 알림`·`머리 사건 후속 답글`·`broadcast` 및 `101/rank/2` `스레드 답글` `zeekad_thread_parent` 마스킹), `/operations` `feedback_summary` 내 `cic17-wed`만 노출(`정밀도 0.00, 결론 1/3 (33.3%)`, `놓친 공격(재현율)` 안내, `syn1-tue`·`lab-20261118`·`lab-fusion-v2` 및 `"정확도"` 미포함), 미허용 `syn1-tue`(`/incidents/201/rank/1`) `403`, 상태 전이 POST `403`, 검토 결정 POST(`/reviews/decide`, `/incidents/101/rank/2/review-decision`) 모두 `403` |
| `ANALYST` 인가·PostgreSQL 전이·검토 결정 | `analyst1`(`cic17-*`) | 미허용 `syn1-tue`·`lab-20261118` 조회 및 `job 201` 검토 결정 IDOR 모두 `403`, `/operations` `feedback_summary` 내 `cic17-wed`만 노출(타 캡처 미노출), 허용 사건 원문(`192.168.10.50`) 조회 `200 OK`, `open → investigating` `POST /transition` `302` 후 반영 확인, `101/rank/2` `confirm` 검토 결정 `302` 후 `결정: confirm`·`반영 중` 확인, 중복 결정 재시도 시 `22023` 오류 및 새로고침 안내 확인 |
| `ADMIN` TOTP + v2.1/`zeekad-fusion/3`/Slack/검토/결론 집계 E2E | `admin`(`*`) + `lab-20261118` · `lab-fusion-v2` | TOTP 2차 인증(`302`) 후 `lab-20261118` 기본 큐·보고서 없음(`502/rank/1`)·이력 합산(`501+502`), `502/rank/2` `closed`(`true_positive`) 전이 후 `/operations`에서 `zeekad-fusion/3`·`feedback_summary` 전체 캡처(`cic17-wed`·`syn1-tue`·`lab-20261118`·`lab-fusion-v2`)·`전체 (all)`·`정밀도 1.00, 결론 1/2 (50.0%)`·알림 정밀도 `정밀도 1.00, 결론 1/1 (100.0%)`·재현율 안내 확인, `602/rank/1` `zeekad-fusion/3`(45분 사건)·재생성 보고서(`602`) 뒤에도 `incident_id` 단독 Slack(`job #601`) 조회, `/reviews/decide` `dismiss` 결정 후 중복(`601`) 제거 및 `반영 중`·`반영 실패(운영자 확인)` 표시 확인 |
| 감사 로그 불변 트리거 | `UPDATE audit_logs SET action_type = 'TAMPERED' ...` | PostgreSQL 17 Flyway 트리거가 `ERROR: audit_logs is append-only: UPDATE is forbidden`으로 차단 |

---

## 4. CycloneDX SBOM 및 Trivy 스캔 결과

### 4.1 초기 스캔 대비 조치 내역
1. **Java 의존성 CVE 조치 (`build.gradle`)**:
   - 초기 스캔에서 Spring Boot `3.5.3` 기본 의존성 기준 `bom.json` `82`건 / `app.jar` `83`건(CRITICAL 16, HIGH 28, MEDIUM 28, LOW 11)이 탐지되었습니다.
   - Spring Boot `3.5.16` 및 하위 라이브러리 패치 버전(`tomcat 10.1.62`, `thymeleaf 3.1.7.RELEASE`, `spring-security 6.5.11`, `spring-framework 6.2.19`, `jackson 2.22.4`, `postgresql 42.7.14`, `logback 1.5.38`, `log4j2 2.26.1`, `mybatis-spring-boot-starter 3.0.5` / `mybatis 3.5.19`)으로 상향해 재스캔했습니다.
2. **OS 패키지 및 Dockerfile 정적 점검 조치**:
   - `Dockerfile`에 `apk upgrade --no-cache`를 추가해 `zeek-ad-dashboard-app:local`의 Alpine `zlib 1.3.2-r1` MEDIUM 1건을 `0`건으로 해소했습니다.
   - `docker/nginx-waf/Dockerfile`에 `USER nginx`와 `HEALTHCHECK`를 명시해 `Trivy FS` Dockerfile 오설정(`DS-0002`, `DS-0026`) 2건을 `0`건으로 해소했습니다.

### 4.2 최종 Trivy 스캔 요약

| 스캔 대상 | 유형 | CRITICAL | HIGH | MEDIUM | LOW | 비고 |
|---|---|---:|---:|---:|---:|---|
| `build/reports/bom.json` (`trivy sbom`) | Java SBOM | 2 | 0 | 0 | 0 | 초기 82건 → 2건 |
| 저장소 전체 (`trivy fs`) | Dockerfile / Secret | 0 | 0 | 0 | 0 | 오설정 0건, 비밀값 노출 0건 |
| `zeek-ad-dashboard-app:local` | Alpine 3.24.4 OS | 0 | 0 | 0 | 0 | 초기 1건 → 0건 |
| `zeek-ad-dashboard-app:local` | `app/app.jar` | 2 | 0 | 1 | 0 | 초기 83건 → 3건 |
| `zeek-ad-dashboard-waf:local` | Alpine 3.24.4 OS (`nginx`) | 0 | 5 | 4 | 0 | 기반 이미지 `owasp/modsecurity-crs:nginx-alpine` 내 `nginx 1.30.6-r1` (Fixed: `1.30.7-r0`) |

### 4.3 잔여 위험 및 수용 근거
1. **`org.springframework:spring-webmvc 6.2.19` (`CVE-2026-47884`, `CVE-2026-47890` — CRITICAL, Fixed in `7.0.9`)**:
   - Spring Framework `7.0.9`(Spring Boot `4.x` 세대) 메이저 업그레이드가 필요한 항목입니다.
   - `CVE-2026-47884`는 `XsltView` 경로 제한 우회, `CVE-2026-47890`은 SSE(Server-Sent Events) 뷰 스트림 손상 취약점이며, 본 대시보드는 Thymeleaf SSR 템플릿만 사용하고 `XsltView`와 SSE 뷰를 전혀 사용하지 않아 실질적 공격 표면이 없습니다. 향후 Spring Boot 4.x 전환 시 해소 대상입니다.
2. **`ognl:ognl 3.4.4` (`CVE-2026-113730` — MEDIUM, Fixed in `3.4.13`)**:
   - `mybatis-3.5.19.jar` 내부에 shaded(`org.apache.ibatis.ognl`) 형태로 내장된 라이브러리입니다.
   - 본 애플리케이션은 MyBatis 정적 XML 매퍼(`#{}` 바인딩 전용, `${}` 0건)만 사용하며 외부 사용자 입력을 OGNL 표현식으로 평가하지 않으므로 직접적인 악용 경로가 없습니다.
3. **`zeek-ad-dashboard-waf:local` 기반 이미지 `nginx 1.30.6-r1` (`CVE-2026-113425` 외 HIGH 5건 · MEDIUM 4건, Fixed in `1.30.7-r0`)**:
   - 업스트림 `owasp/modsecurity-crs:nginx-alpine` 이미지에 포함된 Alpine `nginx 1.30.6-r1` 패키지 항목입니다(애플리케이션 컨테이너에는 미포함). 업스트림 베이스 이미지 갱신(`1.30.7-r0` 이상 반영) 시 재빌드로 해소 대상이며, 본 WAF 구성은 mail/client-cert/HTTP2 취약 구성 기능을 사용하지 않습니다.

---

## 5. OWASP ZAP 베이스라인 스캔 결과 (`zap-baseline.py`)

기동된 `https://nginx-waf:8443/` 대상(`--network <compose_net>`)으로 `ghcr.io/zaproxy/zaproxy:stable zap-baseline.py`를 실행했습니다.

### 5.1 조치 및 재스캔 내역
- **1차 스캔 (`ZAP_EXIT_CODE=2`)**: `High: 0`, `Medium: 0`, `Low: 4`(`Cross-Origin-Embedder-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `Permissions-Policy` 헤더 미설정), `Informational: 3`, `PASS: 63`.
- **조치 (`SecurityConfig.java`)**: 동일 출처(Same-Origin) 기반 애플리케이션 특성에 맞게 `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()` 응답 헤더를 추가하고 재빌드·재스캔했습니다.
- **최종 스캔 (`ZAP_EXIT_CODE=2`)**:
  - **High**: `0`
  - **Medium**: `0`
  - **Low**: `0`
  - **Informational**: `3` (`Authentication Request Identified [10111]`, `Non-Storable Content [10049]` — 보안 페이지 `Cache-Control: no-store` 정책에 따른 정상 판정, `Session Management Response Identified [10112]`)
  - **PASS**: `65`건 (`FAIL-NEW: 0`)
