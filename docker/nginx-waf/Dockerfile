# 기반 이미지는 태그와 digest로 고정한다. 움직이는 태그(nginx-alpine)를 쓰면 빌드할 때마다 nginx·ModSecurity·CRS 규칙이
# 바뀌어, 검증한 조합과 배포한 조합이 달라질 수 있다. 기반을 올릴 때는 태그와 digest를 함께 바꾸고 다시 검증한다.
FROM owasp/modsecurity-crs:4.30.0-nginx-alpine-202611190211@sha256:f7b4ec036553aa65e65fe792394099f597d6130465e63ff58d84f087617f5412

# libxml2만 고친 판으로 올린다(CVE-2026-86144). 이 기반에는 취약한 2.13.9-r2가 들어 있고, libmodsecurity가 링크해
# XML Content-Type 요청 본문을 로그인 전에 파싱한다.
# - 전체 apk upgrade는 하지 않는다. ModSecurity nginx 모듈은 상류가 특정 nginx 버전에 맞춰 빌드한 것이라 nginx 패키지가
#   함께 올라가면 모듈과 어긋날 수 있다.
# - 하한만 건다(>=). 정확한 판으로 묶으면 Alpine이 옛 -r 판을 저장소에서 지웠을 때 빌드가 깨진다. 하한을 채우는 판이 없으면
#   apk가 실패해 빌드도 실패한다(apk upgrade libxml2는 올릴 판이 없어도 성공으로 끝나 쓰지 않는다).
# - 기반을 올렸는데 그 기반에 이미 2.13.9-r3 이상이 들어 있으면 이 RUN 줄을 지운다.
USER root
RUN apk add --no-cache --upgrade 'libxml2>=2.13.9-r3'

COPY --chown=root:root templates/ /etc/nginx/templates/

# proxy_backend.conf.template의 전달 헤더 값(모든 스택 공통 기본값).
# - X-Forwarded-For: nginx가 정한 클라이언트 IP($remote_addr) 하나로 덮어쓴다. 방문자가 보낸 X-Forwarded-For 뒤에 덧붙이는 값으로
#   바꾸면 앱(forward-headers-strategy: framework)이 맨 왼쪽 값을 클라이언트 IP로 믿어 감사 로그 IP가 위조된다.
# - X-Forwarded-Port: Host의 포트(없으면 리스너 포트). 포트폴리오 스택만 compose에서 바꾼다.
# - RESOLVER_CONFIG: 기반 이미지 nginx.conf의 http 문맥 `resolver RESOLVERS RESOLVER_CONFIG;`에 들어간다. RESOLVERS는 비워 두어
#   /etc/resolv.conf의 nameserver(Docker 사용자 정의 네트워크에서는 내장 DNS 127.0.0.11)를 쓴다. proxy_pass가 변수라
#   업스트림 이름(dashboard-app)을 요청 때 이 resolver로 다시 해석하므로 앱 컨테이너를 다시 만들어 IP가 바뀌어도 502가 남지 않는다.
ENV ZEEKAD_PROXY_X_FORWARDED_FOR=\$remote_addr \
    ZEEKAD_PROXY_X_FORWARDED_PORT=\$forwarded_port \
    RESOLVER_CONFIG="valid=10s ipv6=off"

# ModSecurity 감사 로그에 남기는 부분(T59). 기반 이미지의 modsecurity.conf.template이 이 값을 SecAuditLogParts로 옮긴다.
# - 기반 기본값 ABIJDEFHZ는 요청 헤더(B)와 응답 헤더(F)를 통째로 적어 세션 쿠키·CSRF 토큰·Set-Cookie 값이 컨테이너 로그에 남고,
#   응답 본문(E)도 text/plain·text/html·text/xml이면 남는다(scripts/waf-audit-log-check.ps1로 확인).
# - AHZ만 남긴다: 접속 주소·시각·unique_id·메서드·요청 주소·응답 코드(A), 걸린 규칙의 메시지(H), 끝 표시(Z).
#   요청 헤더가 통째로 빠지므로 차단 요청의 User-Agent·받은 X-Forwarded-For 원문은 접근 로그 줄에서 시각·접속 주소·요청 주소로 찾는다.
#   Host는 접근 로그 서식에 없고 감사 줄의 hostname(A 부분, 포트를 뺀 이름)에 남는다.
# - 설정은 여기 한 곳에 둔다. compose에서 MODSEC_AUDIT_LOG_PARTS를 주면 이 값을 덮으므로 주지 않는다(StaticSecurityAndConfigTest가 본다).
ENV MODSEC_AUDIT_LOG_PARTS=AHZ

USER nginx

# 상태 확인(T61): Host를 이름으로 보낸다. 숫자 주소 Host는 CRS 920350에 걸려 응답이 200이어도 감사 엔진(RelevantOnly)이 상태 확인마다
# 감사 줄을 적었다. 접속 주소는 127.0.0.1 그대로 둔다(localhost 이름으로 접속하면 IPv6 해석에 걸릴 수 있다). 규칙은 끄지 않는다.
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
    CMD wget -q --spider --header "Host: localhost" http://127.0.0.1:8080/healthz || exit 1
