FROM owasp/modsecurity-crs:nginx-alpine

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

USER nginx

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
    CMD wget -q --spider http://127.0.0.1:8080/healthz || exit 1
