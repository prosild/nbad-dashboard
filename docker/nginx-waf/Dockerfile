FROM owasp/modsecurity-crs:nginx-alpine

COPY --chown=root:root templates/ /etc/nginx/templates/

# proxy_backend.conf.template의 전달 헤더 값. 기본값은 이 변수를 넣기 전과 같다($proxy_add_x_forwarded_for, $forwarded_port).
# 포트폴리오 스택(compose.portfolio.yml)만 바꾼다. includes/proxy_backend_extra*.conf는 기본 이미지에 없어 빈 include다.
ENV ZEEKAD_PROXY_X_FORWARDED_FOR=\$proxy_add_x_forwarded_for \
    ZEEKAD_PROXY_X_FORWARDED_PORT=\$forwarded_port

USER nginx

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
    CMD wget -q --spider http://127.0.0.1:8080/healthz || exit 1
