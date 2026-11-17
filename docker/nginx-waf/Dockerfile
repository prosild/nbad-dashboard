FROM owasp/modsecurity-crs:nginx-alpine

COPY --chown=root:root templates/ /etc/nginx/templates/

USER nginx

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
    CMD wget -q --spider http://127.0.0.1:8080/healthz || exit 1
