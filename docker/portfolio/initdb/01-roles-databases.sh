#!/bin/bash
# 포트폴리오 스택 PostgreSQL 초기화 1단계(데이터 폴더가 비어 있을 때 한 번만 실행된다).
# zeek_AD deploy/postgres/init/01-roles-databases.sh와 같은 역할 집합·DB·DB 수준 ACL을 만든다.
# - 스냅샷(pg_dump 단일 DB)에는 역할·DB ACL이 없으므로 여기서 재현하고, 스키마·확장·public 스키마 ACL은
#   덤프에 들어 있으므로 만들지 않는다(02-restore-snapshot.sh가 복원한다).
# - 실제로 로그인하는 역할(zeekad_api, dashboard_ro, dashboard_rw, dashboard_app)만 비밀번호를 받는다.
#   나머지(zeekad_owner, zeekad_worker, mlflow)는 객체 소유·권한 대상으로만 남기고 NOLOGIN이다.
# - 비밀번호가 하나라도 비어 있으면 초기화를 멈춘다(컨테이너가 healthy가 되지 않아 앱·API도 뜨지 않는다).
set -euo pipefail

for var in ZEEKAD_API_PASSWORD DASHBOARD_RO_PASSWORD DASHBOARD_RW_PASSWORD DASHBOARD_APP_PASSWORD; do
    if [ -z "${!var:-}" ]; then
        echo "portfolio-init: ${var} is empty; refusing to initialize" >&2
        exit 1
    fi
done

# 비밀번호는 psql 변수(:'name')로 넘겨 SQL 문자열 이스케이프를 psql이 맡게 한다.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v api_pw="$ZEEKAD_API_PASSWORD" \
    -v ro_pw="$DASHBOARD_RO_PASSWORD" \
    -v rw_pw="$DASHBOARD_RW_PASSWORD" \
    -v app_pw="$DASHBOARD_APP_PASSWORD" <<'SQL'
CREATE ROLE zeekad_owner  NOLOGIN;
CREATE ROLE zeekad_worker NOLOGIN;
CREATE ROLE zeekad_api    LOGIN PASSWORD :'api_pw';
CREATE ROLE dashboard_ro  LOGIN PASSWORD :'ro_pw';
CREATE ROLE dashboard_rw  LOGIN PASSWORD :'rw_pw';
CREATE ROLE mlflow        NOLOGIN;
CREATE ROLE dashboard_app LOGIN PASSWORD :'app_pw';

CREATE DATABASE zeekad OWNER zeekad_owner;
CREATE DATABASE zeekad_dashboard OWNER dashboard_app;
-- 기본으로 모든 역할이 접속할 수 있다. 필요한 역할만 남긴다(zeek_AD 01-roles-databases.sh와 같다).
REVOKE ALL ON DATABASE zeekad FROM PUBLIC;
REVOKE ALL ON DATABASE zeekad_dashboard FROM PUBLIC;
GRANT CONNECT ON DATABASE zeekad TO zeekad_worker, zeekad_api, dashboard_ro, dashboard_rw;

-- 데모 계정 시드(docker/portfolio/seed)가 앱과 같은 BCrypt 해시를 만들 때 쓴다(crypt + gen_salt('bf', 12)).
-- 앱 DB(zeekad_dashboard)나 스냅샷 DB(zeekad)에는 두지 않고 관리용 postgres DB에만 둔다.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
SQL
