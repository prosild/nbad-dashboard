#!/bin/sh
set -eu

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=ON_ERROR_STOP=1 \
    -v app_pw="$VERIFY_APP_DB_PASSWORD" \
    -v ro_pw="$VERIFY_RO_DB_PASSWORD" \
    -v rw_pw="$VERIFY_RW_DB_PASSWORD" <<'EOSQL'
CREATE ROLE dashboard_app WITH LOGIN PASSWORD :'app_pw';
CREATE ROLE dashboard_ro WITH LOGIN PASSWORD :'ro_pw';
CREATE ROLE dashboard_rw WITH LOGIN PASSWORD :'rw_pw';

CREATE DATABASE zeekad_dashboard OWNER dashboard_app;
CREATE DATABASE zeekad OWNER postgres;
EOSQL
