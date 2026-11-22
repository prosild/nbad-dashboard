#!/bin/bash
# 포트폴리오 스택 체험 계정 초기화 설정 도구(T33). compose.portfolio.yml의 sandbox-setup(profile seed, 일회용)으로 실행한다.
#   docker compose ... --profile seed run --rm sandbox-setup                       # 설정(멱등)
#   docker compose ... --profile seed run --rm sandbox-setup --rebuild-baseline    # 새 스냅샷을 올린 뒤 기준선 다시 만들기
# 슈퍼유저(postgres)로 붙어 아래를 만든다. 다시 실행해도 안전하다.
# - zeekad DB
#   - 스키마 sandbox_baseline(소유 zeekad_owner, 초기화 역할 권한 없음): 앱 쓰기 함수 둘이 바꾸는 표 셋의 기준선 사본과 표지(marker).
#     표지는 지금 DB가 어느 스냅샷인지 판별하는 값(인시던트 수·탐지 작업 수·최대 job_id·세 표의 열 정의 해시)이다.
#   - 스키마 sandbox(소유 zeekad_owner): sandbox.reset_pipeline()(SECURITY DEFINER). 초기화 역할은 이 스키마 USAGE와 함수 EXECUTE만 있다
#     (PostgreSQL은 함수를 부를 때 그 스키마 USAGE가 필요하다. 그래서 기준선은 따로 sandbox_baseline에 둔다).
# - zeekad_dashboard DB: 스키마 sandbox(소유 dashboard_app)의 sandbox.reset_assignments()(SECURITY DEFINER).
# - 전용 역할 zeekad_sandbox_reset(LOGIN, 비밀번호 SANDBOX_RESET_DB_PASSWORD): 두 DB CONNECT, 두 sandbox 스키마 USAGE, 두 함수 EXECUTE만.
# 기준선은 처음 만들 때와 --rebuild-baseline일 때만 만든다. 그때는 체험 계정(SANDBOX_TRIAL_USERNAME) 흔적이 세 표와 담당 표에
# 하나도 없어야 하고(방문자 변경이 기준선이 되는 것을 막는다), 처음 만들 때는 담당자가 있는 담당 행이 0이어야 하며(공개 기준선의 담당은 0),
# 다시 만들 때는 초기화 역할의 접속이 없어야 한다(sandbox-reset을 먼저 멈춘다). 아니면 아무것도 바꾸지 않고 멈춘다.
# 비밀번호는 psql 변수로만 넘기고 출력하지 않는다.
set -euo pipefail

REBUILD=0
for arg in "$@"; do
    case "$arg" in
        --rebuild-baseline) REBUILD=1 ;;
        *) echo "sandbox-setup: unknown argument '$arg' (only --rebuild-baseline)" >&2; exit 2 ;;
    esac
done

TRIAL="${SANDBOX_TRIAL_USERNAME:-trial-analyst}"
RESET_ROLE=zeekad_sandbox_reset
if [ -z "${SANDBOX_RESET_DB_PASSWORD:-}" ]; then
    echo "sandbox-setup: SANDBOX_RESET_DB_PASSWORD is empty; refusing to set up" >&2
    exit 1
fi
if [ -z "${PGPASSWORD:-}" ]; then
    echo "sandbox-setup: superuser password (POSTGRES_SUPERUSER_PASSWORD) is empty" >&2
    exit 1
fi

export PGOPTIONS="-c client_min_messages=warning"
log() { echo "sandbox-setup: $*"; }
q() { # q <db> <sql>: 값 하나를 읽는다
    psql -X -q -v ON_ERROR_STOP=1 -At -d "$1" -c "$2"
}
run() { # run <db> [psql args...] < sql
    local db="$1"; shift
    psql -X -q -v ON_ERROR_STOP=1 -d "$db" "$@"
}

# --- 0. 전제: 스냅샷 DB와 앱 DB(Flyway 담당 표)가 있다 ---
for t in zeekad.incident_status zeekad.incident_status_history zeekad.analyst_review zeekad.incident zeekad.scoring_job; do
    if [ "$(q zeekad "SELECT to_regclass('$t') IS NOT NULL")" != "t" ]; then
        log "table $t is missing in zeekad; restore the snapshot first"; exit 1
    fi
done
for t in public.incident_assignments public.incident_assignment_history public.users; do
    if [ "$(q zeekad_dashboard "SELECT to_regclass('$t') IS NOT NULL")" != "t" ]; then
        log "table $t is missing in zeekad_dashboard; start dashboard-app once (Flyway) first"; exit 1
    fi
done

# --- 1. 전용 역할 ---
run postgres -v pw="$SANDBOX_RESET_DB_PASSWORD" <<SQL
SELECT 'CREATE ROLE $RESET_ROLE NOLOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$RESET_ROLE') \gexec
ALTER ROLE $RESET_ROLE WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 4 PASSWORD :'pw';
GRANT CONNECT ON DATABASE zeekad TO $RESET_ROLE;
GRANT CONNECT ON DATABASE zeekad_dashboard TO $RESET_ROLE;
SQL
log "role $RESET_ROLE ready (LOGIN, CONNECT on zeekad and zeekad_dashboard)"

# --- 2. zeekad: 스키마와 표지 계산 함수 ---
run zeekad <<'SQL'
CREATE SCHEMA IF NOT EXISTS sandbox AUTHORIZATION zeekad_owner;
CREATE SCHEMA IF NOT EXISTS sandbox_baseline AUTHORIZATION zeekad_owner;
ALTER SCHEMA sandbox OWNER TO zeekad_owner;
ALTER SCHEMA sandbox_baseline OWNER TO zeekad_owner;
REVOKE ALL ON SCHEMA sandbox FROM PUBLIC;
REVOKE ALL ON SCHEMA sandbox_baseline FROM PUBLIC;

-- 지금 DB가 어느 스냅샷인지(초기화가 바꾸지 않는 표의 수·최대 job_id) + 세 표의 열 정의. 열이 바뀌면 초기화 함수의 열 목록도 맞지 않으므로 거부한다.
CREATE OR REPLACE FUNCTION sandbox_baseline.pipeline_fingerprint() RETURNS text
    LANGUAGE sql STABLE
    SET search_path = pg_catalog, pg_temp
AS $$
SELECT concat_ws('|',
    'incident=' || (SELECT count(*) FROM zeekad.incident),
    'scoring_job=' || (SELECT count(*) FROM zeekad.scoring_job),
    'max_job_id=' || COALESCE((SELECT max(job_id) FROM zeekad.scoring_job)::text, 'none'),
    'columns=' || md5((SELECT string_agg(c.relname || '.' || a.attname || ':' || format_type(a.atttypid, a.atttypmod), ','
                                          ORDER BY c.relname, a.attnum)
                       FROM pg_catalog.pg_attribute a
                       JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
                       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                       WHERE n.nspname = 'zeekad'
                         AND c.relname IN ('incident_status', 'incident_status_history', 'analyst_review')
                         AND a.attnum > 0 AND NOT a.attisdropped)))
$$;
ALTER FUNCTION sandbox_baseline.pipeline_fingerprint() OWNER TO zeekad_owner;
REVOKE ALL ON FUNCTION sandbox_baseline.pipeline_fingerprint() FROM PUBLIC;
SQL

# --- 3. 기준선(처음 또는 --rebuild-baseline) ---
HAS_BASELINE="$(q zeekad "SELECT to_regclass('sandbox_baseline.marker') IS NOT NULL")"
if [ "$HAS_BASELINE" != "t" ] || [ "$REBUILD" = "1" ]; then
    TRACES="$(psql -X -q -v ON_ERROR_STOP=1 -At -d zeekad -v trial="$TRIAL" <<'SQL'
SELECT (SELECT count(*) FROM zeekad.incident_status WHERE updated_by = :'trial')
     + (SELECT count(*) FROM zeekad.incident_status_history WHERE actor = :'trial')
     + (SELECT count(*) FROM zeekad.analyst_review WHERE analyst = :'trial');
SQL
)"
    ASSIGN_TRACES="$(psql -X -q -v ON_ERROR_STOP=1 -At -d zeekad_dashboard -v trial="$TRIAL" <<'SQL'
SELECT count(*) FROM public.incident_assignments a JOIN public.users u ON u.id = a.assignee_user_id WHERE u.username = :'trial';
SQL
)"
    ASSIGNED="$(q zeekad_dashboard "SELECT count(*) FROM public.incident_assignments WHERE assignee_user_id IS NOT NULL")"
    log "trial account '$TRIAL' traces: pipeline tables=$TRACES, current assignments=$ASSIGN_TRACES; assignments with an assignee=$ASSIGNED"
    if [ "$TRACES" != "0" ] || [ "$ASSIGN_TRACES" != "0" ]; then
        log "REFUSED: rows with actor '$TRIAL' exist; a visitor change must not become the baseline (reset first, then retry)."
        log "         If this is a fresh snapshot, the snapshot itself already uses '$TRIAL' as an actor name: choose another trial account name."
        exit 1
    fi
    if [ "$HAS_BASELINE" != "t" ] && [ "$ASSIGNED" != "0" ]; then
        log "REFUSED: $ASSIGNED assignment rows have an assignee; the public baseline has none (check the dashboard DB first)"
        exit 1
    fi
    if [ "$REBUILD" = "1" ]; then
        ACTIVE="$(q postgres "SELECT count(*) FROM pg_stat_activity WHERE usename = '$RESET_ROLE'")"
        if [ "$ACTIVE" != "0" ]; then
            log "REFUSED: $ACTIVE sessions of $RESET_ROLE are active; stop sandbox-reset first"
            exit 1
        fi
    fi
    run zeekad <<'SQL'
BEGIN;
SET LOCAL lock_timeout = '5s';
-- 진행 중인 쓰기를 기다리고 새 쓰기를 막은 채 사본을 뜬다(초기화 함수와 같은 잠금).
LOCK TABLE zeekad.incident_status, zeekad.incident_status_history, zeekad.analyst_review IN SHARE ROW EXCLUSIVE MODE;
DROP TABLE IF EXISTS sandbox_baseline.marker, sandbox_baseline.incident_status,
                     sandbox_baseline.incident_status_history, sandbox_baseline.analyst_review;
CREATE TABLE sandbox_baseline.incident_status (LIKE zeekad.incident_status);
CREATE TABLE sandbox_baseline.incident_status_history (LIKE zeekad.incident_status_history);
CREATE TABLE sandbox_baseline.analyst_review (LIKE zeekad.analyst_review);
INSERT INTO sandbox_baseline.incident_status SELECT * FROM zeekad.incident_status;
INSERT INTO sandbox_baseline.incident_status_history SELECT * FROM zeekad.incident_status_history;
INSERT INTO sandbox_baseline.analyst_review SELECT * FROM zeekad.analyst_review;
ALTER TABLE sandbox_baseline.incident_status ADD PRIMARY KEY (incident_id);
ALTER TABLE sandbox_baseline.incident_status_history ADD PRIMARY KEY (history_id);
ALTER TABLE sandbox_baseline.analyst_review ADD PRIMARY KEY (job_id, incident_id);
CREATE TABLE sandbox_baseline.marker (
    id integer PRIMARY KEY CHECK (id = 1),
    fingerprint text NOT NULL,
    restore_marker text,
    incident_status_rows bigint NOT NULL,
    incident_status_history_rows bigint NOT NULL,
    analyst_review_rows bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO sandbox_baseline.marker (id, fingerprint, restore_marker, incident_status_rows, incident_status_history_rows, analyst_review_rows)
SELECT 1, sandbox_baseline.pipeline_fingerprint(),
       -- 스냅샷 복원 표지(02-restore-snapshot.sh가 데이터 폴더에 남긴 덤프 SHA-256). 기록용이다.
       btrim(pg_read_file('portfolio-restore.ok', true), E' \n'),
       (SELECT count(*) FROM sandbox_baseline.incident_status),
       (SELECT count(*) FROM sandbox_baseline.incident_status_history),
       (SELECT count(*) FROM sandbox_baseline.analyst_review);
ALTER TABLE sandbox_baseline.incident_status OWNER TO zeekad_owner;
ALTER TABLE sandbox_baseline.incident_status_history OWNER TO zeekad_owner;
ALTER TABLE sandbox_baseline.analyst_review OWNER TO zeekad_owner;
ALTER TABLE sandbox_baseline.marker OWNER TO zeekad_owner;
REVOKE ALL ON ALL TABLES IN SCHEMA sandbox_baseline FROM PUBLIC;
COMMIT;
SQL
    log "baseline $( [ "$HAS_BASELINE" = "t" ] && echo rebuilt || echo created ): $(q zeekad "SELECT format('status=%s history=%s review=%s restore_marker=%s fingerprint=%s', incident_status_rows, incident_status_history_rows, analyst_review_rows, left(COALESCE(restore_marker, '(none)'), 12), fingerprint) FROM sandbox_baseline.marker")"
else
    MATCH="$(q zeekad "SELECT fingerprint = sandbox_baseline.pipeline_fingerprint() FROM sandbox_baseline.marker WHERE id = 1")"
    log "baseline kept: $(q zeekad "SELECT format('created_at=%s status=%s history=%s review=%s', created_at, incident_status_rows, incident_status_history_rows, analyst_review_rows) FROM sandbox_baseline.marker")"
    if [ "$MATCH" != "t" ]; then
        log "REFUSED: the baseline does not match the current snapshot (stop sandbox-reset, then run with --rebuild-baseline)"
        exit 1
    fi
fi

# --- 4. zeekad: 초기화 함수 ---
run zeekad <<'SQL'
-- 세 표를 기준선과 기본키로 맞춘다: 기준선에 없는 키는 지우고, 칸이 다르면(모든 칸 IS DISTINCT FROM) 기준선 값으로 되돌리고, 없어진 행은 넣는다.
-- 처음에 세 표를 SHARE ROW EXCLUSIVE로 잠가 진행 중인 쓰기(아직 커밋 안 된 새 행 포함)를 기다리고 새 쓰기를 막는다. 5초 안에 못 잡으면 오류(다음 정각에 다시).
-- 표지가 지금 DB와 다르면(새 스냅샷인데 옛 기준선) 아무것도 바꾸지 않고 오류를 낸다.
CREATE OR REPLACE FUNCTION sandbox.reset_pipeline()
    RETURNS TABLE (table_name text, deleted bigint, inserted bigint, reverted bigint)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    SET lock_timeout = '5s'
AS $$
DECLARE
    v_expected text;
    v_current text;
    d bigint;
    i bigint;
    r bigint;
BEGIN
    LOCK TABLE zeekad.incident_status, zeekad.incident_status_history, zeekad.analyst_review IN SHARE ROW EXCLUSIVE MODE;

    SELECT m.fingerprint INTO v_expected FROM sandbox_baseline.marker m WHERE m.id = 1;
    v_current := sandbox_baseline.pipeline_fingerprint();
    IF v_expected IS NULL OR v_expected IS DISTINCT FROM v_current THEN
        RAISE EXCEPTION 'sandbox baseline does not match the current snapshot (baseline %, current %); rebuild the baseline',
            COALESCE(v_expected, '(none)'), v_current USING ERRCODE = '55000';
    END IF;

    -- incident_status (PK incident_id)
    DELETE FROM zeekad.incident_status t
     WHERE NOT EXISTS (SELECT 1 FROM sandbox_baseline.incident_status b WHERE b.incident_id = t.incident_id);
    GET DIAGNOSTICS d = ROW_COUNT;
    UPDATE zeekad.incident_status t
       SET last_job_id = b.last_job_id, status = b.status, resolution = b.resolution,
           updated_at = b.updated_at, updated_by = b.updated_by
      FROM sandbox_baseline.incident_status b
     WHERE b.incident_id = t.incident_id
       AND (t.last_job_id, t.status, t.resolution, t.updated_at, t.updated_by)
           IS DISTINCT FROM (b.last_job_id, b.status, b.resolution, b.updated_at, b.updated_by);
    GET DIAGNOSTICS r = ROW_COUNT;
    INSERT INTO zeekad.incident_status (last_job_id, incident_id, status, resolution, updated_at, updated_by)
    SELECT b.last_job_id, b.incident_id, b.status, b.resolution, b.updated_at, b.updated_by
      FROM sandbox_baseline.incident_status b
     WHERE NOT EXISTS (SELECT 1 FROM zeekad.incident_status t WHERE t.incident_id = b.incident_id);
    GET DIAGNOSTICS i = ROW_COUNT;
    table_name := 'incident_status'; deleted := d; inserted := i; reverted := r;
    RETURN NEXT;

    -- incident_status_history (PK history_id)
    DELETE FROM zeekad.incident_status_history t
     WHERE NOT EXISTS (SELECT 1 FROM sandbox_baseline.incident_status_history b WHERE b.history_id = t.history_id);
    GET DIAGNOSTICS d = ROW_COUNT;
    UPDATE zeekad.incident_status_history t
       SET job_id = b.job_id, incident_id = b.incident_id, from_status = b.from_status, to_status = b.to_status,
           resolution = b.resolution, actor = b.actor, reason = b.reason, changed_at = b.changed_at
      FROM sandbox_baseline.incident_status_history b
     WHERE b.history_id = t.history_id
       AND (t.job_id, t.incident_id, t.from_status, t.to_status, t.resolution, t.actor, t.reason, t.changed_at)
           IS DISTINCT FROM (b.job_id, b.incident_id, b.from_status, b.to_status, b.resolution, b.actor, b.reason, b.changed_at);
    GET DIAGNOSTICS r = ROW_COUNT;
    -- history_id는 GENERATED ALWAYS identity라 기준선 값을 그대로 넣으려면 OVERRIDING SYSTEM VALUE가 필요하다.
    INSERT INTO zeekad.incident_status_history (history_id, job_id, incident_id, from_status, to_status, resolution, actor, reason, changed_at)
    OVERRIDING SYSTEM VALUE
    SELECT b.history_id, b.job_id, b.incident_id, b.from_status, b.to_status, b.resolution, b.actor, b.reason, b.changed_at
      FROM sandbox_baseline.incident_status_history b
     WHERE NOT EXISTS (SELECT 1 FROM zeekad.incident_status_history t WHERE t.history_id = b.history_id);
    GET DIAGNOSTICS i = ROW_COUNT;
    table_name := 'incident_status_history'; deleted := d; inserted := i; reverted := r;
    RETURN NEXT;

    -- analyst_review (PK job_id, incident_id)
    DELETE FROM zeekad.analyst_review t
     WHERE NOT EXISTS (SELECT 1 FROM sandbox_baseline.analyst_review b
                        WHERE b.job_id = t.job_id AND b.incident_id = t.incident_id);
    GET DIAGNOSTICS d = ROW_COUNT;
    UPDATE zeekad.analyst_review t
       SET requested_at = b.requested_at, reason = b.reason, action = b.action, analyst = b.analyst, note = b.note,
           decided_at = b.decided_at, resumed_at = b.resumed_at, resume_error = b.resume_error
      FROM sandbox_baseline.analyst_review b
     WHERE b.job_id = t.job_id AND b.incident_id = t.incident_id
       AND (t.requested_at, t.reason, t.action, t.analyst, t.note, t.decided_at, t.resumed_at, t.resume_error)
           IS DISTINCT FROM (b.requested_at, b.reason, b.action, b.analyst, b.note, b.decided_at, b.resumed_at, b.resume_error);
    GET DIAGNOSTICS r = ROW_COUNT;
    INSERT INTO zeekad.analyst_review (job_id, incident_id, requested_at, reason, action, analyst, note, decided_at, resumed_at, resume_error)
    SELECT b.job_id, b.incident_id, b.requested_at, b.reason, b.action, b.analyst, b.note, b.decided_at, b.resumed_at, b.resume_error
      FROM sandbox_baseline.analyst_review b
     WHERE NOT EXISTS (SELECT 1 FROM zeekad.analyst_review t WHERE t.job_id = b.job_id AND t.incident_id = b.incident_id);
    GET DIAGNOSTICS i = ROW_COUNT;
    table_name := 'analyst_review'; deleted := d; inserted := i; reverted := r;
    RETURN NEXT;
END
$$;
ALTER FUNCTION sandbox.reset_pipeline() OWNER TO zeekad_owner;
REVOKE ALL ON FUNCTION sandbox.reset_pipeline() FROM PUBLIC;
GRANT USAGE ON SCHEMA sandbox TO zeekad_sandbox_reset;
GRANT EXECUTE ON FUNCTION sandbox.reset_pipeline() TO zeekad_sandbox_reset;
SQL
log "zeekad: sandbox.reset_pipeline() ready"

# --- 5. zeekad_dashboard: 담당 해제 함수 ---
run zeekad_dashboard <<'SQL'
CREATE SCHEMA IF NOT EXISTS sandbox AUTHORIZATION dashboard_app;
ALTER SCHEMA sandbox OWNER TO dashboard_app;
REVOKE ALL ON SCHEMA sandbox FROM PUBLIC;

-- 공개 기준선의 담당은 0이다. 담당자가 있는 현재 행을 모두 해제하고(NULL, version 올림, 행은 지우지 않음)
-- 추가만 하는 담당 이력에 해제 행을 덧붙인다(행위자 sandbox-reset, reason은 기존 값 manual). 감사 로그·이력은 지우지 않는다.
CREATE OR REPLACE FUNCTION sandbox.reset_assignments()
    RETURNS TABLE (released bigint, history_rows bigint)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    SET lock_timeout = '5s'
AS $$
BEGIN
    LOCK TABLE public.incident_assignments IN SHARE ROW EXCLUSIVE MODE;
    RETURN QUERY
    WITH old AS (
        SELECT a.incident_id, a.capture_id, a.assignee_user_id
          FROM public.incident_assignments a
         WHERE a.assignee_user_id IS NOT NULL
    ), upd AS (
        UPDATE public.incident_assignments a
           SET assignee_user_id = NULL, assigned_at = now(), assigned_by = 'sandbox-reset', version = a.version + 1
          FROM old
         WHERE a.incident_id = old.incident_id
        RETURNING a.incident_id
    ), ins AS (
        INSERT INTO public.incident_assignment_history
               (incident_id, capture_id, job_id, from_user_id, to_user_id, actor_username, reason, changed_at)
        SELECT old.incident_id, old.capture_id, NULL, old.assignee_user_id, NULL, 'sandbox-reset', 'manual', now()
          FROM old
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM upd), (SELECT count(*) FROM ins);
END
$$;
ALTER FUNCTION sandbox.reset_assignments() OWNER TO dashboard_app;
REVOKE ALL ON FUNCTION sandbox.reset_assignments() FROM PUBLIC;
GRANT USAGE ON SCHEMA sandbox TO zeekad_sandbox_reset;
GRANT EXECUTE ON FUNCTION sandbox.reset_assignments() TO zeekad_sandbox_reset;
SQL
log "zeekad_dashboard: sandbox.reset_assignments() ready"

# --- 6. 권한 점검: 초기화 역할은 두 함수 EXECUTE와 그 스키마 USAGE만(CREATE·표 권한 없음) ---
CHECK_SQL="SELECT concat_ws(' ',
  'public_create=' || has_schema_privilege('$RESET_ROLE', 'public', 'CREATE'),
  'sandbox_create=' || has_schema_privilege('$RESET_ROLE', 'sandbox', 'CREATE'),
  'db_create=' || has_database_privilege('$RESET_ROLE', current_database(), 'CREATE'),
  'db_temp=' || has_database_privilege('$RESET_ROLE', current_database(), 'TEMP'),
  'table_grants=' || (SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = '$RESET_ROLE'))"
Z="$(q zeekad "$CHECK_SQL") baseline_usage=$(q zeekad "SELECT has_schema_privilege('$RESET_ROLE', 'sandbox_baseline', 'USAGE')::text")"
D="$(q zeekad_dashboard "$CHECK_SQL")"
log "privileges of $RESET_ROLE: zeekad[$Z] zeekad_dashboard[$D]"
for v in $Z $D; do
    case "$v" in
        *=true|*=t|table_grants=[1-9]*)
            log "REFUSED: unexpected privilege $v for $RESET_ROLE"; exit 1 ;;
    esac
done
log "RESULT: OK"
