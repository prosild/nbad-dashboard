-- T58 감사 로그 보관 기한.
-- 감사 로그는 여전히 추가만 한다. 바뀌는 것은 하나다: 보관 기한이 지난 행을 전용 함수로 지울 수 있다.
-- - UPDATE와 TRUNCATE는 어떤 경우에도 거부한다(TRUNCATE는 이 migration부터 막는다).
-- - DELETE는 아래 둘이 모두 참일 때만 통과한다.
--     1) 표식 dashboard.audit_retention_purge = 'on'
--     2) 행의 occurred_at이 30일보다 오래됨(바닥값. SQL에 박았고 설정으로 줄일 수 없다)
-- - 표식은 권한 경계가 아니라 실수 방지다. 사용자 정의 설정은 어느 역할이든 세션에서 켤 수 있고 트리거는 누가 켰는지 가르지 못한다.
--   권한 경계는 표 소유권(표에 DELETE 권한이 있는 역할은 소유자 dashboard_app뿐)과 바닥값 30일이다.
-- - 기한(일)은 앱이 모른다. 배포가 정해 public.purge_expired_audit_logs(<일>)를 부른다(부르지 않으면 아무것도 지워지지 않는다).
--   앱 코드에는 감사 로그를 지우는 문장이 없다.
-- 되돌린 뒤(앱 DB 백업 복원) 이 파일이 다시 돌 수 있으므로 모두 CREATE OR REPLACE로 만든다.

CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- TG_OP를 먼저 본다: 문장 수준(TRUNCATE) 호출에는 OLD가 없다.
    IF TG_OP = 'DELETE' THEN
        IF current_setting('dashboard.audit_retention_purge', true) = 'on'
           AND OLD.occurred_at < CURRENT_TIMESTAMP - INTERVAL '30 days' THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'audit_logs is append-only: % is forbidden', TG_OP;
END;
$$;

CREATE OR REPLACE TRIGGER trg_audit_logs_no_truncate
BEFORE TRUNCATE ON audit_logs
FOR EACH STATEMENT
EXECUTE FUNCTION prevent_audit_log_mutation();

-- 보관 기한(일)이 지난 감사 행을 지우고 지운 수와 기준 시각을 돌려준다.
-- 한 행이라도 지웠으면 그 사실을 감사 행 하나로 남긴다(이 행도 기한이 지나면 지워진다).
-- 표식은 트랜잭션 지역 값으로 켜고 지운 뒤 끈다(오류로 끝나면 트랜잭션과 함께 되돌아간다).
CREATE OR REPLACE FUNCTION public.purge_expired_audit_logs(p_retention_days integer)
RETURNS TABLE (deleted bigint, cutoff timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '5s'
AS $$
DECLARE
    v_cutoff timestamptz;
    v_deleted bigint;
BEGIN
    IF p_retention_days IS NULL OR p_retention_days < 30 THEN
        RAISE EXCEPTION 'audit retention must be at least 30 days (got %)', COALESCE(p_retention_days::text, 'NULL')
            USING ERRCODE = '22023';
    END IF;
    v_cutoff := CURRENT_TIMESTAMP - make_interval(days => p_retention_days);

    PERFORM set_config('dashboard.audit_retention_purge', 'on', true);
    DELETE FROM public.audit_logs a WHERE a.occurred_at < v_cutoff;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    PERFORM set_config('dashboard.audit_retention_purge', 'off', true);

    IF v_deleted > 0 THEN
        INSERT INTO public.audit_logs (actor_username, actor_role, action_type, detail_json)
        VALUES ('audit-retention', 'SYSTEM', 'AUDIT_RETENTION_PURGE',
                json_build_object(
                    'deleted', v_deleted,
                    'cutoff', to_char(v_cutoff AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    'retentionDays', p_retention_days)::text);
    END IF;

    deleted := v_deleted;
    cutoff := v_cutoff;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION public.purge_expired_audit_logs(integer) FROM PUBLIC;
