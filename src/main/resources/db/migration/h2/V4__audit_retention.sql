-- T58 감사 로그 보관 기한(PostgreSQL V4와 버전만 맞추는 빈 migration). H2는 시험 전용이다.
-- H2에는 삭제 함수(purge_expired_audit_logs)가 없고 트리거(H2AuditLogImmutableTrigger)는 지금처럼 UPDATE·DELETE를 늘 거부한다.
-- 기한 지난 행 삭제·TRUNCATE 차단·30일 바닥값은 PostgreSQL에서만 있고 scripts/audit-retention-check.ps1이 PostgreSQL에서 직접 시험한다.

COMMENT ON TABLE audit_logs IS 'append-only (H2: test only; the retention purge function exists only in the PostgreSQL V4 migration)';
