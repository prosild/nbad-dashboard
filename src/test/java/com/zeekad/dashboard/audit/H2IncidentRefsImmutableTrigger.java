package com.zeekad.dashboard.audit;

import org.h2.api.Trigger;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * H2 테스트 DB에서 incident_refs 테이블(T27 인시던트 번호)의 UPDATE/DELETE를 차단하는 불변성 트리거.
 */
public class H2IncidentRefsImmutableTrigger implements Trigger {

    @Override
    public void init(Connection conn, String schemaName, String triggerName, String tableName, boolean before, int type) {
        // 초기화 작업 없음
    }

    @Override
    public void fire(Connection conn, Object[] oldRow, Object[] newRow) throws SQLException {
        throw new SQLException("incident_refs is append-only: UPDATE and DELETE are forbidden", "42501");
    }

    @Override
    public void close() {
        // 정리 작업 없음
    }

    @Override
    public void remove() {
        // 정리 작업 없음
    }
}
