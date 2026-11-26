package com.zeekad.dashboard.audit;

import org.h2.api.Trigger;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * H2 테스트 DB에서 incident_response_actions 테이블(T56)의 UPDATE/DELETE를 늘 차단하는 불변성 트리거.
 * PostgreSQL(V5)은 초기화 함수가 켠 트랜잭션 표식이 있을 때만 DELETE를 통과시킨다. H2에는 초기화 함수가 없다.
 */
public class H2ResponseActionImmutableTrigger implements Trigger {

    @Override
    public void init(Connection conn, String schemaName, String triggerName, String tableName, boolean before, int type) {
        // 초기화 작업 없음
    }

    @Override
    public void fire(Connection conn, Object[] oldRow, Object[] newRow) throws SQLException {
        throw new SQLException("incident_response_actions is append-only: UPDATE and DELETE are forbidden", "42501");
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
