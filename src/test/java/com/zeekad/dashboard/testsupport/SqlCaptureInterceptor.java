package com.zeekad.dashboard.testsupport;

import org.apache.ibatis.executor.statement.StatementHandler;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Intercepts;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Signature;
import org.apache.ibatis.session.SqlSessionFactory;

import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * T51 시험용: SqlSessionFactory에 붙여 실행하려고 준비한 SQL 글을 모은다(문장 하나에 한 번, StatementHandler.prepare).
 * 켠 동안만 모으고, 결과와 실행은 건드리지 않는다. 같은 설정에 두 번 붙이지 않는다.
 */
@Intercepts(@Signature(type = StatementHandler.class, method = "prepare", args = {Connection.class, Integer.class}))
public class SqlCaptureInterceptor implements Interceptor {

    private final List<String> statements = new CopyOnWriteArrayList<>();
    private volatile boolean capturing;

    /** 이미 붙어 있으면 그것을, 없으면 새로 붙여 돌려준다 */
    public static SqlCaptureInterceptor attach(SqlSessionFactory factory) {
        for (Interceptor i : factory.getConfiguration().getInterceptors()) {
            if (i instanceof SqlCaptureInterceptor existing) {
                return existing;
            }
        }
        SqlCaptureInterceptor created = new SqlCaptureInterceptor();
        factory.getConfiguration().addInterceptor(created);
        return created;
    }

    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        if (capturing) {
            statements.add(((StatementHandler) invocation.getTarget()).getBoundSql().getSql());
        }
        return invocation.proceed();
    }

    public void start() {
        statements.clear();
        capturing = true;
    }

    /** 모으기를 멈추고 그동안 실행한 SQL 글을 돌려준다 */
    public List<String> stop() {
        capturing = false;
        List<String> out = new ArrayList<>(statements);
        statements.clear();
        return out;
    }

    /** 표지가 든 문장 수 */
    public static long countContaining(List<String> sqls, String marker) {
        return sqls.stream().filter(s -> s.contains(marker)).count();
    }
}
