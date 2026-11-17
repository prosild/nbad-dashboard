package com.zeekad.dashboard.testsupport;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;

/**
 * test 프로필 전용 zeekadReadDataSource(인메모리 H2) dashboard 스키마·뷰·샘플 데이터 초기화.
 */
@Component
@Profile("test")
public class ZeekadReadTestDataInitializer {

    private final DataSource zeekadReadDataSource;

    public ZeekadReadTestDataInitializer(@Qualifier("zeekadReadDataSource") DataSource zeekadReadDataSource) {
        this.zeekadReadDataSource = zeekadReadDataSource;
    }

    @PostConstruct
    public void initialize() {
        JdbcTemplate jdbc = new JdbcTemplate(zeekadReadDataSource);
        Integer existing = jdbc.queryForObject(
                "SELECT COUNT(*) FROM information_schema.tables "
                        + "WHERE LOWER(table_schema) = 'dashboard' AND LOWER(table_name) = 'scoring_jobs'",
                Integer.class);
        if (existing != null && existing > 0) {
            return;
        }
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.setSqlScriptEncoding("UTF-8");
        populator.addScript(new ClassPathResource("testdb/zeekad-read-schema.sql"));
        populator.addScript(new ClassPathResource("testdb/zeekad-read-sample-data.sql"));
        populator.execute(zeekadReadDataSource);
    }
}
