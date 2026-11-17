package com.zeekad.dashboard.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zaxxer.hikari.HikariDataSource;
import com.zeekad.dashboard.mybatis.JsonNodeTypeHandler;
import com.zeekad.dashboard.mybatis.StringListTypeHandler;
import org.apache.ibatis.mapping.DatabaseIdProvider;
import org.apache.ibatis.mapping.VendorDatabaseIdProvider;
import org.apache.ibatis.session.SqlSessionFactory;
import org.flywaydb.core.Flyway;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.mybatis.spring.annotation.MapperScan;
import org.mybatis.spring.annotation.MapperScans;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;
import java.io.IOException;
import java.time.Clock;
import java.util.Properties;

/**
 * 3중 DataSource(대시보드 자체 DB, zeekad 읽기 전용, zeekad 쓰기 전용) 및 MyBatis 매퍼 분리 설정.
 */
@Configuration
@MapperScans({
        @MapperScan(
                basePackages = "com.zeekad.dashboard.mapper.app",
                sqlSessionFactoryRef = "appSqlSessionFactory"
        ),
        @MapperScan(
                basePackages = "com.zeekad.dashboard.mapper.zeekad.read",
                sqlSessionFactoryRef = "zeekadReadSqlSessionFactory"
        ),
        @MapperScan(
                basePackages = "com.zeekad.dashboard.mapper.zeekad.write",
                sqlSessionFactoryRef = "zeekadWriteSqlSessionFactory"
        )
})
public class DataSourceConfig {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }

    @Primary
    @Bean(name = "appDataSource")
    public DataSource appDataSource(DashboardProperties properties) {
        return buildHikariDataSource(properties.getDatasource().getApp(), "dashboard-app-pool", false);
    }

    @Bean(name = "zeekadReadDataSource")
    public DataSource zeekadReadDataSource(DashboardProperties properties) {
        return buildHikariDataSource(properties.getDatasource().getZeekadRead(), "zeekad-read-pool", true);
    }

    @Bean(name = "zeekadWriteDataSource")
    public DataSource zeekadWriteDataSource(DashboardProperties properties) {
        return buildHikariDataSource(properties.getDatasource().getZeekadWrite(), "zeekad-write-pool", false);
    }

    @Bean(name = "appFlyway", initMethod = "migrate")
    public Flyway appFlyway(@Qualifier("appDataSource") DataSource appDataSource,
                            DashboardProperties properties) {
        String url = properties.getDatasource().getApp().getUrl();
        String vendor = (url != null && url.startsWith("jdbc:h2:")) ? "h2" : "postgresql";
        return Flyway.configure()
                .dataSource(appDataSource)
                .locations("classpath:db/migration/" + vendor)
                .load();
    }

    @Primary
    @Bean(name = "appSqlSessionFactory")
    @DependsOn("appFlyway")
    public SqlSessionFactory appSqlSessionFactory(@Qualifier("appDataSource") DataSource dataSource,
                                                  ObjectMapper objectMapper)
            throws Exception {
        return createSqlSessionFactory(dataSource, "classpath*:mapper/app/*.xml", objectMapper);
    }

    @Bean(name = "zeekadReadSqlSessionFactory")
    public SqlSessionFactory zeekadReadSqlSessionFactory(@Qualifier("zeekadReadDataSource") DataSource dataSource,
                                                         ObjectMapper objectMapper)
            throws Exception {
        return createSqlSessionFactory(dataSource, "classpath*:mapper/zeekad/read/*.xml", objectMapper);
    }

    @Bean(name = "zeekadWriteSqlSessionFactory")
    public SqlSessionFactory zeekadWriteSqlSessionFactory(@Qualifier("zeekadWriteDataSource") DataSource dataSource,
                                                          ObjectMapper objectMapper)
            throws Exception {
        return createSqlSessionFactory(dataSource, "classpath*:mapper/zeekad/write/*.xml", objectMapper);
    }

    @Primary
    @Bean(name = "appSqlSessionTemplate")
    public SqlSessionTemplate appSqlSessionTemplate(@Qualifier("appSqlSessionFactory") SqlSessionFactory factory) {
        return new SqlSessionTemplate(factory);
    }

    @Bean(name = "zeekadReadSqlSessionTemplate")
    public SqlSessionTemplate zeekadReadSqlSessionTemplate(
            @Qualifier("zeekadReadSqlSessionFactory") SqlSessionFactory factory) {
        return new SqlSessionTemplate(factory);
    }

    @Bean(name = "zeekadWriteSqlSessionTemplate")
    public SqlSessionTemplate zeekadWriteSqlSessionTemplate(
            @Qualifier("zeekadWriteSqlSessionFactory") SqlSessionFactory factory) {
        return new SqlSessionTemplate(factory);
    }

    @Primary
    @Bean(name = "appTransactionManager")
    public PlatformTransactionManager appTransactionManager(@Qualifier("appDataSource") DataSource dataSource) {
        return new DataSourceTransactionManager(dataSource);
    }

    private HikariDataSource buildHikariDataSource(DashboardProperties.DbSpec spec,
                                                   String poolName,
                                                   boolean readOnly) {
        HikariDataSource ds = new HikariDataSource();
        ds.setPoolName(poolName);
        ds.setJdbcUrl(spec.getUrl());
        ds.setUsername(spec.getUsername());
        ds.setPassword(spec.getPassword() == null ? "" : spec.getPassword());
        if (spec.getDriverClassName() != null && !spec.getDriverClassName().isBlank()) {
            ds.setDriverClassName(spec.getDriverClassName());
        }
        ds.setReadOnly(readOnly);
        return ds;
    }

    @Bean
    public DatabaseIdProvider databaseIdProvider() {
        VendorDatabaseIdProvider provider = new VendorDatabaseIdProvider();
        Properties properties = new Properties();
        properties.setProperty("PostgreSQL", "postgresql");
        properties.setProperty("H2", "h2");
        provider.setProperties(properties);
        return provider;
    }

    private SqlSessionFactory createSqlSessionFactory(DataSource dataSource,
                                                      String mapperLocationPattern,
                                                      ObjectMapper objectMapper)
            throws Exception {
        SqlSessionFactoryBean factoryBean = new SqlSessionFactoryBean();
        factoryBean.setDataSource(dataSource);
        factoryBean.setDatabaseIdProvider(databaseIdProvider());
        org.apache.ibatis.session.Configuration config = new org.apache.ibatis.session.Configuration();
        config.setMapUnderscoreToCamelCase(true);
        config.getTypeHandlerRegistry().register(JsonNode.class, new JsonNodeTypeHandler(objectMapper));
        config.getTypeHandlerRegistry().register(StringListTypeHandler.class);
        factoryBean.setConfiguration(config);
        Resource[] resources = resolveMapperResources(mapperLocationPattern);
        if (resources.length > 0) {
            factoryBean.setMapperLocations(resources);
        }
        return factoryBean.getObject();
    }

    private Resource[] resolveMapperResources(String pattern) throws IOException {
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        return resolver.getResources(pattern);
    }
}
