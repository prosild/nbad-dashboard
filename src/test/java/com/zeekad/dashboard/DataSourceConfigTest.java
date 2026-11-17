package com.zeekad.dashboard;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadProbeMapper;
import com.zeekad.dashboard.mapper.zeekad.write.ZeekadWriteProbeMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class DataSourceConfigTest {

    @Autowired
    @Qualifier("appDataSource")
    private DataSource appDataSource;

    @Autowired
    @Qualifier("zeekadReadDataSource")
    private DataSource zeekadReadDataSource;

    @Autowired
    @Qualifier("zeekadWriteDataSource")
    private DataSource zeekadWriteDataSource;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private ZeekadReadProbeMapper zeekadReadProbeMapper;

    @Autowired
    private ZeekadWriteProbeMapper zeekadWriteProbeMapper;

    @Autowired
    private DashboardProperties dashboardProperties;

    @Test
    void threeDataSourcesAndMappersAreDistinctAndOperational() {
        assertThat(appDataSource).isNotSameAs(zeekadReadDataSource);
        assertThat(appDataSource).isNotSameAs(zeekadWriteDataSource);
        assertThat(zeekadReadDataSource).isNotSameAs(zeekadWriteDataSource);

        assertThat(userMapper.countAll()).isGreaterThanOrEqualTo(0L);
        assertThat(zeekadReadProbeMapper.selectOne()).isEqualTo(1);
        assertThat(zeekadWriteProbeMapper.selectOne()).isEqualTo(1);
        assertThat(dashboardProperties.getEvidenceApi().getUrl()).isEqualTo("http://127.0.0.1:8000");
    }
}
