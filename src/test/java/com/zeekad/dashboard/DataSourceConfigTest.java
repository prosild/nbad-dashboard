package com.zeekad.dashboard;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadProbeMapper;
import com.zeekad.dashboard.mapper.zeekad.write.ZeekadWriteProbeMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ActiveProfiles;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;

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
        // T41: 시험 프로필은 임시 포트 범위 밖의 닫힌 포트를 쓴다(application-test.yml 주석). 앱 기본값은 아래에서 따로 본다.
        assertThat(dashboardProperties.getEvidenceApi().getUrl()).isEqualTo("http://127.0.0.1:1");
    }

    @Test
    void evidenceApiDefaultUrlInApplicationYmlIsUnchanged() throws Exception {
        String yml = new String(new ClassPathResource("application.yml").getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertThat(yml).contains("url: ${ZEEKAD_EVIDENCE_API_URL:http://127.0.0.1:8000}");
    }
}
