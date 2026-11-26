package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.UnifiedQueueResponse;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.DashboardUserPrincipal;
import com.zeekad.dashboard.service.IncidentQueueService;
import com.zeekad.dashboard.service.IncidentQueueService.QueueParams;
import com.zeekad.dashboard.service.UserAdminService;
import com.zeekad.dashboard.testsupport.MutableTestClock;
import com.zeekad.dashboard.testsupport.T51QueueSeed;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T52: 중요 자산을 등록한 채로 T51 대조(새 목록 한 문장 = 옛 문장 조합)를 그대로 돌린다.
 * 시험 본문은 {@link T51QueuePageEquivalenceIntegrationTest}를 물려받아 고치지 않는다(같은 criteria를 copy()해 옛 문장에 주고
 * 행 객체의 모든 속성을 견준다. 그래서 자산 배열이 copy()로 넘어가고 옛 문장과 새 문장이 같은 기반 식을 써야 통과한다).
 * 이 클래스는 전용 DB와 자산 등록만 더한다. 자산: 조합 표 호스트 가운데 순위 % 3 == 1(36개)과 가져온 데이터의 짝수 호스트.
 */
@SpringBootTest(properties = {
        "dashboard.datasource.app.url=jdbc:h2:mem:t52e_app;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-read.url=jdbc:h2:mem:t52e_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
        "dashboard.datasource.zeekad-write.url=jdbc:h2:mem:t52e_zeekad;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"
})
class T52QueuePageEquivalenceWithAssetsIntegrationTest extends T51QueuePageEquivalenceIntegrationTest {

    /** 물려받은 클래스의 안쪽 설정은 이 클래스에서 찾지 않으므로 같은 시계를 다시 둔다 */
    @TestConfiguration
    static class AssetClockConfig {
        @Bean
        @Primary
        MutableTestClock mutableTestClock() {
            return new MutableTestClock(T51QueueSeed.NOW);
        }
    }

    @Autowired @Qualifier("appDataSource") private DataSource assetAppDataSource;
    @Autowired private IncidentQueueService assetQueueService;
    @Autowired private UserAdminService assetUserAdminService;
    @Autowired private ObjectMapper assetObjectMapper;

    @BeforeEach
    void registerAssets() {
        JdbcTemplate app = new JdbcTemplate(assetAppDataSource);
        app.update("DELETE FROM critical_assets");
        for (int rank = 1; rank <= T51QueueSeed.COMBINATIONS; rank++) {
            if (rank % 3 == 1) {
                insert(app, T51QueueSeed.liveHost(rank), "대상 " + rank);
            }
        }
        for (int k = 2; k <= T51QueueSeed.IMPORTED_ROWS; k += 2) {
            insert(app, "10.52.0." + k, "가져온 " + k);
        }
    }

    @AfterEach
    void removeAssets() {
        new JdbcTemplate(assetAppDataSource).update("DELETE FROM critical_assets");
    }

    private static void insert(JdbcTemplate app, String host, String name) {
        app.update("INSERT INTO critical_assets (host_ip, name, description, created_by, created_at, updated_by, updated_at) "
                + "VALUES (?, ?, NULL, 't52', TIMESTAMP WITH TIME ZONE '2026-11-20 00:00:00Z', 't52', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-20 00:00:00Z')", host, name);
    }

    /** 대조가 빈 효과만 보지 않는다: 같은 자료에서 우선순위가 실제로 올라간 행과 같은 무리 안 중요·보통 행이 있다 */
    @Test
    void assetsActuallyRaiseRowsInTheComparedData() throws Exception {
        DashboardUser user = assetUserAdminService.createUser("t52e_u" + System.nanoTime() % 100000, "표시", "Pass1234!",
                UserRole.ANALYST, "*", "seed", "ADMIN", "127.0.0.1");
        DashboardUserPrincipal analyst = new DashboardUserPrincipal(user, List.of("*"), T51QueueSeed.NOW);
        UnifiedQueueResponse res = assetQueueService.loadQueue(analyst, new QueueParams("all", null, T51QueueSeed.LIVE,
                null, null, null, null, null, null, null, null, null, null, null, null, "100"), "127.0.0.1");
        JsonNode items = assetObjectMapper.valueToTree(res).get("items");
        int raised = 0;
        int critical = 0;
        for (JsonNode it : items) {
            if (it.path("assetCritical").asBoolean()) critical++;
            if (!it.path("priority").isNull() && !it.path("priority").asText().equals(it.path("priorityBase").asText())) raised++;
        }
        assertThat(critical).isEqualTo(36);
        assertThat(raised).isPositive();
    }
}
