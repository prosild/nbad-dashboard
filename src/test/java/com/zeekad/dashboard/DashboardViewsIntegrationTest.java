package com.zeekad.dashboard;

import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Clock;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class DashboardViewsIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserAdminService userAdminService;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private TotpService totpService;

    @Autowired
    private Clock clock;

    @Test
    void incidentQueueRendersOnRootAndIncidentsWithFiltersMultiModelBadgeAndDetailLink() throws Exception {
        String analyst = "view_analyst_1";
        userAdminService.createUser(analyst, "화면분석가", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(analyst, "Pass1234!");

        // GET / 및 GET /incidents 모두 리다이렉트 없이 200 OK 렌더링
        mockMvc.perform(get("/").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("이상탐지 조사 큐")))
                .andExpect(content().string(containsString("다중 탐지")))
                .andExpect(content().string(containsString("autoencoder")))
                .andExpect(content().string(containsString("hbos")))
                .andExpect(content().string(containsString("/incidents/101/rank/1")))
                .andExpect(content().string(containsString("보고서 없음")));

        // 모델 필터
        mockMvc.perform(get("/incidents").param("pickedBy", "iforest").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("192.168.10.50")))
                .andExpect(content().string(not(containsString("10.20.30.40"))));

        // 역할 필터
        mockMvc.perform(get("/incidents").param("role", "responder").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("10.20.30.40")))
                .andExpect(content().string(not(containsString("192.168.10.50"))));

        // 자산 호스트명 부분 일치 필터 (Java 계층)
        mockMvc.perform(get("/incidents").param("asset", "filesrv02").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("10.20.30.40")))
                .andExpect(content().string(not(containsString("192.168.10.50"))));

        // 상태 필터
        mockMvc.perform(get("/incidents").param("status", "closed").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("172.16.5.99")))
                .andExpect(content().string(not(containsString("192.168.10.50"))));

        // 보고서 유무 필터
        mockMvc.perform(get("/incidents").param("hasReport", "false").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("172.16.5.99")))
                .andExpect(content().string(not(containsString("192.168.10.50"))));

        // 실제 전송 여부 필터
        mockMvc.perform(get("/incidents").param("wouldSend", "true").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("192.168.10.50")))
                .andExpect(content().string(not(containsString("10.20.30.40"))));

        // XSS 입력 이스케이프 확인
        mockMvc.perform(get("/incidents").param("asset", "<script>alert(1)</script>").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("&lt;script&gt;alert(1)&lt;/script&gt;")))
                .andExpect(content().string(not(containsString("<script>alert(1)</script>"))));
    }

    @Test
    void operationsAndReviewsScreensRenderRequiredIndicatorsAndNavigation() throws Exception {
        String analyst = "ops_analyst_1";
        userAdminService.createUser(analyst, "운영분석가", "Pass1234!", UserRole.ANALYST,
                "*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(analyst, "Pass1234!");

        // 운영 상태 화면
        mockMvc.perform(get("/operations").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("zeekad-fusion/1")))
                .andExpect(content().string(containsString("iforest: 0.72")))
                .andExpect(content().string(containsString("기록만(dry-run)")))
                .andExpect(content().string(containsString("조사 큐")))
                .andExpect(content().string(containsString("운영 상태")))
                .andExpect(content().string(containsString("승인 대기")))
                .andExpect(content().string(not(containsString("/admin/users"))));

        // 분석가 승인 대기 목록 (전체 vs 대기 건만)
        mockMvc.perform(get("/reviews").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Python 에이전트 재개 API 연결 예정")))
                .andExpect(content().string(containsString("disabled=\"disabled\"")))
                .andExpect(content().string(containsString("confirm")));

        mockMvc.perform(get("/reviews").param("pendingOnly", "true").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("10.20.30.40")))
                .andExpect(content().string(not(containsString("192.168.10.50"))));
    }

    @Test
    void userWithNoMatchingCapturesGets200EmptyStateAndAdminSeesFullNav() throws Exception {
        String noCapUser = "nocap_viewer_1";
        userAdminService.createUser(noCapUser, "무캡처사용자", "Pass1234!", UserRole.VIEWER,
                "unmatched-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession noCapSession = loginAs(noCapUser, "Pass1234!");

        mockMvc.perform(get("/incidents").session(noCapSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("허용된 캡처 데이터가 없거나")));
        mockMvc.perform(get("/operations").session(noCapSession))
                .andExpect(status().isOk());
        mockMvc.perform(get("/reviews").session(noCapSession))
                .andExpect(status().isOk());

        // ADMIN은 TOTP 인증 후 공통 네비게이션에서 관리자 메뉴까지 모두 표시
        String adminUser = "nav_admin_1";
        userAdminService.createUser(adminUser, "네비관리자", "AdminPass!88", UserRole.ADMIN,
                "*", "seed", "ADMIN", "127.0.0.1");
        DashboardUser admin = userMapper.findByUsername(adminUser);

        MvcResult loginResult = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", adminUser)
                        .param("password", "AdminPass!88"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        MockHttpSession adminSession = (MockHttpSession) loginResult.getRequest().getSession(false);

        String code = totpService.generateCode(admin.getTotpSecret(), clock.instant());
        mockMvc.perform(post("/login/totp/setup")
                        .session(adminSession)
                        .with(csrf())
                        .param("code", code))
                .andExpect(status().is3xxRedirection());

        mockMvc.perform(get("/admin/users").session(adminSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("/incidents")))
                .andExpect(content().string(containsString("/operations")))
                .andExpect(content().string(containsString("/reviews")))
                .andExpect(content().string(containsString("/admin/users")))
                .andExpect(content().string(containsString("/admin/audit-logs")));
    }

    private MockHttpSession loginAs(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", username)
                        .param("password", password))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }
}
