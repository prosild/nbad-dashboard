package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.security.TotpService;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Clock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class DashboardViewsIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserAdminService userAdminService;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private TotpService totpService;

    @Autowired
    private Clock clock;

    @Test
    void incidentQueueApiAndSpaRoutesSupportFiltersMultiModelBadgeAndDetailData() throws Exception {
        String analyst = "view_analyst_1";
        userAdminService.createUser(analyst, "화면분석가", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(analyst, "Pass1234!");

        // GET / 및 GET /incidents 는 SPA index.html 로 포워딩
        mockMvc.perform(get("/").session(session))
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/index.html"));
        mockMvc.perform(get("/incidents").session(session))
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/index.html"));

        // GET /api/incidents 기본 조회
        mockMvc.perform(get("/api/incidents").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.maskedView").value(false))
                .andExpect(jsonPath("$.selectedCaptureId").value("cic17-wed"))
                .andExpect(jsonPath("$.selectedJob.jobId").value(101))
                .andExpect(jsonPath("$.incidents.length()").value(3))
                .andExpect(jsonPath("$.incidents[0].zeekadAlsoFlaggedBy[0]").value("autoencoder"))
                .andExpect(jsonPath("$.incidents[0].zeekadAlsoFlaggedBy[1]").value("hbos"))
                .andExpect(jsonPath("$.incidents[2].hasReport").value(false));

        // 모델 필터
        mockMvc.perform(get("/api/incidents").param("pickedBy", "iforest").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidents.length()").value(1))
                .andExpect(jsonPath("$.incidents[0].hostIp").value("192.168.10.50"));

        // 역할 필터
        mockMvc.perform(get("/api/incidents").param("role", "responder").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidents.length()").value(1))
                .andExpect(jsonPath("$.incidents[0].hostIp").value("10.20.30.40"));

        // 자산 호스트명 부분 일치 필터 (Java 계층)
        mockMvc.perform(get("/api/incidents").param("asset", "filesrv02").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidents.length()").value(1))
                .andExpect(jsonPath("$.incidents[0].hostIp").value("10.20.30.40"));

        // 상태 필터
        mockMvc.perform(get("/api/incidents").param("status", "closed").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidents.length()").value(1))
                .andExpect(jsonPath("$.incidents[0].hostIp").value("172.16.5.99"));

        // 보고서 유무 필터
        mockMvc.perform(get("/api/incidents").param("hasReport", "false").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidents.length()").value(1))
                .andExpect(jsonPath("$.incidents[0].hostIp").value("172.16.5.99"));

        // 실제 전송 여부 필터
        mockMvc.perform(get("/api/incidents").param("wouldSend", "true").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidents.length()").value(1))
                .andExpect(jsonPath("$.incidents[0].hostIp").value("192.168.10.50"));

        // 비정상 asset 입력 시 빈 결과 정상 JSON 응답
        mockMvc.perform(get("/api/incidents").param("asset", "<script>alert(1)</script>").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidents.length()").value(0));
    }

    @Test
    void labCaptureUsesLatestSucceededJobQueueAndShowsV21IndicatorsAndReviewLinks() throws Exception {
        String labAnalyst = "lab_view_analyst";
        userAdminService.createUser(labAnalyst, "실습화면분석가", "Pass1234!", UserRole.ANALYST,
                "lab-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(labAnalyst, "Pass1234!");

        mockMvc.perform(get("/api/incidents").param("captureId", "lab-20261118").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.selectedJob.jobId").value(502))
                .andExpect(jsonPath("$.incidents.length()").value(2))
                .andExpect(jsonPath("$.incidents[0].jobId").value(502))
                .andExpect(jsonPath("$.incidents[0].queueRank").value(1))
                .andExpect(jsonPath("$.incidents[0].hasReport").value(false))
                .andExpect(jsonPath("$.incidents[1].jobId").value(502))
                .andExpect(jsonPath("$.incidents[1].queueRank").value(2))
                .andExpect(jsonPath("$.incidents[1].zeekadReportJobId").value(501))
                .andExpect(jsonPath("$.incidents[1].zeekadReviewPending").value(true));

        mockMvc.perform(get("/api/reviews").param("captureId", "lab-20261118").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reviews.length()").value(1))
                .andExpect(jsonPath("$.reviews[0].jobId").value(502))
                .andExpect(jsonPath("$.reviews[0].queueRank").value(2))
                .andExpect(jsonPath("$.reviews[0].reviewJobId").value(501));
    }

    @Test
    void operationsAndReviewsApisReturnRequiredIndicatorsWithoutAccuracyWording() throws Exception {
        String analyst = "ops_analyst_1";
        userAdminService.createUser(analyst, "운영분석가", "Pass1234!", UserRole.ANALYST,
                "*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(analyst, "Pass1234!");

        // 운영 상태 API (zeekad-fusion/1..3 및 feedback_summary 포함, "정확도" 미사용)
        MvcResult opsRes = mockMvc.perform(get("/api/operations").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("zeekad-fusion/1")))
                .andExpect(content().string(containsString("zeekad-fusion/3")))
                // T20: 판정 1건(10건 미만)은 정탐률 대신 표본 부족, 판정 0건은 판정 없음
                .andExpect(content().string(containsString("표본 부족 · 판정 1/3건(33.3%)")))
                .andExpect(jsonPath("$.feedbackSummaries[?(@.captureId == 'lab-fusion-v2' && @.zeekadPickedBy == 'all')].precisionSummaryText")
                        .value(hasItem("판정 없음")))
                .andExpect(content().string(not(containsString("정확도"))))
                .andExpect(content().string(not(containsString("정밀도"))))
                .andExpect(jsonPath("$.slackSummaries[1].dryRunOrRecorded").value(true))
                .andReturn();

        JsonNode opsJson = objectMapper.readTree(opsRes.getResponse().getContentAsString());
        assertThat(opsJson.get("feedbackSummaries").get(0).get("allModel").asBoolean()).isTrue();

        // 운영 상태 캡처 필터 연동 확인
        mockMvc.perform(get("/api/operations").param("captureId", "lab-fusion-v2").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.selectedCaptureId").value("lab-fusion-v2"))
                .andExpect(jsonPath("$.feedbackSummaries[?(@.zeekadPickedBy == 'all')].precisionSummaryText")
                        .value(hasItem("판정 없음")))
                .andExpect(content().string(not(containsString("표본 부족 · 판정 1/3건(33.3%)"))));

        // 분석가 승인 대기 목록 API (전체 vs 대기 건만, 반영 상태 3종)
        mockMvc.perform(get("/api/reviews").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.canDecideReview").value(true))
                .andExpect(content().string(containsString("반영됨")))
                .andExpect(content().string(containsString("반영 중")))
                .andExpect(content().string(containsString("반영 실패(관리자 확인 필요)")))
                .andExpect(content().string(not(containsString("구 작업(601) 중복 검토 요청"))));

        mockMvc.perform(get("/api/reviews").param("pendingOnly", "true").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("10.20.30.40")))
                .andExpect(content().string(not(containsString("192.168.10.50"))));
    }

    @Test
    void userWithNoMatchingCapturesGets200EmptyStateAndAdminCanAccessAllSpaRoutes() throws Exception {
        String noCapUser = "nocap_viewer_1";
        userAdminService.createUser(noCapUser, "무캡처사용자", "Pass1234!", UserRole.VIEWER,
                "unmatched-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession noCapSession = loginAs(noCapUser, "Pass1234!");

        mockMvc.perform(get("/api/incidents").session(noCapSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowedCaptures.length()").value(0))
                .andExpect(jsonPath("$.incidents.length()").value(0));
        mockMvc.perform(get("/api/operations").session(noCapSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.jobs.length()").value(0));
        mockMvc.perform(get("/api/reviews").session(noCapSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reviews.length()").value(0));

        // ADMIN은 TOTP 인증 후 모든 SPA 클라이언트 라우트가 index.html 로 포워딩됨
        String adminUser = "nav_admin_1";
        userAdminService.createUser(adminUser, "네비관리자", "AdminPass!88", UserRole.ADMIN,
                "*", "seed", "ADMIN", "127.0.0.1");
        DashboardUser admin = userMapper.findByUsername(adminUser);

        MockHttpSession adminSession = loginAs(adminUser, "AdminPass!88");

        String code = totpService.generateCode(admin.getTotpSecret(), clock.instant());
        Cookie csrfCookie = fetchCsrfCookie();
        mockMvc.perform(post("/api/auth/totp/setup")
                        .session(adminSession)
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest(code))))
                .andExpect(status().isOk());

        for (String spaRoute : new String[]{
                "/incidents", "/operations", "/reviews", "/admin/users", "/admin/audit-logs"}) {
            mockMvc.perform(get(spaRoute).session(adminSession))
                    .andExpect(status().isOk())
                    .andExpect(forwardedUrl("/index.html"));
        }
    }

    private Cookie fetchCsrfCookie() throws Exception {
        MvcResult res = mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        return res.getResponse().getCookie("XSRF-TOKEN");
    }

    private MockHttpSession loginAs(String username, String password) throws Exception {
        Cookie csrfCookie = fetchCsrfCookie();
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, password))))
                .andExpect(status().isOk())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }
}
