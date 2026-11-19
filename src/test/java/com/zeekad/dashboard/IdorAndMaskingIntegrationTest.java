package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.dto.TotpCodeRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.AuditActionType;
import com.zeekad.dashboard.model.AuditLog;
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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IdorAndMaskingIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserAdminService userAdminService;

    @Autowired
    private AuditLogMapper auditLogMapper;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private TotpService totpService;

    @Autowired
    private Clock clock;

    @Test
    void unauthorizedOrNonExistentCaptureAndJobRequestsReturn403AndRecordIdorAuditLog() throws Exception {
        String viewer = "idor_viewer_1";
        userAdminService.createUser(viewer, "IDOR조회자", "Pass1234!", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(viewer, "Pass1234!");

        // 허용되지 않은 capture_id 요청 (syn1-tue)
        mockMvc.perform(get("/api/incidents").param("captureId", "syn1-tue").session(session))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
        mockMvc.perform(get("/api/operations").param("captureId", "syn1-tue").session(session))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/reviews").param("captureId", "syn1-tue").session(session))
                .andExpect(status().isForbidden());

        // 허용되지 않은 job_id (job 201은 syn1-tue 소유)
        mockMvc.perform(get("/api/incidents").param("jobId", "201").session(session))
                .andExpect(status().isForbidden());

        // captureId와 jobId 불일치 (cic17-wed + jobId=201)
        mockMvc.perform(get("/api/incidents")
                        .param("captureId", "cic17-wed")
                        .param("jobId", "201")
                        .session(session))
                .andExpect(status().isForbidden());

        // 존재하지 않는 capture_id 및 job_id 직접 지정 (열거 방지)
        mockMvc.perform(get("/api/incidents").param("captureId", "cic17-nonexistent").session(session))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/incidents").param("jobId", "999999").session(session))
                .andExpect(status().isForbidden());

        List<AuditLog> idorLogs = auditLogMapper.findFiltered(
                AuditActionType.ACCESS_DENIED_IDOR.name(), viewer, 20);
        assertThat(idorLogs).hasSize(7);
    }

    @Test
    void viewerSeesMaskedIpsAcrossApisWhileAnalystSeesUnmaskedForAllowedCaptures() throws Exception {
        String viewer = "mask_viewer_1";
        String analyst = "mask_analyst_1";
        userAdminService.createUser(viewer, "마스킹조회자", "Pass1234!", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        userAdminService.createUser(analyst, "원문분석가", "Pass1234!", UserRole.ANALYST,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");

        MockHttpSession viewerSession = loginAs(viewer, "Pass1234!");

        // 조사 큐: VIEWER에게 원문 IP 미노출, 마스킹 IP 노출
        mockMvc.perform(get("/api/incidents").session(viewerSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.maskedView").value(true))
                .andExpect(content().string(containsString("192.168.*.*")))
                .andExpect(content().string(containsString("10.20.*.*")))
                .andExpect(content().string(not(containsString("192.168.10.50"))))
                .andExpect(content().string(not(containsString("10.20.30.40"))))
                .andExpect(content().string(not(containsString("10.99.88.77"))));

        // 운영 상태: slack_payload 내 IP 마스킹 및 feedback_summary 포함 허용되지 않은 캡처 미노출
        mockMvc.perform(get("/api/operations").session(viewerSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.maskedView").value(true))
                .andExpect(content().string(containsString("192.168.*.*")))
                .andExpect(content().string(containsString("정밀도 0.00, 결론 1/3 (33.3%)")))
                .andExpect(content().string(not(containsString("192.168.10.50"))))
                .andExpect(content().string(not(containsString("syn1-tue"))))
                .andExpect(content().string(not(containsString("lab-20261118"))))
                .andExpect(content().string(not(containsString("lab-fusion-v2"))));

        // 승인 대기: host_ip 마스킹 및 허용되지 않은 syn1-tue 미노출
        mockMvc.perform(get("/api/reviews").session(viewerSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.maskedView").value(true))
                .andExpect(jsonPath("$.canDecideReview").value(false))
                .andExpect(content().string(containsString("10.20.*.*")))
                .andExpect(content().string(not(containsString("10.20.30.40"))))
                .andExpect(content().string(not(containsString("syn1-tue"))));

        // ANALYST: 허용된 캡처 원문 IP 및 cic17-* 집계만 노출, 타 캡처 집계 미노출·차단
        MockHttpSession analystSession = loginAs(analyst, "Pass1234!");
        mockMvc.perform(get("/api/incidents").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.maskedView").value(false))
                .andExpect(content().string(containsString("192.168.10.50")))
                .andExpect(content().string(containsString("10.20.30.40")))
                .andExpect(content().string(not(containsString("10.99.88.77"))));

        mockMvc.perform(get("/api/operations").session(analystSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("192.168.10.50")))
                .andExpect(content().string(containsString("cic17-wed")))
                .andExpect(content().string(not(containsString("syn1-tue"))))
                .andExpect(content().string(not(containsString("lab-20261118"))))
                .andExpect(content().string(not(containsString("lab-fusion-v2"))));

        mockMvc.perform(get("/api/incidents").param("captureId", "syn1-tue").session(analystSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/incidents").param("captureId", "lab-20261118").session(analystSession))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/incidents/502/rank/2").session(analystSession))
                .andExpect(status().isForbidden());

        // lab-* 허용 분석가는 lab-20261118 정상 조회, cic17-wed 차단
        String labAnalyst = "lab_idor_analyst";
        userAdminService.createUser(labAnalyst, "실습분석가", "Pass1234!", UserRole.ANALYST,
                "lab-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession labSession = loginAs(labAnalyst, "Pass1234!");
        mockMvc.perform(get("/api/incidents").param("captureId", "lab-20261118").session(labSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("10.20.0.15")))
                .andExpect(content().string(containsString("10.20.0.25")));
        mockMvc.perform(get("/api/incidents").param("captureId", "cic17-wed").session(labSession))
                .andExpect(status().isForbidden());

        // ADMIN (*): TOTP 인증 후 전체 캡처 feedback_summary 노출
        String opsAdmin = "idor_ops_admin";
        userAdminService.createUser(opsAdmin, "전체관리자", "AdminPass!88", UserRole.ADMIN,
                "*", "seed", "ADMIN", "127.0.0.1");
        DashboardUser adminUser = userMapper.findByUsername(opsAdmin);
        MockHttpSession adminSession = loginAs(opsAdmin, "AdminPass!88");
        String code = totpService.generateCode(adminUser.getTotpSecret(), clock.instant());
        Cookie csrfCookie = fetchCsrfCookie();
        mockMvc.perform(post("/api/auth/totp/setup")
                        .session(adminSession)
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TotpCodeRequest(code))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/operations").session(adminSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("cic17-wed")))
                .andExpect(content().string(containsString("syn1-tue")))
                .andExpect(content().string(containsString("lab-20261118")))
                .andExpect(content().string(containsString("lab-fusion-v2")));
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
