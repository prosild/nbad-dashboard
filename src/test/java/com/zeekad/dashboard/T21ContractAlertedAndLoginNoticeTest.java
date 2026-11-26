package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.controller.LoginNoticeController;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.zeekad.read.ZeekadReadMapper;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.model.zeekad.FeedbackSummaryRecord;
import com.zeekad.dashboard.model.zeekad.IncidentQueueItem;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T21: zeek_AD 결정 반영 계약 조합 규칙(H2 테스트 데이터), "경보 발송"(alerted) 정의, 로그인 안내 문구.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T21ContractAlertedAndLoginNoticeTest {

    private static final String SYN_WED_DISMISSED = "syn1-wed|10.99.70.11|originator|1763352000";
    private static final String CIC_CONFIRMED = "cic17-wed|192.168.10.50|originator|1700000000";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserAdminService userAdminService;

    @Autowired
    private ZeekadReadMapper zeekadReadMapper;

    @Autowired
    @Qualifier("zeekadReadDataSource")
    private DataSource zeekadReadDataSource;

    /**
     * 계약(zeek_AD data-contract-v2 decide_review): 반영되면 confirm → 분석 중(이미 더 나아갔으면 그대로),
     * dismiss → 종결(오탐). H2 테스트 데이터에 이 규칙을 어기는 조합이 없어야 한다.
     */
    @Test
    void resumedReviewDecisionsMatchIncidentStatusInTestData() {
        JdbcTemplate jdbc = new JdbcTemplate(zeekadReadDataSource);
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT a.job_id, a.incident_id, a.zeekad_review_action,
                       COALESCE(s.zeekad_status, 'open') AS zeekad_status, s.zeekad_resolution
                FROM dashboard.analyst_review_queue a
                LEFT JOIN dashboard.incident_status s ON s.incident_id = a.incident_id
                WHERE a.zeekad_review_resumed_at IS NOT NULL
                """);
        assertThat(rows).extracting(r -> r.get("zeekad_review_action")).contains("confirm", "dismiss");
        for (Map<String, Object> r : rows) {
            String action = String.valueOf(r.get("zeekad_review_action"));
            String status = String.valueOf(r.get("zeekad_status"));
            if ("confirm".equals(action)) {
                assertThat(status).as("반영된 승인은 분석 중 이상: %s", r).isIn("investigating", "closed");
            } else {
                assertThat(action).as("결정 값: %s", r).isEqualTo("dismiss");
                assertThat(status).as("반영된 오탐 종결은 종결: %s", r).isEqualTo("closed");
                assertThat(r.get("zeekad_resolution")).as("반영된 오탐 종결의 판정: %s", r).isEqualTo("false_positive");
            }
        }

        // 반영된 승인: 이력 1건(결정한 분석가), 반영된 오탐 종결: 이력 2건(사유 = 결정 메모)
        List<Map<String, Object>> confirmHistory = jdbc.queryForList(
                "SELECT from_status, to_status, actor, reason FROM dashboard.incident_status_history WHERE incident_id = ?",
                CIC_CONFIRMED);
        assertThat(confirmHistory).hasSize(1);
        assertThat(confirmHistory.get(0)).containsEntry("to_status", "investigating").containsEntry("actor", "analyst1");

        List<Map<String, Object>> dismissHistory = jdbc.queryForList(
                "SELECT from_status, to_status, zeekad_resolution, actor, reason FROM dashboard.incident_status_history "
                        + "WHERE incident_id = ? ORDER BY changed_at",
                SYN_WED_DISMISSED);
        assertThat(dismissHistory).hasSize(2);
        assertThat(dismissHistory.get(0)).containsEntry("from_status", "open").containsEntry("to_status", "investigating");
        assertThat(dismissHistory.get(1)).containsEntry("to_status", "closed").containsEntry("zeekad_resolution", "false_positive");
        assertThat(dismissHistory).allSatisfy(h -> assertThat(h)
                .containsEntry("actor", "analyst2")
                .containsEntry("reason", "정기 백업 작업 트래픽으로 확인(오탐)"));
    }

    /**
     * 목록의 경보 발송 수가 캡처마다 feedback_summary 'all' 행 alerted와 같다(같은 식).
     * H2 모의 feedback_summary는 원본과 같은 식을 dashboard.slack_deliveries로 옮긴 것이라(모의 뷰 기준),
     * 원본(zeekad.slack_delivery)과의 동치는 리허설 E2E [3e]·[3f]가 확인한다.
     */
    @Test
    void listAlertedCountEqualsFeedbackSummaryAllRowPerCapture() {
        List<String> captures = zeekadReadMapper.findDistinctCaptureIds();
        assertThat(captures).isNotEmpty();
        for (String capture : captures) {
            List<IncidentQueueItem> queue = zeekadReadMapper.findLatestIncidentQueue(capture, null, null, null, null, null);
            long listAlerted = queue.stream().filter(IncidentQueueItem::isAlerted).count();
            List<FeedbackSummaryRecord> allRows = zeekadReadMapper.findRawFeedbackSummaries(capture).stream()
                    .map(FeedbackSummaryRecord::fromRawMap)
                    .filter(FeedbackSummaryRecord::isAllModel)
                    .toList();
            if (queue.isEmpty()) {
                continue;
            }
            assertThat(allRows).as("%s 'all' 행", capture).hasSize(1);
            assertThat(listAlerted).as("%s 목록 경보 발송 수 = feedback_summary 'all' alerted", capture)
                    .isEqualTo(allRows.get(0).getAlerted());
        }
    }

    /** 경보 발송 매핑: 사건 알림(다른 작업 기록 포함)은 true, 상태 후속 알림만 있으면 false, 기록 없으면 false. 발송 판단과 별개다. */
    @Test
    void alertedFlagUsesIncidentSlackRecordsNotSendDecision() throws Exception {
        Map<String, IncidentQueueItem> byIncident = new java.util.HashMap<>();
        for (String capture : List.of("cic17-wed", "lab-fusion-v2", "syn1-wed")) {
            zeekadReadMapper.findLatestIncidentQueue(capture, null, null, null, null, null)
                    .forEach(i -> byIncident.put(i.getIncidentId(), i));
        }
        // 사건 알림 dry-run 기록 + 상태 후속 알림, 발송 판단 send
        assertThat(byIncident.get(CIC_CONFIRMED).isAlerted()).isTrue();
        // 스레드 답글 사건 알림, 발송 판단 hold → 발송 판단과 다르다
        IncidentQueueItem threadReply = byIncident.get("cic17-wed|10.20.30.40|responder|1700000300");
        assertThat(threadReply.isAlerted()).isTrue();
        assertThat(threadReply.isZeekadWouldSend()).isFalse();
        // 기록 없음
        assertThat(byIncident.get("cic17-wed|172.16.5.99|originator|1700000600").isAlerted()).isFalse();
        // 최신 작업(602)이 아닌 처음 작업(601)의 사건 알림도 incident_id로 센다
        assertThat(byIncident.get("lab-fusion-v2|10.40.0.10|originator|1763514000").isAlerted()).isTrue();
        // 상태 후속 알림(status:investigating·status:closed)만 있는 사건은 경보 발송이 아니다
        assertThat(byIncident.get(SYN_WED_DISMISSED).isAlerted()).isFalse();

        // 작업 지정 목록·상세 단건도 같은 값
        assertThat(zeekadReadMapper.findIncidentQueueItemByJobAndRank(211L, 1).isAlerted()).isFalse();
        assertThat(zeekadReadMapper.findIncidentQueueItemByJobAndRank(101L, 2).isAlerted()).isTrue();
        assertThat(zeekadReadMapper.findIncidentQueue(101L, null, null, null, null, null))
                .filteredOn(IncidentQueueItem::isAlerted).hasSize(2);

        // API: 목록 항목과 상세 incident에 alerted, VIEWER 마스킹 사본도 값을 유지
        String viewer = "t21_alerted_viewer";
        userAdminService.createUser(viewer, "경보조회자", "Pass1234!", UserRole.VIEWER,
                "cic17-*", "seed", "ADMIN", "127.0.0.1");
        MockHttpSession session = loginAs(viewer, "Pass1234!");
        MvcResult list = mockMvc.perform(get("/api/incidents").param("captureId", "cic17-wed").session(session))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode incidents = objectMapper.readTree(list.getResponse().getContentAsString()).get("incidents");
        long alertedCount = 0;
        for (JsonNode n : incidents) {
            assertThat(n.has("alerted")).isTrue();
            if (n.get("alerted").asBoolean()) {
                alertedCount++;
            }
        }
        assertThat(alertedCount).isEqualTo(2);
        mockMvc.perform(get("/api/incidents/101/rank/2").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.incident.alerted").value(true))
                .andExpect(jsonPath("$.detail.incident.zeekadWouldSend").value(false));
        mockMvc.perform(get("/api/incidents/101/rank/3").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail.incident.alerted").value(false));
    }

    /**
     * 로그인 안내 문구: 로그인 전 GET으로 읽는다. 응답 필드는 notice, 그리고 검사를 통과한 link뿐이다(T50).
     * 테스트 설정은 기본 빈 값이고 링크 설정도 없으므로 필드는 notice 하나다(link는 null로도 내려가지 않는다).
     * 링크가 있을 때의 응답은 T50LoginNoticeLinkIntegrationTest가 본다.
     */
    @Test
    void loginNoticeIsPublicGetOnlyAndEmptyByDefault() throws Exception {
        MvcResult res = mockMvc.perform(get("/api/auth/login-notice"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.notice").value(""))
                .andReturn();
        JsonNode body = objectMapper.readTree(res.getResponse().getContentAsString());
        assertThat(body.size()).as("기본 설정(링크 없음)의 응답 필드는 notice 하나").isEqualTo(1);
        assertThat(body.has("link")).as("link 필드 자체가 없다").isFalse();

        // 공개는 GET 하나뿐이다(POST는 CSRF·인증에 막힌다)
        int postStatus = mockMvc.perform(post("/api/auth/login-notice")).andReturn().getResponse().getStatus();
        assertThat(postStatus).isIn(401, 403, 405);
    }

    @Test
    void loginNoticeTrimsPlainTextAndRejectsOverLength() {
        DashboardProperties props = new DashboardProperties();
        props.setLoginNotice("  포트폴리오 공개 데모입니다.\n<b>태그는 글자 그대로</b>  ");
        assertThat(new LoginNoticeController(props).loginNotice().notice())
                .isEqualTo("포트폴리오 공개 데모입니다.\n<b>태그는 글자 그대로</b>");

        props.setLoginNotice(null);
        assertThat(new LoginNoticeController(props).loginNotice().notice()).isEmpty();

        props.setLoginNotice("가".repeat(LoginNoticeController.MAX_LENGTH));
        assertThat(new LoginNoticeController(props).loginNotice().notice()).hasSize(LoginNoticeController.MAX_LENGTH);

        props.setLoginNotice("가".repeat(LoginNoticeController.MAX_LENGTH + 1));
        assertThatThrownBy(() -> new LoginNoticeController(props))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("300자");
    }

    private MockHttpSession loginAs(String username, String password) throws Exception {
        MvcResult csrf = mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        Cookie csrfCookie = csrf.getResponse().getCookie("XSRF-TOKEN");
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
