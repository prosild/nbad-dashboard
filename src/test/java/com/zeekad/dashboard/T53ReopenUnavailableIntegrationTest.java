package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.AuditLogMapper;
import com.zeekad.dashboard.mapper.zeekad.write.ZeekadWriteMapper;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.UncategorizedSQLException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T53 다시 열기의 DB 오류 처리를 쓰기 매퍼 대역으로 본다(H2로는 PostgreSQL의 SQLSTATE를 만들 수 없는 경우).
 * 42883(함수 없음, migration 018 전의 스냅샷 DB)·42501(실행 권한 없음) → 501 REOPEN_UNAVAILABLE, 고정 문장, DB 메시지 없음.
 * 22023 → 409 CONFLICT 고정 문장(DB 문구의 상태·판정 코드 원문 없음), 02000 → 404 NOT_FOUND, 그 밖 → 500.
 * 어느 거부도 상태 변경 감사를 남기지 않는다. 시험용 zeekad 행은 job 97548~97549.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T53ReopenUnavailableIntegrationTest {

    static final String LIVE = "lab-t53u";
    static final long JOB = 97548L;
    static final String INCIDENT = "lab-t53u|10.53.9.1|originator|t53u";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserAdminService userAdminService;
    @Autowired private AuditLogMapper auditLogMapper;
    @Autowired @Qualifier("zeekadReadDataSource") private DataSource zeekadReadDataSource;
    @MockitoBean private ZeekadWriteMapper zeekadWriteMapper;

    private static int seq = 0;

    @BeforeEach
    void seed() {
        cleanup();
        JdbcTemplate z = new JdbcTemplate(zeekadReadDataSource);
        z.update("INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-25T00:55:00Z', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-25T00:58:00Z', NULL, 1)", JOB, LIVE);
        z.update("INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip, "
                + "zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name) "
                + "VALUES (?, ?, 'zeekad-fusion/1', 1, ?, '10.53.9.1', 'originator', TIMESTAMP WITH TIME ZONE '2026-11-25T00:40:00Z', "
                + "TIMESTAMP WITH TIME ZONE '2026-11-25T00:45:00Z', 'hbos', NULL, 10, NULL)", JOB, LIVE, INCIDENT);
        z.update("INSERT INTO dashboard.raw_incident_status (job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                + "VALUES (?, ?, 'closed', 'false_positive', TIMESTAMP WITH TIME ZONE '2026-11-25T01:10:00Z', 't53u')", JOB, INCIDENT);
    }

    @AfterEach
    void cleanup() {
        reset(zeekadWriteMapper);
        JdbcTemplate z = new JdbcTemplate(zeekadReadDataSource);
        String range = "job_id BETWEEN 97548 AND 97549";
        z.update("DELETE FROM dashboard.raw_incident_status_history WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_status WHERE " + range);
        z.update("DELETE FROM dashboard.raw_incident_queue WHERE " + range);
        z.update("DELETE FROM dashboard.raw_scoring_jobs WHERE " + range);
    }

    @Test
    void missingFunctionOrPermissionIs501WithoutDbMessage() throws Exception {
        MockHttpSession analyst = login();
        String name = (String) analyst.getAttribute("t53u.name");
        String[][] cases = {
                {"42883", "ERROR: function dashboard.reopen_incident(p_job => bigint, p_incident => character varying) does not exist"},
                {"42501", "ERROR: permission denied for function reopen_incident"},
        };
        for (String[] c : cases) {
            when(zeekadWriteMapper.reopenIncident(anyLong(), anyString(), anyString(), anyString(), anyString()))
                    .thenThrow(new BadSqlGrammarException("reopen", "SELECT dashboard.reopen_incident(...)", new SQLException(c[1], c[0])));
            MvcResult r = reopen(analyst).andExpect(status().isNotImplemented()).andReturn();
            String body = r.getResponse().getContentAsString(StandardCharsets.UTF_8);
            JsonNode json = objectMapper.readTree(body);
            assertThat(json.get("succeeded").asBoolean()).as(c[0]).isFalse();
            assertThat(json.get("code").asText()).isEqualTo("REOPEN_UNAVAILABLE");
            assertThat(json.get("message").asText()).isEqualTo("이 환경의 탐지 DB에는 다시 열기 기능이 아직 없습니다.");
            assertThat(body).doesNotContain("reopen_incident", "does not exist", "permission denied", "ERROR", "SELECT", c[0]);
            reset(zeekadWriteMapper);
        }
        assertThat(auditLogMapper.findFiltered("INCIDENT_STATUS_TRANSITION", name, 10)).isEmpty();
    }

    @Test
    void conflictNotFoundAndOtherErrorsAreMappedWithoutDbText() throws Exception {
        MockHttpSession analyst = login();
        String name = (String) analyst.getAttribute("t53u.name");

        when(zeekadWriteMapper.reopenIncident(anyLong(), anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new UncategorizedSQLException("reopen", "SELECT",
                        new SQLException("ERROR: 종료 결론이 화면과 다르다. 지금 결론: true_positive", "22023")));
        MvcResult conflict = reopen(analyst).andExpect(status().isConflict()).andReturn();
        String body = conflict.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(objectMapper.readTree(body).get("code").asText()).isEqualTo("CONFLICT");
        assertThat(objectMapper.readTree(body).get("message").asText())
                .isEqualTo("다른 사람이 먼저 상태나 판정을 바꿨습니다. '다시 불러오기'로 최신 상태를 확인하세요.");
        assertThat(body).doesNotContain("true_positive", "지금 결론", "ERROR");
        reset(zeekadWriteMapper);

        when(zeekadWriteMapper.reopenIncident(anyLong(), anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new UncategorizedSQLException("reopen", "SELECT",
                        new SQLException("ERROR: 사건이 없다: 97548 " + INCIDENT, "02000")));
        JsonNode notFound = objectMapper.readTree(reopen(analyst).andExpect(status().isNotFound()).andReturn()
                .getResponse().getContentAsString(StandardCharsets.UTF_8));
        assertThat(notFound.get("code").asText()).isEqualTo("NOT_FOUND");
        // T68(M3): DB 문장에 안내가 없으면 대시보드 안내("다시 불러오기", 화면 단추 이름)를 붙인다
        assertThat(notFound.get("message").asText()).contains("'다시 불러오기'로 최신 상태를 확인하세요.").doesNotContain("ERROR", "새로고침");
        reset(zeekadWriteMapper);

        when(zeekadWriteMapper.reopenIncident(anyLong(), anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new UncategorizedSQLException("reopen", "SELECT",
                        new SQLException("ERROR: could not serialize access", "40001")));
        MvcResult other = reopen(analyst).andExpect(status().isInternalServerError()).andReturn();
        String otherBody = other.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(objectMapper.readTree(otherBody).get("code").asText()).isEqualTo("INTERNAL_ERROR");
        assertThat(otherBody).doesNotContain("serialize", "40001");

        assertThat(auditLogMapper.findFiltered("INCIDENT_STATUS_TRANSITION", name, 10)).isEmpty();
    }

    @Test
    void successPassesNormalizedValuesToWriteMapper() throws Exception {
        MockHttpSession analyst = login();
        String name = (String) analyst.getAttribute("t53u.name");
        when(zeekadWriteMapper.reopenIncident(any(), any(), any(), any(), any())).thenReturn("investigating");
        mockMvc.perform(post("/api/incidents/" + JOB + "/rank/1/reopen").session(analyst).with(csrf(analyst))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("reason", "  사유  ", "expectedResolution", " False_Positive "))))
                .andExpect(status().isOk());
        org.mockito.Mockito.verify(zeekadWriteMapper).reopenIncident(JOB, INCIDENT, name, "사유", "false_positive");
    }

    private org.springframework.test.web.servlet.ResultActions reopen(MockHttpSession s) throws Exception {
        return mockMvc.perform(post("/api/incidents/" + JOB + "/rank/1/reopen").session(s).with(csrf(s))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("reason", "재검토", "expectedResolution", "false_positive"))));
    }

    private org.springframework.test.web.servlet.request.RequestPostProcessor csrf(MockHttpSession s) throws Exception {
        Cookie c = mockMvc.perform(get("/api/auth/csrf").session(s)).andReturn().getResponse().getCookie("XSRF-TOKEN");
        return req -> {
            if (c != null) {
                req.setCookies(c);
                req.addHeader("X-XSRF-TOKEN", c.getValue());
            }
            return req;
        };
    }

    private MockHttpSession login() throws Exception {
        String username = "t53u_" + (++seq) + "_" + System.nanoTime() % 100000;
        userAdminService.createUser(username, "표시 " + username, "Pass1234!", UserRole.ANALYST, LIVE, "seed", "ADMIN", "127.0.0.1");
        Cookie csrf = mockMvc.perform(get("/api/auth/csrf")).andReturn().getResponse().getCookie("XSRF-TOKEN");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .cookie(csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, "Pass1234!"))))
                .andExpect(status().isOk())
                .andReturn();
        MockHttpSession s = (MockHttpSession) result.getRequest().getSession(false);
        s.setAttribute("t53u.name", username);
        return s;
    }
}
