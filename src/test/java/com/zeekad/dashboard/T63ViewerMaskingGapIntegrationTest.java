package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.dto.LoginRequest;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.service.UserAdminService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T63 설계자 결정(b): T63 전부터 조회자에게 가리지 않던 칸을 지금의 조회자 가림으로 가린다(가리는 쪽으로만).
 * <ul>
 *   <li>옛 목록 API(GET /api/incidents)의 selectedJob·captureJobs[]와 상세의 detail.job: 작업 오류 글(maskScoringJob, 현황판·운영 현황과 같다)</li>
 *   <li>상세의 detail.report.attackCandidates[].name·tactics[]: 현황판 위협 패널(DashboardThreatService)과 같은 조회자 가림</li>
 * </ul>
 * 분석가는 원문 그대로이고 ATT&amp;CK ID(식별자)는 바뀌지 않는다. 모의 환경: H2 + MockMvc.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class T63ViewerMaskingGapIntegrationTest {

    static final String CAP = "t63-gap";
    static final long JOB_FAILED = 64990L;
    static final long JOB = 65001L;
    static final String INCIDENT = CAP + "|10.64.0.1|originator|1700065001";
    static final String PASSWORD = "Pass1234!";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private UserAdminService userAdminService;
    @Autowired
    private UserMapper userMapper;
    @Autowired
    @Qualifier("zeekadReadDataSource")
    private DataSource zeekadReadDataSource;

    private JdbcTemplate zeekadJdbc;
    private MockHttpSession analyst;
    private MockHttpSession viewer;

    @BeforeAll
    void seed() throws Exception {
        zeekadJdbc = new JdbcTemplate(zeekadReadDataSource);
        cleanup();
        for (String[] u : List.of(new String[]{"t63g_analyst", "ANALYST"}, new String[]{"t63g_viewer", "VIEWER"})) {
            if (userMapper.findByUsername(u[0]) == null) {
                userAdminService.createUser(u[0], u[0], PASSWORD, UserRole.valueOf(u[1]), "t63-*", "seed", "ADMIN", "127.0.0.1");
            }
        }
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
                VALUES (?, ?, 'zeekad-fusion/1', 'failed', TIMESTAMP WITH TIME ZONE '2026-11-22 00:00:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-22 00:01:00Z', 'connect to 10.9.8.7:5432 refused', 0)
                """, JOB_FAILED, CAP);
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_scoring_jobs (job_id, capture_id, bundle_id, status, started_at, finished_at, error, incident_count)
                VALUES (?, ?, 'zeekad-fusion/1', 'succeeded', TIMESTAMP WITH TIME ZONE '2026-11-22 01:00:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-22 01:05:00Z', 'partial retry 10.9.8.6', 1)
                """, JOB, CAP);
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_queue (job_id, capture_id, bundle_id, queue_rank, incident_id, host_ip,
                    zeekad_role, event_start, event_end, zeekad_picked_by, zeekad_also_flagged_by, connection_count, host_name)
                VALUES (?, ?, 'zeekad-fusion/1', 1, ?, '10.64.0.1', 'originator', TIMESTAMP WITH TIME ZONE '2026-11-22 00:30:00Z',
                        TIMESTAMP WITH TIME ZONE '2026-11-22 00:45:00Z', 'iforest', NULL, 3, ?)
                """, JOB, CAP, INCIDENT, new String[]{"gap-host"});
        zeekadJdbc.update("""
                INSERT INTO dashboard.raw_incident_reports (job_id, incident_id, zeekad_report_kind, zeekad_report_version,
                    zeekad_input_version, zeekad_report, zeekad_attack_candidates, zeekad_source_run, created_at)
                VALUES (?, ?, 'llm', 'llm-report.v1', 'evidence.v1', '{"observation_summary": "gap"}' FORMAT JSON,
                        '[{"attack_id": "T1021", "name": "Remote Services via 10.9.8.5", "tactics": ["Lateral Movement", "pivot 10.9.8.4"]}]' FORMAT JSON,
                        'run-t63-gap', TIMESTAMP WITH TIME ZONE '2026-11-22 01:06:00Z')
                """, JOB, INCIDENT);
        analyst = login("t63g_analyst");
        viewer = login("t63g_viewer");
    }

    @AfterAll
    void cleanup() {
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_reports WHERE incident_id = ?", INCIDENT);
        zeekadJdbc.update("DELETE FROM dashboard.raw_incident_queue WHERE capture_id = ?", CAP);
        zeekadJdbc.update("DELETE FROM dashboard.raw_scoring_jobs WHERE job_id IN (?, ?)", JOB_FAILED, JOB);
    }

    @Test
    void legacyListJobsAreMaskedForViewerAndRawForAnalyst() throws Exception {
        JsonNode viewerList = json(viewer, get("/api/incidents").param("captureId", CAP));
        assertThat(errors(viewerList.get("captureJobs")))
                .containsExactlyInAnyOrder("connect to 10.9.*.*:5432 refused", "partial retry 10.9.*.*");
        assertThat(viewerList.get("selectedJob").get("error").asText()).isEqualTo("partial retry 10.9.*.*");
        JsonNode viewerFailed = json(viewer, get("/api/incidents").param("jobId", String.valueOf(JOB_FAILED)));
        assertThat(viewerFailed.get("selectedJob").get("error").asText()).isEqualTo("connect to 10.9.*.*:5432 refused");

        JsonNode analystList = json(analyst, get("/api/incidents").param("captureId", CAP));
        assertThat(errors(analystList.get("captureJobs")))
                .containsExactlyInAnyOrder("connect to 10.9.8.7:5432 refused", "partial retry 10.9.8.6");
        assertThat(json(analyst, get("/api/incidents").param("jobId", String.valueOf(JOB_FAILED)))
                .get("selectedJob").get("error").asText()).isEqualTo("connect to 10.9.8.7:5432 refused");
    }

    @Test
    void detailJobErrorIsMaskedForViewerAndRawForAnalyst() throws Exception {
        JsonNode v = json(viewer, get("/api/incidents/" + JOB + "/rank/1")).get("detail");
        assertThat(v.get("job").get("error").asText()).isEqualTo("partial retry 10.9.*.*");
        JsonNode a = json(analyst, get("/api/incidents/" + JOB + "/rank/1")).get("detail");
        assertThat(a.get("job").get("error").asText()).isEqualTo("partial retry 10.9.8.6");
    }

    @Test
    void detailAttackCandidateNameAndTacticsAreMaskedForViewerAndRawForAnalyst() throws Exception {
        JsonNode vc = json(viewer, get("/api/incidents/" + JOB + "/rank/1")).get("detail")
                .get("report").get("attackCandidates").get(0);
        assertThat(vc.get("attackId").asText()).isEqualTo("T1021");
        assertThat(vc.get("name").asText()).isEqualTo("Remote Services via 10.9.*.*");
        assertThat(texts(vc.get("tactics"))).containsExactly("Lateral Movement", "pivot 10.9.*.*");

        JsonNode ac = json(analyst, get("/api/incidents/" + JOB + "/rank/1")).get("detail")
                .get("report").get("attackCandidates").get(0);
        assertThat(ac.get("attackId").asText()).isEqualTo("T1021");
        assertThat(ac.get("name").asText()).isEqualTo("Remote Services via 10.9.8.5");
        assertThat(texts(ac.get("tactics"))).containsExactly("Lateral Movement", "pivot 10.9.8.4");
    }

    private static List<String> errors(JsonNode jobs) {
        List<String> out = new ArrayList<>();
        jobs.forEach(j -> {
            if (j.hasNonNull("error")) {
                out.add(j.get("error").asText());
            }
        });
        return out;
    }

    private static List<String> texts(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(n -> out.add(n.asText()));
        return out;
    }

    private JsonNode json(MockHttpSession session, MockHttpServletRequestBuilder request) throws Exception {
        MvcResult res = mockMvc.perform(request.session(session)).andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(res.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private MockHttpSession login(String username) throws Exception {
        Cookie csrf = mockMvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn()
                .getResponse().getCookie("XSRF-TOKEN");
        MvcResult result = mockMvc.perform(post("/api/auth/login").cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, PASSWORD))))
                .andExpect(status().isOk()).andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }
}
