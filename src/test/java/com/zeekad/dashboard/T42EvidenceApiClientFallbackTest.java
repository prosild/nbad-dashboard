package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.client.EvidenceApiClient;
import com.zeekad.dashboard.client.EvidenceApiResponse;
import com.zeekad.dashboard.client.EvidenceData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * T42: 근거 API가 깨진 응답을 줘도 클라이언트가 예외를 올리지 않고 폴백하며,
 * 로그에는 경로·예외 종류·상태 수만 남고 응답 본문(예외 글)이 남지 않는다.
 */
@ExtendWith(OutputCaptureExtension.class)
class T42EvidenceApiClientFallbackTest {

    private static final String BASE = "http://127.0.0.1:8000";
    private static final String INCIDENT_1 = BASE + "/api/v1/jobs/101/incidents/1";

    private MockRestServiceServer mockServer;
    private EvidenceApiClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder().baseUrl(BASE);
        mockServer = MockRestServiceServer.bindTo(builder).build();
        client = new EvidenceApiClient(builder.build(), new ObjectMapper());
    }

    @Test
    void illegalArgumentFromHttpLayerFallsBackForAllThreeMethods(CapturedOutput output) {
        // 응답 상태 줄이 깨지면 스프링이 IllegalArgumentException("Status code '-1' ...")을 던진다(T41 조사).
        mockServer.expect(requestTo(INCIDENT_1)).andRespond(request -> {
            throw new IllegalArgumentException("Status code '-1' MARKER_IAE_MESSAGE");
        });
        mockServer.expect(requestTo(BASE + "/api/v1/jobs")).andRespond(request -> {
            throw new IllegalArgumentException("MARKER_IAE_MESSAGE");
        });
        mockServer.expect(requestTo(BASE + "/api/v1/captures/cic17-wed/queue?limit=10")).andRespond(request -> {
            throw new IllegalStateException("MARKER_IAE_MESSAGE");
        });

        assertUnavailable(client.fetchIncidentEvidence(101L, 1));
        assertThat(client.fetchJobs()).isEmpty();
        assertThat(client.fetchCaptureQueue("cic17-wed", 10)).isEmpty();
        mockServer.verify();

        assertThat(output.getAll())
                .doesNotContain("MARKER_IAE_MESSAGE")
                .contains("/api/v1/jobs/101/incidents/1")
                .contains("java.lang.IllegalArgumentException")
                .contains("java.lang.IllegalStateException");
    }

    @Test
    void shapeMismatchedJsonFallsBackWholeWithoutHalfFilledResponse(CapturedOutput output) {
        // 객체 자리에 글·수, 목록 자리의 원소가 객체가 아님 등. 풀이 코드가 예외를 내는 꼴은 통째로 unavailable이다.
        List<String> bodies = List.of(
                "{\"evidence\":{\"connection_count\":5,\"peers\":{\"top\":[\"MARKER_SHAPE_VALUE\"]}}}",
                "{\"evidence\":{\"connection_count\":5,\"destination_ports\":{\"top\":[1,2,\"MARKER_SHAPE_VALUE\"]}}}",
                "{\"evidence\":{\"connection_count\":5,\"representative_connections\":[\"MARKER_SHAPE_VALUE\"]}}",
                "{\"evidence\":{\"connection_count\":5,\"representative_connections\":[[\"MARKER_SHAPE_VALUE\"]]}}"
        );
        for (int i = 0; i < bodies.size(); i++) {
            mockServer.expect(requestTo(BASE + "/api/v1/jobs/101/incidents/" + (i + 1)))
                    .andRespond(withSuccess(bodies.get(i), MediaType.APPLICATION_JSON));
        }
        mockServer.expect(requestTo(BASE + "/api/v1/jobs"))
                .andRespond(withSuccess("[\"MARKER_SHAPE_VALUE\"]", MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo(BASE + "/api/v1/captures/cic17-wed/queue?limit=10"))
                .andRespond(withSuccess("{\"items\":[\"MARKER_SHAPE_VALUE\"]}", MediaType.APPLICATION_JSON));

        for (int i = 0; i < bodies.size(); i++) {
            EvidenceApiResponse response = client.fetchIncidentEvidence(101L, i + 1);
            assertUnavailable(response);
            assertThat(response.getEvidence().getConnectionCount()).as("반쯤 채운 값이 없다").isNull();
        }
        assertThat(client.fetchJobs()).isEmpty();
        assertThat(client.fetchCaptureQueue("cic17-wed", 10)).isEmpty();
        mockServer.verify();

        assertThat(output.getAll()).doesNotContain("MARKER_SHAPE_VALUE").contains("폴백 반환");
    }

    @Test
    void nonJsonBodyFallsBackAndFirstWordIsNotLogged(CapturedOutput output) {
        mockServer.expect(requestTo(INCIDENT_1))
                .andRespond(withSuccess("MARKER_NONJSON_FIRST rest of the body host.internal", MediaType.TEXT_PLAIN));
        mockServer.expect(requestTo(BASE + "/api/v1/jobs"))
                .andRespond(withSuccess("MARKER_NONJSON_FIRST <html>", MediaType.TEXT_HTML));
        mockServer.expect(requestTo(BASE + "/api/v1/captures/cic17-wed/queue?limit=10"))
                .andRespond(withSuccess("{\"items\": MARKER_NONJSON_FIRST", MediaType.APPLICATION_JSON));

        assertUnavailable(client.fetchIncidentEvidence(101L, 1));
        assertThat(client.fetchJobs()).isEmpty();
        assertThat(client.fetchCaptureQueue("cic17-wed", 10)).isEmpty();
        mockServer.verify();

        assertThat(output.getAll())
                .doesNotContain("MARKER_NONJSON_FIRST")
                .doesNotContain("host.internal")
                .contains("com.fasterxml.jackson");
    }

    @Test
    void clientAndServerErrorBodiesAreNotLoggedOnlyStatusNumber(CapturedOutput output) {
        mockServer.expect(requestTo(INCIDENT_1))
                .andRespond(withStatus(HttpStatus.NOT_FOUND).contentType(MediaType.APPLICATION_JSON)
                        .body("{\"detail\":\"MARKER_4XX_BODY evidence-api.internal\"}"));
        mockServer.expect(requestTo(BASE + "/api/v1/jobs/101/incidents/2"))
                .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE).contentType(MediaType.TEXT_PLAIN)
                        .body("MARKER_5XX_BODY upstream.internal:5432"));
        mockServer.expect(requestTo(BASE + "/api/v1/jobs"))
                .andRespond(withStatus(HttpStatus.BAD_REQUEST).body("MARKER_4XX_BODY"));
        mockServer.expect(requestTo(BASE + "/api/v1/captures/cic17-wed/queue?limit=10"))
                .andRespond(withStatus(HttpStatus.BAD_GATEWAY).body("MARKER_5XX_BODY"));

        assertUnavailable(client.fetchIncidentEvidence(101L, 1));
        assertUnavailable(client.fetchIncidentEvidence(101L, 2));
        assertThat(client.fetchJobs()).isEmpty();
        assertThat(client.fetchCaptureQueue("cic17-wed", 10)).isEmpty();
        mockServer.verify();

        String log = output.getAll();
        assertThat(log)
                .doesNotContain("MARKER_4XX_BODY")
                .doesNotContain("MARKER_5XX_BODY")
                .doesNotContain("evidence-api.internal")
                .doesNotContain("upstream.internal")
                .contains("status=404")
                .contains("status=503")
                .contains("status=400")
                .contains("status=502");
    }

    @Test
    void normalResponseIsUnchangedAndWritesNoFallbackLog(CapturedOutput output) throws Exception {
        mockServer.expect(requestTo(INCIDENT_1))
                .andRespond(withSuccess(EvidenceApiClientTest.readSample(), MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo(BASE + "/api/v1/jobs"))
                .andRespond(withSuccess("[{\"job_id\":101}]", MediaType.APPLICATION_JSON));

        EvidenceApiResponse response = client.fetchIncidentEvidence(101L, 1);
        assertThat(response.isAvailable()).isTrue();
        assertThat(response.getEvidence().isAvailable()).isTrue();
        assertThat(response.getEvidence().getConnectionCount()).isEqualTo(155261L);
        assertThat(client.fetchJobs()).hasSize(1);
        mockServer.verify();

        assertThat(output.getAll()).doesNotContain("폴백 반환");
    }

    private static void assertUnavailable(EvidenceApiResponse response) {
        assertThat(response.isAvailable()).isFalse();
        assertThat(response.getStatusMessage()).isEqualTo(EvidenceData.FALLBACK_MESSAGE);
        assertThat(response.getEvidence().isAvailable()).isFalse();
        assertThat(response.getEvidence().getAdditionalFields()).isEmpty();
    }
}
