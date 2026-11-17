package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.client.EvidenceApiClient;
import com.zeekad.dashboard.client.EvidenceApiResponse;
import com.zeekad.dashboard.client.EvidenceData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class EvidenceApiClientTest {

    private MockRestServiceServer mockServer;
    private EvidenceApiClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder().baseUrl("http://127.0.0.1:8000");
        mockServer = MockRestServiceServer.bindTo(builder).build();
        client = new EvidenceApiClient(builder.build(), new ObjectMapper());
    }

    @Test
    void parsesJobsCaptureQueueAndFullEvidenceV1Payload() {
        String evidencePayload = """
                {
                  "incident": {"incident_id": "cic17-wed|192.168.10.50|originator|1700000000"},
                  "evidence": {
                    "connection_count": 412,
                    "orig_bytes": 98304,
                    "resp_bytes": 524288,
                    "transport_counts": {"tcp": 390, "udp": 22},
                    "conn_state_counts": {"SF": 300, "S0": 112},
                    "peers": {"top": [{"ip": "203.0.113.45", "count": 210}]},
                    "ports": {"top": [{"port": 88, "count": 195}]},
                    "dns": 12, "http": 4, "tls": 18, "ssh": 0, "ftp": 0,
                    "smb": 11, "kerberos": 195, "dce_rpc": 3, "ntlm": 2,
                    "representative_connections": [
                      {"orig_h": "192.168.10.50", "resp_h": "203.0.113.45", "resp_p": 88, "proto": "tcp"}
                    ],
                    "limitations": ["페이로드 본문은 수집하지 않았습니다."],
                    "extra_note": "preserved"
                  }
                }
                """;

        mockServer.expect(requestTo("http://127.0.0.1:8000/api/v1/jobs"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("[{\"job_id\":101,\"capture_id\":\"cic17-wed\"}]", MediaType.APPLICATION_JSON));

        mockServer.expect(requestTo("http://127.0.0.1:8000/api/v1/captures/cic17-wed/queue?limit=10"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"items\":[{\"queue_rank\":1,\"host_ip\":\"192.168.10.50\"}]}",
                        MediaType.APPLICATION_JSON));

        mockServer.expect(requestTo("http://127.0.0.1:8000/api/v1/jobs/101/incidents/1"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(evidencePayload, MediaType.APPLICATION_JSON));

        List<Map<String, Object>> jobs = client.fetchJobs();
        assertThat(jobs).hasSize(1);
        assertThat(jobs.get(0)).containsEntry("capture_id", "cic17-wed");

        List<Map<String, Object>> queue = client.fetchCaptureQueue("cic17-wed", 10);
        assertThat(queue).hasSize(1);
        assertThat(queue.get(0)).containsEntry("host_ip", "192.168.10.50");

        EvidenceApiResponse response = client.fetchIncidentEvidence(101L, 1);
        assertThat(response.isAvailable()).isTrue();
        EvidenceData ev = response.getEvidence();
        assertThat(ev.isAvailable()).isTrue();
        assertThat(ev.getConnectionCount()).isEqualTo(412L);
        assertThat(ev.getOrigBytes()).isEqualTo(98304L);
        assertThat(ev.getRespBytes()).isEqualTo(524288L);
        assertThat(ev.getTransportCounts()).containsEntry("tcp", 390);
        assertThat(ev.getConnStateCounts()).containsEntry("SF", 300);
        assertThat(ev.getTopPeers()).hasSize(1);
        assertThat(ev.getTopPorts()).hasSize(1);
        assertThat(ev.getProtocolCounts()).containsKeys(
                "dns", "http", "tls", "ssh", "ftp", "smb", "kerberos", "dce_rpc", "ntlm");
        assertThat(ev.getRepresentativeConnections()).hasSize(1);
        assertThat(ev.getLimitations()).containsExactly("페이로드 본문은 수집하지 않았습니다.");
        assertThat(ev.getRawEvidence()).containsEntry("extra_note", "preserved");

        mockServer.verify();
    }

    @Test
    void returnsFallbackWithoutThrowingOnHttpErrorOrTimeout() {
        mockServer.expect(requestTo("http://127.0.0.1:8000/api/v1/jobs/101/incidents/1"))
                .andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));
        mockServer.expect(requestTo("http://127.0.0.1:8000/api/v1/jobs/101/incidents/2"))
                .andRespond(request -> {
                    throw new ResourceAccessException("Read timed out", new SocketTimeoutException("timeout"));
                });
        mockServer.expect(requestTo("http://127.0.0.1:8000/api/v1/jobs"))
                .andRespond(withStatus(HttpStatus.BAD_GATEWAY));
        mockServer.expect(requestTo("http://127.0.0.1:8000/api/v1/captures/cic17-wed/queue?limit=10"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        EvidenceApiResponse serverErr = client.fetchIncidentEvidence(101L, 1);
        assertThat(serverErr.isAvailable()).isFalse();
        assertThat(serverErr.getStatusMessage()).isEqualTo(EvidenceData.FALLBACK_MESSAGE);
        assertThat(serverErr.getEvidence().isAvailable()).isFalse();
        assertThat(serverErr.getEvidence().getStatusMessage()).isEqualTo(EvidenceData.FALLBACK_MESSAGE);

        EvidenceApiResponse timeoutErr = client.fetchIncidentEvidence(101L, 2);
        assertThat(timeoutErr.isAvailable()).isFalse();
        assertThat(timeoutErr.getStatusMessage()).isEqualTo("근거 API 연결 불가(DB 뷰 정보만 표시)");

        assertThat(client.fetchJobs()).isEmpty();
        assertThat(client.fetchCaptureQueue("cic17-wed", 10)).isEmpty();

        mockServer.verify();
    }
}
