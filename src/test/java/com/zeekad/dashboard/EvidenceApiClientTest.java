package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
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

import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@SuppressWarnings("unchecked")
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
        // T16: 옛 가짜 키(orig_bytes·transport_counts·ports·limitations 등)를 zeek_AD evidence.v1 실제 키로 바꿨다.
        String evidencePayload = """
                {
                  "zeekad_job_id": 101,
                  "zeekad_rank": 1,
                  "detection": {"zeekad_picked_by": "tgn_recon"},
                  "evidence": {
                    "version": "evidence.v1",
                    "connection_count": 412,
                    "network": {
                      "bytes": {"sent": 98304, "received": 524288},
                      "transport": {"tcp": 390, "udp": 22},
                      "protocol": {"krb": 195, "dns": 12},
                      "zeekad_payload_bytes_inflated": 0
                    },
                    "zeek_conn_state": {"SF": 300, "S0": 112},
                    "peers": {"unique": 3, "top": [{"ip": "203.0.113.45", "connections": 210}]},
                    "destination_ports": {"unique": 2, "top": [{"port": 88, "transport": "tcp", "connections": 195}]},
                    "protocol_logs": {"dns": {"queries": 12}, "kerberos": {"requests": 195, "failures": 0}},
                    "representative_connections": [
                      {"source": {"ip": "192.168.10.50"}, "destination": {"ip": "203.0.113.45", "port": 88}}
                    ],
                    "limits": ["페이로드 본문은 수집하지 않았습니다."],
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
        assertThat(ev.getBytesSent()).isEqualTo(98304L);
        assertThat(ev.getBytesReceived()).isEqualTo(524288L);
        assertThat(ev.getPayloadBytesInflated()).isEqualTo(0L);
        assertThat(ev.getTransportCounts()).containsEntry("tcp", 390);
        assertThat(ev.getServiceProtocolCounts()).containsEntry("krb", 195);
        assertThat(ev.getConnStateCounts()).containsEntry("SF", 300);
        assertThat(ev.getTopPeers()).hasSize(1);
        assertThat(ev.getUniquePeers()).isEqualTo(3L);
        assertThat(ev.getTopPorts()).hasSize(1);
        assertThat(ev.getUniquePorts()).isEqualTo(2L);
        assertThat(ev.getProtocolLogs()).containsOnlyKeys("dns", "kerberos");
        assertThat(ev.getRepresentativeConnections()).hasSize(1);
        assertThat(ev.getLimits()).containsExactly("페이로드 본문은 수집하지 않았습니다.");
        assertThat(ev.getAdditionalFields()).containsEntry("extra_note", "preserved")
                .containsEntry("version", "evidence.v1")
                .doesNotContainKeys("network", "peers", "limits", "detection");

        mockServer.verify();
    }

    @Test
    void realEvidenceApiSampleFillsEveryStructuredField() throws Exception {
        expectIncident(101L, 1, readSample());

        EvidenceApiResponse response = client.fetchIncidentEvidence(101L, 1);
        EvidenceData ev = response.getEvidence();
        assertThat(response.isAvailable()).isTrue();
        assertThat(ev.isAvailable()).isTrue();
        assertThat(ev.getConnectionCount()).isEqualTo(155261L);
        assertThat(ev.getBytesSent()).isEqualTo(1791339786L);
        assertThat(ev.getBytesReceived()).isEqualTo(123985880L);
        assertThat(ev.getPayloadBytesInflated()).isEqualTo(724L);
        assertThat(ev.getTransportCounts()).containsExactlyInAnyOrderEntriesOf(Map.of("tcp", 155221, "udp", 40));
        assertThat(ev.getServiceProtocolCounts()).containsExactlyInAnyOrderEntriesOf(Map.of(
                "dns", 40, "ftp", 22, "ssh", 44, "http", 147460, "gssapi", 10, "ftp-data", 22, "unidentified", 7663));
        assertThat(ev.getConnStateCounts()).hasSize(9).containsEntry("RSTO", 91898).containsEntry("SF", 58598);
        assertThat(ev.getTopPeers()).hasSize(5);
        assertThat(ev.getTopPeers().get(0)).containsEntry("ip", "172.16.0.1").containsEntry("connections", 155111);
        assertThat(ev.getUniquePeers()).isEqualTo(12L);
        assertThat(ev.getTopPorts()).hasSize(5);
        assertThat(ev.getTopPorts().get(2)).containsEntry("port", 137).containsEntry("transport", "udp")
                .containsEntry("connections", 40);
        assertThat(ev.getUniquePorts()).isEqualTo(27L);
        assertThat(ev.getProtocolLogs()).containsOnlyKeys(
                "dns", "ftp", "smb", "ssh", "tls", "http", "ntlm", "dce_rpc", "kerberos");
        assertThat((Map<String, Object>) ev.getProtocolLogs().get("dns"))
                .containsEntry("queries", 80).containsEntry("nxdomain", 0);
        assertThat((Map<String, Object>) ev.getProtocolLogs().get("http")).containsEntry("requests", 150493);
        Map<String, Object> dce = (Map<String, Object>) ev.getProtocolLogs().get("dce_rpc");
        assertThat(dce).containsEntry("calls", 10);
        assertThat((List<Object>) dce.get("top_operations")).hasSize(1);
        assertThat(ev.getRepresentativeConnections()).hasSize(10);
        assertThat(ev.getRepresentativeConnections().get(0))
                .containsKeys("zeek", "event", "source", "destination", "network");
        assertThat(ev.getLimits()).hasSize(4);
        assertThat(ev.getLimits().get(0)).startsWith("Zeek 네트워크 메타데이터만 본다");
        assertThat(ev.getAdditionalFields()).containsOnlyKeys("version", "host", "event", "zeekad_role")
                .containsEntry("version", "evidence.v1")
                .containsEntry("zeekad_role", "responder");
    }

    @Test
    void everyEvidenceTopLevelKeyIsStructuredOrAllowlisted() throws Exception {
        // evidence 최상위 키만 본다(하위 키 변경은 이 테스트가 잡지 않는다).
        JsonNode evidence = new ObjectMapper().readTree(readSample()).get("evidence");
        Set<String> sampleKeys = new HashSet<>();
        evidence.fieldNames().forEachRemaining(sampleKeys::add);

        Set<String> known = new HashSet<>(EvidenceApiClient.STRUCTURED_EVIDENCE_KEYS);
        known.addAll(EvidenceApiClient.ADDITIONAL_EVIDENCE_KEYS);
        assertThat(sampleKeys)
                .as("정형 필드에도 additionalFields 허용 목록에도 없는 evidence 최상위 키")
                .isSubsetOf(known);
        assertThat(EvidenceApiClient.STRUCTURED_EVIDENCE_KEYS)
                .as("실제 응답에 없는 정형 키")
                .isSubsetOf(sampleKeys);
        assertThat(EvidenceApiClient.STRUCTURED_EVIDENCE_KEYS)
                .doesNotContainAnyElementsOf(EvidenceApiClient.ADDITIONAL_EVIDENCE_KEYS);
    }

    @Test
    void nullOrMissingEvidenceIsNoEvidenceAndNeverFallsBackToTopLevel() {
        String topLevel = """
                "zeekad_job_id": 101,
                "host": {"ip": "198.51.100.77", "name": ["SECRET-HOST$"]},
                "detection": {"zeekad_picked_by": "tgn_recon"},
                "zeekad_asset_observations": [{"zeekad_name_kind": "kerberos_user", "zeekad_name": "krb_secret_user"}],
                "connection_count": 999
                """;
        expectIncident(101L, 1, "{" + topLevel + ", \"evidence\": null}");
        expectIncident(101L, 2, "{" + topLevel + "}");
        expectIncident(101L, 3, "{" + topLevel + ", \"evidence\": [1, 2]}");

        for (int rank = 1; rank <= 3; rank++) {
            EvidenceApiResponse response = client.fetchIncidentEvidence(101L, rank);
            assertThat(response.isAvailable()).isTrue();
            EvidenceData ev = response.getEvidence();
            assertThat(ev.isAvailable()).isFalse();
            assertThat(ev.getStatusMessage()).isEqualTo(EvidenceData.NO_EVIDENCE_MESSAGE);
            assertThat(ev.getConnectionCount()).isNull();
            assertThat(ev.getAdditionalFields()).isEmpty();
        }
        mockServer.verify();
    }

    private void expectIncident(long jobId, int rank, String body) {
        mockServer.expect(requestTo("http://127.0.0.1:8000/api/v1/jobs/" + jobId + "/incidents/" + rank))
                .andRespond(withSuccess(body, MediaType.APPLICATION_JSON));
    }

    static String readSample() throws Exception {
        try (InputStream in = EvidenceApiClientTest.class.getResourceAsStream(
                "/evidence/evidence-api-sample-job2-rank1.json")) {
            assertThat(in).as("evidence API 표본 리소스").isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
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
        assertThat(timeoutErr.getStatusMessage()).isEqualTo("상세 증적을 불러오지 못했습니다. 기본 정보만 표시합니다.");

        assertThat(client.fetchJobs()).isEmpty();
        assertThat(client.fetchCaptureQueue("cic17-wed", 10)).isEmpty();

        mockServer.verify();
    }
}
