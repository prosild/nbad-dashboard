package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.model.UserRole;
import com.zeekad.dashboard.service.MaskingService;
import com.zeekad.dashboard.service.PseudonymAnnotator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PseudonymAnnotatorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final MaskingService maskingService = new MaskingService(objectMapper);
    private final PseudonymAnnotator annotator = new PseudonymAnnotator(maskingService);

    @Test
    void annotatesWordBoundaryPseudonymsInSinglePassWithoutPartialWordOrDoubleReplacement() throws Exception {
        JsonNode pseudonyms = objectMapper.readTree("""
                {
                  "H": "192.168.10.50",
                  "X1": "172.16.0.1",
                  "X10": "203.0.113.10",
                  "172": "10.0.0.99"
                }
                """);

        String text = "H에서 X1 및 X10으로 HTTP 요청 발생 (H_backup은 제외, X1-edge는 치환).";

        String annotated = annotator.annotate(text, pseudonyms, UserRole.ANALYST);

        assertThat(annotated).isEqualTo(
                "H(192.168.10.50)에서 X1(172.16.0.1) 및 X10(203.0.113.10)으로 HTTP 요청 발생 (H_backup은 제외, X1(172.16.0.1)-edge는 치환).");
        // 치환된 IP(172.16.0.1)의 172가 재치환되지 않았는지 검증
        assertThat(annotated).doesNotContain("172(10.0.0.99)");
        // HTTP 내부의 H가 치환되지 않았는지 검증
        assertThat(annotated).contains("HTTP");
    }

    @Test
    void masksRawIpsAndPseudonymsBeforeSinglePassAnnotationForViewer() throws Exception {
        JsonNode pseudonyms = objectMapper.readTree("""
                {
                  "H": "192.168.10.50",
                  "X1": "172.16.0.1"
                }
                """);

        String text = "H가 X1 및 10.20.30.40과 HTTP 통신함";

        String viewerAnnotated = annotator.annotate(text, pseudonyms, UserRole.VIEWER);

        assertThat(viewerAnnotated).isEqualTo("H(192.168.*.*)가 X1(172.16.*.*) 및 10.20.*.*과 HTTP 통신함");
        assertThat(viewerAnnotated).doesNotContain("192.168.10.50");
        assertThat(viewerAnnotated).doesNotContain("172.16.0.1");
        assertThat(viewerAnnotated).doesNotContain("10.20.30.40");
    }

    @Test
    void handlesEmptyNullOrSpecialCharacterPseudonymsSafely() throws Exception {
        JsonNode pseudonyms = objectMapper.readTree("{\"\": \"1.1.1.1\", \"H$1\": \"10.1.2.3\"}");

        assertThat(annotator.annotate(null, pseudonyms, UserRole.ANALYST)).isNull();
        assertThat(annotator.annotate("", pseudonyms, UserRole.ANALYST)).isEmpty();
        assertThat(annotator.annotate("대상 H$1 확인", pseudonyms, UserRole.ANALYST))
                .isEqualTo("대상 H$1(10.1.2.3) 확인");
        assertThat(annotator.annotate("원문 8.8.8.8", (JsonNode) null, UserRole.VIEWER))
                .isEqualTo("원문 8.8.*.*");
    }
}
