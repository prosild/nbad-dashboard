package com.zeekad.dashboard;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T67 정적 시험: favicon 파일(ICO 머리, 두 HTML이 가리킴)과 공개 스택 postgres 상태 검사의 start_period.
 */
class T67StaticTest {

    private static final Path FAVICON = Path.of("frontend", "public", "favicon.ico");

    @Test
    void faviconIsAnIcoFileThatBothHtmlShellsPointTo() throws IOException {
        assertThat(FAVICON).as("Vite public/ → dist/ → processResources가 static/으로 복사").isRegularFile();
        byte[] ico = Files.readAllBytes(FAVICON);
        assertThat(ico.length).isBetween(22, 16 * 1024);
        ByteBuffer buf = ByteBuffer.wrap(ico).order(ByteOrder.LITTLE_ENDIAN);
        // ICONDIR: reserved 0, type 1(아이콘), 개수 1 이상
        assertThat(buf.getShort(0)).isZero();
        assertThat(buf.getShort(2)).isEqualTo((short) 1);
        int count = buf.getShort(4);
        assertThat(count).isBetween(1, 8);
        for (int i = 0; i < count; i++) {
            int entry = 6 + 16 * i;
            int size = Byte.toUnsignedInt(ico[entry]);
            int bytes = buf.getInt(entry + 8);
            int offset = buf.getInt(entry + 12);
            assertThat(size).as("항목 %d의 크기", i).isIn(16, 32, 48);
            assertThat(offset + bytes).as("항목 %d가 파일 안에 있음", i).isLessThanOrEqualTo(ico.length);
            // 안에 PNG를 담았다(모든 최신 브라우저가 읽는다)
            assertThat(new byte[] {ico[offset], ico[offset + 1], ico[offset + 2], ico[offset + 3]})
                    .as("항목 %d의 PNG 머리", i)
                    .containsExactly(0x89, 'P', 'N', 'G');
        }

        String link = "<link rel=\"icon\" href=\"/favicon.ico\" />";
        assertThat(Files.readString(Path.of("frontend/index.html"), StandardCharsets.UTF_8)).contains(link);
        assertThat(Files.readString(Path.of("src/main/resources/static/index.html"), StandardCharsets.UTF_8)).contains(link);

        // 바이너리로 다룬다(줄바꿈 변환 없음)
        List<String> attrs = Files.readAllLines(Path.of(".gitattributes"), StandardCharsets.UTF_8);
        assertThat(attrs).anyMatch(line -> line.strip().equals("*.ico binary"));
    }

    @Test
    void portfolioPostgresHealthcheckStartPeriodCoversNasRestore() throws IOException {
        String compose = Files.readString(Path.of("compose.portfolio.yml"), StandardCharsets.UTF_8);
        String postgres = serviceBlock(compose, "postgres");
        assertThat(postgres).as("compose.portfolio.yml postgres 서비스").isNotBlank();
        int at = postgres.indexOf("    healthcheck:\n");
        assertThat(at).as("postgres healthcheck").isGreaterThanOrEqualTo(0);
        String healthcheck = postgres.substring(at);
        // T67: NAS 스냅샷 복원(약 7분, T65)이 120s + 10s x 12를 넘었다. unhealthy까지 최대 900 + 10 x 12초
        assertThat(healthcheck).containsPattern("(?m)^      start_period: 900s(\\s+#.*)?$")
                .doesNotContainPattern("(?m)^      start_period: 120s")
                // 나머지는 그대로
                .containsPattern("(?m)^      interval: 10s$")
                .containsPattern("(?m)^      timeout: 5s$")
                .containsPattern("(?m)^      retries: 12$");
    }

    private static String serviceBlock(String compose, String service) {
        StringBuilder block = new StringBuilder();
        boolean inside = false;
        for (String line : compose.lines().toList()) {
            if (line.equals("  " + service + ":")) {
                inside = true;
                continue;
            }
            if (inside && line.matches("^ {0,2}\\S.*") && !line.trim().startsWith("#")) {
                break;
            }
            if (inside) {
                block.append(line).append('\n');
            }
        }
        return block.toString();
    }
}
