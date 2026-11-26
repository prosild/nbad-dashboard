package com.zeekad.dashboard;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T53 다시 열기의 정적 검사: 쓰기 매퍼의 재개 문장 두 판, 공개 스택 initdb의 셋째 스크립트와 zeek_AD migration 018 사본
 * (하위 폴더, 바이트 그대로, sha256이 SOURCE.md와 같음, LF), .gitattributes, 쓰기 속도 제한의 reopen 경로,
 * 초기화 설정 SQL에 dashboard_rw가 여전히 없음.
 */
class T53ReopenStaticTest {

    static final Path INITDB = Path.of("docker/portfolio/initdb");
    static final Path COPY = INITDB.resolve("zeekad-sql/018_incident_reopen.sql");
    static final Path SOURCE = INITDB.resolve("zeekad-sql/SOURCE.md");
    static final Path THIRD = INITDB.resolve("03-zeekad-functions.sh");

    @Test
    void writeMapperHasReopenStatementForBothDatabasesWithoutDollarSubstitution() throws IOException {
        String xml = Files.readString(Path.of("src/main/resources/mapper/zeekad/write/ZeekadWriteMapper.xml"), StandardCharsets.UTF_8);
        String java = Files.readString(
                Path.of("src/main/java/com/zeekad/dashboard/mapper/zeekad/write/ZeekadWriteMapper.java"), StandardCharsets.UTF_8);
        assertThat(xml).doesNotContain("${");
        assertThat(java).doesNotContain("${").contains("String reopenIncident(");

        String pg = statement(xml, "reopenIncident", "postgresql");
        // 이름 인자: 함수 서명 (p_job, p_incident, p_actor, p_reason, p_expected_resolution)과 같아야 한다(틀리면 42883 → 501)
        assertThat(pg).contains("SELECT dashboard.reopen_incident(",
                "p_job => #{jobId,jdbcType=BIGINT}",
                "p_incident => #{incidentId,jdbcType=VARCHAR}",
                "p_actor => #{loginUser,jdbcType=VARCHAR}",
                "p_reason => #{reason,jdbcType=VARCHAR}",
                "p_expected_resolution => #{expectedResolution,jdbcType=VARCHAR}");
        String h2 = statement(xml, "reopenIncident", "h2");
        assertThat(h2).contains("SELECT dashboard.reopen_incident(").doesNotContain("=>");
        assertThat(h2.indexOf("#{jobId")).isLessThan(h2.indexOf("#{incidentId"));
        assertThat(h2.indexOf("#{incidentId")).isLessThan(h2.indexOf("#{loginUser"));
        assertThat(h2.indexOf("#{loginUser")).isLessThan(h2.indexOf("#{reason"));
        assertThat(h2.indexOf("#{reason")).isLessThan(h2.indexOf("#{expectedResolution"));
        // 기존 전이 문장은 그대로다
        assertThat(statement(xml, "transitionIncident", "postgresql")).contains("SELECT dashboard.transition_incident(");

        String schema = Files.readString(Path.of("src/test/resources/testdb/zeekad-read-schema.sql"), StandardCharsets.UTF_8);
        assertThat(schema).contains("CREATE ALIAS IF NOT EXISTS dashboard.reopen_incident FOR "
                + "\"com.zeekad.dashboard.testsupport.H2ZeekadTransitionFunctions.reopenIncident\";");
    }

    @Test
    void initdbRunsCopiedMigrationFromSubfolderThroughThirdScript() throws IOException {
        // 맨 위의 *.sql은 공식 이미지가 postgres DB에 자동 실행한다. 사본은 하위 폴더에만 둔다.
        try (Stream<Path> top = Files.list(INITDB)) {
            List<String> names = top.filter(Files::isRegularFile).map(p -> p.getFileName().toString()).sorted().toList();
            assertThat(names).noneMatch(n -> n.toLowerCase(Locale.ROOT).endsWith(".sql")
                    || n.toLowerCase(Locale.ROOT).endsWith(".sql.gz") || n.toLowerCase(Locale.ROOT).endsWith(".sql.xz"));
            // T57(설계자 결정 2026-11-27): 넷째 스크립트(계약 뷰를 빠르게 하는 인덱스)를 더했다. 검사는 T57InitdbIndexStaticTest
            assertThat(names).containsExactly("01-roles-databases.sh", "02-restore-snapshot.sh", "03-zeekad-functions.sh", "04-zeekad-indexes.sh");
        }
        assertThat(COPY).exists();
        assertThat(SOURCE).exists();

        String script = Files.readString(THIRD, StandardCharsets.UTF_8);
        assertThat(script).startsWith("#!/bin/bash\n").doesNotContain("\r");
        assertThat(script).contains("set -euo pipefail",
                "--dbname zeekad",
                "-v ON_ERROR_STOP=1",
                "/docker-entrypoint-initdb.d/zeekad-sql/018_incident_reopen.sql",
                "n.nspname = 'dashboard' AND p.proname = 'reopen_incident'",
                "$PGDATA/portfolio-restore.ok",
                "rm -f");
        // 사본을 실행하는 줄은 zeekad DB에 -f로
        assertThat(script).containsPattern("psql [^\\n]*--dbname zeekad[^\\n]*-f \"\\$ZEEKAD_REOPEN_SQL\"");
        // 실행 권한 없이 source로 읽혀도 entrypoint를 끝내지 않게 exit 0을 쓰지 않는다
        assertThat(script).doesNotContainPattern("(?m)^\\s*exit 0\\b").doesNotContain("trap ");
        // 함수 이름만 보고 건너뛴다(서명까지 보지 않는다). compose의 상태 확인과 둘째 스크립트는 그대로다.
        String compose = Files.readString(Path.of("compose.portfolio.yml"), StandardCharsets.UTF_8);
        assertThat(compose).contains("test -s \\\"$$PGDATA/portfolio-restore.ok\\\"", "./docker/portfolio/initdb:/docker-entrypoint-initdb.d:ro");
    }

    @Test
    void migrationCopyMatchesRecordedSha256AndContract() throws IOException, NoSuchAlgorithmException {
        byte[] bytes = Files.readAllBytes(COPY);
        String text = new String(bytes, StandardCharsets.UTF_8);
        assertThat(text).doesNotContain("\r");
        String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));

        String source = Files.readString(SOURCE, StandardCharsets.UTF_8);
        Matcher m = Pattern.compile("(?m)^018_incident_reopen\\.sql sha256: `([0-9a-f]{64})`\\r?$").matcher(source);
        assertThat(m.find()).as("SOURCE.md에 sha256이 있어야 한다").isTrue();
        assertThat(sha).isEqualTo(m.group(1));
        assertThat(source).contains("db/migrations/018_incident_reopen.sql", "zeek_AD");
        assertThat(source).containsPattern("(?m)^018_incident_reopen\\.sql zeek_AD commit: `[0-9a-f]{40}`\\r?$");

        // 계약: 함수 정의, 소유자, PUBLIC 회수, 대시보드 쓰기 계정에만 실행 권한. 머리말을 붙이지 않았다(첫 줄이 원본과 같다).
        assertThat(text).startsWith("-- 018. 종료한 사건을 다시 여는 함수 dashboard.reopen_incident");
        assertThat(text).contains("CREATE OR REPLACE FUNCTION dashboard.reopen_incident(",
                "p_expected_resolution text DEFAULT NULL",
                "ALTER FUNCTION dashboard.reopen_incident(bigint, text, text, text, text) OWNER TO zeekad_owner;",
                "REVOKE ALL ON FUNCTION dashboard.reopen_incident(bigint, text, text, text, text) FROM PUBLIC;",
                "GRANT EXECUTE ON FUNCTION dashboard.reopen_incident(bigint, text, text, text, text) TO dashboard_rw;");
        assertThat(text).doesNotContain("transition_incident(p_");
    }

    @Test
    void gitattributesKeepsCopyLfAndSandboxSetupStillHasNoDashboardRw() throws IOException {
        List<String> lines = Files.readAllLines(Path.of(".gitattributes"), StandardCharsets.UTF_8);
        assertThat(lines).contains("*.sh text eol=lf", "docker/portfolio/initdb/zeekad-sql/*.sql text eol=lf");

        String setupSql = Files.readString(Path.of("docker/portfolio/sandbox/sandbox-setup.sh"), StandardCharsets.UTF_8);
        assertThat(setupSql.toLowerCase(Locale.ROOT)).doesNotContain("dashboard_rw");
        String reset = Files.readString(Path.of("docker/portfolio/sandbox/sandbox-reset.sh"), StandardCharsets.UTF_8);
        assertThat(reset).doesNotContain("reopen_incident");
    }

    @Test
    void writeRateLimitCoversReopenPath() throws IOException {
        String template = Files.readString(
                Path.of("docker/portfolio/nginx/zeekad-portfolio-http.conf.template"), StandardCharsets.UTF_8);
        List<String> lines = template.lines().map(String::trim)
                .filter(line -> line.startsWith("\"~^POST:") && line.endsWith("$binary_remote_addr;"))
                .toList();
        assertThat(lines).hasSize(2);
        assertThat(lines.get(0)).contains("(transition|assignment|review-decision|response-actions|reopen)");
        List<Pattern> keys = lines.stream()
                .map(line -> Pattern.compile(line.substring(2, line.indexOf("\" $binary_remote_addr;"))))
                .toList();
        java.util.function.Predicate<String> limited = key -> keys.stream().anyMatch(p -> p.matcher(key).find());
        assertThat(limited.test("POST:/api/incidents/42/rank/1/reopen")).isTrue();
        assertThat(limited.test("POST:/api/incidents/42/rank/1/reopen/")).isTrue();
        assertThat(limited.test("GET:/api/incidents/42/rank/1/reopen")).isFalse();
        assertThat(limited.test("POST:/api/incidents/42/rank/1/reopen/x")).isFalse();
        assertThat(limited.test("POST:/api/incidents/42/rank/1/reopened")).isFalse();
    }

    /** databaseId가 붙은 select 문장 하나의 본문 */
    private static String statement(String xml, String id, String databaseId) {
        Matcher m = Pattern.compile("<select id=\"" + id + "\" resultType=\"string\" databaseId=\"" + databaseId + "\">(.*?)</select>",
                Pattern.DOTALL).matcher(xml);
        assertThat(m.find()).as("%s(%s) 문장이 있어야 한다", id, databaseId).isTrue();
        String body = m.group(1);
        assertThat(m.find()).as("%s(%s) 문장은 하나다", id, databaseId).isFalse();
        return body;
    }
}
