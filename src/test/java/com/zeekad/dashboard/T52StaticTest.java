package com.zeekad.dashboard;

import com.zeekad.dashboard.model.AuditActionType;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T52 정적 확인: migration 두 판, 감사 유형과 화면 사전, DELETE 메서드 없음, 읽기 매퍼의 우선순위 식 한 곳과 자산 배열 바인드 한 곳,
 * criteria를 만드는 곳(정해진 메서드 안에서만 만들고 모두 자산 배열을 채운다), 화면 경로.
 */
class T52StaticTest {

    private static String read(String path) throws IOException {
        return Files.readString(Path.of(path), StandardCharsets.UTF_8).replace("\r", "");
    }

    @Test
    void migrationsCreateCriticalAssetsInBothDialects() throws IOException {
        for (String dialect : List.of("postgresql", "h2")) {
            String sql = read("src/main/resources/db/migration/" + dialect + "/V6__critical_assets.sql");
            String flat = sql.replaceAll("[ \\t]+", " ");
            assertThat(flat).as(dialect).contains("CREATE TABLE critical_assets (");
            assertThat(flat).as(dialect).containsPattern("host_ip VARCHAR\\(\\d+\\) NOT NULL UNIQUE");
            assertThat(flat).as(dialect).containsPattern("name VARCHAR\\(\\d+\\) NOT NULL");
            assertThat(flat).as(dialect).containsPattern("description VARCHAR\\(\\d+\\)");
            assertThat(flat).as(dialect).contains("created_by", "created_at", "updated_by", "updated_at");
        }
        // 마지막 판이 V6이다(다른 작업과 번호가 겹치지 않는다)
        for (String dialect : List.of("postgresql", "h2")) {
            try (Stream<Path> files = Files.list(Path.of("src/main/resources/db/migration/" + dialect))) {
                assertThat(files.map(p -> p.getFileName().toString()).filter(n -> n.startsWith("V6__")).toList())
                        .as(dialect).containsExactly("V6__critical_assets.sql");
            }
        }
    }

    @Test
    void auditTypeAndScreenLabelExist() throws IOException {
        assertThat(AuditActionType.valueOf("CRITICAL_ASSET_CHANGE")).isNotNull();
        String labels = read("frontend/src/utils/labels.ts");
        String auditDict = labels.substring(labels.indexOf("  auditAction: {"));
        auditDict = auditDict.substring(0, auditDict.indexOf("\n  },"));
        assertThat(auditDict).contains("\n    CRITICAL_ASSET_CHANGE: '중요 자산 변경',");
    }

    @Test
    void noControllerUsesDeleteMappingAndAssetDeleteIsAPost() throws IOException {
        List<Path> controllers;
        try (Stream<Path> files = Files.walk(Path.of("src/main/java/com/zeekad/dashboard"))) {
            controllers = files.filter(p -> p.toString().endsWith(".java")).toList();
        }
        assertThat(controllers).isNotEmpty();
        for (Path file : controllers) {
            String text = Files.readString(file, StandardCharsets.UTF_8);
            assertThat(text).as("%s", file).doesNotContain("@DeleteMapping", "RequestMethod.DELETE", "HttpMethod.DELETE");
        }
        String admin = read("src/main/java/com/zeekad/dashboard/controller/AdminApiController.java");
        assertThat(admin).contains("@PostMapping(\"/critical-assets/{id}/delete\")");
        // 앱이 쓰는 메서드는 WAF 허용 목록 안이다(compose 두 벌 모두 DELETE·PATCH 없음)
        for (String compose : List.of("compose.yml", "compose.portfolio.yml")) {
            Matcher m = Pattern.compile("(?m)^\\s*ALLOWED_METHODS:\\s*\"([^\"]*)\"").matcher(read(compose));
            assertThat(m.find()).as(compose).isTrue();
            assertThat(List.of(m.group(1).trim().split("\\s+"))).as(compose)
                    .contains("GET", "POST", "PUT").doesNotContain("DELETE", "PATCH");
        }
        // 화면의 API 묶음도 DELETE를 쓰지 않는다
        assertThat(read("frontend/src/api/endpoints.ts")).doesNotContain("'DELETE'");
    }

    /** CASE … END 쌍(중첩 포함)의 본문. 낱말 경계로 센다 */
    static List<String> caseBlocks(String sql) {
        Matcher m = Pattern.compile("\\b(CASE|END)\\b").matcher(sql);
        Deque<Integer> open = new ArrayDeque<>();
        List<String> blocks = new ArrayList<>();
        while (m.find()) {
            if ("CASE".equals(m.group(1))) {
                open.push(m.start());
            } else if (!open.isEmpty()) {
                blocks.add(sql.substring(open.pop(), m.end()));
            }
        }
        return blocks;
    }

    @Test
    void readMappersHaveOneBasePriorityCaseAndOneGuardedCriticalArrayBind() throws IOException {
        String zeekad = read("src/main/resources/mapper/zeekad/read/ZeekadReadMapper.xml");
        String host = read("src/main/resources/mapper/zeekad/read/HostReadMapper.xml");
        String all = zeekad + "\n" + host;
        // XML 주석은 세지 않는다
        String code = all.replaceAll("(?s)<!--.*?-->", "");

        // 기본 규칙 CASE(zeekad_would_send가 든 CASE 가운데 안에 그런 CASE를 품지 않은 것)는 하나다
        List<String> withRule = caseBlocks(code).stream().filter(b -> b.contains("zeekad_would_send")).toList();
        List<String> innermost = withRule.stream()
                .filter(b -> withRule.stream().noneMatch(o -> o != b && b.contains(o)))
                .toList();
        assertThat(innermost).as("기본 규칙 CASE").hasSize(1);
        assertThat(innermost.get(0)).contains("THEN 'high'", "THEN 'medium'", "ELSE 'low'");
        assertThat(code).contains("END AS priority_base");

        // 중요 자산 배열 바인드는 하나이고 <if test="c.hasCriticalHostIps"> 안에 있다
        Matcher bind = Pattern.compile("#\\{c\\.criticalHostIps\\b").matcher(code);
        int binds = 0;
        while (bind.find()) {
            binds++;
            String before = code.substring(0, bind.start());
            int ifOpen = before.lastIndexOf("<if test=\"c.hasCriticalHostIps\">");
            assertThat(ifOpen).as("바인드를 감싼 if").isGreaterThanOrEqualTo(0);
            assertThat(before.substring(ifOpen)).as("if와 바인드 사이에 닫는 태그가 없다").doesNotContain("</if>");
        }
        assertThat(binds).as("중요 자산 배열 바인드 수").isEqualTo(1);
        assertThat(code).doesNotContain("criticalHostIps}");
        // 정렬: 우선순위 키 바로 다음이 중요 자산 키다(두 방향)
        assertThat(code).contains("b.priority_order ASC NULLS LAST, b.asset_critical DESC,");
        assertThat(code).contains("b.priority_order DESC NULLS LAST, b.asset_critical ASC,");
        // 기반 표지는 그대로 하나다
        assertThat(code.split(Pattern.quote("/* unifiedQueueBase */"), -1)).hasSize(2);
    }

    private static String blank(String text, String regex) {
        return Pattern.compile(regex).matcher(text).replaceAll(m -> " ".repeat(m.group().length()));
    }

    /** 자바 소스에서 위치 at을 품은 메서드 이름(중괄호 깊이로 찾는다). 클래스 몸 바로 안의 메서드만 본다 */
    static String enclosingMethod(String src, int at) {
        // 주석·글자 상수를 같은 길이의 공백으로 바꿔 위치를 지킨 채 중괄호만 센다
        String stripped = blank(src, "(?s)/\\*.*?\\*/");
        stripped = blank(stripped, "//[^\\n]*");
        stripped = blank(stripped, "\"(?:\\\\.|[^\"\\\\\\n])*\"");
        stripped = blank(stripped, "'(?:\\\\.|[^'\\\\])'");
        int depth = 0;
        int methodStart = -1;
        String method = null;
        for (int i = 0; i < stripped.length(); i++) {
            char ch = stripped.charAt(i);
            if (ch == '{') {
                depth++;
                if (depth == 2) {
                    methodStart = i;
                    String head = stripped.substring(Math.max(0, i - 400), i);
                    Matcher name = Pattern.compile("(\\w+)\\s*\\([^()]*(?:\\([^()]*\\)[^()]*)*\\)\\s*(?:throws [\\w.,\\s]+)?\\s*$").matcher(head);
                    method = name.find() ? name.group(1) : "?";
                }
            } else if (ch == '}') {
                if (depth == 2 && methodStart >= 0 && at > methodStart && at < i) {
                    return method;
                }
                depth--;
            }
        }
        return null;
    }

    @Test
    void criteriaAreCreatedOnlyInKnownMethodsAndEachFillsTheCriticalArray() throws IOException {
        Set<String> found = new TreeSet<>();
        try (Stream<Path> files = Files.walk(Path.of("src/main/java"))) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String src = Files.readString(file, StandardCharsets.UTF_8).replace("\r", "");
                Matcher m = Pattern.compile("new\\s+UnifiedQueueCriteria\\s*\\(").matcher(src);
                while (m.find()) {
                    String cls = file.getFileName().toString().replace(".java", "");
                    String method = enclosingMethod(src, m.start());
                    found.add(cls + "." + method);
                    if (!"UnifiedQueueCriteria".equals(cls)) {
                        // 만든 메서드 안에서 중요 자산 배열을 채운다
                        int end = src.indexOf("\n    }\n", m.start());
                        assertThat(src.substring(m.start(), end)).as("%s.%s", cls, method).contains("setCriticalHostIps(");
                    }
                }
            }
        }
        // copy()는 만든 것을 그대로 옮긴다(배열 포함)
        assertThat(found).containsExactlyInAnyOrder(
                "IncidentQueueService.findLatestRow",
                "IncidentQueueService.resolveScope",
                "RelatedHostIncidentService.load",
                "UnifiedQueueCriteria.copy");
        String criteria = read("src/main/java/com/zeekad/dashboard/model/zeekad/UnifiedQueueCriteria.java");
        assertThat(criteria).contains("c.criticalHostIps = criticalHostIps;");
    }

    @Test
    void screenRouteIsRegisteredForAdminsOnly() throws IOException {
        assertThat(read("src/main/java/com/zeekad/dashboard/controller/SpaForwardController.java"))
                .contains("\"/admin/critical-assets\"");
        String security = read("src/main/java/com/zeekad/dashboard/config/SecurityConfig.java");
        Matcher adminGet = Pattern.compile("requestMatchers\\(HttpMethod\\.GET,([^)]*)\\)\\s*\\.hasRole\\(\"ADMIN\"\\)")
                .matcher(security);
        assertThat(adminGet.find()).isTrue();
        assertThat(adminGet.group(1)).contains("\"/admin/critical-assets\"");
        String app = read("frontend/src/App.tsx");
        assertThat(app).contains("path=\"/admin/critical-assets\"");
        String shell = read("frontend/src/components/AppShell.tsx");
        assertThat(shell).containsPattern("\\{ to: '/admin/critical-assets', label: '중요 자산',[^}]*adminOnly: true \\}");
    }
}
