package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T68 정적 시험(설계자 답 L1): 서버 소스(src/main/java)의 문자열 리터럴(텍스트 블록 포함, 주석 제외)에 화면에서 없앤 옛 말이 없다.
 * 막는 낱말은 화면 시험과 같은 닫힌 목록 파일(frontend/src/test/fixtures/screen-terms.json의 oldTerms + t68Terms)이다.
 * 서버가 화면에 돌려주는 글(예외·안내 문장)과 로그 글을 함께 본다. 허용 목록은 파일 + 정확한 글 + 까닭이고 지금은 비어 있다.
 */
class T68ScreenWordingStaticTest {

    private static final Path TERMS = Path.of("frontend", "src", "test", "fixtures", "screen-terms.json");
    private static final Path MAIN = Path.of("src", "main", "java");

    /** 허용 목록(파일은 src/main/java 기준 상대 경로, 글은 리터럴 전체). 항목마다 지금도 그 파일에 있는지 단언한다 */
    private record Allowed(String file, String text, String reason) {
    }

    private static final List<Allowed> ALLOWED = List.of();

    private record Literal(int line, String text) {
    }

    @Test
    void bannedTermsAreTheSharedClosedList() throws IOException {
        Set<String> banned = bannedTerms();
        assertThat(banned).contains("틀 문장", "거르기", "채점", "조사 중", "조사 시작", "조사를 시작", "자산 검색", "부푼",
                "기준 시각 기준", "쪽당", "함께 탐지한 모델", "이상 판정 구간", "첫 알림", "이동 목록", "사전에 없는", "증적", "탐지 사건", "작업 #");
        assertThat(banned).hasSize(44 + 16 - 4); // oldTerms 44개 + T68 16개(추가 결정 "증적" 포함), 겹치는 4개(조사 중·함께 탐지한 모델·이상 판정 구간·첫 알림)
    }

    @Test
    void positiveControlsCatchLiteralsAndTextBlocksButNotComments() {
        String sample = String.join("\n",
                "// 거르기는 한 줄 주석이라 괜찮다",
                "/* 채점은 덩어리 주석이라 괜찮다 */",
                "/** 쪽당은 Javadoc이라 괜찮다 */",
                "class X {",
                "  String a = \"전환 거르기 값이 올바르지 않습니다.\";",
                "  String b = \"\"\"",
                "      자산 검색어는 100자를",
                "      \"\"\";",
                "  char c = '\"'; String d = \"따옴표 \\\" 뒤의 조사 시작\";",
                "}");
        List<String> hits = findBanned("Sample.java", sample, Set.of("거르기", "채점", "쪽당", "자산 검색", "조사 시작"));
        assertThat(hits).anyMatch(h -> h.startsWith("Sample.java:5 \"거르기\""));
        assertThat(hits).anyMatch(h -> h.startsWith("Sample.java:6 \"자산 검색\""));
        assertThat(hits).anyMatch(h -> h.startsWith("Sample.java:9 \"조사 시작\""));
        assertThat(hits).noneMatch(h -> h.contains("채점") || h.contains("쪽당"));
        assertThat(hits).hasSize(3);
    }

    @Test
    void serverSourceStringLiteralsHaveNoBannedTerms() throws IOException {
        Set<String> banned = bannedTerms();
        List<String> hits = new ArrayList<>();
        List<Path> files;
        try (Stream<Path> walk = Files.walk(MAIN)) {
            files = walk.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }
        assertThat(files).hasSizeGreaterThan(100);
        for (Path f : files) {
            String rel = MAIN.relativize(f).toString().replace('\\', '/');
            hits.addAll(findBanned(rel, Files.readString(f, StandardCharsets.UTF_8), banned));
        }
        assertThat(hits).as(String.join("\n", hits)).isEmpty();
        for (Allowed a : ALLOWED) {
            String src = Files.readString(MAIN.resolve(a.file()), StandardCharsets.UTF_8);
            assertThat(literals(src).stream().map(Literal::text)).as("%s 허용 글(%s)", a.file(), a.reason()).contains(a.text());
        }
    }

    private static Set<String> bannedTerms() throws IOException {
        JsonNode root = new ObjectMapper().readTree(Files.readString(TERMS, StandardCharsets.UTF_8));
        Set<String> out = new LinkedHashSet<>();
        for (JsonNode group : root.get("oldTerms")) {
            group.get("terms").forEach(t -> out.add(t.asText()));
        }
        root.get("t68Terms").get("terms").forEach(t -> out.add(t.asText()));
        return out;
    }

    private static List<String> findBanned(String file, String source, Set<String> banned) {
        List<String> hits = new ArrayList<>();
        for (Literal lit : literals(source)) {
            boolean allowed = ALLOWED.stream().anyMatch(a -> a.file().equals(file) && a.text().equals(lit.text()));
            if (allowed) {
                continue;
            }
            String flat = lit.text().replaceAll("\\s+", " ");
            for (String term : banned) {
                if (flat.contains(term)) {
                    hits.add(file + ":" + lit.line() + " \"" + term + "\" ← " + flat.substring(0, Math.min(80, flat.length())));
                }
            }
        }
        return hits;
    }

    /** 자바 소스의 문자열 리터럴과 텍스트 블록. 주석(한 줄·덩어리·Javadoc)과 문자 리터럴은 건너뛴다. 이스케이프는 풀지 않는다. */
    private static List<Literal> literals(String src) {
        List<Literal> out = new ArrayList<>();
        int i = 0;
        int line = 1;
        int n = src.length();
        while (i < n) {
            char c = src.charAt(i);
            if (c == '\n') {
                line++;
                i++;
            } else if (src.startsWith("//", i)) {
                int j = src.indexOf('\n', i);
                i = j < 0 ? n : j;
            } else if (src.startsWith("/*", i)) {
                int j = src.indexOf("*/", i + 2);
                int end = j < 0 ? n : j + 2;
                line += count(src, i, end);
                i = end;
            } else if (src.startsWith("\"\"\"", i)) {
                int j = i + 3;
                while (j < n && !src.startsWith("\"\"\"", j)) {
                    j += src.charAt(j) == '\\' ? 2 : 1;
                }
                out.add(new Literal(line, src.substring(i + 3, Math.min(j, n))));
                line += count(src, i, Math.min(j, n));
                i = j + 3;
            } else if (c == '"' || c == '\'') {
                int j = i + 1;
                while (j < n && src.charAt(j) != c && src.charAt(j) != '\n') {
                    j += src.charAt(j) == '\\' ? 2 : 1;
                }
                if (c == '"') {
                    out.add(new Literal(line, src.substring(i + 1, Math.min(j, n))));
                }
                i = j + 1;
            } else {
                i++;
            }
        }
        return out;
    }

    private static int count(String s, int from, int to) {
        int k = 0;
        for (int i = from; i < to; i++) {
            if (s.charAt(i) == '\n') {
                k++;
            }
        }
        return k;
    }
}
