package com.zeekad.dashboard.service;

import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * T63 글자 정책: 서버가 내보내는 바깥 글자열(호스트·계정 이름, LLM 보고서 글, 사람이 쓴 메모 등)을 신뢰하지 않는 입력으로 다룬다.
 *
 * <p>숨은 문자 = 제어 문자(Cc. 여러 줄 칸에서는 \n·\t를 뺀다), 서식 문자(Cf), 줄·문단 구분자(Zl·Zp),
 * Default_Ignorable_Code_Point, 짝 없는 서러게이트, 한 글자에 3개를 넘게 이어 붙은 결합 문자(Mn·Me)의 넘는 몫.
 * 여러 줄 칸에서 \r\n은 \n으로 바꾸고(센 수에 넣지 않는다) 홀로 있는 \r은 숨은 문자다.
 *
 * <ul>
 *   <li>분석가·관리자: 숨은 문자를 그 자리에 보이는 표지 {@code [U+202E]}로 바꾼다(이름에 그런 문자가 있다는 것 자체가 단서다).</li>
 *   <li>조회자: 숨은 문자를 지우고 끝에 {@code " [보이지 않는 문자 N개 제거]"}를 붙인다(표지는 없다). 주소 가림 순서는
 *       {@link MaskingService#maskViewerText}가 정한다.</li>
 *   <li>칸 종류별 길이 상한(코드 포인트). 표지를 넣거나 가린 뒤의 값에 적용하고, 표지 한가운데나 서러게이트 쌍을 가르지 않는다.
 *       붙이는 글 {@code "…(N자 생략)"}과 제거 표시는 상한에 넣지 않는다.</li>
 * </ul>
 * 결합 문자를 셀 때 숨은 문자는 건너뛴다(지운 뒤 다시 이어 붙는 결합 문자 연속을 막는다).
 */
public final class UntrustedText {

    /** 칸의 종류. 상한은 코드 포인트, multiline이면 \n·\t를 남긴다. */
    public enum Kind {
        /** 호스트·계정·표시 이름, 감사 로그 행위자 */
        NAME(256, false),
        /** LLM 보고서 글, 오류·사유, 사람이 쓴 글, Slack 페이로드의 글자 잎 */
        TEXT(4000, true),
        /** 위에 없는 모든 글자 값의 기본(근거 값, 키 등) */
        VALUE(1000, false);

        private final int maxCodePoints;
        private final boolean multiline;

        Kind(int maxCodePoints, boolean multiline) {
            this.maxCodePoints = maxCodePoints;
            this.multiline = multiline;
        }

        public int maxCodePoints() {
            return maxCodePoints;
        }

        public boolean multiline() {
            return multiline;
        }
    }

    /** 한 글자에 붙어도 되는 결합 문자 수. 넘는 몫은 숨은 문자다. */
    public static final int MAX_COMBINING_RUN = 3;

    /** 표지 꼴(16진 대문자 4~6자리). 자르기가 표지 한가운데를 가르지 않게 찾을 때도 쓴다. */
    private static final Pattern MARKER = Pattern.compile("\\[U\\+[0-9A-F]{4,6}\\]");
    private static final int MARKER_MAX_LENGTH = "[U+10FFFF]".length();
    // 붙이는 글은 값의 맨 끝(\z)에서만 찾는다. $는 끝 줄바꿈 앞에서도 맞아 여러 줄 값의 마지막 줄바꿈을 잃게 한다
    private static final Pattern TRUNCATION_NOTE = Pattern.compile("…\\((\\d{1,9})자 생략\\)\\z");
    private static final Pattern REMOVAL_NOTE = Pattern.compile(" \\[보이지 않는 문자 (\\d{1,9})개 제거\\]\\z");

    /**
     * Unicode Default_Ignorable_Code_Point. Java 정규식·Character가 이 속성을 모르므로 범위를 옮겨 적었다.
     * 출처: Unicode 15.0.0 DerivedCoreProperties.txt(https://www.unicode.org/Public/15.0.0/ucd/DerivedCoreProperties.txt)의
     * "Default_Ignorable_Code_Point" 줄 전부(2026-11-26 받아 대조). 한글 채움 문자 U+115F·U+1160·U+3164·U+FFA0,
     * 변형 선택자 U+FE00~FE0F·U+E0100~E01EF, U+034F, U+17B4~17B5, U+180B~180F, U+00AD가 여기 든다.
     */
    private static final int[][] DEFAULT_IGNORABLE = {
            {0x00AD, 0x00AD}, {0x034F, 0x034F}, {0x061C, 0x061C}, {0x115F, 0x1160}, {0x17B4, 0x17B5},
            {0x180B, 0x180D}, {0x180E, 0x180E}, {0x180F, 0x180F}, {0x200B, 0x200F}, {0x202A, 0x202E},
            {0x2060, 0x2064}, {0x2065, 0x2065}, {0x2066, 0x206F}, {0x3164, 0x3164}, {0xFE00, 0xFE0F},
            {0xFEFF, 0xFEFF}, {0xFFA0, 0xFFA0}, {0xFFF0, 0xFFF8}, {0x1BCA0, 0x1BCA3}, {0x1D173, 0x1D17A},
            {0xE0000, 0xE0000}, {0xE0001, 0xE0001}, {0xE0002, 0xE001F}, {0xE0020, 0xE007F}, {0xE0080, 0xE00FF},
            {0xE0100, 0xE01EF}, {0xE01F0, 0xE0FFF}
    };

    private UntrustedText() {
    }

    /** 숨은 문자를 지운 결과와 지운 코드 포인트 수 */
    public record Stripped(String text, int removed) {
    }

    /* ───────────────────────── 문자 판정 ───────────────────────── */

    /** 앞뒤 문맥(여러 줄 칸의 \n·\t, 결합 문자 연속)을 보지 않는 숨은 문자 판정 */
    public static boolean isHidden(int cp) {
        if (cp >= Character.MIN_SURROGATE && cp <= Character.MAX_SURROGATE) {
            return true;
        }
        int type = Character.getType(cp);
        if (type == Character.CONTROL || type == Character.FORMAT
                || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR) {
            return true;
        }
        return isDefaultIgnorable(cp);
    }

    static boolean isDefaultIgnorable(int cp) {
        for (int[] range : DEFAULT_IGNORABLE) {
            if (cp < range[0]) {
                return false;
            }
            if (cp <= range[1]) {
                return true;
            }
        }
        return false;
    }

    private static boolean isCombining(int cp) {
        int type = Character.getType(cp);
        return type == Character.NON_SPACING_MARK || type == Character.ENCLOSING_MARK;
    }

    private interface Sink {
        void keep(int cp);

        void hidden(int cp);
    }

    /** 코드 포인트를 앞에서부터 보며 남길 것과 숨은 것을 알린다. 짝 없는 서러게이트는 그 값 하나로 본다. */
    private static void scan(String s, boolean multiline, Sink sink) {
        int run = 0;
        int i = 0;
        int n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            int cp;
            if (Character.isHighSurrogate(c) && i + 1 < n && Character.isLowSurrogate(s.charAt(i + 1))) {
                cp = Character.toCodePoint(c, s.charAt(i + 1));
                i += 2;
            } else {
                cp = c;
                i += 1;
            }
            if (multiline) {
                if (cp == '\r' && i < n && s.charAt(i) == '\n') {
                    continue; // \r\n → \n (다음 \n이 남는다)
                }
                if (cp == '\n' || cp == '\t') {
                    sink.keep(cp);
                    run = 0;
                    continue;
                }
            }
            if (isHidden(cp)) {
                sink.hidden(cp); // 결합 문자 연속을 세는 데에서는 건너뛴다
                continue;
            }
            if (isCombining(cp)) {
                run++;
                if (run > MAX_COMBINING_RUN) {
                    sink.hidden(cp);
                } else {
                    sink.keep(cp);
                }
                continue;
            }
            run = 0;
            sink.keep(cp);
        }
    }

    /* ───────────────────────── 표지·지우기 ───────────────────────── */

    public static String marker(int cp) {
        return String.format(Locale.ROOT, "[U+%04X]", cp);
    }

    /** 분석가·관리자: 숨은 문자를 그 자리에 표지로 바꾼다(자르지 않는다). */
    public static String mark(String s, boolean multiline) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        scan(s, multiline, new Sink() {
            @Override
            public void keep(int cp) {
                sb.appendCodePoint(cp);
            }

            @Override
            public void hidden(int cp) {
                sb.append(marker(cp));
            }
        });
        return sb.toString();
    }

    /** 조회자: 숨은 문자를 지운다(자르지 않는다. 제거 표시를 붙이지 않는다). */
    public static Stripped strip(String s, boolean multiline) {
        if (s == null || s.isEmpty()) {
            return new Stripped(s, 0);
        }
        StringBuilder sb = new StringBuilder(s.length());
        int[] removed = {0};
        scan(s, multiline, new Sink() {
            @Override
            public void keep(int cp) {
                sb.appendCodePoint(cp);
            }

            @Override
            public void hidden(int cp) {
                removed[0]++;
            }
        });
        return new Stripped(sb.toString(), removed[0]);
    }

    /** 숨은 문자가 하나라도 있는가(문맥 판정 포함) */
    public static boolean hasHidden(String s, boolean multiline) {
        return s != null && strip(s, multiline).removed() > 0;
    }

    /* ───────────────────────── 자르기 ───────────────────────── */

    /**
     * 코드 포인트 상한으로 자른다. 표지 한가운데에서 자르게 되면 그 표지 앞으로 물러난다(코드 포인트로 세므로 서러게이트 쌍은 갈리지 않는다).
     * 붙이는 글은 {@code "…(N자 생략)"}이고 N은 버린 코드 포인트 수다. 이미 자른 값(본문이 상한 안이고 끝이 생략 표시)은 그대로 둔다.
     */
    public static String truncate(String s, int maxCodePoints) {
        if (s == null) {
            return null;
        }
        int total = s.codePointCount(0, s.length());
        if (total <= maxCodePoints) {
            return s;
        }
        Matcher done = TRUNCATION_NOTE.matcher(s);
        if (done.find()) {
            String body = s.substring(0, done.start());
            if (body.codePointCount(0, body.length()) <= maxCodePoints) {
                return s;
            }
        }
        int cut = s.offsetByCodePoints(0, maxCodePoints);
        int from = Math.max(0, cut - (MARKER_MAX_LENGTH - 1));
        Matcher m = MARKER.matcher(s);
        m.region(from, Math.min(s.length(), cut + MARKER_MAX_LENGTH));
        while (m.find()) {
            if (m.start() < cut && m.end() > cut) {
                cut = m.start();
                break;
            }
        }
        String kept = s.substring(0, cut);
        int dropped = total - kept.codePointCount(0, kept.length());
        return kept + "…(" + dropped + "자 생략)";
    }

    /* ───────────────────────── 역할별 최종 처리 ───────────────────────── */

    /** 분석가·관리자 응답 값: 표지 → 상한 */
    public static String forAnalyst(String s, Kind kind) {
        if (s == null) {
            return null;
        }
        return truncate(mark(s, kind.multiline()), kind.maxCodePoints());
    }

    /**
     * 조회자 응답 값: 가림 단계가 붙인 제거 표시를 떼고, 남은 숨은 문자를 지우고(가림 단계를 거치지 않은 칸), 상한으로 자른 뒤
     * 제거 표시를 다시 붙인다(N은 합). 가림 단계에서 처리한 값에 다시 적용해도 바뀌지 않는다.
     */
    public static String forViewer(String s, Kind kind) {
        if (s == null) {
            return null;
        }
        long already = 0;
        String body = s;
        Matcher note = REMOVAL_NOTE.matcher(s);
        if (note.find()) {
            already = Long.parseLong(note.group(1));
            body = s.substring(0, note.start());
        }
        Stripped stripped = strip(body, kind.multiline());
        String out = truncate(stripped.text(), kind.maxCodePoints());
        long removed = already + stripped.removed();
        return removed > 0 ? out + removalNote(removed) : out;
    }

    public static String removalNote(long count) {
        return " [보이지 않는 문자 " + count + "개 제거]";
    }

    /** 끝의 제거 표시를 뗀 값(조회자 검색의 비교 대상) */
    public static String withoutRemovalNote(String s) {
        if (s == null) {
            return null;
        }
        Matcher note = REMOVAL_NOTE.matcher(s);
        return note.find() ? s.substring(0, note.start()) : s;
    }

    /* ───────────────────────── 검색·로그·저장 ───────────────────────── */

    /**
     * 검색어와 비교 대상에 같이 쓰는 정규화: 숨은 문자 제거(한 줄 기준) → NFKC → 소문자(Locale.ROOT).
     * NFKC가 호환 문자를 풀며 숨은 문자를 만들 수 있어 한 번 더 지운다. 혼동 문자(키릴 а 등)는 맞추지 않는다.
     */
    public static String normalizeForSearch(String s) {
        if (s == null) {
            return null;
        }
        String once = strip(s, false).text();
        String nfkc = Normalizer.normalize(once, Normalizer.Form.NFKC);
        return strip(nfkc, false).text().toLowerCase(Locale.ROOT);
    }

    /** 서버 로그에 바깥 글자열을 찍을 때: 표지 + 값 상한(줄바꿈도 표지라 로그 줄을 만들지 못한다) */
    public static String forLog(String s) {
        return s == null ? null : forAnalyst(s, Kind.VALUE);
    }

    /**
     * 저장 열 자르기(감사 로그): UTF-16 단위 상한 이하이고 서러게이트 쌍을 가르지 않는다(걸치면 그 쌍을 통째로 버린다).
     * H2는 VARCHAR 길이를 UTF-16 단위로, PostgreSQL은 문자로 세므로 두 DB 모두 들어간다. 값의 뜻(숨은 문자)은 바꾸지 않는다.
     */
    public static String truncateUtf16(String s, int maxUnits) {
        if (s == null || s.length() <= maxUnits) {
            return s;
        }
        int cut = maxUnits;
        if (cut > 0 && Character.isHighSurrogate(s.charAt(cut - 1)) && Character.isLowSurrogate(s.charAt(cut))) {
            cut--;
        }
        return s.substring(0, cut);
    }
}
