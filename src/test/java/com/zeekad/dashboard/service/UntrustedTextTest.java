package com.zeekad.dashboard.service;

import com.zeekad.dashboard.service.UntrustedText.Kind;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** T63 글자 정책 단위 시험(숨은 문자 집합, 표지, 지우기, 자르기, 검색 정규화, 저장 열 자르기) */
class UntrustedTextTest {

    @Test
    void hiddenCharacterSetCoversControlsFormatsSeparatorsIgnorablesAndLoneSurrogates() {
        for (int cp : List.of(0x00, 0x1B, 0x7F, 0x85, 0x200B, 0x200D, 0x202E, 0x2066, 0xFEFF, 0x2028, 0x2029, 0x00AD,
                0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0xFE0F, 0x17B4, 0x180B, 0x180E, 0xE0001, 0xE0100, 0xD800, 0xDC00)) {
            assertThat(UntrustedText.isHidden(cp)).as("U+%04X", cp).isTrue();
        }
        for (int cp : List.of((int) 'a', (int) '가', 0x0301, 0x3000, 0x00A0, 0x1F600, (int) '[', 0xFFFD)) {
            assertThat(UntrustedText.isHidden(cp)).as("U+%04X", cp).isFalse();
        }
    }

    @Test
    void analystSeesMarkersInPlaceAndTextFieldsKeepNewlinesAndTabs() {
        assertThat(UntrustedText.mark("a\u202eb\u200bc", false)).isEqualTo("a[U+202E]b[U+200B]c");
        assertThat(UntrustedText.mark("x😀\udb40\udc01y", false)).isEqualTo("x😀[U+E0001]y");
        assertThat(UntrustedText.mark("lone\ud800", false)).isEqualTo("lone[U+D800]");
        // 한 줄 칸: \n·\t·\r도 표지
        assertThat(UntrustedText.mark("a\nb\tc\r", false)).isEqualTo("a[U+000A]b[U+0009]c[U+000D]");
        // 여러 줄 칸: \r\n → \n, \n·\t는 남기고 홀로 있는 \r은 표지
        assertThat(UntrustedText.mark("a\r\nb\tc\rd", true)).isEqualTo("a\nb\tc[U+000D]d");
    }

    @Test
    void combiningMarksBeyondThreePerCharacterAreHiddenAndHiddenCharactersDoNotResetTheRun() {
        String zalgo = "ź̂̃̄̅";
        assertThat(UntrustedText.mark(zalgo, false)).isEqualTo("ź̂̃[U+0304][U+0305]");
        assertThat(UntrustedText.strip(zalgo, false)).isEqualTo(new UntrustedText.Stripped("ź̂̃", 2));
        // 숨은 문자를 끼워 연속을 끊어도(지운 뒤 다시 이어진다) 넘는 몫은 숨은 문자다
        UntrustedText.Stripped split = UntrustedText.strip("ź̂\u200b̃̄", false);
        assertThat(split).isEqualTo(new UntrustedText.Stripped("ź̂̃", 2));
        // 한글 결합(자모)은 결합 문자가 아니다
        assertThat(UntrustedText.strip("한글́", false).removed()).isZero();
    }

    @Test
    void viewerStripsCountsAndAppendsTheRemovalNoteOutsideTheCap() {
        assertThat(UntrustedText.forViewer("ab\u202ec", Kind.NAME)).isEqualTo("abc [보이지 않는 문자 1개 제거]");
        assertThat(UntrustedText.forViewer("plain", Kind.NAME)).isEqualTo("plain");
        // 가림 단계가 붙인 제거 표시는 떼고 다시 붙인다(N은 합). 다시 적용해도 같다
        String once = UntrustedText.forViewer("x" + " [보이지 않는 문자 2개 제거]", Kind.VALUE);
        assertThat(once).isEqualTo("x [보이지 않는 문자 2개 제거]");
        assertThat(UntrustedText.forViewer("y\u200b [보이지 않는 문자 2개 제거]", Kind.VALUE))
                .isEqualTo("y [보이지 않는 문자 3개 제거]");
        String longName = "A".repeat(300) + "\u200b";
        String viewer = UntrustedText.forViewer(longName, Kind.NAME);
        assertThat(viewer).isEqualTo("A".repeat(256) + "…(44자 생략) [보이지 않는 문자 1개 제거]");
        assertThat(UntrustedText.forViewer(viewer, Kind.NAME)).isEqualTo(viewer);
        assertThat(viewer).doesNotContain("[U+");
    }

    @Test
    void truncationCountsCodePointsNeverSplitsMarkersOrPairsAndIsIdempotent() {
        assertThat(UntrustedText.truncate("abcdef", 4)).isEqualTo("abcd…(2자 생략)");
        assertThat(UntrustedText.truncate("abcd", 4)).isEqualTo("abcd");
        // 서러게이트 쌍은 코드 포인트 하나로 센다
        String emoji = "😀".repeat(5);
        assertThat(UntrustedText.truncate(emoji, 3)).isEqualTo("😀".repeat(3) + "…(2자 생략)");
        // 표지 한가운데에서 자르게 되면 표지 앞으로 물러난다(N은 처리한 값에서 버린 코드 포인트 수)
        String marked = "ab[U+202E]cd"; // 12 코드 포인트
        assertThat(UntrustedText.truncate(marked, 5)).isEqualTo("ab…(10자 생략)");
        assertThat(UntrustedText.truncate(marked, 10)).isEqualTo("ab[U+202E]…(2자 생략)");
        // 이미 자른 값은 그대로
        String cut = UntrustedText.forAnalyst("Z".repeat(5000), Kind.TEXT);
        assertThat(cut).isEqualTo("Z".repeat(4000) + "…(1000자 생략)");
        assertThat(UntrustedText.forAnalyst(cut, Kind.TEXT)).isEqualTo(cut);
        assertThat(UntrustedText.forAnalyst("Q".repeat(1001), Kind.VALUE)).endsWith("Q…(1자 생략)");
    }

    @Test
    void analystProcessingMarksBeforeCappingSoTheCapCountsTheMarkers() {
        String name = "\u202e".repeat(40); // 표지 하나 8자 × 40 = 320 > 256
        String out = UntrustedText.forAnalyst(name, Kind.NAME);
        assertThat(out).startsWith("[U+202E]".repeat(32)).endsWith("…(64자 생략)");
        assertThat(out.codePointCount(0, out.indexOf('…'))).isEqualTo(256);
    }

    @Test
    void searchNormalizationStripsHiddenCharactersAppliesNfkcAndLowercases() {
        assertThat(UntrustedText.normalizeForSearch("WEB\u200b-ｓｅｒｖｅｒ\u202e-01")).isEqualTo("web-server-01");
        assertThat(UntrustedText.normalizeForSearch("\u200b\u3164\u2060")).isEmpty();
        assertThat(UntrustedText.normalizeForSearch("ﬁle")).isEqualTo("file");
        assertThat(UntrustedText.withoutRemovalNote("10.0.*.* [보이지 않는 문자 1개 제거]")).isEqualTo("10.0.*.*");
        assertThat(TextSearch.contains("Web-ｓｅｒｖｅｒ-01 [보이지 않는 문자 1개 제거]", "web-server")).isTrue();
        // 제거 표시 글은 비교 대상이 아니다
        assertThat(TextSearch.contains("abc [보이지 않는 문자 1개 제거]", "보이지")).isFalse();
    }

    @Test
    void storedColumnTruncationIsUtf16AndDropsAPairThatStraddlesTheLimit() {
        String actor = "q".repeat(99) + "😀tail";
        assertThat(UntrustedText.truncateUtf16(actor, 100)).isEqualTo("q".repeat(99));
        assertThat(UntrustedText.truncateUtf16("q".repeat(98) + "😀tail", 100)).isEqualTo("q".repeat(98) + "😀");
        assertThat(UntrustedText.truncateUtf16("short\u202e", 100)).isEqualTo("short\u202e"); // 저장값의 뜻은 바꾸지 않는다
        assertThat(UntrustedText.truncateUtf16(null, 100)).isNull();
    }

    @Test
    void notesAreRecognizedOnlyAtTheVeryEndSoATrailingNewlineIsKept() {
        // 바깥 글이 제거 표시 글 뒤에 줄바꿈으로 끝나도 표시로 읽지 않는다(마지막 줄바꿈을 잃지 않는다)
        String viewerText = "x [보이지 않는 문자 2개 제거]\n";
        assertThat(UntrustedText.forViewer(viewerText, Kind.TEXT)).isEqualTo(viewerText);
        assertThat(UntrustedText.withoutRemovalNote(viewerText)).isEqualTo(viewerText);
        // 생략 표시 글 뒤에 줄바꿈이 있으면 이미 자른 값으로 보지 않고 다시 자른다
        assertThat(UntrustedText.truncate("abcd…(5자 생략)\n", 4)).isEqualTo("abcd…(9자 생략)");
    }

    @Test
    void logValuesCannotStartANewLine() {
        assertThat(UntrustedText.forLog("id\nFAKE LINE\r\u202e")).isEqualTo("id[U+000A]FAKE LINE[U+000D][U+202E]");
    }
}
