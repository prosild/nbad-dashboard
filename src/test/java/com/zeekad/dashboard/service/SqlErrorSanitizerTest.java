package com.zeekad.dashboard.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SqlErrorSanitizerTest {

    private static final String FALLBACK = "대상 사건을 찾을 수 없습니다.";

    @Test
    void keepsSingleGuideWhenDbMessageAlreadyHasRefreshAndCheck() {
        String raw = "ERROR: 이미 'investigating' 상태로 변경되었습니다. 화면을 새로고침하여 최신 상태를 확인해 주세요.\n  Where: PL/pgSQL function";

        String message = SqlErrorSanitizer.withRefreshGuide(SqlErrorSanitizer.sanitizeSqlMessage(raw, FALLBACK));

        assertThat(message).isEqualTo("이미 'investigating' 상태로 변경되었습니다. 화면을 새로고침하여 최신 상태를 확인해 주세요.");
        assertThat(countGuide(message)).isEqualTo(1);
        // T68(M3): DB 문장에 "새로고침"이 이미 있으면 대시보드 안내("다시 불러오기")를 붙이지 않는다
        assertThat(message).doesNotContain("다시 불러오기");
    }

    @Test
    void keepsSingleGuideWhenDbMessageAlreadyHasRefreshAndRetry() {
        String raw = "ERROR: 다른 사용자가 먼저 검토 결정을 완료했습니다. 화면을 새로고침한 뒤 다시 확인해 주세요.";

        String message = SqlErrorSanitizer.withRefreshGuide(SqlErrorSanitizer.sanitizeSqlMessage(raw, FALLBACK));

        assertThat(message).isEqualTo("다른 사용자가 먼저 검토 결정을 완료했습니다. 화면을 새로고침한 뒤 다시 확인해 주세요.");
        assertThat(countGuide(message)).isEqualTo(1);
        assertThat(message).doesNotContain("다시 불러오기");
    }

    @Test
    void appendsGuideOnceWhenDbMessageHasNoGuide() {
        String raw = "ERROR: 검토 대상이 없습니다.";

        String message = SqlErrorSanitizer.withRefreshGuide(SqlErrorSanitizer.sanitizeSqlMessage(raw, FALLBACK));

        assertThat(message).isEqualTo("검토 대상이 없습니다." + SqlErrorSanitizer.REFRESH_GUIDE);
        assertThat(countGuide(message)).isEqualTo(1);
        // T68(M3): 대시보드 안내는 화면 단추 이름에 맞춘다
        assertThat(SqlErrorSanitizer.REFRESH_GUIDE).isEqualTo(" '다시 불러오기'로 최신 상태를 확인하세요.");
    }

    @Test
    void appendsGuideOnceToFallbackMessage() {
        String emptyMessage = SqlErrorSanitizer.withRefreshGuide(SqlErrorSanitizer.sanitizeSqlMessage("", FALLBACK));
        String unsafeMessage = SqlErrorSanitizer.withRefreshGuide(
                SqlErrorSanitizer.sanitizeSqlMessage("org.h2.jdbc.JdbcSQLException: SELECT * FROM t", FALLBACK));

        assertThat(emptyMessage).isEqualTo(FALLBACK + SqlErrorSanitizer.REFRESH_GUIDE);
        assertThat(countGuide(emptyMessage)).isEqualTo(1);
        assertThat(unsafeMessage).isEqualTo(FALLBACK + SqlErrorSanitizer.REFRESH_GUIDE);
        assertThat(countGuide(unsafeMessage)).isEqualTo(1);
    }

    @Test
    void doesNotAppendTwiceToDashboardGuide() {
        String once = SqlErrorSanitizer.withRefreshGuide("검토 대상이 없습니다.");
        assertThat(SqlErrorSanitizer.withRefreshGuide(once)).isEqualTo(once);
        assertThat(countGuide(once)).isEqualTo(1);
    }

    /** T68(M3): 안내 낱말은 DB 함수 문장의 "새로고침"과 대시보드 안내의 "다시 불러오기" 둘이다(전에는 "새로고침"만 셌다) */
    private static int countGuide(String message) {
        return (message.split("새로고침", -1).length - 1) + (message.split("다시 불러오기", -1).length - 1);
    }
}
