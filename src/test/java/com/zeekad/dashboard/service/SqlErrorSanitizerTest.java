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
        assertThat(countRefresh(message)).isEqualTo(1);
    }

    @Test
    void keepsSingleGuideWhenDbMessageAlreadyHasRefreshAndRetry() {
        String raw = "ERROR: 다른 사용자가 먼저 검토 결정을 완료했습니다. 화면을 새로고침한 뒤 다시 확인해 주세요.";

        String message = SqlErrorSanitizer.withRefreshGuide(SqlErrorSanitizer.sanitizeSqlMessage(raw, FALLBACK));

        assertThat(message).isEqualTo("다른 사용자가 먼저 검토 결정을 완료했습니다. 화면을 새로고침한 뒤 다시 확인해 주세요.");
        assertThat(countRefresh(message)).isEqualTo(1);
    }

    @Test
    void appendsGuideOnceWhenDbMessageHasNoGuide() {
        String raw = "ERROR: 검토 대상이 없습니다.";

        String message = SqlErrorSanitizer.withRefreshGuide(SqlErrorSanitizer.sanitizeSqlMessage(raw, FALLBACK));

        assertThat(message).isEqualTo("검토 대상이 없습니다." + SqlErrorSanitizer.REFRESH_GUIDE);
        assertThat(countRefresh(message)).isEqualTo(1);
    }

    @Test
    void appendsGuideOnceToFallbackMessage() {
        String emptyMessage = SqlErrorSanitizer.withRefreshGuide(SqlErrorSanitizer.sanitizeSqlMessage("", FALLBACK));
        String unsafeMessage = SqlErrorSanitizer.withRefreshGuide(
                SqlErrorSanitizer.sanitizeSqlMessage("org.h2.jdbc.JdbcSQLException: SELECT * FROM t", FALLBACK));

        assertThat(emptyMessage).isEqualTo(FALLBACK + SqlErrorSanitizer.REFRESH_GUIDE);
        assertThat(countRefresh(emptyMessage)).isEqualTo(1);
        assertThat(unsafeMessage).isEqualTo(FALLBACK + SqlErrorSanitizer.REFRESH_GUIDE);
        assertThat(countRefresh(unsafeMessage)).isEqualTo(1);
    }

    private static int countRefresh(String message) {
        return message.split("새로고침", -1).length - 1;
    }
}
