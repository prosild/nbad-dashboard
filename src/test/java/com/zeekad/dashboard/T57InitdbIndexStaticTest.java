package com.zeekad.dashboard;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T57 공개 스택 initdb의 넷째 스크립트(계약 뷰를 빠르게 하는 인덱스)의 정적 검사.
 * 계약 뷰 dashboard.latest_incident_queue가 행마다 zeekad.agent_report를 incident_id로 찾는데 그 표에는 기본 키 (job_id, incident_id)뿐이라
 * 2026-11-26 스냅샷에서 목록·상세가 약 3배 느려졌다(handoff/T57/evidence/slowdown-diagnosis.md). 결과를 바꾸지 않는 인덱스 하나를 더한다.
 */
class T57InitdbIndexStaticTest {

    static final Path FOURTH = Path.of("docker/portfolio/initdb/04-zeekad-indexes.sh");

    @Test
    void fourthInitdbScriptCreatesTheAgentReportIndexIdempotentlyAndFailsClosed() throws IOException {
        assertThat(FOURTH).exists();
        String script = Files.readString(FOURTH, StandardCharsets.UTF_8);
        // LF 줄 끝(.gitattributes *.sh eol=lf), bash, 실패하면 멈춤
        assertThat(script).startsWith("#!/bin/bash\n").doesNotContain("\r");
        assertThat(script).contains("set -euo pipefail");
        // 정확한 문장(IF NOT EXISTS: 새 스냅샷이 이미 담고 있어도 실패하지 않는다)과 통계 갱신, zeekad DB에 슈퍼유저로
        assertThat(script).contains("CREATE INDEX IF NOT EXISTS agent_report_incident_job_idx ON zeekad.agent_report (incident_id, job_id DESC);");
        assertThat(script).contains("ANALYZE zeekad.agent_report;");
        assertThat(script).containsPattern("psql -v ON_ERROR_STOP=1 --username \"\\$POSTGRES_USER\" --dbname zeekad");
        // 로그 한 줄(절차서 S4와 리허설이 찾는 글)
        assertThat(script).contains("echo \"portfolio-indexes: agent_report_incident_job_idx created\"",
                "echo \"portfolio-indexes: agent_report_incident_job_idx already exists\"");
        // 실패하면 복원 표지를 지우고 0이 아닌 값으로 끝낸다(상태 확인이 healthy가 되지 않는다). source로 읽혀도 되게 exit 0·trap 없음
        assertThat(script).contains("$PGDATA/portfolio-restore.ok", "rm -f \"$ZEEKAD_INDEXES_MARKER\"", "exit 1");
        assertThat(script).doesNotContainPattern("(?m)^\\s*exit 0\\b").doesNotContain("trap ");
        // 같은 폴더의 다른 스크립트처럼 맨 위에 둔다(하위 폴더가 아니다). 순서는 복원(02)·함수(03) 뒤
        assertThat(FOURTH.getParent().resolve("02-restore-snapshot.sh")).exists();
        assertThat(FOURTH.getParent().resolve("03-zeekad-functions.sh")).exists();
    }
}
