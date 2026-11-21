package com.zeekad.dashboard.dto;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * 담당자(T25) API 모양. VIEWER도 담당자 이름을 본다(상태 이력의 변경자와 같은 기준).
 */
public final class AssignmentDtos {

    private AssignmentDtos() {
    }

    /** 담당자 한 사람. enabled=false면 화면이 "비활성" 표지를 붙인다. */
    public record Assignee(String username, String displayName, boolean enabled) {
    }

    /** 현재 담당. assignee가 null이면 미배정(행이 없거나 해제됨) */
    public record Assignment(Assignee assignee, OffsetDateTime assignedAt, String assignedByDisplay) {
        public static Assignment none() {
            return new Assignment(null, null, null);
        }
    }

    /** 담당 변경 이력 한 행. from·to가 null이면 미배정. reason: manual · auto_on_start */
    public record HistoryItem(Long jobId, Assignee from, Assignee to, String actorDisplay, String reason,
                              OffsetDateTime changedAt) {
    }

    /** POST .../assignment 본문. assignee null = 해제, expected = 화면이 본 현재 담당자(username 또는 null) */
    public record AssignRequest(String assignee, String expected) {
    }

    public record AssignResponse(Assignment assignment) {
    }

    /** 담당자가 될 수 있는 사용자(ANALYST·ADMIN만 받는다) */
    public record Candidate(String username, String displayName) {
    }

    public record CandidatesResponse(List<Candidate> assignees) {
    }
}
