package com.zeekad.dashboard.testsupport;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Set;

/**
 * 테스트 프로필(H2)용 dashboard.transition_incident 및 dashboard.decide_review 함수 ALIAS 구현체.
 * PostgreSQL 함수와 동일하게 정방향 1단계 전이(open -> investigating -> closed),
 * 검토 결정(confirm/dismiss), SQLSTATE 22023(규칙 위반·동시 충돌·입력 오류) 및 02000(대상 없음)을 재현한다.
 */
public final class H2ZeekadTransitionFunctions {

    private static final Set<String> VALID_RESOLUTIONS = Set.of("true_positive", "false_positive", "benign");

    private H2ZeekadTransitionFunctions() {
    }

    public static String transitionIncident(Connection conn,
                                            Long jobId,
                                            String incidentId,
                                            String toStatus,
                                            String actor,
                                            String reason,
                                            String resolution) throws SQLException {
        if (jobId == null || isBlank(incidentId) || isBlank(toStatus) || isBlank(actor)) {
            throw new SQLException("상태 변경 필수 파라미터(job, incident, to, actor)가 누락되었습니다.", "22023");
        }
        String cleanReason = reason == null ? "" : reason.trim();
        if (cleanReason.isEmpty()) {
            throw new SQLException("상태 변경 사유를 입력해야 합니다.", "22023");
        }
        String targetStatus = toStatus.trim();
        if (!"investigating".equals(targetStatus) && !"closed".equals(targetStatus)) {
            throw new SQLException("허용되지 않는 목표 상태입니다: " + targetStatus, "22023");
        }

        String cleanResolution = isBlank(resolution) ? null : resolution.trim();
        if ("closed".equals(targetStatus)) {
            if (cleanResolution == null || !VALID_RESOLUTIONS.contains(cleanResolution)) {
                throw new SQLException(
                        "사건 종료(closed) 시에는 유효한 결론(true_positive, false_positive, benign)을 선택해야 합니다.",
                        "22023");
            }
        } else {
            cleanResolution = null;
        }

        if (!incidentExists(conn, jobId, incidentId)) {
            throw new SQLException("요청한 사건을 찾을 수 없습니다.", "02000");
        }

        String currentStatus = findCurrentStatus(conn, incidentId);
        boolean rowExists = currentStatus != null;
        String effectiveCurrent = rowExists ? currentStatus : "open";

        validateTransition(effectiveCurrent, targetStatus);

        if (!rowExists) {
            try (PreparedStatement insertStatus = conn.prepareStatement(
                    "INSERT INTO dashboard.raw_incident_status "
                            + "(job_id, incident_id, zeekad_status, zeekad_resolution, updated_at, updated_by) "
                            + "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP(), ?)")) {
                insertStatus.setLong(1, jobId);
                insertStatus.setString(2, incidentId);
                insertStatus.setString(3, targetStatus);
                insertStatus.setString(4, cleanResolution);
                insertStatus.setString(5, actor.trim());
                insertStatus.executeUpdate();
            } catch (SQLException ex) {
                if ("23505".equals(ex.getSQLState())) {
                    throw new SQLException(
                            "다른 사용자가 먼저 사건 상태를 변경했습니다. 화면을 새로고침한 뒤 다시 확인해 주세요.",
                            "22023", ex);
                }
                throw ex;
            }
        } else {
            int updated;
            try (PreparedStatement updateStatus = conn.prepareStatement(
                    "UPDATE dashboard.raw_incident_status "
                            + "SET job_id = ?, zeekad_status = ?, zeekad_resolution = ?, updated_at = CURRENT_TIMESTAMP(), updated_by = ? "
                            + "WHERE incident_id = ? AND zeekad_status = ?")) {
                updateStatus.setLong(1, jobId);
                updateStatus.setString(2, targetStatus);
                updateStatus.setString(3, cleanResolution);
                updateStatus.setString(4, actor.trim());
                updateStatus.setString(5, incidentId);
                updateStatus.setString(6, effectiveCurrent);
                updated = updateStatus.executeUpdate();
            }
            if (updated == 0) {
                throw new SQLException(
                        "다른 사용자가 먼저 사건 상태를 변경했습니다. 화면을 새로고침한 뒤 다시 확인해 주세요.",
                        "22023");
            }
        }

        try (PreparedStatement insertHistory = conn.prepareStatement(
                "INSERT INTO dashboard.raw_incident_status_history "
                        + "(job_id, incident_id, from_status, to_status, zeekad_resolution, actor, reason, changed_at) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP())")) {
            insertHistory.setLong(1, jobId);
            insertHistory.setString(2, incidentId);
            insertHistory.setString(3, effectiveCurrent);
            insertHistory.setString(4, targetStatus);
            insertHistory.setString(5, cleanResolution);
            insertHistory.setString(6, actor.trim());
            insertHistory.setString(7, cleanReason);
            insertHistory.executeUpdate();
        }

        return targetStatus;
    }

    public static String decideReview(Connection conn,
                                      Long jobId,
                                      String incidentId,
                                      String action,
                                      String analyst,
                                      String note) throws SQLException {
        if (jobId == null || isBlank(incidentId) || isBlank(action) || isBlank(analyst)) {
            throw new SQLException(
                    "검토 결정 필수 파라미터(p_job, p_incident, p_action, p_analyst)가 누락되었습니다.",
                    "22023");
        }
        String normalizedAction = action.trim().toLowerCase(Locale.ROOT);
        if (!"confirm".equals(normalizedAction) && !"dismiss".equals(normalizedAction)) {
            throw new SQLException(
                    "허용되지 않는 검토 결정입니다: " + normalizedAction + " (confirm 또는 dismiss만 허용)",
                    "22023");
        }
        String cleanAnalyst = analyst.trim();

        String existingAction;
        try (PreparedStatement selectPs = conn.prepareStatement(
                "SELECT zeekad_review_action FROM dashboard.raw_analyst_review_queue "
                        + "WHERE job_id = ? AND incident_id = ? FOR UPDATE")) {
            selectPs.setLong(1, jobId);
            selectPs.setString(2, incidentId);
            try (ResultSet rs = selectPs.executeQuery()) {
                if (!rs.next()) {
                    throw new SQLException("요청한 분석가 검토 항목을 찾을 수 없습니다.", "02000");
                }
                existingAction = rs.getString(1);
            }
        }

        if (!isBlank(existingAction)) {
            throw new SQLException(
                    "이미 '" + existingAction + "'(으)로 검토 결정이 완료되었습니다. 화면을 새로고침하여 최신 상태를 확인해 주세요.",
                    "22023");
        }

        int updated;
        try (PreparedStatement updatePs = conn.prepareStatement(
                "UPDATE dashboard.raw_analyst_review_queue "
                        + "SET zeekad_review_action = ?, analyst = ?, decided_at = CURRENT_TIMESTAMP(), "
                        + "zeekad_review_resumed_at = NULL, zeekad_review_resume_failed = FALSE "
                        + "WHERE job_id = ? AND incident_id = ? "
                        + "AND (zeekad_review_action IS NULL OR TRIM(zeekad_review_action) = '')")) {
            updatePs.setString(1, normalizedAction);
            updatePs.setString(2, cleanAnalyst);
            updatePs.setLong(3, jobId);
            updatePs.setString(4, incidentId);
            updated = updatePs.executeUpdate();
        }
        if (updated == 0) {
            throw new SQLException(
                    "다른 사용자가 먼저 검토 결정을 완료했습니다. 화면을 새로고침한 뒤 다시 확인해 주세요.",
                    "22023");
        }

        return normalizedAction;
    }

    private static boolean incidentExists(Connection conn, Long jobId, String incidentId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT 1 FROM dashboard.raw_incident_queue WHERE job_id = ? AND incident_id = ?")) {
            ps.setLong(1, jobId);
            ps.setString(2, incidentId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private static String findCurrentStatus(Connection conn, String incidentId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT zeekad_status FROM dashboard.raw_incident_status WHERE incident_id = ? FOR UPDATE")) {
            ps.setString(1, incidentId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    private static void validateTransition(String currentStatus, String targetStatus) throws SQLException {
        if (currentStatus.equals(targetStatus)) {
            throw new SQLException(
                    "이미 '" + targetStatus + "' 상태로 변경되었습니다. 화면을 새로고침하여 최신 상태를 확인해 주세요.",
                    "22023");
        }
        if ("open".equals(currentStatus) && "investigating".equals(targetStatus)) {
            return;
        }
        if ("investigating".equals(currentStatus) && "closed".equals(targetStatus)) {
            return;
        }
        if ("closed".equals(currentStatus)) {
            throw new SQLException("이미 종료(closed)된 사건은 상태를 되돌리거나 변경할 수 없습니다.", "22023");
        }
        throw new SQLException(
                "현재 상태(" + currentStatus + ")에서 '" + targetStatus + "'(으)로 건너뛰거나 되돌릴 수 없습니다.",
                "22023");
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
