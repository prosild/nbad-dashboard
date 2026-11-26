package com.zeekad.dashboard.mapper.app;

import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * 대시보드 사용자 및 허용 캡처 패턴 매퍼.
 */
@Mapper
public interface UserMapper {

    long countAll();

    DashboardUser findById(@Param("id") Long id);

    DashboardUser findByUsername(@Param("username") String username);

    List<DashboardUser> findAll();

    List<String> findCapturePatternsByUserId(@Param("userId") Long userId);

    void insertUser(DashboardUser user);

    void insertCapturePattern(@Param("userId") Long userId, @Param("capturePattern") String capturePattern);

    void deleteCapturePatternsByUserId(@Param("userId") Long userId);

    /**
     * 실패 횟수와 잠금 시각을 받은 값으로 덮어쓴다. 인증 경로는 쓰지 않는다(T60: 읽은 값으로 덮어쓰면 그 사이의 실패분이 지워진다).
     * 인증 경로는 {@link #claimFailedAttempt}와 {@link #lockIfLimitReached}를 쓴다.
     */
    void updateLoginFailure(@Param("id") Long id,
                            @Param("failedAttempts") int failedAttempts,
                            @Param("lockedUntil") OffsetDateTime lockedUntil,
                            @Param("updatedAt") OffsetDateTime updatedAt);

    /**
     * T60 실패 시도 하나를 차지한다(조건부 원자 갱신 한 문장). 잠겨 있지 않고(만료된 잠금은 잠기지 않은 것) 횟수가 한도 미만일 때만
     * 횟수를 하나 올린다. 만료된 잠금이 남아 있으면 잠금을 지우고 1부터 다시 센다.
     *
     * @return 차지했으면 1, 잠겨 있거나 한도에 닿아 있으면 0
     */
    int claimFailedAttempt(@Param("id") Long id,
                           @Param("now") OffsetDateTime now,
                           @Param("maxFailedAttempts") int maxFailedAttempts);

    /**
     * T60 횟수가 한도에 닿았고 아직 잠기지 않았을 때만 잠근다(조건부 원자 갱신 한 문장).
     *
     * @return 이 호출이 잠갔으면 1(잠금 감사는 이때만 남긴다), 아니면 0
     */
    int lockIfLimitReached(@Param("id") Long id,
                           @Param("maxFailedAttempts") int maxFailedAttempts,
                           @Param("lockedUntil") OffsetDateTime lockedUntil,
                           @Param("now") OffsetDateTime now);

    void resetLoginFailure(@Param("id") Long id, @Param("updatedAt") OffsetDateTime updatedAt);

    void updateTotpState(@Param("id") Long id,
                         @Param("totpSecret") String totpSecret,
                         @Param("totpEnabled") boolean totpEnabled,
                         @Param("updatedAt") OffsetDateTime updatedAt);

    void updateUserRoleAndDisplayName(@Param("id") Long id,
                                      @Param("displayName") String displayName,
                                      @Param("role") UserRole role,
                                      @Param("updatedAt") OffsetDateTime updatedAt);

    void updateEnabled(@Param("id") Long id,
                       @Param("enabled") boolean enabled,
                       @Param("updatedAt") OffsetDateTime updatedAt);
}
