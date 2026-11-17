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

    void updateLoginFailure(@Param("id") Long id,
                            @Param("failedAttempts") int failedAttempts,
                            @Param("lockedUntil") OffsetDateTime lockedUntil,
                            @Param("updatedAt") OffsetDateTime updatedAt);

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
