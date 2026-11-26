package com.zeekad.dashboard.security;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.DashboardUser;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * T60 인증 실패 횟수와 계정 잠금(users.failed_attempts·locked_until). 비밀번호 실패와 관리자 TOTP 확인 실패가 같은 횟수를 쓴다.
 * 읽은 값으로 덮어쓰지 않고 조건부 원자 갱신 두 문장만 쓴다(차지, 잠금). 그래서 동시에 온 요청이 서로의 실패분을 지우지 못하고,
 * 차지에 성공하는 요청 수가 한도를 넘지 못한다. 트랜잭션으로 묶지 않는다(문장마다 바로 반영돼야 다른 요청이 그 값을 본다).
 */
@Component
public class FailedAttemptService {

    private final UserMapper userMapper;
    private final DashboardProperties properties;

    public FailedAttemptService(UserMapper userMapper, DashboardProperties properties) {
        this.userMapper = userMapper;
        this.properties = properties;
    }

    /**
     * 실패 시도 하나를 차지한다. 잠겨 있지 않고 횟수가 한도 미만일 때만 횟수가 하나 오른다(만료된 잠금이 남아 있으면 1부터).
     *
     * @return 차지했으면 true. false면 잠겨 있거나 한도에 닿아 있다
     */
    public boolean claim(Long userId, Instant now) {
        return userMapper.claimFailedAttempt(userId, utc(now), maxFailedAttempts()) == 1;
    }

    /**
     * 차지하지 못했거나 판정이 틀린 뒤에 부른다. 횟수가 한도에 닿았고 아직 잠기지 않았으면 잠그고, 갱신 뒤의 값을 다시 읽어 돌려준다.
     * 한도에 닿았는데 잠금이 없는 행(차지와 잠금 사이에 프로세스가 죽었거나 한도 설정을 낮춘 경우)도 여기서 잠겨, 풀리지 않는 상태로 남지 않는다.
     */
    public State settle(Long userId, Instant now) {
        OffsetDateTime lockedUntil = utc(now.plusSeconds(properties.getSecurity().getLockoutMinutes() * 60L));
        boolean lockedByThisCall = userMapper.lockIfLimitReached(userId, maxFailedAttempts(), lockedUntil, utc(now)) == 1;
        DashboardUser fresh = userMapper.findById(userId);
        if (fresh == null) {
            return new State(0, null, false, false);
        }
        OffsetDateTime freshLockedUntil = fresh.getLockedUntil() == null
                ? null
                : fresh.getLockedUntil().withOffsetSameInstant(ZoneOffset.UTC);
        boolean locked = freshLockedUntil != null && freshLockedUntil.toInstant().isAfter(now);
        return new State(fresh.getFailedAttempts(), freshLockedUntil, lockedByThisCall, locked);
    }

    /** 횟수와 잠금을 지운다(관리자의 TOTP 확인 성공과 등록 완료) */
    public void reset(Long userId, Instant now) {
        userMapper.resetLoginFailure(userId, utc(now));
    }

    private int maxFailedAttempts() {
        return properties.getSecurity().getMaxFailedAttempts();
    }

    private static OffsetDateTime utc(Instant instant) {
        return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    /**
     * 갱신 뒤 다시 읽은 상태.
     *
     * @param failedAttempts   지금 실패 횟수
     * @param lockedUntil      지금 잠금 시각(UTC, 없으면 null)
     * @param lockedByThisCall 이 호출이 잠갔다(잠금 감사는 이때만 남긴다)
     * @param locked           지금 잠겨 있다(누가 잠갔든)
     */
    public record State(int failedAttempts, OffsetDateTime lockedUntil, boolean lockedByThisCall, boolean locked) {
    }
}
