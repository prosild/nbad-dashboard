package com.zeekad.dashboard.security;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.mapper.app.UserMapper;
import com.zeekad.dashboard.model.DashboardUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * T29·T33 잠금 제외 목록 시작 점검. 목록의 계정이 없거나 허용 역할(VIEWER·ANALYST)이 아니면 경고 로그만 남긴다(이름만, 시작은 막지 않는다).
 * 허용 역할이 아닌 계정(ADMIN)은 목록에 있어도 로그인 때 잠금이 그대로 적용된다(DashboardAuthenticationProvider).
 */
@Component
public class LockoutExemptionStartupCheck {

    private static final Logger log = LoggerFactory.getLogger(LockoutExemptionStartupCheck.class);

    private final DashboardProperties properties;
    private final UserMapper userMapper;

    public LockoutExemptionStartupCheck(DashboardProperties properties, UserMapper userMapper) {
        this.properties = properties;
        this.userMapper = userMapper;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        check();
    }

    /** 경고한 이름 목록(시험용으로 돌려준다) */
    public List<String> check() {
        Set<String> names = new TreeSet<>(properties.getSecurity().normalizedLockoutExemptUsernames());
        List<String> warned = new ArrayList<>();
        if (names.isEmpty()) {
            return warned;
        }
        for (String name : names) {
            DashboardUser user;
            try {
                user = userMapper.findByUsername(name);
            } catch (RuntimeException e) {
                log.warn("잠금 제외 목록 점검 실패: 계정 '{}'을 읽지 못했습니다 ({})", name, e.getClass().getSimpleName());
                warned.add(name);
                continue;
            }
            if (user == null) {
                log.warn("잠금 제외 목록의 계정 '{}'이 없습니다. 만들어지면 VIEWER·ANALYST일 때만 잠금에서 빠집니다.", name);
                warned.add(name);
            } else if (!DashboardProperties.Security.isLockoutExemptRole(user.getRole())) {
                log.warn("잠금 제외 목록의 계정 '{}'은 VIEWER·ANALYST가 아니라({}) 잠금이 그대로 적용됩니다. 목록에는 비밀번호를 공개한 공유 계정만 넣으세요.",
                        name, user.getRole().name());
                warned.add(name);
            }
        }
        if (warned.size() < names.size()) {
            log.info("계정 잠금 제외(공유 계정) {}개 적용", names.size() - warned.size());
        }
        return warned;
    }
}
