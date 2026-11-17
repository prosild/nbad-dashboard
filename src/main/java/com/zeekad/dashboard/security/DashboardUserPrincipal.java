package com.zeekad.dashboard.security;

import com.zeekad.dashboard.model.DashboardUser;
import com.zeekad.dashboard.model.UserRole;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

/**
 * Spring Security 세션에 보관되는 인증 사용자 주체.
 */
public class DashboardUserPrincipal implements UserDetails {

    private final Long id;
    private final String username;
    private final String displayName;
    private final UserRole role;
    private final boolean totpEnabled;
    private final boolean enabled;
    private final boolean locked;
    private final List<String> capturePatterns;

    public DashboardUserPrincipal(DashboardUser user, List<String> capturePatterns, Instant now) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.displayName = user.getDisplayName();
        this.role = user.getRole();
        this.totpEnabled = user.isTotpEnabled();
        this.enabled = user.isEnabled();
        this.locked = user.getLockedUntil() != null && user.getLockedUntil().toInstant().isAfter(now);
        this.capturePatterns = capturePatterns == null ? List.of() : List.copyOf(capturePatterns);
    }

    public Long getId() {
        return id;
    }

    public String getDisplayName() {
        return displayName;
    }

    public UserRole getRole() {
        return role;
    }

    public boolean isTotpEnabled() {
        return totpEnabled;
    }

    public List<String> getCapturePatterns() {
        return capturePatterns;
    }

    public boolean isCaptureAllowed(String captureId) {
        return CapturePatternMatcher.matchesAny(capturePatterns, captureId);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
