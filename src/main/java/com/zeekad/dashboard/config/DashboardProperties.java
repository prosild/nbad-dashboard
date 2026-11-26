package com.zeekad.dashboard.config;

import com.zeekad.dashboard.model.UserRole;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 대시보드 애플리케이션 환경 설정 바인딩.
 */
@ConfigurationProperties(prefix = "dashboard")
public class DashboardProperties {

    private final Datasource datasource = new Datasource();
    private final EvidenceApi evidenceApi = new EvidenceApi();
    private final Security security = new Security();
    private final Bootstrap bootstrap = new Bootstrap();
    /** 로그인 화면 안내 문구(T21, 환경 변수 DASHBOARD_LOGIN_NOTICE). 일반 텍스트, 기본 빈 값. */
    private String loginNotice = "";
    /**
     * 안내 문구 아래에 붙는 링크 하나(T50, 환경 변수 DASHBOARD_LOGIN_NOTICE_LINK_URL·DASHBOARD_LOGIN_NOTICE_LINK_LABEL).
     * 둘 다 있고 검사(https, 호스트 있음, 사용자 정보 없음, 제어·양방향 문자 없음, 길이)를 통과하고 안내 문구도 있을 때만 보인다.
     */
    private String loginNoticeLinkUrl = "";
    private String loginNoticeLinkLabel = "";
    /**
     * 기준 시각 모드(T23, 환경 변수 DASHBOARD_TIME_ANCHOR). now = 서버 현재 시각,
     * latest-data = 사용자 허용 캡처 안 성공 작업 완료 시각의 최대값(고정 스냅샷). 다른 값이면 시작 때 실패한다.
     */
    private String timeAnchor = "now";
    private final CaptureSources captureSources = new CaptureSources();
    private final Sla sla = new Sla();

    public Sla getSla() {
        return sla;
    }

    /** 착수 목표(T25). dashboard.sla.ack.high·medium·low */
    public static class Sla {
        private final Ack ack = new Ack();

        public Ack getAck() {
            return ack;
        }
    }

    /**
     * 우선순위별 착수 목표 시간(T25): 실습망 신규 인시던트가 탐지 뒤 이 시간을 넘기면 착수 지연이다.
     * Spring Duration 형식(30m, 4h). 0 이하이거나 high ≤ medium ≤ low가 아니면 시작 때 실패한다.
     */
    public static class Ack {
        private Duration high = Duration.ofMinutes(30);
        private Duration medium = Duration.ofHours(4);
        private Duration low = Duration.ofHours(24);

        public Duration getHigh() {
            return high;
        }

        public void setHigh(Duration high) {
            this.high = high;
        }

        public Duration getMedium() {
            return medium;
        }

        public void setMedium(Duration medium) {
            this.medium = medium;
        }

        public Duration getLow() {
            return low;
        }

        public void setLow(Duration low) {
            this.low = low;
        }
    }

    public String getTimeAnchor() {
        return timeAnchor;
    }

    public void setTimeAnchor(String timeAnchor) {
        this.timeAnchor = timeAnchor;
    }

    public CaptureSources getCaptureSources() {
        return captureSources;
    }

    public String getLoginNotice() {
        return loginNotice;
    }

    public void setLoginNotice(String loginNotice) {
        this.loginNotice = loginNotice;
    }

    public String getLoginNoticeLinkUrl() {
        return loginNoticeLinkUrl;
    }

    public void setLoginNoticeLinkUrl(String loginNoticeLinkUrl) {
        this.loginNoticeLinkUrl = loginNoticeLinkUrl;
    }

    public String getLoginNoticeLinkLabel() {
        return loginNoticeLinkLabel;
    }

    public void setLoginNoticeLinkLabel(String loginNoticeLinkLabel) {
        this.loginNoticeLinkLabel = loginNoticeLinkLabel;
    }

    public Datasource getDatasource() {
        return datasource;
    }

    public EvidenceApi getEvidenceApi() {
        return evidenceApi;
    }

    public Security getSecurity() {
        return security;
    }

    public Bootstrap getBootstrap() {
        return bootstrap;
    }

    /** 수집원 분류(T23). live-patterns에 맞는 캡처는 실습망 센서(live), 아니면 가져온 데이터(imported)다. */
    public static class CaptureSources {
        /** 쉼표 목록, CapturePatternMatcher 문법(접두어*). 기본 lab-* */
        private String livePatterns = "lab-*";
        /**
         * 센서 상태(T24): 기준 시각 − 센서 마지막 채점이 이 값 이하면 정상(ok). 기본 15분(5분 파일 채점 세 번).
         * Spring Duration 형식(PT15M, 15m). 0 이하이거나 down-after 이상이면 시작 때 실패한다.
         */
        private Duration staleAfter = Duration.ofMinutes(15);
        /** 센서 상태(T24): 이 값 이하면 지연(stale), 넘으면 중단(down). 기본 1시간 */
        private Duration downAfter = Duration.ofHours(1);

        public Duration getStaleAfter() {
            return staleAfter;
        }

        public void setStaleAfter(Duration staleAfter) {
            this.staleAfter = staleAfter;
        }

        public Duration getDownAfter() {
            return downAfter;
        }

        public void setDownAfter(Duration downAfter) {
            this.downAfter = downAfter;
        }

        public String getLivePatterns() {
            return livePatterns;
        }

        public void setLivePatterns(String livePatterns) {
            this.livePatterns = livePatterns;
        }
    }

    public static class Datasource {
        private final DbSpec app = new DbSpec();
        private final DbSpec zeekadRead = new DbSpec();
        private final DbSpec zeekadWrite = new DbSpec();

        public DbSpec getApp() {
            return app;
        }

        public DbSpec getZeekadRead() {
            return zeekadRead;
        }

        public DbSpec getZeekadWrite() {
            return zeekadWrite;
        }
    }

    public static class DbSpec {
        private String url;
        private String username;
        private String password;
        private String driverClassName;

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getDriverClassName() {
            return driverClassName;
        }

        public void setDriverClassName(String driverClassName) {
            this.driverClassName = driverClassName;
        }
    }

    public static class EvidenceApi {
        private String url = "http://127.0.0.1:8000";
        private int connectTimeoutMs = 3000;
        private int readTimeoutMs = 5000;

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public int getConnectTimeoutMs() {
            return connectTimeoutMs;
        }

        public void setConnectTimeoutMs(int connectTimeoutMs) {
            this.connectTimeoutMs = connectTimeoutMs;
        }

        public int getReadTimeoutMs() {
            return readTimeoutMs;
        }

        public void setReadTimeoutMs(int readTimeoutMs) {
            this.readTimeoutMs = readTimeoutMs;
        }
    }

    public static class Security {
        private int bcryptStrength = 12;
        private int maxFailedAttempts = 5;
        private long lockoutMinutes = 15;
        private long idleTimeoutMinutes = 30;
        private long absoluteTimeoutMinutes = 480;
        private String totpIssuer = "NBAD Dashboard";
        /**
         * T29·T33 잠금 제외 계정(쉼표 목록, 기본 비어 있음). 비밀번호를 공개한 공유 계정(VIEWER 또는 ANALYST)만 넣는다.
         * 역할 판정은 로그인 때 DB 역할로 하며 VIEWER·ANALYST가 아니면(ADMIN) 목록에 있어도 잠긴다(DashboardAuthenticationProvider).
         * 실제 분석가 이름을 넣으면 그 계정도 잠기지 않으므로 여러 IP 대입을 IP당 속도 제한만 막게 된다.
         */
        private List<String> lockoutExemptUsernames = new ArrayList<>();
        /**
         * T32 전달 헤더를 믿을 프록시 주소(쉼표 목록, 환경 변수 DASHBOARD_TRUSTED_PROXIES, 기본 비어 있음).
         * IPv4·IPv6 주소 그대로만 받는다(대역·호스트 이름·정규식은 시작 실패). 비어 있으면 아무 연결의 X-Forwarded-*도 믿지 않는다.
         * 해석·적용은 TrustedProxies·TrustedProxyValveCustomizer가 한다.
         */
        private List<String> trustedProxies = new ArrayList<>();

        public List<String> getTrustedProxies() {
            return trustedProxies;
        }

        public void setTrustedProxies(List<String> trustedProxies) {
            this.trustedProxies = trustedProxies == null ? new ArrayList<>() : trustedProxies;
        }

        public int getBcryptStrength() {
            return bcryptStrength;
        }

        public void setBcryptStrength(int bcryptStrength) {
            this.bcryptStrength = bcryptStrength;
        }

        public int getMaxFailedAttempts() {
            return maxFailedAttempts;
        }

        public void setMaxFailedAttempts(int maxFailedAttempts) {
            this.maxFailedAttempts = maxFailedAttempts;
        }

        public long getLockoutMinutes() {
            return lockoutMinutes;
        }

        public void setLockoutMinutes(long lockoutMinutes) {
            this.lockoutMinutes = lockoutMinutes;
        }

        public long getIdleTimeoutMinutes() {
            return idleTimeoutMinutes;
        }

        public void setIdleTimeoutMinutes(long idleTimeoutMinutes) {
            this.idleTimeoutMinutes = idleTimeoutMinutes;
        }

        public long getAbsoluteTimeoutMinutes() {
            return absoluteTimeoutMinutes;
        }

        public void setAbsoluteTimeoutMinutes(long absoluteTimeoutMinutes) {
            this.absoluteTimeoutMinutes = absoluteTimeoutMinutes;
        }

        public String getTotpIssuer() {
            return totpIssuer;
        }

        public void setTotpIssuer(String totpIssuer) {
            this.totpIssuer = totpIssuer;
        }

        public List<String> getLockoutExemptUsernames() {
            return lockoutExemptUsernames;
        }

        public void setLockoutExemptUsernames(List<String> lockoutExemptUsernames) {
            this.lockoutExemptUsernames = lockoutExemptUsernames == null ? new ArrayList<>() : lockoutExemptUsernames;
        }

        /** 정규화한 잠금 제외 이름(앞뒤 공백 제거·소문자, 빈 항목 버림) */
        public Set<String> normalizedLockoutExemptUsernames() {
            return lockoutExemptUsernames.stream()
                    .filter(v -> v != null)
                    .map(v -> v.trim().toLowerCase(Locale.ROOT))
                    .filter(v -> !v.isEmpty())
                    .collect(Collectors.toUnmodifiableSet());
        }

        /** 잠금 제외를 허용하는 역할(T33: VIEWER·ANALYST). ADMIN은 목록에 있어도 늘 잠근다. */
        public static boolean isLockoutExemptRole(UserRole role) {
            return role == UserRole.VIEWER || role == UserRole.ANALYST;
        }

        /** 저장 이름(DB users.username)이 잠금 제외 목록에 있는가(대소문자 무시). 역할은 따로 본다. */
        public boolean isLockoutExemptName(String storedUsername) {
            return storedUsername != null
                    && normalizedLockoutExemptUsernames().contains(storedUsername.trim().toLowerCase(Locale.ROOT));
        }
    }

    public static class Bootstrap {
        private String commonPassword;
        private String viewer1Password;
        private String analyst1Password;
        private String analyst2Password;
        private String adminPassword;
        private String adminTotpSecret;

        public String getCommonPassword() {
            return commonPassword;
        }

        public void setCommonPassword(String commonPassword) {
            this.commonPassword = commonPassword;
        }

        public String getViewer1Password() {
            return viewer1Password;
        }

        public void setViewer1Password(String viewer1Password) {
            this.viewer1Password = viewer1Password;
        }

        public String getAnalyst1Password() {
            return analyst1Password;
        }

        public void setAnalyst1Password(String analyst1Password) {
            this.analyst1Password = analyst1Password;
        }

        public String getAnalyst2Password() {
            return analyst2Password;
        }

        public void setAnalyst2Password(String analyst2Password) {
            this.analyst2Password = analyst2Password;
        }

        public String getAdminPassword() {
            return adminPassword;
        }

        public void setAdminPassword(String adminPassword) {
            this.adminPassword = adminPassword;
        }

        public String getAdminTotpSecret() {
            return adminTotpSecret;
        }

        public void setAdminTotpSecret(String adminTotpSecret) {
            this.adminTotpSecret = adminTotpSecret;
        }
    }
}
