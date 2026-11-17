package com.zeekad.dashboard.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 대시보드 애플리케이션 환경 설정 바인딩.
 */
@ConfigurationProperties(prefix = "dashboard")
public class DashboardProperties {

    private final Datasource datasource = new Datasource();
    private final EvidenceApi evidenceApi = new EvidenceApi();
    private final Security security = new Security();
    private final Bootstrap bootstrap = new Bootstrap();

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
        private String totpIssuer = "zeek_AD Dashboard";

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
