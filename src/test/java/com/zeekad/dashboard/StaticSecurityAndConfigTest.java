package com.zeekad.dashboard;

import com.zeekad.dashboard.config.DashboardProperties;
import com.zeekad.dashboard.security.CapturePatternMatcher;
import com.zeekad.dashboard.security.TotpService;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class StaticSecurityAndConfigTest {

    @Test
    void mybatisMappersContainZeroDollarSubstitutions() throws IOException {
        Path xmlRoot = Path.of("src/main/resources/mapper");
        if (Files.exists(xmlRoot)) {
            try (Stream<Path> files = Files.walk(xmlRoot)) {
                List<Path> xmlFiles = files.filter(p -> p.toString().endsWith(".xml")).toList();
                assertThat(xmlFiles).isNotEmpty();
                for (Path file : xmlFiles) {
                    String content = Files.readString(file, StandardCharsets.UTF_8);
                    assertThat(content)
                            .as("MyBatis XML 매퍼 %s에 ${} 치환이 없어야 합니다", file)
                            .doesNotContain("${");
                }
            }
        }

        Path mapperJavaRoot = Path.of("src/main/java/com/zeekad/dashboard/mapper");
        try (Stream<Path> files = Files.walk(mapperJavaRoot)) {
            List<Path> javaFiles = files.filter(p -> p.toString().endsWith(".java")).toList();
            assertThat(javaFiles).isNotEmpty();
            for (Path file : javaFiles) {
                String content = Files.readString(file, StandardCharsets.UTF_8);
                assertThat(content)
                        .as("MyBatis 매퍼 인터페이스 %s에 ${} 치환이 없어야 합니다", file)
                        .doesNotContain("${");
            }
        }
    }

    @Test
    void postgresqlMigrationContainsRequiredTablesAndImmutableTrigger() throws IOException {
        Path pgMigration = Path.of("src/main/resources/db/migration/postgresql/V1__init_dashboard_auth_audit.sql");
        assertThat(pgMigration).exists();
        String sql = Files.readString(pgMigration, StandardCharsets.UTF_8);

        assertThat(sql).containsIgnoringCase("CREATE TABLE users");
        assertThat(sql).containsIgnoringCase("CREATE TABLE user_capture_access");
        assertThat(sql).containsIgnoringCase("CREATE TABLE audit_logs");
        assertThat(sql).containsIgnoringCase("BEFORE UPDATE OR DELETE ON audit_logs");
        assertThat(sql).containsIgnoringCase("RAISE EXCEPTION");
    }

    @Test
    void applicationYamlInjectsSecretsFromEnvVarsWithoutHardcodedPasswords() throws IOException {
        Path appYml = Path.of("src/main/resources/application.yml");
        String content = Files.readString(appYml, StandardCharsets.UTF_8);

        assertThat(content).contains("DASHBOARD_DB_HOST");
        assertThat(content).contains("DASHBOARD_APP_PASSWORD");
        assertThat(content).contains("ZEEKAD_RO_PASSWORD");
        assertThat(content).contains("ZEEKAD_RW_PASSWORD");
        assertThat(content).contains("ZEEKAD_EVIDENCE_API_URL");
        assertThat(content).contains("DASHBOARD_COOKIE_SECURE:true");

        Pattern literalPassword = Pattern.compile("password:\\s*[^$\\s\"']+");
        assertThat(literalPassword.matcher(content).find())
                .as("application.yml에 평문 비밀번호가 하드코딩되어서는 안 됩니다")
                .isFalse();
    }

    @Test
    void capturePatternMatcherFollowsNormalizationAndPrefixRules() {
        assertThat(CapturePatternMatcher.matches("*", "cic17-wed")).isTrue();
        assertThat(CapturePatternMatcher.matches("  CIC17-* ", "cic17-wed")).isTrue();
        assertThat(CapturePatternMatcher.matches("cic17-*", "syn1-tue")).isFalse();
        assertThat(CapturePatternMatcher.matches("syn1-tue", "syn1-tue")).isTrue();
        assertThat(CapturePatternMatcher.matches("syn1-tue", "syn1-wed")).isFalse();
        assertThat(CapturePatternMatcher.isValidPattern("cic17-*")).isTrue();
        assertThat(CapturePatternMatcher.isValidPattern("cic17-*-wed")).isFalse();
    }

    @Test
    void totpServiceGeneratesAndVerifiesRfc6238Codes() {
        TotpService totpService = new TotpService(new DashboardProperties(), Clock.systemUTC());
        String secret = totpService.generateSecret();
        assertThat(secret).hasSize(32);

        Instant now = Instant.parse("2026-11-17T09:00:00Z");
        String code = totpService.generateCode(secret, now);
        assertThat(code).matches("^\\d{6}$");
        assertThat(totpService.verifyCode(secret, code, now)).isTrue();
        assertThat(totpService.verifyCode(secret, code, now.plusSeconds(25))).isTrue();
        assertThat(totpService.verifyCode(secret, "000000", now.plusSeconds(3600))).isFalse();
        assertThat(totpService.buildOtpAuthUri("admin", secret))
                .startsWith("otpauth://totp/")
                .contains("secret=" + secret);
    }

    @Test
    void dockerAndWafConfigFilesExistWithoutSecretsOrPrivateKeys() throws IOException {
        List<Path> requiredFiles = List.of(
                Path.of("Dockerfile"),
                Path.of(".dockerignore"),
                Path.of("compose.yml"),
                Path.of("docker/verify/compose.verify.yml"),
                Path.of(".env.example"),
                Path.of("docker/nginx-waf/Dockerfile"),
                Path.of("docker/nginx-waf/templates/conf.d/default.conf.template"),
                Path.of("docker/nginx-waf/templates/includes/location_common.conf.template"),
                Path.of("docker/nginx-waf/templates/includes/cors.conf.template")
        );
        for (Path path : requiredFiles) {
            assertThat(path).as("필수 배포/WAF 파일 %s가 존재해야 합니다", path).exists();
        }

        String dockerfile = Files.readString(Path.of("Dockerfile"), StandardCharsets.UTF_8);
        assertThat(dockerfile).contains("USER ").contains("/login").doesNotContain("/actuator/health");
        assertThat(dockerfile).contains("COPY src/main").doesNotContain("COPY src/test");

        String dockerignore = Files.readString(Path.of(".dockerignore"), StandardCharsets.UTF_8);
        assertThat(dockerignore).contains(".git", ".env", "*.key", "*.pem", "handoff", "security-reports");

        String compose = Files.readString(Path.of("compose.yml"), StandardCharsets.UTF_8);
        assertThat(compose).contains("dashboard-app:", "nginx-waf:", "host.docker.internal:host-gateway");
        assertThat(compose).contains("http://api:8000").doesNotContain("http://evidence-api:8000");
        assertThat(compose).contains("MODSEC_RULE_ENGINE", "PARANOIA", "SERVER_TOKENS");
        assertThat(compose).contains("WAF_HTTP_PORT:-80", "WAF_HTTPS_PORT:-443", "SSL_CERT_FILE", "SSL_CERT_KEY_FILE");
        assertThat(compose).contains("./docker/certs:/etc/nginx/ssl:ro");
        assertThat(compose).doesNotContain("ports:\n      - \"8080:8080\"");

        String wafLocationCommon = Files.readString(
                Path.of("docker/nginx-waf/templates/includes/location_common.conf.template"),
                StandardCharsets.UTF_8);
        assertThat(wafLocationCommon).contains("location ^~ /actuator").contains("return 403");

        String envExample = Files.readString(Path.of(".env.example"), StandardCharsets.UTF_8);
        assertThat(envExample).contains("ZEEKAD_EVIDENCE_API_URL=http://api:8000")
                .doesNotContain("http://evidence-api:8000");
        for (String requiredVar : List.of(
                "DASHBOARD_DB_HOST", "DASHBOARD_DB_PORT", "DASHBOARD_DB_NAME",
                "DASHBOARD_DB_USER", "DASHBOARD_APP_PASSWORD",
                "ZEEKAD_DB_HOST", "ZEEKAD_DB_PORT", "ZEEKAD_DB_NAME",
                "ZEEKAD_RO_USER", "ZEEKAD_RO_PASSWORD",
                "ZEEKAD_RW_USER", "ZEEKAD_RW_PASSWORD",
                "ZEEKAD_EVIDENCE_API_URL", "DASHBOARD_COOKIE_SECURE",
                "DASHBOARD_BOOTSTRAP_PASSWORD", "BOOTSTRAP_ADMIN_TOTP_SECRET",
                "WAF_HTTPS_PORT", "WAF_HTTP_PORT", "WAF_SERVER_NAME",
                "SSL_CERT_FILE", "SSL_CERT_KEY_FILE")) {
            assertThat(envExample).contains(requiredVar + "=");
        }

        Pattern nasLegacyPattern = Pattern.compile("(?i)시놀로지|synology|\\bNAS\\b");
        for (Path docOrConfig : List.of(
                Path.of("compose.yml"),
                Path.of(".env.example"),
                Path.of("docs/deployment-guide.md"))) {
            String text = Files.readString(docOrConfig, StandardCharsets.UTF_8);
            assertThat(nasLegacyPattern.matcher(text).find())
                    .as("%s에 취소된 NAS 관련 표현이 남아있으면 안 됩니다", docOrConfig)
                    .isFalse();
        }

        Pattern privateKeyPattern = Pattern.compile("BEGIN [A-Z ]*PRIVATE KEY");
        Pattern hardcodedSecretLine = Pattern.compile(
                "(?m)^[ \\t]*[A-Z0-9_]*(?:PASSWORD|SECRET)[ \\t]*[:=][ \\t]*(?!$|\\r|\\n|\"\"|\\$\\{|<CHANGE_ME)[^\\s#]+");

        List<Path> inspectTargets = new java.util.ArrayList<>(requiredFiles);
        try (Stream<Path> initFiles = Files.walk(Path.of("docker/verify/init"))) {
            initFiles.filter(Files::isRegularFile).forEach(inspectTargets::add);
        }
        for (Path target : inspectTargets) {
            String content = Files.readString(target, StandardCharsets.UTF_8);
            assertThat(privateKeyPattern.matcher(content).find())
                    .as("%s에 TLS 개인키가 포함되어서는 안 됩니다", target)
                    .isFalse();
            assertThat(hardcodedSecretLine.matcher(content).find())
                    .as("%s에 평문 비밀번호/시크릿이 하드코딩되어서는 안 됩니다", target)
                    .isFalse();
        }
    }

    @Test
    void dockerfileBuildsSpaInNodeStageOnlyAndWafAllowsPutWithoutRelaxation() throws IOException {
        String dockerfile = Files.readString(Path.of("Dockerfile"), StandardCharsets.UTF_8);
        assertThat(dockerfile).contains("npm ci", "npm run build");
        assertThat(dockerfile).doesNotContain("--omit=dev");
        assertThat(dockerfile).containsPattern("(?m)^FROM node:\\S+ AS frontend\\s*$");
        assertThat(dockerfile).containsPattern("(?m)^COPY --from=frontend \\S+/dist \\./frontend/dist\\s*$");

        List<String> fromLines = dockerfile.lines().filter(line -> line.startsWith("FROM ")).toList();
        assertThat(fromLines).hasSizeGreaterThanOrEqualTo(3);
        assertThat(fromLines.get(fromLines.size() - 1).trim()).isEqualTo("FROM eclipse-temurin:17-jre-alpine");

        String finalStage = dockerfile.substring(dockerfile.lastIndexOf("\nFROM "));
        assertThat(finalStage)
                .as("최종 런타임 단계에 Node.js·npm이 없어야 합니다")
                .doesNotContainPattern("(?i)\\bnode\\b|\\bnpm\\b|node_modules")
                .contains("USER appuser");

        String dockerignore = Files.readString(Path.of(".dockerignore"), StandardCharsets.UTF_8);
        assertThat(dockerignore.lines().map(String::trim).toList())
                .contains("frontend/node_modules", "frontend/dist");

        String compose = Files.readString(Path.of("compose.yml"), StandardCharsets.UTF_8);
        java.util.regex.Matcher allowedMethods = Pattern
                .compile("(?m)^\\s*ALLOWED_METHODS:\\s*\"([^\"]*)\"")
                .matcher(compose);
        assertThat(allowedMethods.find()).as("compose.yml nginx-waf ALLOWED_METHODS").isTrue();
        List<String> methods = List.of(allowedMethods.group(1).trim().split("\\s+"));
        assertThat(methods).contains("GET", "HEAD", "POST", "PUT", "OPTIONS").doesNotContain("DELETE", "PATCH");

        assertThat(compose).contains("MODSEC_RULE_ENGINE: \"on\"", "PARANOIA: \"1\"",
                "BLOCKING_PARANOIA: \"1\"", "ANOMALY_INBOUND: \"5\"");
        assertThat(compose).doesNotContainPattern("(?i)DetectionOnly|MODSEC_RULE_ENGINE:\\s*\"?off");
        assertThat(compose).doesNotContainPattern("(?m)^\\s*(BLOCKING_)?PARANOIA:\\s*\"?0");
    }

    @Test
    void portfolioStackBindsOnlyLoopbackAndKeepsSecretsOutOfTrackedFiles() throws IOException {
        List<Path> requiredFiles = List.of(
                Path.of("compose.portfolio.yml"),
                Path.of(".env.portfolio.example"),
                Path.of("docker/portfolio/initdb/01-roles-databases.sh"),
                Path.of("docker/portfolio/initdb/02-restore-snapshot.sh"),
                Path.of("docker/portfolio/nginx/zeekad-portfolio-http.conf.template"),
                Path.of("docker/portfolio/nginx/proxy_backend_extra_portfolio.conf.template"),
                Path.of("docker/portfolio/seed/seed_demo.py"),
                Path.of("scripts/portfolio-snapshot.ps1"),
                Path.of("scripts/portfolio-verify.ps1"),
                Path.of("docs/portfolio-deployment.md"));
        for (Path path : requiredFiles) {
            assertThat(path).as("포트폴리오 배포 파일 %s가 존재해야 합니다", path).exists();
        }

        String compose = Files.readString(Path.of("compose.portfolio.yml"), StandardCharsets.UTF_8);
        String composeWithoutComments = String.join("\n",
                compose.lines().filter(line -> !line.trim().startsWith("#")).toList());
        assertThat(composeWithoutComments)
                .as("필수 보간은 빈 비밀값 예시 파일로 실행하는 config -q를 깨뜨린다")
                .doesNotContainPattern("\\$\\{[A-Za-z0-9_]+:?\\?");
        List<String> hostPorts = compose.lines()
                .map(String::trim)
                .filter(line -> line.matches("^- \"[^\"]*:\\d+\"$") && line.contains("PORTFOLIO_HTTP_PORT"))
                .toList();
        assertThat(hostPorts).containsExactly("- \"127.0.0.1:${PORTFOLIO_HTTP_PORT:-18480}:8080\"");
        assertThat(compose.lines().filter(line -> line.trim().equals("ports:")).count())
                .as("포트를 여는 서비스는 nginx-waf 하나뿐")
                .isEqualTo(1);
        assertThat(compose).contains("DASHBOARD_COOKIE_SECURE: \"true\"", "NGINX_ALWAYS_TLS_REDIRECT: \"off\"",
                "ZEEKAD_PROXY_X_FORWARDED_FOR: \"$$remote_addr\"", "REAL_IP_HEADER: \"X-Forwarded-For\"",
                "DASHBOARD_MAX_FAILED_ATTEMPTS: ${PORTFOLIO_MAX_FAILED_ATTEMPTS:-1000000}",
                "cap_drop: [ALL]", "no-new-privileges:true", "subnet: ${PORTFOLIO_SUBNET:-10.203.48.0/24}");
        assertThat(compose).doesNotContainPattern("(?i)DetectionOnly|MODSEC_RULE_ENGINE:\\s*\"?off");

        String httpConf = Files.readString(
                Path.of("docker/portfolio/nginx/zeekad-portfolio-http.conf.template"), StandardCharsets.UTF_8);
        assertThat(httpConf).contains("limit_req_status 429;", "real_ip_header X-Forwarded-For;",
                "real_ip_recursive on;", "\"POST:/api/auth/login\" $binary_remote_addr;");

        // 공유 WAF 템플릿은 변수로만 바뀌고 기존(VMware) 기본값은 이미지 ENV로 그대로 유지한다.
        String wafDockerfile = Files.readString(Path.of("docker/nginx-waf/Dockerfile"), StandardCharsets.UTF_8);
        assertThat(wafDockerfile).contains("ZEEKAD_PROXY_X_FORWARDED_FOR=\\$proxy_add_x_forwarded_for",
                "ZEEKAD_PROXY_X_FORWARDED_PORT=\\$forwarded_port");

        String envExample = Files.readString(Path.of(".env.portfolio.example"), StandardCharsets.UTF_8);
        Pattern filledSecret = Pattern.compile("(?m)^[A-Z0-9_]*(?:PASSWORD|SECRET)=\\S+");
        assertThat(filledSecret.matcher(envExample).find())
                .as(".env.portfolio.example의 비밀값은 비어 있어야 합니다")
                .isFalse();
        for (String requiredVar : List.of(
                "POSTGRES_SUPERUSER_PASSWORD", "ZEEKAD_API_PASSWORD", "DASHBOARD_RO_PASSWORD",
                "DASHBOARD_RW_PASSWORD", "DASHBOARD_APP_PASSWORD", "DEMO_PASSWORD",
                "BOOTSTRAP_VIEWER1_PASSWORD", "BOOTSTRAP_ANALYST1_PASSWORD", "BOOTSTRAP_ANALYST2_PASSWORD",
                "BOOTSTRAP_ADMIN_PASSWORD", "BOOTSTRAP_ADMIN_TOTP_SECRET", "PORTFOLIO_HTTP_PORT", "PORTFOLIO_SUBNET")) {
            assertThat(envExample).contains(requiredVar + "=");
        }

        Pattern privateKeyPattern = Pattern.compile("BEGIN [A-Z ]*PRIVATE KEY");
        try (Stream<Path> files = Files.walk(Path.of("docker/portfolio"))) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                assertThat(privateKeyPattern.matcher(Files.readString(file, StandardCharsets.UTF_8)).find())
                        .as("%s에 개인키가 없어야 합니다", file)
                        .isFalse();
            }
        }

        String gitignore = Files.readString(Path.of(".gitignore"), StandardCharsets.UTF_8);
        assertThat(gitignore).contains("!.env.portfolio.example", "build/");
    }

    @Test
    void gitignoreExcludesSecretsKeysAndSecurityReports() throws IOException {
        String gitignore = Files.readString(Path.of(".gitignore"), StandardCharsets.UTF_8);
        assertThat(gitignore).contains(
                ".env", ".env.*", "!.env.example", "*.key", "*.pem", "security-reports/",
                "frontend/node_modules/", "frontend/dist/");
    }

    @Test
    void frontendProductionSourcesComplyWithStrictCspAndNoHardcodedLabData() throws IOException {
        Path frontendIndex = Path.of("frontend/index.html");
        assertThat(frontendIndex).exists();
        Path frontendSrc = Path.of("frontend/src");
        assertThat(frontendSrc).exists();

        List<Path> targets = new java.util.ArrayList<>();
        targets.add(frontendIndex);
        try (Stream<Path> files = Files.walk(frontendSrc)) {
            files.filter(Files::isRegularFile)
                    .filter(StaticSecurityAndConfigTest::isFrontendProductionSource)
                    .forEach(targets::add);
        }

        assertThat(targets.size()).isGreaterThan(1);
        for (Path file : targets) {
            String content = Files.readString(file, StandardCharsets.UTF_8);
            assertThat(content)
                    .as("프론트엔드 프로덕션 파일 %s는 엄격한 CSP/XSS/도메인 규칙을 준수해야 합니다", file)
                    .doesNotContain("dangerouslySetInnerHTML")
                    .doesNotContain("innerHTML")
                    .doesNotContain("eval(")
                    .doesNotContain("new Function")
                    .doesNotContain("style={{")
                    .doesNotContain("style=\"")
                    .doesNotContain("정확도")
                    .doesNotContain("lab-20261119")
                    .doesNotContain("10.10.0.50")
                    .doesNotContain("10.10.0.10")
                    .doesNotContain("https://fonts.googleapis.com")
                    .doesNotContain("https://cdn.jsdelivr.net")
                    .doesNotContain("https://unpkg.com");
        }

        Path distIndex = Path.of("frontend/dist/index.html");
        if (Files.exists(distIndex)) {
            String distHtml = Files.readString(distIndex, StandardCharsets.UTF_8);
            assertThat(distHtml)
                    .contains("<div id=\"root\"></div>")
                    .doesNotContain("style=")
                    .doesNotContain("<style")
                    .doesNotContain("https://fonts.googleapis.com")
                    .doesNotContain("https://cdn.jsdelivr.net")
                    .doesNotContain("https://unpkg.com");

            Pattern scriptElement = Pattern.compile("(?is)<script\\b([^>]*)>(.*?)</script>");
            Pattern localAssetSrc = Pattern.compile("(?i)\\bsrc\\s*=\\s*\"/assets/[^\"]+\"");
            var matcher = scriptElement.matcher(distHtml);
            while (matcher.find()) {
                assertThat(localAssetSrc.matcher(matcher.group(1)).find())
                        .as("빌드된 index.html의 <script>는 /assets/ 경로만 허용해야 합니다")
                        .isTrue();
                assertThat(matcher.group(2).trim())
                        .as("빌드된 index.html에 인라인 <script> 본문이 없어야 합니다")
                        .isEmpty();
            }
        }
    }

    private static boolean isFrontendProductionSource(Path path) {
        String normalized = path.toString().replace('\\', '/');
        if (normalized.contains("/__tests__/") || normalized.contains("/test/")) {
            return false;
        }
        return !normalized.endsWith(".test.ts")
                && !normalized.endsWith(".test.tsx")
                && !normalized.endsWith(".spec.ts")
                && !normalized.endsWith(".spec.tsx");
    }

    @Test
    void buildGradleConfiguresCycloneDxAndKeepsH2TestOnly() throws IOException {
        String buildGradle = Files.readString(Path.of("build.gradle"), StandardCharsets.UTF_8);
        assertThat(buildGradle).contains("org.cyclonedx.bom");
        assertThat(buildGradle).contains("runtimeOnly 'org.postgresql:postgresql'");
        assertThat(buildGradle).contains("testImplementation 'com.h2database:h2'");
        assertThat(buildGradle).doesNotContain("implementation 'com.h2database:h2'");
        assertThat(buildGradle).doesNotContain("runtimeOnly 'com.h2database:h2'");
    }

    @Test
    void readMapperIncludesV21LatestIncidentQueueAndWriteMapperIncludesDecideReview() throws IOException {
        String mapperJava = Files.readString(
                Path.of("src/main/java/com/zeekad/dashboard/mapper/zeekad/read/ZeekadReadMapper.java"),
                StandardCharsets.UTF_8);
        String mapperXml = Files.readString(
                Path.of("src/main/resources/mapper/zeekad/read/ZeekadReadMapper.xml"),
                StandardCharsets.UTF_8);
        assertThat(mapperJava).contains("findLatestIncidentQueue")
                .contains("findAnalystReviewByJobAndIncident")
                .contains("findRawFeedbackSummaries");
        assertThat(mapperXml).contains("dashboard.latest_incident_queue").contains("zeekad_report_job_id");
        assertThat(mapperXml).contains("zeekad_thread_parent").contains("zeekad_reply_broadcast");
        assertThat(mapperXml).contains("zeekad_review_resumed_at").contains("zeekad_review_resume_failed");
        assertThat(mapperXml).contains("dashboard.feedback_summary");

        String writeMapperJava = Files.readString(
                Path.of("src/main/java/com/zeekad/dashboard/mapper/zeekad/write/ZeekadWriteMapper.java"),
                StandardCharsets.UTF_8);
        String writeMapperXml = Files.readString(
                Path.of("src/main/resources/mapper/zeekad/write/ZeekadWriteMapper.xml"),
                StandardCharsets.UTF_8);
        assertThat(writeMapperJava).contains("decideReview");
        assertThat(writeMapperXml).contains("dashboard.decide_review").doesNotContain("${");
    }

    @Test
    void thymeleafIsCompletelyRemovedSpaShellExistsAndSensitiveModelFieldsAreJsonIgnored() throws IOException {
        String buildGradle = Files.readString(Path.of("build.gradle"), StandardCharsets.UTF_8);
        assertThat(buildGradle)
                .doesNotContain("spring-boot-starter-thymeleaf")
                .doesNotContain("thymeleaf-extras-springsecurity6")
                .doesNotContain("thymeleaf.version");

        String appYml = Files.readString(Path.of("src/main/resources/application.yml"), StandardCharsets.UTF_8);
        String testYml = Files.readString(Path.of("src/test/resources/application-test.yml"), StandardCharsets.UTF_8);
        assertThat(appYml).doesNotContain("thymeleaf");
        assertThat(testYml).doesNotContain("thymeleaf");

        assertThat(Path.of("src/main/resources/templates")).doesNotExist();
        assertThat(Path.of("src/main/resources/static/css/dashboard.css")).doesNotExist();
        assertThat(Path.of("src/main/java/com/zeekad/dashboard/security/DashboardAuthSuccessHandler.java"))
                .doesNotExist();
        assertThat(Path.of("src/main/java/com/zeekad/dashboard/security/DashboardAuthFailureHandler.java"))
                .doesNotExist();

        Path indexHtml = Path.of("src/main/resources/static/index.html");
        assertThat(indexHtml).exists();
        String indexContent = Files.readString(indexHtml, StandardCharsets.UTF_8);
        assertThat(indexContent)
                .contains("<div id=\"root\"></div>")
                .doesNotContain("<script")
                .doesNotContain("style=");

        String dashboardUserJava = Files.readString(
                Path.of("src/main/java/com/zeekad/dashboard/model/DashboardUser.java"),
                StandardCharsets.UTF_8);
        assertThat(dashboardUserJava)
                .containsPattern("@JsonIgnore\\s+private String passwordHash;")
                .containsPattern("@JsonIgnore\\s+private String totpSecret;");

        String modelScoreJava = Files.readString(
                Path.of("src/main/java/com/zeekad/dashboard/model/zeekad/IncidentModelScore.java"),
                StandardCharsets.UTF_8);
        assertThat(modelScoreJava)
                .containsPattern("@JsonIgnore\\s+private Double maxScore;");
    }

    @Test
    void appCodeDoesNotHardcodeLab20261119OrTestHostIps() throws IOException {
        try (Stream<Path> files = Files.walk(Path.of("src/main"))) {
            List<Path> appFiles = files.filter(Files::isRegularFile).toList();
            assertThat(appFiles).isNotEmpty();
            for (Path file : appFiles) {
                String content = Files.readString(file, StandardCharsets.UTF_8);
                assertThat(content)
                        .as("애플리케이션 소스 %s에 시험 날짜/호스트 IP를 하드코딩하면 안 됩니다", file)
                        .doesNotContain("lab-20261119")
                        .doesNotContain("10.10.0.50")
                        .doesNotContain("10.10.0.10");
            }
        }
    }
}
