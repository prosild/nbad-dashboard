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
        // 허용 목록 방식: 첫 규칙이 "*"(모두 뺌)이고, 다시 넣는("!") 항목은 Dockerfile이 복사하는 빌드 입력뿐이다.
        java.util.List<String> ignoreRules = dockerignore.lines().map(String::trim)
                .filter(line -> !line.isEmpty() && !line.startsWith("#")).toList();
        assertThat(ignoreRules).as(".dockerignore 첫 규칙은 *").first().isEqualTo("*");
        assertThat(ignoreRules.stream().filter(line -> line.startsWith("!")).toList())
                .as(".dockerignore가 다시 넣는 항목은 빌드 입력뿐")
                .containsExactlyInAnyOrder("!frontend", "!gradlew", "!settings.gradle", "!build.gradle", "!gradle", "!src/main");
        assertThat(ignoreRules)
                .as("빌드 입력 안의 산출물·캐시·비밀값 모양 파일은 다시 뺀다")
                .contains("frontend/node_modules", "frontend/dist", "frontend/.vite",
                        "**/.env*", "**/*.key", "**/*.pem", "**/*.crt");
        assertThat(ignoreRules.indexOf("**/.env*"))
                .as("비밀값 모양 제외는 다시 넣기(!) 뒤에 있어야 효과가 있다")
                .isGreaterThan(ignoreRules.indexOf("!src/main"));

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
                Path.of("docker/nginx-waf/templates/includes/proxy_backend.conf.template"),
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
                // T29·T33: 잠금은 5회 고정(.env 변수 없음), 비밀번호를 공개한 공유 계정 demo·trial-analyst만 잠금 제외
                "DASHBOARD_MAX_FAILED_ATTEMPTS: \"5\"",
                "DASHBOARD_LOCKOUT_EXEMPT_USERNAMES: ${DASHBOARD_LOCKOUT_EXEMPT_USERNAMES:-demo,trial-analyst}",
                "cap_drop: [ALL]", "no-new-privileges:true", "subnet: ${PORTFOLIO_SUBNET:-10.203.48.0/24}");
        assertThat(compose).doesNotContain("PORTFOLIO_MAX_FAILED_ATTEMPTS:-");
        assertThat(compose).doesNotContainPattern("(?i)DetectionOnly|MODSEC_RULE_ENGINE:\\s*\"?off");

        String httpConf = Files.readString(
                Path.of("docker/portfolio/nginx/zeekad-portfolio-http.conf.template"), StandardCharsets.UTF_8);
        assertThat(httpConf).contains("limit_req_status 429;", "real_ip_header X-Forwarded-For;",
                "real_ip_recursive on;", "\"POST:/api/auth/login\" $binary_remote_addr;");

        // 공유 WAF 템플릿은 변수로만 바뀌고 기본값은 이미지 ENV에 있다(T14: X-Forwarded-For는 모든 스택에서 덮어쓴다).
        String wafDockerfile = Files.readString(Path.of("docker/nginx-waf/Dockerfile"), StandardCharsets.UTF_8);
        assertThat(wafDockerfile).contains("ZEEKAD_PROXY_X_FORWARDED_FOR=\\$remote_addr",
                "ZEEKAD_PROXY_X_FORWARDED_PORT=\\$forwarded_port");
        // T14: 방문자가 붙인 전달 헤더 지우기는 포트폴리오 전용 파일에서 공유 템플릿으로 옮겼다.
        String sharedProxyBackend = Files.readString(
                Path.of("docker/nginx-waf/templates/includes/proxy_backend.conf.template"), StandardCharsets.UTF_8);
        assertThat(sharedProxyBackend).contains("proxy_set_header Forwarded \"\";",
                "proxy_set_header X-Forwarded-Host \"\";", "proxy_set_header X-Forwarded-Prefix \"\";",
                "proxy_set_header X-Forwarded-Ssl \"\";");

        String envExample = Files.readString(Path.of(".env.portfolio.example"), StandardCharsets.UTF_8);
        Pattern filledSecret = Pattern.compile("(?m)^[A-Z0-9_]*(?:PASSWORD|SECRET)=\\S+");
        assertThat(filledSecret.matcher(envExample).find())
                .as(".env.portfolio.example의 비밀값은 비어 있어야 합니다")
                .isFalse();
        for (String requiredVar : List.of(
                "POSTGRES_SUPERUSER_PASSWORD", "ZEEKAD_API_PASSWORD", "DASHBOARD_RO_PASSWORD",
                "DASHBOARD_RW_PASSWORD", "DASHBOARD_APP_PASSWORD", "DEMO_PASSWORD",
                "BOOTSTRAP_VIEWER1_PASSWORD", "BOOTSTRAP_ANALYST1_PASSWORD", "BOOTSTRAP_ANALYST2_PASSWORD",
                "BOOTSTRAP_ADMIN_PASSWORD", "BOOTSTRAP_ADMIN_TOTP_SECRET", "PORTFOLIO_HTTP_PORT", "PORTFOLIO_SUBNET",
                "PORTFOLIO_WAF_IP", "PORTFOLIO_GATEWAY_IP")) {
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
    void wafClientIpAndForwardingHeadersAreNotSpoofableInAnyStack() throws IOException {
        // (a) VMware 스택: WAF가 맨 앞이므로 127.0.0.1만 신뢰하고 사설망 대역을 신뢰하지 않는다.
        String compose = Files.readString(Path.of("compose.yml"), StandardCharsets.UTF_8);
        java.util.regex.Matcher realIpFrom = Pattern.compile("(?m)^\\s*SET_REAL_IP_FROM:\\s*\"([^\"]*)\"").matcher(compose);
        assertThat(realIpFrom.find()).as("compose.yml nginx-waf SET_REAL_IP_FROM").isTrue();
        assertThat(realIpFrom.group(1)).isEqualTo("127.0.0.1");
        assertThat(realIpFrom.find()).as("SET_REAL_IP_FROM은 한 번만").isFalse();
        assertThat(compose).doesNotContain("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "WAF_TRUSTED_PROXIES");
        assertThat(compose).contains("REAL_IP_HEADER: \"X-Forwarded-For\"", "REAL_IP_RECURSIVE: \"on\"");

        // (b) 앱에 넘기는 X-Forwarded-For 기본은 덮어쓰기($remote_addr)이고, 방문자 값 뒤에 덧붙이는 nginx 변수는 어디에도 없다.
        String wafDockerfile = Files.readString(Path.of("docker/nginx-waf/Dockerfile"), StandardCharsets.UTF_8);
        assertThat(wafDockerfile).contains("ZEEKAD_PROXY_X_FORWARDED_FOR=\\$remote_addr");
        List<Path> nginxConfigFiles = new java.util.ArrayList<>();
        try (Stream<Path> rootFiles = Files.list(Path.of("."))) {
            rootFiles.filter(p -> p.getFileName().toString().matches("compose.*\\.ya?ml")).forEach(nginxConfigFiles::add);
        }
        try (Stream<Path> dockerFiles = Files.walk(Path.of("docker"))) {
            dockerFiles.filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".template") || p.toString().endsWith(".yml")
                            || p.getFileName().toString().equals("Dockerfile"))
                    .forEach(nginxConfigFiles::add);
        }
        assertThat(nginxConfigFiles).contains(Path.of("./compose.yml"), Path.of("./compose.portfolio.yml"),
                Path.of("docker/nginx-waf/Dockerfile"), Path.of("docker/verify/compose.verify.yml"));
        for (Path file : nginxConfigFiles) {
            assertThat(Files.readString(file, StandardCharsets.UTF_8))
                    .as("%s에 X-Forwarded-For 덧붙이기 변수가 없어야 합니다", file)
                    .doesNotContain("$proxy_add_x_forwarded_for");
        }

        // (c) 공유 템플릿이 방문자가 붙인 전달 헤더 넷을 지우고, 같은 헤더를 두 번 설정하지 않는다.
        String proxyBackend = Files.readString(
                Path.of("docker/nginx-waf/templates/includes/proxy_backend.conf.template"), StandardCharsets.UTF_8);
        assertThat(proxyBackend).contains("proxy_set_header Forwarded \"\";", "proxy_set_header X-Forwarded-Host \"\";",
                "proxy_set_header X-Forwarded-Prefix \"\";", "proxy_set_header X-Forwarded-Ssl \"\";",
                "proxy_set_header X-Forwarded-For ${ZEEKAD_PROXY_X_FORWARDED_FOR};",
                "proxy_set_header ${REAL_IP_PROXY_HEADER} $remote_addr;");
        List<String> headerNames = proxyBackend.lines()
                .map(String::trim)
                .filter(line -> line.startsWith("proxy_set_header "))
                .map(line -> line.split("\\s+")[1].toLowerCase(java.util.Locale.ROOT))
                .toList();
        assertThat(headerNames).doesNotHaveDuplicates();

        // (d) 업스트림 이름을 요청 때 다시 해석한다: 변수 proxy_pass + 이미지 nginx.conf의 resolver(RESOLVER_CONFIG).
        assertThat(proxyBackend).contains("set $zeekad_backend ${BACKEND};", "proxy_pass $zeekad_backend;")
                .doesNotContainPattern("proxy_pass\\s+\\$\\{BACKEND\\}");
        assertThat(wafDockerfile).contains("RESOLVER_CONFIG=\"valid=10s ipv6=off\"")
                .doesNotContainPattern("(?m)^\\s*(ENV\\s+)?RESOLVERS=");

        // (e) 어느 스택도 dashboard-app 포트를 호스트에 열지 않는다. T32부터 앱은 WAF 고정 주소에서 온 전달 헤더만 믿으므로
        //     이 단언은 유일한 방어가 아니라 겹 방어다(같은 네트워크 컨테이너의 직접 접속은 T32 시험이 덮는다).
        for (Path composeFile : List.of(Path.of("compose.yml"), Path.of("compose.portfolio.yml"),
                Path.of("docker/verify/compose.verify.yml"))) {
            String text = Files.readString(composeFile, StandardCharsets.UTF_8);
            String appBlock = serviceBlock(text, "dashboard-app");
            assertThat(appBlock).as("%s dashboard-app 서비스", composeFile).isNotEmpty();
            assertThat(appBlock).as("%s dashboard-app에 ports:가 없어야 합니다", composeFile)
                    .doesNotContainPattern("(?m)^\\s+ports:");
        }

        // (f) 포트폴리오 전용 전달 헤더 파일과 그 마운트·include가 없다(공유 템플릿으로 옮김).
        assertThat(Path.of("docker/portfolio/nginx/proxy_backend_extra_portfolio.conf.template")).doesNotExist();
        assertThat(Files.readString(Path.of("compose.portfolio.yml"), StandardCharsets.UTF_8)).doesNotContain("proxy_backend_extra");
        assertThat(proxyBackend).doesNotContain("proxy_backend_extra");
        assertThat(wafDockerfile).doesNotContain("proxy_backend_extra");
    }

    @Test
    void wafAuditLogPartsAreSetOnlyInTheWafImageAndExcludeHeadersAndBodies() throws IOException {
        // T59: ModSecurity 감사 로그의 부분은 WAF 이미지 한 곳(Dockerfile의 ENV)에서 정한다. 기반 이미지의 템플릿이 이 환경 값을
        // SecAuditLogParts로 옮긴다(실제로 걸리는지는 scripts/waf-audit-log-check.ps1이 띄운 컨테이너의 렌더된 설정으로 본다).
        Pattern partsAssignment = Pattern.compile("MODSEC_AUDIT_LOG_PARTS=\"?([A-Za-z]*)\"?");
        List<String> partsValues = Files.readString(Path.of("docker/nginx-waf/Dockerfile"), StandardCharsets.UTF_8).lines()
                .filter(line -> !line.trim().startsWith("#"))
                .flatMap(line -> partsAssignment.matcher(line).results().map(match -> match.group(1)))
                .toList();
        assertThat(partsValues).as("WAF Dockerfile의 MODSEC_AUDIT_LOG_PARTS는 한 번만").hasSize(1);
        String parts = partsValues.get(0);
        // 요청 헤더(B), 요청 본문(C, I), 응답 본문(E), 응답 헤더(F)를 적지 않는다: 쿠키·CSRF 토큰·Set-Cookie·본문이 컨테이너 로그에 남는다.
        assertThat(parts).as("감사 로그 부분에 B·C·I·E·F가 없어야 합니다").doesNotContainPattern("(?i)[BCIEF]");
        // 값을 바꾸면 재현 시험(-ExpectedParts)으로 무엇이 남는지 다시 재야 하므로 정한 값 그대로인지 본다.
        assertThat(parts).isEqualTo("AHZ");

        // 다른 곳에서 덮지 않는다: compose 파일(루트와 docker/ 아래)에 그 환경 값이 없고, 저장소의 nginx·ModSecurity 템플릿에
        // SecAuditLogParts나 요청마다 부분을 바꾸는 ctl:auditLogParts가 없다(override 템플릿은 기반 설정 뒤에 읽혀 이긴다).
        List<Path> composeFiles = new java.util.ArrayList<>();
        try (Stream<Path> rootFiles = Files.list(Path.of("."))) {
            rootFiles.filter(p -> p.getFileName().toString().matches("compose.*\\.ya?ml")).forEach(composeFiles::add);
        }
        List<Path> templates = new java.util.ArrayList<>();
        try (Stream<Path> dockerFiles = Files.walk(Path.of("docker"))) {
            dockerFiles.filter(Files::isRegularFile).forEach(p -> {
                if (p.toString().endsWith(".yml") || p.toString().endsWith(".yaml")) {
                    composeFiles.add(p);
                } else if (p.toString().endsWith(".template")) {
                    templates.add(p);
                }
            });
        }
        assertThat(composeFiles).contains(Path.of("./compose.yml"), Path.of("./compose.portfolio.yml"),
                Path.of("docker/verify/compose.verify.yml"));
        for (Path file : composeFiles) {
            assertThat(Files.readString(file, StandardCharsets.UTF_8))
                    .as("%s에서 MODSEC_AUDIT_LOG_PARTS를 주면 이미지의 값을 덮습니다", file)
                    .doesNotContain("MODSEC_AUDIT_LOG_PARTS");
        }
        assertThat(templates).contains(Path.of("docker/nginx-waf/templates/modsecurity.d/modsecurity-override.conf.template"));
        for (Path file : templates) {
            List<String> activeLines = Files.readString(file, StandardCharsets.UTF_8).lines()
                    .filter(line -> !line.trim().startsWith("#"))
                    .toList();
            assertThat(activeLines).as("%s에 감사 로그 부분 지시어가 없어야 합니다", file)
                    .noneMatch(line -> line.toLowerCase(java.util.Locale.ROOT).contains("auditlogparts"));
        }
    }

    @Test
    void t32WafAddressIsFixedAndIsTheOnlyTrustedProxy() throws IOException {
        record Stack(Path compose, String wafVar, String wafDefault, String subnet, String ipRange) {
        }
        for (Stack stack : List.of(
                new Stack(Path.of("compose.yml"), "DASHBOARD_WAF_IP", "10.203.49.250", "10.203.49.0/24", "10.203.49.0/25"),
                new Stack(Path.of("compose.portfolio.yml"), "PORTFOLIO_WAF_IP", "10.203.48.250", "10.203.48.0/24", null))) {
            String text = Files.readString(stack.compose(), StandardCharsets.UTF_8);
            String ref = "${" + stack.wafVar() + ":-" + stack.wafDefault() + "}";
            assertThat(serviceBlock(text, "nginx-waf")).as("%s nginx-waf 고정 주소", stack.compose())
                    .contains("ipv4_address: " + ref);
            assertThat(serviceBlock(text, "dashboard-app")).as("%s 앱 신뢰 목록은 WAF 주소와 같은 변수·기본값", stack.compose())
                    .contains("DASHBOARD_TRUSTED_PROXIES: " + ref);
            assertThat(text.split(java.util.regex.Pattern.quote("DASHBOARD_TRUSTED_PROXIES:"), -1)).hasSize(2);
            assertThat(inCidr(stack.wafDefault(), stack.subnet())).as("기본 WAF 주소는 기본 서브넷 안").isTrue();
            assertThat(text).contains("subnet: ${" + (stack.ipRange() == null ? "PORTFOLIO_SUBNET" : "DASHBOARD_SUBNET")
                    + ":-" + stack.subnet() + "}");
            if (stack.ipRange() != null) {
                assertThat(text).contains("ip_range: ${DASHBOARD_IP_RANGE:-" + stack.ipRange() + "}");
                assertThat(inCidr(stack.wafDefault(), stack.ipRange())).as("WAF 주소는 동적 배정 범위 밖").isFalse();
                assertThat(inCidr("10.203.49.1", stack.ipRange())).isTrue();
            }
        }

        // 공개 스택 WAF는 127.0.0.1과 게이트웨이만 믿는다(서브넷 변수 없음).
        String portfolio = Files.readString(Path.of("compose.portfolio.yml"), StandardCharsets.UTF_8);
        String waf = serviceBlock(portfolio, "nginx-waf");
        java.util.regex.Matcher setRealIp = Pattern.compile("(?m)^\\s*SET_REAL_IP_FROM:\\s*\"([^\"]*)\"").matcher(waf);
        assertThat(setRealIp.find()).isTrue();
        assertThat(setRealIp.group(1)).isEqualTo("127.0.0.1,${PORTFOLIO_GATEWAY_IP:-10.203.48.1}");
        assertThat(setRealIp.find()).as("SET_REAL_IP_FROM은 한 번만").isFalse();
        assertThat(waf).contains("ZEEKAD_GATEWAY_IP: ${PORTFOLIO_GATEWAY_IP:-10.203.48.1}");
        assertThat(inCidr("10.203.48.1", "10.203.48.0/24")).isTrue();
        String template = Files.readString(
                Path.of("docker/portfolio/nginx/zeekad-portfolio-http.conf.template"), StandardCharsets.UTF_8);
        for (String text : List.of(portfolio, template)) {
            assertThat(text).doesNotContain("ZEEKAD_TRUSTED_SUBNET");
        }
        List<String> realIpFrom = template.lines().map(String::trim)
                .filter(line -> line.startsWith("set_real_ip_from")).toList();
        assertThat(realIpFrom).containsExactly("set_real_ip_from 127.0.0.1;", "set_real_ip_from ${ZEEKAD_GATEWAY_IP};");

        // X-Forwarded-Proto·Port는 연결 출처(realip 적용 전 주소)가 127.0.0.1·게이트웨이일 때만 들어온 값을 쓴다.
        assertThat(template.replace("\r", "").replaceAll("[ \\t]+", " ")).contains(
                "geo $realip_remote_addr $zeekad_from_proxy {\n default 0;\n 127.0.0.1 1;\n ${ZEEKAD_GATEWAY_IP} 1;\n}",
                "map \"$zeekad_from_proxy:$http_x_forwarded_proto\" $zeekad_forwarded_proto {\n default $scheme;\n"
                        + " \"1:https\" https;\n}",
                "map \"$zeekad_from_proxy:$http_x_forwarded_proto\" $zeekad_forwarded_port {\n \"1:https\" 443;\n"
                        + " default $forwarded_port;\n}");
        assertThat(template).doesNotContain("map $http_x_forwarded_proto");

        // 앱은 Tomcat RemoteIpValve(native)로 처리하고 Spring framework 전략·Tomcat trusted-proxies 설정을 쓰지 않는다.
        String appYml = Files.readString(Path.of("src/main/resources/application.yml"), StandardCharsets.UTF_8);
        assertThat(appYml).contains("forward-headers-strategy: native", "trusted-proxies: ${DASHBOARD_TRUSTED_PROXIES:}")
                .doesNotContain("framework").doesNotContainPattern("(?m)^\\s*remoteip:");
    }

    @Test
    void t33SandboxResetServiceAndWriteRateLimitInPortfolioStack() throws IOException {
        String compose = Files.readString(Path.of("compose.portfolio.yml"), StandardCharsets.UTF_8);

        // 초기화 서비스: 포트 없음, 모든 capability 제거, 권한 상승 금지, 읽기 전용 루트, 메모리 상한, 같은 postgres 이미지(새 이미지 없음)
        String reset = serviceBlock(compose, "sandbox-reset");
        assertThat(reset).as("sandbox-reset 서비스").isNotBlank()
                .contains("image: ${PORTFOLIO_POSTGRES_IMAGE:-pgvector/pgvector:0.8.1-pg17}",
                        "entrypoint: [\"bash\", \"/sandbox/sandbox-reset.sh\"]", "cap_drop: [ALL]",
                        "security_opt: [\"no-new-privileges:true\"]", "read_only: true", "mem_limit:",
                        "SANDBOX_RESET_INTERVAL_MINUTES: ${SANDBOX_RESET_INTERVAL_MINUTES:-60}",
                        "SANDBOX_RESET_DB_PASSWORD: ${SANDBOX_RESET_DB_PASSWORD:-}", "./docker/portfolio/sandbox:/sandbox:ro")
                .doesNotContain("ports:", "expose:", "profiles:", "POSTGRES_SUPERUSER_PASSWORD", "PGUSER: postgres");
        // 설정 도구: profile seed의 일회용(슈퍼유저), 같은 이미지
        String setup = serviceBlock(compose, "sandbox-setup");
        assertThat(setup).contains("profiles: [\"seed\"]", "image: ${PORTFOLIO_POSTGRES_IMAGE:-pgvector/pgvector:0.8.1-pg17}",
                "entrypoint: [\"bash\", \"/sandbox/sandbox-setup.sh\"]", "cap_drop: [ALL]", "read_only: true",
                "SANDBOX_TRIAL_USERNAME: trial-analyst").doesNotContain("ports:", "restart:");
        assertThat(serviceBlock(compose, "demo-seed")).contains("TRIAL_ANALYST_PASSWORD: ${TRIAL_ANALYST_PASSWORD:-}");

        // 초기화 SQL: SECURITY DEFINER 함수는 search_path 고정(pg_temp 마지막)·PUBLIC 회수, 전용 역할에만 EXECUTE.
        // 기존 쓰기 계정 권한·추가만 하는 기록·트리거·Flyway 표는 건드리지 않고, 캡처 ID를 적지 않는다.
        String setupSql = Files.readString(Path.of("docker/portfolio/sandbox/sandbox-setup.sh"), StandardCharsets.UTF_8);
        String resetSh = Files.readString(Path.of("docker/portfolio/sandbox/sandbox-reset.sh"), StandardCharsets.UTF_8);
        assertThat(setupSql).contains("CREATE OR REPLACE FUNCTION sandbox.reset_pipeline()",
                "CREATE OR REPLACE FUNCTION sandbox.reset_assignments()",
                "REVOKE ALL ON FUNCTION sandbox.reset_pipeline() FROM PUBLIC;",
                "REVOKE ALL ON FUNCTION sandbox.reset_assignments() FROM PUBLIC;",
                "GRANT EXECUTE ON FUNCTION sandbox.reset_pipeline() TO zeekad_sandbox_reset;",
                "GRANT EXECUTE ON FUNCTION sandbox.reset_assignments() TO zeekad_sandbox_reset;",
                "LOCK TABLE zeekad.incident_status, zeekad.incident_status_history, zeekad.analyst_review IN SHARE ROW EXCLUSIVE MODE;",
                "SET lock_timeout = '5s'", "ALTER FUNCTION sandbox.reset_pipeline() OWNER TO zeekad_owner;",
                "ALTER FUNCTION sandbox.reset_assignments() OWNER TO dashboard_app;", "--rebuild-baseline");
        // T56: 정의자 권한 함수가 하나 늘었다(sandbox.reset_response_actions). 설계 변경으로 두 수를 3→4, 4→5로 고쳤다.
        assertThat(setupSql.split("LANGUAGE plpgsql SECURITY DEFINER", -1)).hasSize(4);
        assertThat(setupSql.split(Pattern.quote("SET search_path = pg_catalog, pg_temp"), -1)).hasSize(5);
        assertThat(setupSql.toLowerCase(java.util.Locale.ROOT)).doesNotContain("dashboard_rw", "disable trigger",
                "drop trigger", "delete from public.audit_logs", "delete from public.incident_assignment_history",
                "truncate", "grant select", "grant update", "grant insert", "grant delete", "grant create", "grant all");
        for (String text : List.of(setupSql, resetSh)) {
            assertThat(text).doesNotContainPattern("lab-\\d|cic17-|syn1-");
        }
        assertThat(resetSh).contains("PGUSER=zeekad_sandbox_reset", "NOT_CONFIGURED", "--once")
                .doesNotContain("PGPASSWORD=\"${POSTGRES");

        // 쓰기 속도 제한: 다섯 쓰기 경로(T56: 대응 조치 기록이 더해졌다)의 POST만 정규화된 $uri로, 로그인 제한과 다른 영역
        assertThat(serviceBlock(compose, "nginx-waf")).contains("ZEEKAD_WRITE_RATE: ${PORTFOLIO_WRITE_RATE:-10r/m}",
                "ZEEKAD_WRITE_BURST: ${PORTFOLIO_WRITE_BURST:-5}");
        String template = Files.readString(
                Path.of("docker/portfolio/nginx/zeekad-portfolio-http.conf.template"), StandardCharsets.UTF_8);
        assertThat(template).contains("map \"$request_method:$uri\" $zeekad_write_limit_key {",
                "limit_req_zone $zeekad_write_limit_key zone=zeekad_write:10m rate=${ZEEKAD_WRITE_RATE};",
                "limit_req zone=zeekad_write burst=${ZEEKAD_WRITE_BURST} nodelay;",
                "limit_req zone=zeekad_login burst=${ZEEKAD_LOGIN_BURST} nodelay;");
        List<Pattern> writeKeys = template.lines().map(String::trim)
                .filter(line -> line.startsWith("\"~^POST:") && line.endsWith("$binary_remote_addr;"))
                .map(line -> Pattern.compile(line.substring(2, line.indexOf("\" $binary_remote_addr;"))))
                .toList();
        assertThat(writeKeys).hasSize(2);
        java.util.function.Predicate<String> limited = key -> writeKeys.stream().anyMatch(p -> p.matcher(key).find());
        for (String key : List.of("POST:/api/incidents/42/rank/1/transition", "POST:/api/incidents/42/rank/1/assignment",
                "POST:/api/incidents/42/rank/1/review-decision", "POST:/api/reviews/decide",
                "POST:/api/incidents/42/rank/1/transition/", "POST:/api/reviews/decide/",
                "POST:/api/incidents/42/rank/1/response-actions", "POST:/api/incidents/42/rank/1/response-actions/")) {
            assertThat(limited.test(key)).as("쓰기 제한 대상 %s", key).isTrue();
        }
        for (String key : List.of("GET:/api/incidents/42/rank/1/transition", "GET:/api/reviews/decide",
                "POST:/api/auth/login", "GET:/api/incidents/42/rank/1/assignees", "POST:/api/admin/users",
                "POST:/api/incidents/42/rank/1/transition/x", "GET:/api/incidents/42/rank/1/response-actions",
                "POST:/api/incidents/42/rank/1/response-actions/x", "POST:/api/incidents/42/rank/1/response-action")) {
            assertThat(limited.test(key)).as("쓰기 제한 밖 %s", key).isFalse();
        }

        String envExample = Files.readString(Path.of(".env.portfolio.example"), StandardCharsets.UTF_8);
        assertThat(envExample).containsPattern("(?m)^TRIAL_ANALYST_PASSWORD=\r?$")
                .containsPattern("(?m)^SANDBOX_RESET_DB_PASSWORD=\r?$");
        assertThat(envExample).contains("PORTFOLIO_WRITE_RATE=10r/m", "PORTFOLIO_WRITE_BURST=5", "SANDBOX_RESET_INTERVAL_MINUTES=60");
    }

    @Test
    void t36SandboxTmpfsReadRateLimitOnPublicPathAndSingleHsts() throws IOException {
        String compose = Files.readString(Path.of("compose.portfolio.yml"), StandardCharsets.UTF_8);
        // 익명 볼륨: 이미지 VOLUME 경로를 작은 tmpfs로 덮고 다른 보안 설정은 그대로
        for (String service : List.of("sandbox-setup", "sandbox-reset")) {
            assertThat(serviceBlock(compose, service)).as(service)
                    .contains("tmpfs: [\"/tmp\", \"/var/lib/postgresql/data:size=1m\"]", "read_only: true",
                            "cap_drop: [ALL]", "security_opt: [\"no-new-privileges:true\"]", "user: postgres")
                    .doesNotContain("pgdata");
        }
        // 조회 한도 값은 compose 변수(기본값은 빠른 사람 사용 측정의 3배·2배 이상), 로그인·쓰기 값은 그대로
        assertThat(serviceBlock(compose, "nginx-waf")).contains("ZEEKAD_READ_RATE: ${PORTFOLIO_READ_RATE:-200r/m}",
                "ZEEKAD_READ_BURST: ${PORTFOLIO_READ_BURST:-30}", "ZEEKAD_LOGIN_RATE: ${PORTFOLIO_LOGIN_RATE:-10r/m}",
                "ZEEKAD_WRITE_RATE: ${PORTFOLIO_WRITE_RATE:-10r/m}");
        String envExample = Files.readString(Path.of(".env.portfolio.example"), StandardCharsets.UTF_8);
        assertThat(envExample).contains("PORTFOLIO_READ_RATE=200r/m", "PORTFOLIO_READ_BURST=30");

        String template = Files.readString(
                Path.of("docker/portfolio/nginx/zeekad-portfolio-http.conf.template"), StandardCharsets.UTF_8);
        assertThat(template).contains("map \"$zeekad_from_proxy:$request_method:$uri\" $zeekad_read_limit_key {",
                "limit_req_zone $zeekad_read_limit_key zone=zeekad_read:10m rate=${ZEEKAD_READ_RATE};",
                "limit_req zone=zeekad_read burst=${ZEEKAD_READ_BURST} nodelay;",
                "proxy_hide_header Strict-Transport-Security;");
        List<Pattern> readKeys = template.lines().map(String::trim)
                .filter(line -> line.startsWith("\"~^1:") && line.endsWith("$binary_remote_addr;"))
                .map(line -> Pattern.compile(line.substring(2, line.indexOf("\" $binary_remote_addr;"))))
                .toList();
        assertThat(readKeys).hasSize(1);
        java.util.function.Predicate<String> counted = key -> readKeys.get(0).matcher(key).find();
        for (String key : List.of("1:GET:/api/incidents/queue", "1:HEAD:/api/dashboard/overview",
                "1:GET:/api/incidents/42/rank/1", "1:GET:/api/operations")) {
            assertThat(counted.test(key)).as("조회 한도 대상 %s", key).isTrue();
        }
        // 다른 출처(8443 리스너·스택 안 컨테이너), 쓰기, /api/auth/(설계자 답 1), 정적 파일·SPA 경로는 세지 않는다
        for (String key : List.of("0:GET:/api/incidents/queue", "1:POST:/api/incidents/42/rank/1/transition",
                "1:GET:/api/auth/me", "1:GET:/api/auth/csrf", "1:GET:/api/auth/login-notice", "1:GET:/assets/index.js",
                "1:GET:/incidents/42", "1:GET:/", "1:GET:/api")) {
            assertThat(counted.test(key)).as("조회 한도 밖 %s", key).isFalse();
        }

        // HSTS 숨김 상속이 끊기지 않게 하위 문맥에는 proxy_hide_header가 없고, 8443 리스너는 자기 HSTS를 그대로 붙인다
        for (Path p : List.of(Path.of("docker/nginx-waf/templates/conf.d/default.conf.template"),
                Path.of("docker/nginx-waf/templates/includes/proxy_backend.conf.template"),
                Path.of("docker/nginx-waf/templates/includes/location_common.conf.template"),
                Path.of("docker/nginx-waf/templates/includes/cors.conf.template"))) {
            assertThat(Files.readString(p, StandardCharsets.UTF_8)).as(p.toString()).doesNotContain("proxy_hide_header");
        }
        assertThat(Files.readString(Path.of("docker/nginx-waf/templates/conf.d/default.conf.template"), StandardCharsets.UTF_8))
                .contains("more_set_headers 'Strict-Transport-Security: max-age=31536000; includeSubDomains';");
        assertThat(Files.readString(Path.of("compose.yml"), StandardCharsets.UTF_8))
                .doesNotContain("zeekad-portfolio-http", "ZEEKAD_READ_RATE");
    }

    @Test
    void t60TotpVerifyIsInLoginRateLimitMapAsLiteralLine() throws IOException {
        String template = Files.readString(
                Path.of("docker/portfolio/nginx/zeekad-portfolio-http.conf.template"), StandardCharsets.UTF_8).replace("\r", "");
        // 로그인 제한 map: 기본값과 리터럴 두 줄뿐이다(로그인, 관리자 TOTP 확인). 두 경로가 로그인 영역 하나를 같이 쓴다
        String mapStart = "map \"$request_method:$uri\" $zeekad_login_limit_key {\n";
        assertThat(template).contains(mapStart);
        String loginMap = template.substring(template.indexOf(mapStart) + mapStart.length());
        loginMap = loginMap.substring(0, loginMap.indexOf("\n}"));
        assertThat(loginMap.lines().map(String::trim).filter(line -> !line.isEmpty()).toList()).containsExactly(
                "default \"\";",
                "\"POST:/api/auth/login\" $binary_remote_addr;",
                "\"POST:/api/auth/totp/verify\" $binary_remote_addr;");
        // 그 키를 쓰는 영역과 적용 줄은 하나씩이다
        assertThat(template.split(Pattern.quote("limit_req_zone $zeekad_login_limit_key zone=zeekad_login:10m rate=${ZEEKAD_LOGIN_RATE};"), -1))
                .hasSize(2);
        assertThat(template.split(Pattern.quote("limit_req zone=zeekad_login burst=${ZEEKAD_LOGIN_BURST} nodelay;"), -1)).hasSize(2);
        // 정규식 줄로 쓰지 않았고(쓰기 map의 줄 수를 세는 단언이 깨진다) 등록 확인 경로는 넣지 않았다
        assertThat(template.lines().map(String::trim).filter(line -> line.startsWith("\"~")))
                .noneMatch(line -> line.contains("totp"));
        assertThat(template.lines().filter(line -> !line.trim().startsWith("#"))).noneMatch(line -> line.contains("totp/setup"));
        // VMware 스택에는 이 설정이 붙지 않는다(속도 제한 없음)
        assertThat(Files.readString(Path.of("compose.yml"), StandardCharsets.UTF_8))
                .doesNotContain("zeekad-portfolio-http", "ZEEKAD_LOGIN_RATE");
    }

    private static boolean inCidr(String ip, String cidr) {
        String[] parts = cidr.split("/");
        int bits = Integer.parseInt(parts[1]);
        long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
        return (ipv4ToLong(ip) & mask) == (ipv4ToLong(parts[0]) & mask);
    }

    private static long ipv4ToLong(String ip) {
        long v = 0;
        for (String octet : ip.split("\\.")) {
            v = (v << 8) | Integer.parseInt(octet);
        }
        return v;
    }

    @Test
    void t58AuditRetentionMigrationResetServiceAndContainerLogLimits() throws IOException {
        // V4(PostgreSQL): 트리거는 DELETE 한 경우만 통과(표식 + 30일 바닥값), TRUNCATE 차단, 삭제 함수는 정의자 권한·search_path 고정·PUBLIC 회수
        String v4 = Files.readString(
                Path.of("src/main/resources/db/migration/postgresql/V4__audit_retention.sql"), StandardCharsets.UTF_8);
        assertThat(v4.replace("\r", "").replaceAll("[ \\t]+", " ")).contains(
                "IF TG_OP = 'DELETE' THEN\n IF current_setting('dashboard.audit_retention_purge', true) = 'on'\n"
                        + " AND OLD.occurred_at < CURRENT_TIMESTAMP - INTERVAL '30 days' THEN\n RETURN OLD;",
                "RAISE EXCEPTION 'audit_logs is append-only: % is forbidden', TG_OP;",
                "BEFORE TRUNCATE ON audit_logs\nFOR EACH STATEMENT\nEXECUTE FUNCTION prevent_audit_log_mutation();",
                "CREATE OR REPLACE FUNCTION public.purge_expired_audit_logs(p_retention_days integer)",
                "SECURITY DEFINER\nSET search_path = pg_catalog, pg_temp\nSET lock_timeout = '5s'",
                "IF p_retention_days IS NULL OR p_retention_days < 30 THEN\n RAISE EXCEPTION",
                "PERFORM set_config('dashboard.audit_retention_purge', 'on', true);",
                "PERFORM set_config('dashboard.audit_retention_purge', 'off', true);",
                "REVOKE ALL ON FUNCTION public.purge_expired_audit_logs(integer) FROM PUBLIC;");
        // UPDATE를 통과시키는 가지가 없다(RETURN은 DELETE 가지의 RETURN OLD와 삭제 함수의 RETURN NEXT뿐)
        assertThat(v4).doesNotContain("RETURN NEW").doesNotContainIgnoringCase("disable trigger")
                .doesNotContainIgnoringCase("drop trigger");
        assertThat(v4.split("RETURN OLD;", -1)).hasSize(2);
        // 이력 표·번호 표의 트리거는 V4가 건드리지 않는다.
        assertThat(v4).doesNotContain("incident_assignment_history", "incident_refs");
        // H2 V4는 버전만 맞춘다(삭제 함수·트리거 변경 없음)
        String h2v4 = Files.readString(
                Path.of("src/main/resources/db/migration/h2/V4__audit_retention.sql"), StandardCharsets.UTF_8);
        String h2Statements = h2v4.lines().filter(line -> !line.startsWith("--")).reduce("", (a, b) -> a + b + "\n");
        assertThat(h2Statements).doesNotContainIgnoringCase("create ").doesNotContainIgnoringCase("trigger")
                .doesNotContainIgnoringCase("delete ").doesNotContainIgnoringCase("alias");

        // 앱 코드(Java, MyBatis 매퍼)에는 감사 로그를 지우거나 삭제 함수를 부르는 문장이 없다.
        Pattern auditRemoval = Pattern.compile(
                "(?i)delete\\s+from\\s+(public\\.)?audit_logs|truncate\\s+(table\\s+)?(only\\s+)?(public\\.)?audit_logs"
                        + "|purge_expired_audit_logs\\s*\\(");
        for (Path root : List.of(Path.of("src/main/java"), Path.of("src/main/resources/mapper"))) {
            try (Stream<Path> files = Files.walk(root)) {
                List<Path> sources = files.filter(Files::isRegularFile).toList();
                assertThat(sources).isNotEmpty();
                for (Path file : sources) {
                    assertThat(Files.readString(file, StandardCharsets.UTF_8))
                            .as("앱 코드 %s에 감사 로그 삭제 문장이 없어야 한다", file)
                            .doesNotContainPattern(auditRemoval);
                }
            }
        }
        assertThat(Files.readString(Path.of("src/main/resources/application.yml"), StandardCharsets.UTF_8))
                .doesNotContainIgnoringCase("retention");

        // 설정 도구: 삭제 함수를 만들지 않고 초기화 역할에 EXECUTE만 준다. 함수가 없으면 멈춘다. (금지 글은 t33 시험이 본다)
        String setupSh = Files.readString(Path.of("docker/portfolio/sandbox/sandbox-setup.sh"), StandardCharsets.UTF_8);
        assertThat(setupSh).contains(
                "GRANT EXECUTE ON FUNCTION public.purge_expired_audit_logs(integer) TO zeekad_sandbox_reset;",
                "PURGE_FN='public.purge_expired_audit_logs(integer)'",
                "is missing in zeekad_dashboard; start dashboard-app with migration V4 (Flyway) first\"; exit 1",
                "purge_public_execute=")
                .doesNotContain("FUNCTION public.purge_expired_audit_logs(p_retention_days");
        // GRANT 문은 여덟뿐이다: DB CONNECT 둘, sandbox 스키마 USAGE 둘, 함수 EXECUTE 넷(표 권한 없음).
        // T56: 대응 조치 초기화 함수의 EXECUTE가 더해져 일곱 → 여덟(설계 변경).
        List<String> grants = setupSh.lines().map(String::trim).filter(line -> line.startsWith("GRANT ")).toList();
        assertThat(grants).containsExactly(
                "GRANT CONNECT ON DATABASE zeekad TO $RESET_ROLE;",
                "GRANT CONNECT ON DATABASE zeekad_dashboard TO $RESET_ROLE;",
                "GRANT USAGE ON SCHEMA sandbox TO zeekad_sandbox_reset;",
                "GRANT EXECUTE ON FUNCTION sandbox.reset_pipeline() TO zeekad_sandbox_reset;",
                "GRANT USAGE ON SCHEMA sandbox TO zeekad_sandbox_reset;",
                "GRANT EXECUTE ON FUNCTION sandbox.reset_assignments() TO zeekad_sandbox_reset;",
                "GRANT EXECUTE ON FUNCTION sandbox.reset_response_actions() TO zeekad_sandbox_reset;",
                "GRANT EXECUTE ON FUNCTION public.purge_expired_audit_logs(integer) TO zeekad_sandbox_reset;");

        // 초기화 서비스: 기한 값 검사(정수 30~3650, 아니면 exit 2), 하루 한 번 판정 함수, 있는지·실행 권한 확인 뒤 호출, 감사 칸
        String resetSh = Files.readString(Path.of("docker/portfolio/sandbox/sandbox-reset.sh"), StandardCharsets.UTF_8);
        assertThat(resetSh).contains(
                "AUDIT_DAYS=\"${SANDBOX_AUDIT_RETENTION_DAYS:-}\"",
                "[ \"$AUDIT_DAYS\" -lt 30 ] || [ \"$AUDIT_DAYS\" -gt 3650 ]",
                "audit_purge_decision() {",
                "has_function_privilege(current_user, to_regprocedure('$AUDIT_FN')::oid, 'EXECUTE')",
                "FROM public.purge_expired_audit_logs($AUDIT_DAYS)",
                "to_char(cutoff AT TIME ZONE 'UTC',",
                "[ \"$r_state\" = ERROR ] && overall=ERROR",
                "; audit[$r_state]${r_result:+ $r_result}\"");
        assertThat(resetSh.toLowerCase(java.util.Locale.ROOT)).doesNotContain("delete from", "truncate",
                "disable trigger", "set_config", "dashboard.audit_retention_purge");

        // compose: 공개 데모 기한 90일(고정 값), 모든 서비스에 같은 로그 크기 한도(json-file 10MB x 5)
        String portfolio = Files.readString(Path.of("compose.portfolio.yml"), StandardCharsets.UTF_8);
        assertThat(serviceBlock(portfolio, "sandbox-reset")).contains("SANDBOX_AUDIT_RETENTION_DAYS: \"90\"");
        assertThat(portfolio).doesNotContain("PORTFOLIO_AUDIT_RETENTION");
        record ComposeFile(Path path, List<String> services) { }
        for (ComposeFile file : List.of(
                new ComposeFile(Path.of("compose.portfolio.yml"), List.of("postgres", "api", "dashboard-app", "nginx-waf",
                        "demo-seed", "sandbox-setup", "sandbox-reset")),
                new ComposeFile(Path.of("compose.yml"), List.of("dashboard-app", "nginx-waf")))) {
            String text = Files.readString(file.path(), StandardCharsets.UTF_8).replace("\r", "");
            assertThat(text).as("%s 로그 한도 앵커", file.path()).contains(
                    "x-zeekad-logging: &zeekad-logging\n  driver: json-file\n  options:\n    max-size: \"10m\"\n    max-file: \"5\"\n");
            // 서비스 이름 목록이 파일의 서비스 전부인지 본다(새 서비스가 한도 없이 들어오지 않게).
            String servicesPart = text.substring(text.indexOf("\nservices:\n") + 1);
            List<String> declared = servicesPart.substring(0, indexOfNextTopLevelKey(servicesPart)).lines()
                    .filter(line -> line.matches("^  [A-Za-z0-9_-]+:\\s*$"))
                    .map(line -> line.trim().replace(":", "")).toList();
            assertThat(declared).as("%s 서비스 목록", file.path()).containsExactlyElementsOf(file.services());
            for (String service : file.services()) {
                String block = serviceBlock(text, service);
                assertThat(block.lines().filter(line -> line.equals("    logging: *zeekad-logging")).count())
                        .as("%s %s 로그 한도", file.path(), service).isEqualTo(1);
            }
        }

        // 감사 로그 화면 사전: enum의 모든 유형에 한국어 라벨이 있다(없으면 화면에 "미등록 값"으로 보인다). 역할 칸의 SYSTEM도.
        String labels = Files.readString(Path.of("frontend/src/utils/labels.ts"), StandardCharsets.UTF_8).replace("\r", "");
        String auditDict = labels.substring(labels.indexOf("  auditAction: {"));
        auditDict = auditDict.substring(0, auditDict.indexOf("\n  },"));
        for (com.zeekad.dashboard.model.AuditActionType type : com.zeekad.dashboard.model.AuditActionType.values()) {
            assertThat(auditDict).as("labels.ts auditAction %s", type).containsPattern("\\n    " + type.name() + ": '[^']+',");
        }
        assertThat(auditDict).contains("AUDIT_RETENTION_PURGE: '보관 기한 지난 기록 삭제',", "INCIDENT_ASSIGNMENT: '담당 지정',");
        String roleDict = labels.substring(labels.indexOf("  userRole: {"));
        assertThat(roleDict.substring(0, roleDict.indexOf("\n  },"))).contains("SYSTEM: '시스템',");
    }

    @Test
    void t56ResponseActionMigrationResetFunctionAndNoMutationInAppCode() throws IOException {
        // V5(PostgreSQL): 종류 일곱 CHECK, 트리거는 표식이 있을 때의 DELETE 한 경우만 통과, UPDATE·TRUNCATE는 늘 거부
        String v5 = Files.readString(
                Path.of("src/main/resources/db/migration/postgresql/V5__incident_response_actions.sql"), StandardCharsets.UTF_8);
        String v5Flat = v5.replace("\r", "").replaceAll("[ \\t]+", " ");
        assertThat(v5Flat).contains(
                "CREATE TABLE incident_response_actions (",
                "action_type VARCHAR(32) NOT NULL CHECK (action_type IN (\n"
                        + " 'block_ip', 'isolate_host', 'lock_account', 'handover', 'monitor', 'none', 'other')),",
                "note VARCHAR(500),",
                "CREATE INDEX idx_incident_response_actions_incident ON incident_response_actions (incident_id);",
                "SET search_path = pg_catalog, pg_temp",
                "IF TG_OP = 'DELETE' THEN\n IF current_setting('dashboard.response_actions_reset', true) = 'on' THEN\n RETURN OLD;",
                "RAISE EXCEPTION 'incident_response_actions is append-only: % is forbidden', TG_OP;",
                "BEFORE UPDATE OR DELETE ON incident_response_actions\nFOR EACH ROW\nEXECUTE FUNCTION prevent_response_action_mutation();",
                "BEFORE TRUNCATE ON incident_response_actions\nFOR EACH STATEMENT\nEXECUTE FUNCTION prevent_response_action_mutation();");
        // UPDATE를 통과시키는 가지가 없고 migration이 표식을 켜지 않는다(켜는 것은 초기화 함수뿐). 다른 표의 트리거는 건드리지 않는다.
        assertThat(v5).doesNotContain("RETURN NEW", "set_config", "SECURITY DEFINER", "audit_logs", "incident_assignment")
                .doesNotContainIgnoringCase("disable trigger").doesNotContainIgnoringCase("drop trigger")
                .doesNotContainIgnoringCase("grant ");
        assertThat(v5.split("RETURN OLD;", -1)).hasSize(2);
        // H2 V5: 같은 열·CHECK, 시험 소스의 트리거 클래스가 UPDATE·DELETE를 늘 거부한다
        String h2v5 = Files.readString(
                Path.of("src/main/resources/db/migration/h2/V5__incident_response_actions.sql"), StandardCharsets.UTF_8);
        assertThat(h2v5.replace("\r", "").replaceAll("[ \\t]+", " ")).contains(
                "'block_ip', 'isolate_host', 'lock_account', 'handover', 'monitor', 'none', 'other')),",
                "BEFORE UPDATE, DELETE ON incident_response_actions\nFOR EACH ROW\n"
                        + "CALL \"com.zeekad.dashboard.audit.H2ResponseActionImmutableTrigger\";");

        // 앱 코드(Java, MyBatis 매퍼)에는 대응 조치 기록을 고치거나 지우는 문장, 표식을 켜는 문장, 초기화 함수 호출이 없다.
        Pattern mutation = Pattern.compile(
                "(?i)update\\s+(public\\.)?incident_response_actions|delete\\s+from\\s+(public\\.)?incident_response_actions"
                        + "|truncate\\s+(table\\s+)?(only\\s+)?(public\\.)?incident_response_actions"
                        + "|response_actions_reset|reset_response_actions\\s*\\(");
        for (Path root : List.of(Path.of("src/main/java"), Path.of("src/main/resources/mapper"))) {
            try (Stream<Path> files = Files.walk(root)) {
                List<Path> sources = files.filter(Files::isRegularFile).toList();
                assertThat(sources).isNotEmpty();
                for (Path file : sources) {
                    assertThat(Files.readString(file, StandardCharsets.UTF_8))
                            .as("앱 코드 %s에 대응 조치 기록을 고치거나 지우는 문장이 없어야 한다", file)
                            .doesNotContainPattern(mutation);
                }
            }
        }
        // 매퍼는 넣기와 읽기뿐이다(update·delete 태그 없음). 컨트롤러에는 POST 하나만 있다.
        String mapperXml = Files.readString(
                Path.of("src/main/resources/mapper/app/IncidentResponseActionMapper.xml"), StandardCharsets.UTF_8);
        assertThat(mapperXml).contains("<insert id=\"insert\"", "<select id=\"findByIncidentId\"", "<select id=\"countByIncidentId\"")
                .doesNotContain("<update", "<delete", "${");
        String controller = Files.readString(
                Path.of("src/main/java/com/zeekad/dashboard/controller/IncidentApiController.java"), StandardCharsets.UTF_8);
        assertThat(controller.split("response-actions", -1)).hasSize(2);
        assertThat(controller).contains("@PostMapping(\"/{jobId}/rank/{queueRank}/response-actions\")")
                .doesNotContain("@DeleteMapping", "@PutMapping", "@PatchMapping");

        // 설정 도구: 기준선 표식은 zeek_AD 기준선의 가지 밖에서 정하고(없으면 만들고 --rebuild-baseline이면 다시 잡는다),
        // 표를 잠근 뒤 체험 계정의 행이 0일 때만 넣는다. 초기화 함수는 표식이 없으면 오류를 내고 표식을 켰다가 끈다.
        String setupSh = Files.readString(Path.of("docker/portfolio/sandbox/sandbox-setup.sh"), StandardCharsets.UTF_8);
        assertThat(setupSh).contains(
                "is missing in zeekad_dashboard; start dashboard-app with migration V5 (Flyway) first\"; exit 1",
                "if [ \"$HAS_RA_MARKER\" != \"t\" ] || [ \"$REBUILD\" = \"1\" ]; then",
                "LOCK TABLE public.incident_response_actions IN SHARE ROW EXCLUSIVE MODE;",
                "ALTER TABLE sandbox.response_action_baseline OWNER TO dashboard_app;",
                "REVOKE ALL ON TABLE sandbox.response_action_baseline FROM PUBLIC;",
                "SELECT count(*) AS n FROM public.incident_response_actions WHERE actor_username = :'trial'",
                "FROM trial WHERE trial.n = 0",
                "CREATE OR REPLACE FUNCTION sandbox.reset_response_actions()",
                "RAISE EXCEPTION 'sandbox response action baseline is missing; run sandbox-setup' USING ERRCODE = '55000';",
                "PERFORM set_config('dashboard.response_actions_reset', 'on', true);",
                "DELETE FROM public.incident_response_actions r WHERE r.id > v_max;",
                "PERFORM set_config('dashboard.response_actions_reset', 'off', true);",
                "ALTER FUNCTION sandbox.reset_response_actions() OWNER TO dashboard_app;",
                "REVOKE ALL ON FUNCTION sandbox.reset_response_actions() FROM PUBLIC;",
                "'marker_select=' || has_table_privilege('$RESET_ROLE', 'sandbox.response_action_baseline', 'SELECT')",
                "for v in $Z $D $R; do");
        // 표식을 정하는 자리는 zeek_AD 기준선 가지("baseline kept"로 끝나는 if/else)보다 뒤에 있다(그 가지 밖).
        assertThat(setupSh.indexOf("if [ \"$SET_RA_MARKER\" = \"1\" ]; then"))
                .isGreaterThan(setupSh.indexOf("REFUSED: the baseline does not match the current snapshot"));

        // 초기화 서비스: assignments 칸과 audit 칸 사이의 responses 칸. 미설정은 전체 상태를 바꾸지 않고 ERROR만 전체를 ERROR로 만든다.
        String resetSh = Files.readString(Path.of("docker/portfolio/sandbox/sandbox-reset.sh"), StandardCharsets.UTF_8);
        assertThat(resetSh).contains(
                "RESPONSES_FN='sandbox.reset_response_actions()'",
                "has_function_privilege(current_user, to_regprocedure('$RESPONSES_FN')::oid, 'EXECUTE')",
                "SELECT format('removed=%s', removed) FROM sandbox.reset_response_actions()",
                "[ \"$s_state\" = ERROR ] && overall=ERROR",
                "; assignments[$a_state] $a_result; responses[$s_state]${s_result:+ $s_result}; audit[$r_state]${r_result:+ $r_result}\"");
        assertThat(resetSh).doesNotContain("response_actions_reset", "incident_response_actions");
    }

    @Test
    void t61PortfolioNetworksSplitCapabilitiesDroppedHealthcheckSendsNameHostAndDeviceFactsMasked() throws IOException {
        String compose = Files.readString(Path.of("compose.portfolio.yml"), StandardCharsets.UTF_8).replace("\r", "");
        String vmCompose = Files.readString(Path.of("compose.yml"), StandardCharsets.UTF_8).replace("\r", "");

        // 서비스별 네트워크: 인터넷 요청을 받는 nginx-waf는 portfolio-net에만, DB·근거 API·초기화·시드 도구는 portfolio-data에만 붙는다.
        // 두 네트워크에 붙는 것은 앱뿐이다(WAF의 요청을 받고 DB·근거 API를 부른다).
        record ServiceNetworks(String service, List<String> networks) { }
        for (ServiceNetworks expected : List.of(
                new ServiceNetworks("postgres", List.of("portfolio-data")),
                new ServiceNetworks("api", List.of("portfolio-data")),
                new ServiceNetworks("dashboard-app", List.of("portfolio-net", "portfolio-data")),
                new ServiceNetworks("nginx-waf", List.of("portfolio-net")),
                new ServiceNetworks("demo-seed", List.of("portfolio-data")),
                new ServiceNetworks("sandbox-setup", List.of("portfolio-data")),
                new ServiceNetworks("sandbox-reset", List.of("portfolio-data")))) {
            assertThat(serviceNetworks(serviceBlock(compose, expected.service())))
                    .as("%s 네트워크", expected.service()).containsExactlyElementsOf(expected.networks());
        }

        // 네트워크는 둘이다. portfolio-net은 이미 NAS에 있는 네트워크라 정의 글을 바꾸지 않는다(바뀌면 다시 만들어야 하고 옛 Compose는
        // 차이를 보지 않는다). portfolio-data는 내부 전용(바깥 길 없음)이고 서브넷은 변수로 바꿀 수 있다.
        String networksPart = compose.substring(compose.indexOf("\nnetworks:\n") + 1);
        networksPart = networksPart.substring(0, indexOfNextTopLevelKey(networksPart));
        assertThat(networksPart.lines().filter(line -> line.matches("^  [A-Za-z0-9_-]+:\\s*$")).map(String::trim).toList())
                .containsExactly("portfolio-net:", "portfolio-data:");
        assertThat(networkDefinition(networksPart, "portfolio-net")).isEqualTo(String.join("\n",
                "  portfolio-net:",
                "    driver: bridge",
                "    ipam:",
                "      config:",
                "        # 고정 서브넷: nginx-waf 고정 주소(PORTFOLIO_WAF_IP)와 게이트웨이(PORTFOLIO_GATEWAY_IP)가 이 안에 있어야 한다.",
                "        # NAS의 기존 Docker 네트워크와 겹치지 않게 배포 전에 확인한다(docs/portfolio-deployment.md).",
                "        # 바꾸면 PORTFOLIO_SUBNET과 함께 PORTFOLIO_WAF_IP·PORTFOLIO_GATEWAY_IP도 그 서브넷 안으로 바꾼다.",
                "        - subnet: ${PORTFOLIO_SUBNET:-10.203.48.0/24}",
                ""));
        assertThat(networkDefinition(networksPart, "portfolio-data")).contains(
                "    driver: bridge\n", "    internal: true\n", "        - subnet: ${PORTFOLIO_DATA_SUBNET:-10.203.47.0/24}\n");
        assertThat(Files.readString(Path.of(".env.portfolio.example"), StandardCharsets.UTF_8)).contains("PORTFOLIO_DATA_SUBNET=");

        // 권한: 공개 스택의 모든 서비스와 VMware 스택의 두 서비스가 capability 없이(cap_drop ALL, 되돌리는 cap_add 없음) 권한 상승 금지로 돈다.
        // postgres는 root로 시작하지 않는다(sandbox-*와 같은 꼴. 진입 스크립트가 chown·gosu를 건너뛴다).
        record ComposeServices(String name, String text, List<String> services) { }
        for (ComposeServices file : List.of(
                new ComposeServices("compose.portfolio.yml", compose, List.of("postgres", "api", "dashboard-app", "nginx-waf",
                        "demo-seed", "sandbox-setup", "sandbox-reset")),
                new ComposeServices("compose.yml", vmCompose, List.of("dashboard-app", "nginx-waf")))) {
            for (String service : file.services()) {
                assertThat(serviceBlock(file.text(), service)).as("%s %s 권한", file.name(), service)
                        .contains("    cap_drop: [ALL]\n", "    security_opt: [\"no-new-privileges:true\"]\n")
                        .doesNotContain("cap_add", "privileged");
            }
        }
        assertThat(serviceBlock(compose, "postgres")).contains("    user: postgres\n");

        // WAF 상태 확인 세 곳은 이름 Host를 보낸다(숫자 주소 Host는 CRS 920350에 걸려 200이어도 감사 줄이 남았다). 접속 주소는 127.0.0.1 그대로.
        String healthTest = "test: [\"CMD\", \"wget\", \"-q\", \"--spider\", \"--header\", \"Host: localhost\", \"http://127.0.0.1:8080/healthz\"]";
        assertThat(serviceBlock(compose, "nginx-waf")).contains(healthTest);
        assertThat(serviceBlock(vmCompose, "nginx-waf")).contains(healthTest);
        String wafDockerfile = Files.readString(Path.of("docker/nginx-waf/Dockerfile"), StandardCharsets.UTF_8);
        assertThat(wafDockerfile).contains("CMD wget -q --spider --header \"Host: localhost\" http://127.0.0.1:8080/healthz || exit 1");
        Pattern oldHealthcheck = Pattern.compile("--spider(\"\\s*,\\s*\"|\\s+)http://127\\.0\\.0\\.1:8080/healthz");
        for (String text : List.of(compose, vmCompose, wafDockerfile)) {
            assertThat(oldHealthcheck.matcher(text).find()).as("Host 없이 /healthz를 치는 옛 상태 확인").isFalse();
        }
        // 규칙을 끄거나 예외를 두어 줄을 없애지 않았다.
        for (Path p : List.of(Path.of("docker/nginx-waf/templates/includes/location_common.conf.template"),
                Path.of("docker/nginx-waf/templates/modsecurity.d/modsecurity-override.conf.template"),
                Path.of("docker/portfolio/nginx/zeekad-portfolio-http.conf.template"))) {
            assertThat(Files.readString(p, StandardCharsets.UTF_8)).as(p.toString())
                    .doesNotContain("modsecurity off").doesNotContain("SecRuleRemoveById").doesNotContain("920350");
        }

        // 운영 기기 정보(모델명, DSM·Docker·Compose 판, 절대 경로, 여유 자원 수치)는 배포 문서와 설정에 적지 않는다.
        // 대상은 명시 목록이다(저장소 전체를 훑으면 node_modules·build·로컬 handoff/·이 시험 파일 자신이 걸린다).
        List<Path> targets = new java.util.ArrayList<>(List.of(Path.of("compose.portfolio.yml"), Path.of("compose.yml"),
                Path.of("README.md"), Path.of(".env.portfolio.example"), Path.of(".env.example")));
        try (Stream<Path> files = Files.walk(Path.of("docs"))) {
            files.filter(Files::isRegularFile).filter(p -> p.toString().endsWith(".md")).forEach(targets::add);
        }
        for (Path root : List.of(Path.of("scripts"), Path.of("docker"))) {
            try (Stream<Path> files = Files.walk(root)) {
                files.filter(Files::isRegularFile).filter(StaticSecurityAndConfigTest::isDeviceFactsTextFile).forEach(targets::add);
            }
        }
        assertThat(targets).hasSizeGreaterThan(20);
        Pattern deviceFacts = Pattern.compile("DS920|/volume1|DSM 7\\.\\d|Compose v2\\.\\d|Docker 24|17GB|1\\.5TB");
        for (Path file : targets) {
            assertThat(file).exists();
            assertThat(Files.readString(file, StandardCharsets.UTF_8)).as("%s에 운영 기기 정보", file).doesNotContainPattern(deviceFacts);
        }
    }

    /** 서비스 블록의 networks: 아래 이름들(목록 꼴 "- 이름"과 지도 꼴 "이름:" 모두). */
    private static List<String> serviceNetworks(String block) {
        List<String> names = new java.util.ArrayList<>();
        boolean inside = false;
        for (String line : block.lines().toList()) {
            if (line.equals("    networks:")) {
                inside = true;
                continue;
            }
            if (!inside || line.isBlank() || line.trim().startsWith("#")) {
                continue;
            }
            if (!line.startsWith("      ")) {
                break;
            }
            java.util.regex.Matcher m = Pattern.compile("^      (?:- )?([A-Za-z0-9_-]+):?\\s*$").matcher(line);
            if (m.matches()) {
                names.add(m.group(1));
            }
        }
        return names;
    }

    /** 최상위 networks: 아래 한 네트워크의 정의 글(이름 줄부터 들여쓰기 4칸 이상인 줄까지, 줄 끝 \n 포함). */
    private static String networkDefinition(String networksPart, String name) {
        StringBuilder block = new StringBuilder();
        boolean inside = false;
        for (String line : networksPart.lines().toList()) {
            if (line.equals("  " + name + ":")) {
                inside = true;
                block.append(line).append('\n');
                continue;
            }
            if (inside && !line.startsWith("    ")) {
                break;
            }
            if (inside) {
                block.append(line).append('\n');
            }
        }
        return block.toString();
    }

    private static boolean isDeviceFactsTextFile(Path path) {
        String name = path.getFileName().toString();
        return name.equals("Dockerfile") || name.endsWith(".sh") || name.endsWith(".sql") || name.endsWith(".template")
                || name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".py") || name.endsWith(".ps1")
                || name.endsWith(".conf") || name.endsWith(".md") || name.endsWith(".txt") || name.endsWith(".json");
    }

    /** services: 줄로 시작하는 글에서 다음 최상위 키(들여쓰기 없는 줄. 주석 제외)가 시작하는 위치. 없으면 끝. */
    private static int indexOfNextTopLevelKey(String fromServicesLine) {
        int pos = fromServicesLine.indexOf('\n') + 1;
        while (pos < fromServicesLine.length()) {
            int next = fromServicesLine.indexOf('\n', pos);
            String line = next < 0 ? fromServicesLine.substring(pos) : fromServicesLine.substring(pos, next);
            if (!line.isEmpty() && !Character.isWhitespace(line.charAt(0)) && !line.startsWith("#")) {
                return pos;
            }
            if (next < 0) {
                break;
            }
            pos = next + 1;
        }
        return fromServicesLine.length();
    }

    @Test
    void t54SeedRecordsExamplesOnlyThroughTheAppApiAndKeepsNoNewSecret() throws IOException {
        String seedPy = Files.readString(Path.of("docker/portfolio/seed/seed_demo.py"), StandardCharsets.UTF_8);

        // (a) 시드가 SQL로 쓰는 표는 users와 그 감사 행(audit_logs)뿐이다. zeek_AD 표·대응 조치·담당·번호 표에는 SQL로 쓰지 않고
        //     zeek_AD 쓰기 함수도 부르지 않는다(예시의 기록은 모두 앱 API를 거친다).
        java.util.regex.Matcher dml = Pattern.compile("(?i)\\b(insert\\s+into|update|delete\\s+from|truncate(?:\\s+table)?)\\s+([a-z_][a-z0-9_.]*)")
                .matcher(seedPy);
        java.util.Set<String> written = new java.util.TreeSet<>();
        while (dml.find()) {
            written.add(dml.group(2).toLowerCase(java.util.Locale.ROOT));
        }
        assertThat(written).as("시드가 SQL로 쓰는 표").containsExactlyInAnyOrder("users", "audit_logs");
        assertThat(seedPy).doesNotContainPattern("(?i)transition_incident|decide_review|reset_pipeline|reset_assignments"
                + "|reset_response_actions|response_actions_reset|incident_refs|set_config");
        // users 표를 바꾸는 문장은 모두 sql_change(같은 트랜잭션의 감사 행)로 넘긴다. execute에 바로 넘기는 문장은 SELECT와 감사 INSERT뿐이다.
        java.util.regex.Matcher updUsers = Pattern.compile("UPDATE users SET").matcher(seedPy);
        int userUpdates = 0;
        while (updUsers.find()) {
            userUpdates++;
            String before = seedPy.substring(Math.max(0, updUsers.start() - 400), updUsers.start());
            assertThat(before).as("UPDATE users #%d는 sql_change 호출 안에 있어야 한다", userUpdates).contains("sql_change(");
        }
        assertThat(userUpdates).isGreaterThanOrEqualTo(5);
        java.util.regex.Matcher exec = Pattern.compile("conn\\.execute\\(\\s*(\"[^\"]*|[a-z_]+)").matcher(seedPy);
        List<String> execHeads = new java.util.ArrayList<>();
        while (exec.find()) {
            execHeads.add(exec.group(1));
        }
        assertThat(execHeads).isNotEmpty().allSatisfy(head -> assertThat(head)
                .matches("\"SELECT .*|\"INSERT INTO audit_logs .*|statement"));
        assertThat(execHeads.stream().filter("statement"::equals).count()).isEqualTo(1);
        // zeekad는 앱과 같은 읽기 계정으로 읽기 전용 연결에서만 읽는다.
        assertThat(seedPy).contains("user=\"dashboard_ro\"", "password=env(\"DASHBOARD_RO_PASSWORD\")", "conn.read_only = True");

        // (b) demo-analyst의 비밀번호는 실행마다 무작위로 만들고 출력·저장하지 않는다: 로그·print에 비밀번호·비밀값 변수가 없고 쓰는 파일이 없다.
        java.util.regex.Matcher logCall = Pattern.compile("(?s)\\b(log|print)\\((.*?)\\)\\s*\\n").matcher(seedPy);
        int logCalls = 0;
        while (logCall.find()) {
            logCalls++;
            assertThat(logCall.group(2)).as("로그 호출 %s", logCall.group(2))
                    .doesNotContainPattern("\\{[^}]*(?i:password|secret|token|cookie)[^}]*}")
                    .doesNotContain("startReason", "closeReason", "responseAction", "\"note\"", "cookies");
        }
        assertThat(logCalls).isGreaterThan(20);
        assertThat(seedPy).contains("secrets.token_urlsafe(32)").doesNotContainPattern("open\\([^)]*[\"'][wax]b?\\+?[\"']")
                .doesNotContain("os.environ[\"DEMO_ANALYST", "DEMO_ANALYST_PASSWORD", "sys.argv");
        String envExample = Files.readString(Path.of(".env.portfolio.example"), StandardCharsets.UTF_8);
        assertThat(envExample).doesNotContain("DEMO_ANALYST").doesNotContain("demo-analyst");
        // 시연 분석가는 잠금 제외가 아니다(비밀번호를 공개한 공유 계정만 뺀다).
        String compose = Files.readString(Path.of("compose.portfolio.yml"), StandardCharsets.UTF_8);
        assertThat(compose).contains("DASHBOARD_LOCKOUT_EXEMPT_USERNAMES: ${DASHBOARD_LOCKOUT_EXEMPT_USERNAMES:-demo,trial-analyst}");

        // (c) demo-seed 블록의 환경 값: T54는 읽기 계정 비밀번호 하나만 더했다(새 비밀값이 아니다. 앱의 ZEEKAD_RO_PASSWORD와 같은 값).
        String seedBlock = serviceBlock(compose, "demo-seed");
        List<String> envKeys = seedBlock.lines().filter(line -> line.matches("^ {6}[A-Z0-9_]+: .*"))
                .map(line -> line.trim().substring(0, line.trim().indexOf(':'))).toList();
        assertThat(envKeys).containsExactlyInAnyOrder("SEED_API_BASE_URL", "SEED_DB_HOST", "SEED_DB_PORT",
                "DASHBOARD_APP_PASSWORD", "DASHBOARD_RO_PASSWORD", "DEMO_PASSWORD", "DEMO_DISPLAY_NAME",
                "TRIAL_ANALYST_PASSWORD", "TRIAL_ANALYST_DISPLAY_NAME", "DEMO_CAPTURE_PATTERNS",
                "BOOTSTRAP_VIEWER1_PASSWORD", "BOOTSTRAP_ANALYST1_PASSWORD", "BOOTSTRAP_ANALYST2_PASSWORD",
                "BOOTSTRAP_ADMIN_PASSWORD", "BOOTSTRAP_ADMIN_TOTP_SECRET");
        assertThat(seedBlock).contains("      DASHBOARD_RO_PASSWORD: ${DASHBOARD_RO_PASSWORD:-}",
                "./docker/portfolio/seed:/seed:ro");
        assertThat(serviceBlock(compose, "dashboard-app")).contains("ZEEKAD_RO_PASSWORD: ${DASHBOARD_RO_PASSWORD:-}");

        // (d) 자료 파일: 인시던트 ID 꼴, 판정 값, 정탐은 대응 조치(메모 필수인 종류면 메모), 글 끝 "(시연)" 관례, 500자 이하, ID 중복 없음.
        com.fasterxml.jackson.databind.JsonNode doc = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(Path.of("docker/portfolio/seed/demo_examples.json").toFile());
        com.fasterxml.jackson.databind.JsonNode examples = doc.get("examples");
        assertThat(examples).isNotNull();
        assertThat(examples.isArray()).isTrue();
        assertThat(examples.size()).isEqualTo(3);
        Pattern idShape = Pattern.compile("^lab-\\d{8}\\|10\\.10\\.0\\.\\d{1,3}\\|(originator|responder)\\|\\d{10}$");
        java.util.Set<String> ids = new java.util.HashSet<>();
        java.util.Map<String, Integer> byResolution = new java.util.TreeMap<>();
        for (com.fasterxml.jackson.databind.JsonNode ex : examples) {
            String id = ex.path("incidentId").asText();
            String resolution = ex.path("resolution").asText();
            assertThat(id).as("예시 %s의 인시던트 ID", ex.path("key").asText()).matches(idShape);
            assertThat(ids.add(id)).as("중복 ID %s", id).isTrue();
            assertThat(resolution).isIn("true_positive", "false_positive", "benign");
            byResolution.merge(resolution, 1, Integer::sum);
            List<String> texts = new java.util.ArrayList<>(List.of(ex.path("startReason").asText(), ex.path("closeReason").asText()));
            com.fasterxml.jackson.databind.JsonNode action = ex.get("responseAction");
            if ("true_positive".equals(resolution)) {
                assertThat(action).as("정탐 예시 %s의 대응 조치", id).isNotNull();
            }
            if (action != null) {
                assertThat(action.path("action").asText()).isIn("block_ip", "isolate_host", "lock_account", "handover",
                        "monitor", "none", "other");
                texts.add(action.path("note").asText());
            }
            for (String text : texts) {
                assertThat(text).as("예시 %s의 글", id).isNotBlank().endsWith("(시연)");
                assertThat(text.codePointCount(0, text.length())).isLessThanOrEqualTo(500);
            }
        }
        assertThat(byResolution).containsEntry("true_positive", 2).containsEntry("false_positive", 1);
    }

    private static String serviceBlock(String compose, String service) {
        List<String> lines = compose.lines().toList();
        StringBuilder block = new StringBuilder();
        boolean inside = false;
        for (String line : lines) {
            if (line.equals("  " + service + ":")) {
                inside = true;
                continue;
            }
            if (inside && line.matches("^ {0,2}\\S.*") && !line.trim().startsWith("#")) {
                break;
            }
            if (inside) {
                block.append(line).append('\n');
            }
        }
        return block.toString();
    }

    @Test
    void wafDockerfilePinsBaseByDigestAndUpgradesOnlyLibxml2() throws IOException {
        // T31: 기반은 태그+digest로 고정하고, libxml2만 고친 판의 하한으로 올린다(전체 apk upgrade 없음).
        String waf = Files.readString(Path.of("docker/nginx-waf/Dockerfile"), StandardCharsets.UTF_8);
        List<String> lines = waf.lines().map(String::trim)
                .filter(line -> !line.isEmpty() && !line.startsWith("#")).toList();
        List<String> froms = lines.stream().filter(line -> line.startsWith("FROM ")).toList();
        assertThat(froms).hasSize(1);
        assertThat(froms.get(0)).as("WAF 기반은 태그와 digest를 함께 쓴다")
                .matches("^FROM owasp/modsecurity-crs:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$");
        List<String> users = lines.stream().filter(line -> line.startsWith("USER ")).toList();
        assertThat(users).as("마지막 USER는 nginx").last().isEqualTo("USER nginx");
        assertThat(lines).anyMatch(line -> line.startsWith("RUN ")
                && line.contains("apk add --no-cache --upgrade 'libxml2>=2.13.9-r3'"));
        assertThat(lines).as("WAF 이미지에서 전체 apk upgrade 금지")
                .noneMatch(line -> line.matches(".*\\bapk\\s+upgrade\\b.*"));
        assertThat(waf).contains("HEALTHCHECK", "RESOLVER_CONFIG=\"valid=10s ipv6=off\"");
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
        // 캡처 표시 이름 사전에 한해 실습망 캡처 ID를 앱 코드에 둔다(2026-11-21 결정, T20). 허용은 이 파일 하나뿐이다.
        Path captureNameDictionary = Path.of("frontend/src/utils/labels.ts");
        assertThat(captureNameDictionary).exists();
        for (Path file : targets) {
            String content = Files.readString(file, StandardCharsets.UTF_8);
            if (!file.normalize().equals(captureNameDictionary.normalize())) {
                assertThat(content)
                        .as("프론트엔드 프로덕션 파일 %s에는 실습망 캡처 ID를 두지 않습니다(캡처 표시 이름 사전 파일만 예외)", file)
                        .doesNotContain("lab-20261119");
            }
            assertThat(content)
                    .as("프론트엔드 프로덕션 파일 %s는 엄격한 CSP/XSS/도메인 규칙을 준수해야 합니다", file)
                    .doesNotContain("dangerouslySetInnerHTML")
                    .doesNotContain("innerHTML")
                    .doesNotContain("eval(")
                    .doesNotContain("new Function")
                    .doesNotContain("style={{")
                    .doesNotContain("style=\"")
                    .doesNotContain("정확도")
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
