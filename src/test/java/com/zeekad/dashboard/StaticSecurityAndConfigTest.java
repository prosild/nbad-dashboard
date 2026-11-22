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
        assertThat(setupSql.split("LANGUAGE plpgsql SECURITY DEFINER", -1)).hasSize(3);
        assertThat(setupSql.split(Pattern.quote("SET search_path = pg_catalog, pg_temp"), -1)).hasSize(4);
        assertThat(setupSql.toLowerCase(java.util.Locale.ROOT)).doesNotContain("dashboard_rw", "disable trigger",
                "drop trigger", "delete from public.audit_logs", "delete from public.incident_assignment_history",
                "truncate", "grant select", "grant update", "grant insert", "grant delete", "grant create", "grant all");
        for (String text : List.of(setupSql, resetSh)) {
            assertThat(text).doesNotContainPattern("lab-\\d|cic17-|syn1-");
        }
        assertThat(resetSh).contains("PGUSER=zeekad_sandbox_reset", "NOT_CONFIGURED", "--once")
                .doesNotContain("PGPASSWORD=\"${POSTGRES");

        // 쓰기 속도 제한: 네 쓰기 경로의 POST만 정규화된 $uri로, 로그인 제한과 다른 영역
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
                "POST:/api/incidents/42/rank/1/transition/", "POST:/api/reviews/decide/")) {
            assertThat(limited.test(key)).as("쓰기 제한 대상 %s", key).isTrue();
        }
        for (String key : List.of("GET:/api/incidents/42/rank/1/transition", "GET:/api/reviews/decide",
                "POST:/api/auth/login", "GET:/api/incidents/42/rank/1/assignees", "POST:/api/admin/users",
                "POST:/api/incidents/42/rank/1/transition/x")) {
            assertThat(limited.test(key)).as("쓰기 제한 밖 %s", key).isFalse();
        }

        String envExample = Files.readString(Path.of(".env.portfolio.example"), StandardCharsets.UTF_8);
        assertThat(envExample).containsPattern("(?m)^TRIAL_ANALYST_PASSWORD=\r?$")
                .containsPattern("(?m)^SANDBOX_RESET_DB_PASSWORD=\r?$");
        assertThat(envExample).contains("PORTFOLIO_WRITE_RATE=10r/m", "PORTFOLIO_WRITE_BURST=5", "SANDBOX_RESET_INTERVAL_MINUTES=60");
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
