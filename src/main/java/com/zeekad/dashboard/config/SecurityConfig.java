package com.zeekad.dashboard.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zeekad.dashboard.security.ApiRequestUtils;
import com.zeekad.dashboard.security.DashboardAuthenticationProvider;
import com.zeekad.dashboard.security.SessionTimeoutFilter;
import com.zeekad.dashboard.security.SpaCsrfTokenRequestHandler;
import com.zeekad.dashboard.security.TotpEnforcementFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.NullRequestCache;
import com.zeekad.dashboard.security.SpaShell;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.CrossOriginEmbedderPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;

/**
 * Spring Security 웹 보안 설정(JSON API + SPA 폴백, 세션 고정 방지, SPA CSRF, 보안 응답 헤더, 역할 인가).
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final String CSP_POLICY =
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                    + "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; "
                    + "form-action 'self'; frame-ancestors 'none'";

    @Bean
    public PasswordEncoder passwordEncoder(DashboardProperties properties) {
        return new BCryptPasswordEncoder(properties.getSecurity().getBcryptStrength());
    }

    @Bean
    public AuthenticationManager authenticationManager(DashboardAuthenticationProvider authProvider) {
        return new ProviderManager(authProvider);
    }

    @Bean
    public CookieCsrfTokenRepository csrfTokenRepository(ServerProperties serverProperties) {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        Boolean secureProp = serverProperties.getServlet().getSession().getCookie().getSecure();
        boolean cookieSecure = secureProp != null ? secureProp : true;
        repository.setCookieCustomizer(cookie -> cookie
                .sameSite("Lax")
                .secure(cookieSecure));
        return repository;
    }

    @Bean
    public SpaCsrfTokenRequestHandler spaCsrfTokenRequestHandler() {
        return new SpaCsrfTokenRequestHandler();
    }

    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy(
            CookieCsrfTokenRepository csrfTokenRepository,
            SpaCsrfTokenRequestHandler spaCsrfTokenRequestHandler) {
        CsrfAuthenticationStrategy csrfStrategy = new CsrfAuthenticationStrategy(csrfTokenRepository);
        csrfStrategy.setRequestHandler(spaCsrfTokenRequestHandler);
        return new CompositeSessionAuthenticationStrategy(List.of(
                new ChangeSessionIdAuthenticationStrategy(),
                csrfStrategy
        ));
    }

    @Bean
    public HttpSessionSecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   CookieCsrfTokenRepository csrfTokenRepository,
                                                   SpaCsrfTokenRequestHandler spaCsrfTokenRequestHandler,
                                                   HttpSessionSecurityContextRepository securityContextRepository,
                                                   SessionTimeoutFilter sessionTimeoutFilter,
                                                   TotpEnforcementFilter totpEnforcementFilter,
                                                   ObjectMapper objectMapper) throws Exception {
        RequestMatcher apiRequestMatcher = ApiRequestUtils::isApiRequest;
        AuthenticationEntryPoint apiEntryPoint = (request, response, authException) ->
                ApiRequestUtils.writeJsonError(
                        response,
                        objectMapper,
                        HttpServletResponse.SC_UNAUTHORIZED,
                        "UNAUTHENTICATED",
                        "인증이 필요합니다. 로그인해 주세요.");
        AccessDeniedHandler jsonAccessDeniedHandler = (request, response, accessDeniedException) ->
                ApiRequestUtils.writeJsonError(
                        response,
                        objectMapper,
                        HttpServletResponse.SC_FORBIDDEN,
                        "FORBIDDEN",
                        "요청하신 기능을 수행할 권한이 없습니다.");

        AuthenticationEntryPoint spaShellEntryPoint = (request, response, authException) ->
                SpaShell.forward(request, response);

        http
                // T27: 원래 주소를 서버 세션에 저장하지 않는다(익명 요청마다 세션을 만들지 않게)
                .requestCache(cache -> cache.requestCache(new NullRequestCache()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/index.html", "/assets/**", "/favicon.ico", "/error").permitAll()
                        .requestMatchers(HttpMethod.GET, "/login", "/api/auth/csrf", "/api/auth/me").permitAll()
                        // T21: 로그인 화면 안내 문구(로그인 전 GET 하나만, 응답은 문구와 T50의 검사한 링크 하나뿐)
                        .requestMatchers(HttpMethod.GET, "/api/auth/login-notice").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/logout").permitAll()
                        .requestMatchers("/api/auth/totp/**", "/api/admin/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET,
                                "/login/totp", "/login/totp/setup", "/admin/users", "/admin/audit-logs",
                                // T52 중요 자산 관리 화면. 정적 파일 경로 /assets/** 와 겹치지 않는 이름
                                "/admin/critical-assets")
                        .hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .securityContext(ctx -> ctx.securityContextRepository(securityContextRepository))
                .sessionManagement(session -> session
                        .sessionFixation(fixation -> fixation.changeSessionId())
                )
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository)
                        .csrfTokenRequestHandler(spaCsrfTokenRequestHandler)
                )
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(CSP_POLICY))
                        .contentTypeOptions(Customizer.withDefaults())
                        .frameOptions(frame -> frame.deny())
                        .referrerPolicy(referrer -> referrer.policy(
                                ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                        .crossOriginOpenerPolicy(coop -> coop.policy(
                                CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN))
                        .crossOriginEmbedderPolicy(coep -> coep.policy(
                                CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP))
                        .crossOriginResourcePolicy(corp -> corp.policy(
                                CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy.SAME_ORIGIN))
                        .addHeaderWriter(new StaticHeadersWriter(
                                "Permissions-Policy",
                                "camera=(), microphone=(), geolocation=(), payment=(), usb=()"))
                )
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(apiEntryPoint, apiRequestMatcher)
                        // T27: 화면 경로를 새로 연 비로그인 GET·HEAD는 302 대신 셸 200(화면이 원래 주소를 싣고 로그인으로 보낸다)
                        .defaultAuthenticationEntryPointFor(spaShellEntryPoint, SpaShell::isShellRequest)
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"), AnyRequestMatcher.INSTANCE)
                        .defaultAccessDeniedHandlerFor(jsonAccessDeniedHandler, apiRequestMatcher)
                        .defaultAccessDeniedHandlerFor(jsonAccessDeniedHandler, AnyRequestMatcher.INSTANCE)
                )
                .addFilterAfter(sessionTimeoutFilter, HeaderWriterFilter.class)
                .addFilterAfter(totpEnforcementFilter, SessionTimeoutFilter.class);

        return http.build();
    }
}
