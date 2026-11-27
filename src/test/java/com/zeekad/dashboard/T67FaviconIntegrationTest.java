package com.zeekad.dashboard;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T67: 첫 화면의 /favicon.ico 404 콘솔 줄을 없앤다. 파일은 frontend/public/favicon.ico 하나이고
 * Vite가 dist/로, processResources가 static/으로 복사한다. 그래서 dist가 있을 때만 돈다(verify는 npm build 뒤에 Gradle을 돌린다).
 * 보안 설정은 넓히지 않았다(/favicon.ico는 이미 permitAll·TOTP 필터 제외·404 셸 제외, CSP img-src 'self').
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T67FaviconIntegrationTest {

    private static final Path SOURCE = Path.of("frontend", "public", "favicon.ico");
    private static final Path DIST = Path.of("frontend", "dist", "favicon.ico");

    @Autowired
    private MockMvc mockMvc;

    @Test
    void anonymousFaviconIs200ImageWithSecurityHeaders() throws Exception {
        Assumptions.assumeTrue(Files.isRegularFile(DIST),
                "frontend/dist/favicon.ico가 없어 건너뜀(npm --prefix frontend run build 뒤에 돈다)");

        MvcResult result = mockMvc.perform(get("/favicon.ico"))
                .andExpect(status().isOk())
                // (c) 정적 파일 응답에도 보안 헤더가 붙는다
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
                .andExpect(header().string("Content-Security-Policy", containsString("img-src 'self'")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"))
                .andExpect(header().string("Cross-Origin-Resource-Policy", "same-origin"))
                .andReturn();

        // (b) 비로그인 200, 이미지 형식, 내용은 저장소의 파일 그대로
        String contentType = result.getResponse().getContentType();
        assertThat(contentType).as("Content-Type").isNotNull().startsWith("image/");
        // 실행 결과로 고정한 값(2026-11-27, Spring 정적 자원 처리기가 확장자로 정한다)
        assertThat(contentType).as("Content-Type").isEqualTo("image/x-icon");
        assertThat(result.getResponse().getContentAsByteArray()).isEqualTo(Files.readAllBytes(SOURCE));
    }
}
