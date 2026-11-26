package com.zeekad.dashboard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T50: 링크 설정이 검사에 걸린 채(https가 아님) 뜬 앱은 시작에 실패하지 않고, 안내문 응답에 link 필드가 없다.
 */
@SpringBootTest(properties = {
        "dashboard.login-notice=안내문은 그대로 내려갑니다.",
        "dashboard.login-notice-link-url=http://example.org/t50-rejected",
        "dashboard.login-notice-link-label=소개 보기"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class T50LoginNoticeLinkRejectedIntegrationTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;

    @Test
    void rejectedLinkIsNotServed() throws Exception {
        MvcResult res = mockMvc.perform(get("/api/auth/login-notice")).andExpect(status().isOk()).andReturn();
        String text = res.getResponse().getContentAsString();
        JsonNode body = objectMapper.readTree(text);
        List<String> names = new ArrayList<>();
        body.fieldNames().forEachRemaining(names::add);
        assertThat(names).as("link 필드 자체가 없다(null로 두지 않는다)").containsExactly("notice");
        assertThat(body.get("notice").asText()).isEqualTo("안내문은 그대로 내려갑니다.");
        assertThat(text).doesNotContain("t50-rejected").doesNotContain("소개 보기").doesNotContain("null");
    }
}
