package com.zeekad.dashboard.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * 근거 조회 FastAPI 호출용 RestClient 설정(연결/응답 타임아웃 적용).
 */
@Configuration
public class RestClientConfig {

    @Bean(name = "evidenceRestClient")
    public RestClient evidenceRestClient(RestClient.Builder builder, DashboardProperties properties) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(properties.getEvidenceApi().getConnectTimeoutMs());
        requestFactory.setReadTimeout(properties.getEvidenceApi().getReadTimeoutMs());
        return builder
                .baseUrl(properties.getEvidenceApi().getUrl())
                .requestFactory(requestFactory)
                .build();
    }
}
