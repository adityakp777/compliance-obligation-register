// RestTemplateConfig.java
// AI Developer 3 — RestTemplate Bean with timeout
// Day 6 — Tool-11 Compliance Obligation Register

package com.internship.tool.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate restTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(10_000);   // 10 seconds to connect
        factory.setReadTimeout(10_000);      // 10 seconds to read response
        return new RestTemplate(factory);
    }
}