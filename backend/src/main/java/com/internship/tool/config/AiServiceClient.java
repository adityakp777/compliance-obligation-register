// AiServiceClient.java
// AI Developer 3 — AI Service HTTP Client
// Day 6 — Tool-11 Compliance Obligation Register

package com.internship.tool.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

import java.util.Map;

@Component
public class AiServiceClient {

    private static final Logger logger = LoggerFactory.getLogger(AiServiceClient.class);

    private final RestTemplate restTemplate;

    @Value("${ai.service.url:http://localhost:5001}")
    private String aiServiceUrl;

    // ------------------------------------------------------------------ //
    // Constructor                                                          //
    // ------------------------------------------------------------------ //

    public AiServiceClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    // ------------------------------------------------------------------ //
    // Private helper — makes the actual HTTP call                         //
    // ------------------------------------------------------------------ //

    private String post(String endpoint, Map<String, Object> body) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                aiServiceUrl + endpoint,
                HttpMethod.POST,
                request,
                String.class
            );

            return response.getBody();

        } catch (ResourceAccessException e) {
            // AI service is down or timed out
            logger.error("AI service unreachable at {}{}: {}", aiServiceUrl, endpoint, e.getMessage());
            return null;

        } catch (HttpClientErrorException e) {
            // 4xx error from AI service
            logger.warn("AI service returned client error at {}{}: {} — {}",
                aiServiceUrl, endpoint, e.getStatusCode(), e.getResponseBodyAsString());
            return null;

        } catch (HttpServerErrorException e) {
            // 5xx error from AI service
            logger.error("AI service returned server error at {}{}: {} — {}",
                aiServiceUrl, endpoint, e.getStatusCode(), e.getResponseBodyAsString());
            return null;

        } catch (Exception e) {
            // Any other unexpected error
            logger.error("Unexpected error calling AI service at {}{}: {}", aiServiceUrl, endpoint, e.getMessage());
            return null;
        }
    }

    // ------------------------------------------------------------------ //
    // Public methods — one per Flask endpoint                             //
    // ------------------------------------------------------------------ //

    public String describe(String text) {
        logger.info("Calling /describe endpoint");
        return post("/describe", Map.of("description", text));
    }

    public String recommend(String text) {
        logger.info("Calling /recommend endpoint");
        return post("/recommend", Map.of("description", text));
    }

    public String categorise(String text) {
        logger.info("Calling /categorise endpoint");
        return post("/categorise", Map.of("description", text));
    }

    public String generateReport(String text) {
        logger.info("Calling /generate-report endpoint");
        return post("/generate-report", Map.of("description", text));
    }

    public String query(String question) {
        logger.info("Calling /query endpoint");
        return post("/query", Map.of("question", question));
    }
}