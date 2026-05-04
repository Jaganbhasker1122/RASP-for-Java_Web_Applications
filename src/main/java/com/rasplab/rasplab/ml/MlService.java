package com.rasplab.rasplab.ml;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class MlService {

    private final String ML_API_URL = "http://localhost:5000/predict";
    private final RestTemplate restTemplate;

    public MlService() {
        this.restTemplate = new RestTemplate();
    }

    public double getProbability(String payload) {
        if (payload == null || payload.isEmpty()) return 0.0;
        
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("payload", payload);

            HttpEntity<Map<String, String>> request = new HttpEntity<>(requestBody, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(ML_API_URL, request, Map.class);
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Object probObj = response.getBody().get("probability");
                if (probObj instanceof Number) {
                    return ((Number) probObj).doubleValue();
                }
            }
        } catch (Exception e) {
            System.err.println("[ML-SERVICE-ERR] Could not reach ML API: " + e.getMessage());
        }
        return 0.0;
    }
}
