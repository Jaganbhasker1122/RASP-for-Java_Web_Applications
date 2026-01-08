package com.rasplab.rasplab.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/lab")
public class AttackLabController {

    private static final Logger logger = LoggerFactory.getLogger(AttackLabController.class);

    /**
     * SQL Injection Test Endpoint
     */
    @RequestMapping(value = "/sql", method = { RequestMethod.GET, RequestMethod.POST })
    public String sqlInjectionTest(@RequestParam(value = "input", required = false) String input) {

        if (input == null) {
            return "SQL Lab is active. Use ?input= to test SQL injection payloads.";
        }

        logger.info("[SQL-LAB] Received input: {}", input);
        return "SQL Input received: " + input;
    }

    /**
     * XSS Test Endpoint
     */
    @RequestMapping(value = "/xss", method = { RequestMethod.GET, RequestMethod.POST })
    public String xssTest(@RequestParam(value = "payload", required = false) String payload) {

        if (payload == null) {
            return "XSS Lab is active. Use ?payload= to test XSS payloads.";
        }

        logger.info("[XSS-LAB] Received payload: {}", payload);
        return "XSS Payload received: " + payload;
    }

    /**
     * HTTP Request Analysis Endpoint
     */
    @PostMapping("/http")
    public String httpRequestTest(
            @RequestBody byte[] bodyBytes,
            @RequestHeader(value = "User-Agent", required = false) String userAgent) {

        String body = new String(bodyBytes);

        System.out.println("[HTTP-LAB] User-Agent: " + userAgent);
        System.out.println("[HTTP-LAB] Body: " + body);

        return "HTTP request received";
    }

}