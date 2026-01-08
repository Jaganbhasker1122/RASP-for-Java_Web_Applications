package com.rasplab.rasplab.detection;

import com.rasplab.rasplab.context.HttpRequestContext;
import org.springframework.stereotype.Component;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

@Component
public class RuleBasedDetector implements RaspDetector {

    @Override
    public DetectionResult analyze(HttpRequestContext ctx) {

        int riskScore = 0;
        String attackType = "NONE";
        String reason = "Clean request";

        // Get raw query
        String rawQuery = String.valueOf(ctx.getQuery());

        // Normalize / decode
        String payload = URLDecoder
                .decode(rawQuery, StandardCharsets.UTF_8)
                .toLowerCase();

        // -------- SQL Injection --------
        if (payload.contains(" or 1=1")
                || payload.contains("union select")) {

            riskScore += 70;
            attackType = "SQL Injection";
            reason = "SQLi keyword pattern detected";
        }

        // -------- XSS --------
        if (payload.contains("<script")
                || payload.contains("onerror=")
                || payload.contains("onload=")
                || payload.contains("javascript:")) {

            riskScore += 60;
            attackType = "XSS";
            reason = "Malicious script pattern detected";
        }

        // -------- Path Traversal --------
        if (payload.contains("../")
                || payload.contains("..\\")
                || payload.contains("/etc/passwd")
                || payload.contains("c:\\windows")) {

            riskScore += 50;
            attackType = "Path Traversal";
            reason = "Directory traversal pattern detected";
        }

        // -------- Obfuscation / Encoding --------
        if (rawQuery.contains("%")) {
            riskScore += 10;
        }

        // -------- Length Anomaly --------
        if (payload.length() > 100) {
            riskScore += 10;
        }

        boolean malicious = riskScore >= 60;

        return new DetectionResult(
                malicious,
                riskScore,
                attackType,
                reason
        );
    }
}
