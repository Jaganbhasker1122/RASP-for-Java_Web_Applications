package com.rasplab.rasplab.detection;

import com.rasplab.rasplab.context.HttpRequestContext;
import com.rasplab.rasplab.scoring.CvssScorer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
public class RuleBasedDetector implements RaspDetector {

    private final CvssScorer cvssScorer;

    @Autowired
    public RuleBasedDetector(CvssScorer cvssScorer) {
        this.cvssScorer = cvssScorer;
    }

    @Override
    public DetectionResult analyze(HttpRequestContext ctx) {

        String attackType = "NONE";
        String reason = "Clean request";
        String rawQuery = String.valueOf(ctx.getQuery());
        
        String payload = "";
        try {
            if (ctx.getQuery() != null && !ctx.getQuery().equalsIgnoreCase("null")) {
                payload = URLDecoder.decode(rawQuery, StandardCharsets.UTF_8).toLowerCase();
            }
        } catch (Exception e) {
            payload = rawQuery.toLowerCase();
        }

        // Incorporate Headers into payload check for Header attacks
        StringBuilder headerValues = new StringBuilder();
        if (ctx.getHeaders() != null) {
            for (Map.Entry<String, String> entry : ctx.getHeaders().entrySet()) {
                headerValues.append(entry.getValue().toLowerCase()).append(" ");
            }
        }
        String extendedPayload = payload + " " + headerValues.toString();

        // -------- Attack Detection --------

        if (extendedPayload.contains(" or 1=1") || extendedPayload.contains("union select") || extendedPayload.contains("drop table")) {
            attackType = "SQL Injection";
            reason = "SQLi keyword pattern detected";
        } else if (extendedPayload.contains("<script") || extendedPayload.contains("onerror=") || extendedPayload.contains("javascript:")) {
            attackType = "XSS";
            reason = "Malicious script pattern detected";
        } else if (extendedPayload.contains("; ls") || extendedPayload.contains("&& cat") || extendedPayload.contains("| bash")) {
            attackType = "Command Injection";
            reason = "OS command execution detected";
        } else if (extendedPayload.contains("../") || extendedPayload.contains("..\\") || extendedPayload.contains("c:\\windows")) {
            attackType = "Path Traversal";
            reason = "Directory traversal pattern detected";
        } else if (extendedPayload.contains("/etc/passwd") || extendedPayload.contains("/etc/shadow")) {
            attackType = "Local File Inclusion";
            reason = "Attempt to read local system files";
        } else if ((extendedPayload.contains("http://") || extendedPayload.contains("https://")) && payload.contains("=")) {
            // Rough heuristic for RFI
            attackType = "Remote File Inclusion";
            reason = "Attempt to include remote files";
        } else if (extendedPayload.contains("{\"") && (extendedPayload.contains("$ne") || extendedPayload.contains("$gt"))) {
            attackType = "JSON Injection";
            reason = "NoSQL/JSON injection pattern detected";
        }

        // -------- Calculate Score --------
        double baseCvss = cvssScorer.getScoreForAttack(attackType);
        int riskScore = (int) (baseCvss * 10);

        // Obfuscation Penalty
        if (rawQuery.contains("%") && attackType.equals("NONE")) {
            riskScore += 10;
        }

        // Length Anomaly Penalty
        if (payload.length() > 100 && attackType.equals("NONE")) {
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
