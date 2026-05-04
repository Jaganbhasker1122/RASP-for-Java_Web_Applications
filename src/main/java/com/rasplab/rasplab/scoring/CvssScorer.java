package com.rasplab.rasplab.scoring;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class CvssScorer {

    private final Map<String, Double> cvssBaseScores;

    public CvssScorer() {
        cvssBaseScores = new HashMap<>();
        // High Severity
        cvssBaseScores.put("Command Injection", 9.8);
        cvssBaseScores.put("SQL Injection", 9.0);
        cvssBaseScores.put("Remote File Inclusion", 9.8);
        
        // Medium/High
        cvssBaseScores.put("Local File Inclusion", 8.0);
        cvssBaseScores.put("Path Traversal", 8.0);
        
        // Medium
        cvssBaseScores.put("XSS", 7.5);
        cvssBaseScores.put("JSON Injection", 6.0);
        cvssBaseScores.put("Header Modification", 5.0);
        
        // Low/None
        cvssBaseScores.put("Scanner/Bot Activity", 4.0);
        cvssBaseScores.put("Anomaly", 3.0);
        cvssBaseScores.put("NONE", 0.0);
    }

    public double getScoreForAttack(String attackType) {
        return cvssBaseScores.getOrDefault(attackType, 5.0); // default fallback
    }
}
