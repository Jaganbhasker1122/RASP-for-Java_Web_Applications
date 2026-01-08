package com.rasplab.rasplab.detection;

public class DetectionResult {

    private boolean malicious;
    private int riskScore;
    private String attackType;
    private String reason;

    public DetectionResult(
            boolean malicious,
            int riskScore,
            String attackType,
            String reason
    ) {
        this.malicious = malicious;
        this.riskScore = riskScore;
        this.attackType = attackType;
        this.reason = reason;
    }

    public boolean isMalicious() {
        return malicious;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getAttackType() {
        return attackType;
    }

    public String getReason() {
        return reason;
    }
}
