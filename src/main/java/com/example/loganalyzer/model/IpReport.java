package com.example.loganalyzer.model;

public class IpReport implements Exportable {

    private final String ipAddress;
    private final int totalRiskScore;
    private final int failureCount;

    public IpReport(String ipAddress, int totalRiskScore, int failureCount) {
        this.ipAddress = ipAddress;
        this.totalRiskScore = totalRiskScore;
        this.failureCount = failureCount;
    }

    public SeverityLevel getSeverity() {
        if (totalRiskScore >= 20) {
            return SeverityLevel.CRITICAL;
        }
        if (totalRiskScore >= 10) {
            return SeverityLevel.HIGH;
        }
        if (totalRiskScore >= 5) {
            return SeverityLevel.MEDIUM;
        }
        return SeverityLevel.LOW;
    }

    @Override
    public String exportReport() {
        return ipAddress + ";score=" + totalRiskScore + ";failures=" + failureCount + ";severity=" + getSeverity();
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public int getTotalRiskScore() {
        return totalRiskScore;
    }

    public int getFailureCount() {
        return failureCount;
    }

    @Override
    public String toString() {
        return ipAddress + " - score " + totalRiskScore + " - " + failureCount + " failure(s) - " + getSeverity();
    }
}
