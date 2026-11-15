package com.example.loganalyzer.model;

import java.time.LocalDateTime;

public abstract class LogEntry {

    private LocalDateTime timestamp;
    private String ipAddress;

    public LogEntry(LocalDateTime timestamp, String ipAddress) {
        setTimestamp(timestamp);
        setIpAddress(ipAddress);
    }

    public abstract int calculateRiskScore();

    public abstract String getType();

    public abstract String getDetails();

    public static boolean isValidIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return false;
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            try {
                int number = Integer.parseInt(part);
                if (number < 0 || number > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    // A log is a failure when something was refused, failed or blocked.
    public boolean isFailure() {
        return calculateRiskScore() > 0;
    }

    public SeverityLevel getSeverity() {
        int score = calculateRiskScore();
        if (score >= 5) {
            return SeverityLevel.CRITICAL;
        }
        if (score >= 3) {
            return SeverityLevel.HIGH;
        }
        if (score >= 1) {
            return SeverityLevel.MEDIUM;
        }
        return SeverityLevel.LOW;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    // Setters are protected: a log should not be modified from outside once it is created.
    protected void setTimestamp(LocalDateTime timestamp) {
        if (timestamp == null) {
            throw new IllegalArgumentException("Timestamp cannot be null");
        }
        this.timestamp = timestamp;
    }

    protected void setIpAddress(String ipAddress) {
        if (!isValidIp(ipAddress)) {
            throw new IllegalArgumentException("Invalid IP address: " + ipAddress);
        }
        this.ipAddress = ipAddress;
    }

    @Override
    public String toString() {
        return timestamp + " | " + getType() + " | " + ipAddress + " | " + getDetails()
                + " | risk=" + calculateRiskScore() + " (" + getSeverity() + ")";
    }
}
