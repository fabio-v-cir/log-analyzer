package com.example.loganalyzer.model;

import java.time.LocalDateTime;

public class AuthLog extends LogEntry {

    private String username;
    private AuthStatus status;

    public AuthLog(LocalDateTime timestamp, String ipAddress, String username, AuthStatus status) {
        super(timestamp, ipAddress);
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        if (status == null) {
            throw new IllegalArgumentException("Auth status cannot be null");
        }
        this.username = username;
        this.status = status;
    }

    @Override
    public int calculateRiskScore() {
        if (status == AuthStatus.SUCCESS) {
            return 0;
        }
        int score = 4;
        // Failed logins on privileged accounts are more dangerous
        if (isPrivilegedAccount()) {
            score = score + 2;
        }
        return score;
    }

    @Override
    public String getType() {
        return "AUTH";
    }

    @Override
    public String getDetails() {
        return "login " + username + " -> " + status;
    }

    public boolean isPrivilegedAccount() {
        return username.equals("root") || username.equals("admin");
    }

    public String getUsername() {
        return username;
    }

    public AuthStatus getStatus() {
        return status;
    }
}
