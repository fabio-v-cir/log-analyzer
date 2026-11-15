package com.example.loganalyzer.model;

import java.time.LocalDateTime;

public class FirewallLog extends LogEntry {

    private int port;
    private boolean blocked;

    public FirewallLog(LocalDateTime timestamp, String ipAddress, int port, boolean blocked) {
        super(timestamp, ipAddress);
        setPort(port);
        this.blocked = blocked;
    }

    @Override
    public int calculateRiskScore() {
        if (!blocked) {
            return 0;
        }
        int score = 2;
        if (isSensitivePort()) {
            score = score + 3;
        }
        return score;
    }

    @Override
    public String getType() {
        return "FIREWALL";
    }

    @Override
    public String getDetails() {
        if (blocked) {
            return "port " + port + " -> BLOCK";
        }
        return "port " + port + " -> ALLOW";
    }

    // SSH, Telnet and RDP are remote access ports, they are the usual targets of scans
    public boolean isSensitivePort() {
        return port == 22 || port == 23 || port == 3389;
    }

    public int getPort() {
        return port;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void setPort(int port) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Invalid port: " + port);
        }
        this.port = port;
    }
}
