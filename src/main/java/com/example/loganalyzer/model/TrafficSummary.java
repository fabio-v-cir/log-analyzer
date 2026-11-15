package com.example.loganalyzer.model;

import java.util.Map;

public class TrafficSummary implements Exportable {

    private final int totalLogs;
    private final double errorRate;
    private final Map<String, Integer> logsByType;

    public TrafficSummary(int totalLogs, double errorRate, Map<String, Integer> logsByType) {
        this.totalLogs = totalLogs;
        this.errorRate = errorRate;
        this.logsByType = logsByType;
    }

    @Override
    public String exportReport() {
        String report = "total=" + totalLogs + ";errorRate=" + errorRate + "%";
        for (String type : logsByType.keySet()) {
            report = report + ";" + type + "=" + logsByType.get(type);
        }
        return report;
    }

    public int getTotalLogs() {
        return totalLogs;
    }

    public double getErrorRate() {
        return errorRate;
    }

    public Map<String, Integer> getLogsByType() {
        return logsByType;
    }
}
