package com.example.loganalyzer.utils;

import com.example.loganalyzer.model.LogEntry;
import com.example.loganalyzer.model.TrafficSummary;

import java.util.List;
import java.util.Map;

public class ReportPrinter {

    public void printTitle(String title) {
        System.out.println();
        System.out.println("===== " + title + " =====");
    }

    public <T> void printList(String title, List<T> items) {
        printTitle(title);
        if (items.isEmpty()) {
            System.out.println("(nothing)");
            return;
        }
        for (T item : items) {
            System.out.println("- " + item);
        }
    }

    public void printRiskScores(List<LogEntry> logs) {
        printTitle("Risk score of each log");
        for (LogEntry log : logs) {
            System.out.println(log.getType() + " from " + log.getIpAddress()
                    + " -> risk " + log.calculateRiskScore() + " (" + log.getSeverity() + ")");
        }
    }

    public void printSummary(TrafficSummary summary, boolean healthy) {
        printTitle("Traffic summary");
        System.out.println("Total logs: " + summary.getTotalLogs());
        Map<String, Integer> logsByType = summary.getLogsByType();
        for (String type : logsByType.keySet()) {
            System.out.println(type + ": " + logsByType.get(type));
        }
        System.out.println("Error rate: " + summary.getErrorRate() + "%");
        if (healthy) {
            System.out.println("Status: healthy");
        } else {
            System.out.println("Status: too many errors, the server may be under attack");
        }
    }
}
