package com.example.loganalyzer.service;

import com.example.loganalyzer.exception.LogAnalysisException;
import com.example.loganalyzer.model.IpReport;
import com.example.loganalyzer.model.LogEntry;
import com.example.loganalyzer.model.SeverityLevel;
import com.example.loganalyzer.model.TrafficSummary;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class LogAnalyzerService {

    private final List<LogEntry> logs;

    public LogAnalyzerService(List<LogEntry> logs) {
        if (logs == null) {
            throw new IllegalArgumentException("The list of logs cannot be null");
        }
        this.logs = logs;
    }

    public int calculateRiskScoreForIp(String ipAddress) {
        checkIp(ipAddress);
        return logs.stream()
                .filter(log -> log.getIpAddress().equals(ipAddress))
                .mapToInt(LogEntry::calculateRiskScore)
                .sum();
    }

    public int countFailuresForIp(String ipAddress) {
        checkIp(ipAddress);
        return (int) logs.stream()
                .filter(log -> log.getIpAddress().equals(ipAddress))
                .filter(LogEntry::isFailure)
                .count();
    }

    public Set<String> getUniqueIps() {
        Set<String> ips = new HashSet<>();
        for (LogEntry log : logs) {
            ips.add(log.getIpAddress());
        }
        return ips;
    }

    // An IP is considered as attacking when it has at least "threshold" failures.
    public List<String> detectBruteForceIps(int threshold) {
        if (threshold <= 0) {
            throw new LogAnalysisException("Threshold must be greater than zero, got " + threshold);
        }
        checkNotEmpty();
        return getUniqueIps().stream()
                .filter(ip -> countFailuresForIp(ip) >= threshold)
                .sorted()
                .toList();
    }

    public List<LogEntry> filterBySeverity(SeverityLevel severity) {
        if (severity == null) {
            throw new IllegalArgumentException("Severity cannot be null");
        }
        return logs.stream()
                .filter(log -> log.getSeverity() == severity)
                .toList();
    }

    public List<LogEntry> filterByDateRange(LocalDateTime start, LocalDateTime end) {
        if (start == null || end == null) {
            throw new IllegalArgumentException("Start and end dates are required");
        }
        if (start.isAfter(end)) {
            throw new IllegalArgumentException("Start date must be before end date");
        }
        return logs.stream()
                .filter(log -> !log.getTimestamp().isBefore(start))
                .filter(log -> !log.getTimestamp().isAfter(end))
                .toList();
    }

    public List<LogEntry> findLogsByIp(String ipAddress) {
        checkIp(ipAddress);
        return logs.stream()
                .filter(log -> log.getIpAddress().equals(ipAddress))
                .toList();
    }

    public Optional<LogEntry> findFirstCriticalLog() {
        return logs.stream()
                .filter(log -> log.getSeverity() == SeverityLevel.CRITICAL)
                .findFirst();
    }

    public double calculateErrorRate() {
        checkNotEmpty();
        long failures = logs.stream()
                .filter(LogEntry::isFailure)
                .count();
        double rate = failures * 100.0 / logs.size();
        return Math.round(rate * 100) / 100.0;
    }

    public boolean isHealthy(double maxErrorRate) {
        if (maxErrorRate < 0 || maxErrorRate > 100) {
            throw new LogAnalysisException("Max error rate must be between 0 and 100");
        }
        return calculateErrorRate() <= maxErrorRate;
    }

    public Map<String, Integer> countLogsByType() {
        Map<String, Integer> counts = new HashMap<>();
        for (LogEntry log : logs) {
            String type = log.getType();
            if (counts.containsKey(type)) {
                counts.put(type, counts.get(type) + 1);
            } else {
                counts.put(type, 1);
            }
        }
        return counts;
    }

    // Most dangerous IP first
    public List<IpReport> getIpRanking() {
        checkNotEmpty();
        List<IpReport> reports = new ArrayList<>();
        for (String ip : getUniqueIps()) {
            reports.add(new IpReport(ip, calculateRiskScoreForIp(ip), countFailuresForIp(ip)));
        }
        return reports.stream()
                .sorted((first, second) -> second.getTotalRiskScore() - first.getTotalRiskScore())
                .toList();
    }

    public Optional<IpReport> findMostDangerousIp() {
        if (logs.isEmpty()) {
            return Optional.empty();
        }
        return getIpRanking().stream().findFirst();
    }

    public TrafficSummary buildTrafficSummary() {
        return new TrafficSummary(logs.size(), calculateErrorRate(), countLogsByType());
    }

    private void checkNotEmpty() {
        if (logs.isEmpty()) {
            throw new LogAnalysisException("Cannot analyze an empty list of logs");
        }
    }

    private void checkIp(String ipAddress) {
        if (!LogEntry.isValidIp(ipAddress)) {
            throw new IllegalArgumentException("Invalid IP address: " + ipAddress);
        }
    }
}
