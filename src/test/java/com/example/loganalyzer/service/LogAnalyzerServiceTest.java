package com.example.loganalyzer.service;

import com.example.loganalyzer.exception.LogAnalysisException;
import com.example.loganalyzer.model.AuthLog;
import com.example.loganalyzer.model.AuthStatus;
import com.example.loganalyzer.model.FirewallLog;
import com.example.loganalyzer.model.HttpAccessLog;
import com.example.loganalyzer.model.HttpMethod;
import com.example.loganalyzer.model.IpReport;
import com.example.loganalyzer.model.LogEntry;
import com.example.loganalyzer.model.SeverityLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogAnalyzerServiceTest {

    private LogAnalyzerService service;

    @BeforeEach
    void setUp() {
        List<LogEntry> logs = new ArrayList<>();
        logs.add(new HttpAccessLog(LocalDateTime.of(2026, 11, 9, 10, 0), "192.168.1.10", HttpMethod.GET, "/index.html", 200));
        logs.add(new HttpAccessLog(LocalDateTime.of(2026, 11, 9, 10, 1), "192.168.1.10", HttpMethod.GET, "/missing", 404));
        logs.add(new AuthLog(LocalDateTime.of(2026, 11, 9, 10, 2), "203.0.113.45", "root", AuthStatus.FAILED));
        logs.add(new AuthLog(LocalDateTime.of(2026, 11, 9, 10, 3), "203.0.113.45", "admin", AuthStatus.FAILED));
        logs.add(new AuthLog(LocalDateTime.of(2026, 11, 9, 10, 4), "203.0.113.45", "alice", AuthStatus.FAILED));
        logs.add(new FirewallLog(LocalDateTime.of(2026, 11, 9, 10, 5), "198.51.100.7", 22, true));
        logs.add(new FirewallLog(LocalDateTime.of(2026, 11, 9, 10, 6), "198.51.100.7", 443, false));
        logs.add(new HttpAccessLog(LocalDateTime.of(2026, 11, 10, 10, 7), "192.168.1.20", HttpMethod.POST, "/login", 403));
        service = new LogAnalyzerService(logs);
    }

    @Test
    void shouldCalculateRiskScoreCorrectly() {
        // Act
        int score = service.calculateRiskScoreForIp("203.0.113.45");

        // Assert
        assertEquals(16, score);
    }

    @Test
    void shouldReturnZeroRiskScoreWhenIpIsUnknown() {
        int score = service.calculateRiskScoreForIp("10.0.0.1");

        assertEquals(0, score);
    }

    @Test
    void shouldThrowExceptionWhenIpIsInvalid() {
        assertThrows(
                IllegalArgumentException.class,
                () -> service.calculateRiskScoreForIp("300.1.1.1")
        );
    }

    @Test
    void shouldDetectBruteForceAttackWhenThresholdExceeded() {
        List<String> attackers = service.detectBruteForceIps(3);

        assertEquals(1, attackers.size());
        assertEquals("203.0.113.45", attackers.get(0));
    }

    @Test
    void shouldDetectNobodyWhenThresholdIsTooHigh() {
        List<String> attackers = service.detectBruteForceIps(4);

        assertTrue(attackers.isEmpty());
    }

    @Test
    void shouldThrowExceptionWhenThresholdIsNegative() {
        LogAnalysisException exception = assertThrows(
                LogAnalysisException.class,
                () -> service.detectBruteForceIps(-1)
        );

        assertEquals("Threshold must be greater than zero, got -1", exception.getMessage());
    }

    @Test
    void shouldThrowExceptionWhenThresholdIsZero() {
        assertThrows(
                LogAnalysisException.class,
                () -> service.detectBruteForceIps(0)
        );
    }

    @Test
    void shouldThrowExceptionWhenAnalyzingEmptyList() {
        // Arrange
        LogAnalyzerService emptyService = new LogAnalyzerService(new ArrayList<>());

        // Act + Assert
        assertThrows(LogAnalysisException.class, () -> emptyService.calculateErrorRate());
    }

    @Test
    void shouldCalculateErrorRate() {
        double rate = service.calculateErrorRate();

        assertEquals(75.0, rate, 0.001);
    }

    @Test
    void shouldNotBeHealthyWhenErrorRateIsAboveLimit() {
        assertFalse(service.isHealthy(30.0));
    }

    @Test
    void shouldBeHealthyWhenErrorRateIsExactlyTheLimit() {
        assertTrue(service.isHealthy(75.0));
    }

    @Test
    void shouldFilterLogsBySeverity() {
        List<LogEntry> criticalLogs = service.filterBySeverity(SeverityLevel.CRITICAL);

        assertEquals(3, criticalLogs.size());
    }

    @Test
    void shouldFilterLogsByDateRange() {
        // Arrange
        LocalDateTime start = LocalDateTime.of(2026, 11, 10, 0, 0);
        LocalDateTime end = LocalDateTime.of(2026, 11, 10, 23, 59);

        // Act
        List<LogEntry> result = service.filterByDateRange(start, end);

        // Assert
        assertEquals(1, result.size());
        assertEquals("192.168.1.20", result.get(0).getIpAddress());
    }

    @Test
    void shouldIncludeLogsExactlyOnTheBoundsOfTheDateRange() {
        LocalDateTime start = LocalDateTime.of(2026, 11, 9, 10, 2);
        LocalDateTime end = LocalDateTime.of(2026, 11, 9, 10, 4);

        List<LogEntry> result = service.filterByDateRange(start, end);

        assertEquals(3, result.size());
    }

    @Test
    void shouldThrowExceptionWhenStartDateIsAfterEndDate() {
        LocalDateTime start = LocalDateTime.of(2026, 11, 10, 0, 0);
        LocalDateTime end = LocalDateTime.of(2026, 11, 9, 0, 0);

        assertThrows(
                IllegalArgumentException.class,
                () -> service.filterByDateRange(start, end)
        );
    }

    @Test
    void shouldCountLogsByType() {
        Map<String, Integer> counts = service.countLogsByType();

        assertEquals(3, counts.get("HTTP"));
        assertEquals(3, counts.get("AUTH"));
        assertEquals(2, counts.get("FIREWALL"));
    }

    @Test
    void shouldRankMostDangerousIpFirst() {
        List<IpReport> ranking = service.getIpRanking();

        assertEquals(4, ranking.size());
        assertEquals("203.0.113.45", ranking.get(0).getIpAddress());
        assertEquals(SeverityLevel.HIGH, ranking.get(0).getSeverity());
    }

    @Test
    void shouldReturnEmptyOptionalWhenThereIsNoLog() {
        LogAnalyzerService emptyService = new LogAnalyzerService(new ArrayList<>());

        Optional<IpReport> result = emptyService.findMostDangerousIp();

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldFindFirstCriticalLog() {
        Optional<LogEntry> result = service.findFirstCriticalLog();

        assertTrue(result.isPresent());
        assertEquals("203.0.113.45", result.get().getIpAddress());
    }
}
