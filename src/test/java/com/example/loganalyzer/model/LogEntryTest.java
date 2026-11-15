package com.example.loganalyzer.model;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LogEntryTest {

    private final LocalDateTime date = LocalDateTime.of(2026, 11, 9, 10, 0);

    @Test
    void shouldGiveNoRiskToSuccessfulHttpRequest() {
        LogEntry log = new HttpAccessLog(date, "192.168.1.10", HttpMethod.GET, "/index.html", 200);

        assertEquals(0, log.calculateRiskScore());
        assertFalse(log.isFailure());
    }

    @Test
    void shouldGiveHigherRiskToForbiddenThanNotFound() {
        LogEntry forbidden = new HttpAccessLog(date, "192.168.1.10", HttpMethod.GET, "/admin", 403);
        LogEntry notFound = new HttpAccessLog(date, "192.168.1.10", HttpMethod.GET, "/nothing", 404);

        assertEquals(3, forbidden.calculateRiskScore());
        assertEquals(1, notFound.calculateRiskScore());
    }

    @Test
    void shouldIncreaseRiskWhenFailedLoginTargetsRoot() {
        LogEntry rootLogin = new AuthLog(date, "203.0.113.45", "root", AuthStatus.FAILED);
        LogEntry userLogin = new AuthLog(date, "203.0.113.45", "alice", AuthStatus.FAILED);

        assertEquals(6, rootLogin.calculateRiskScore());
        assertEquals(4, userLogin.calculateRiskScore());
    }

    @Test
    void shouldBeCriticalWhenSensitivePortIsBlocked() {
        LogEntry log = new FirewallLog(date, "198.51.100.7", 22, true);

        assertEquals(SeverityLevel.CRITICAL, log.getSeverity());
    }

    @Test
    void shouldBeLowWhenFirewallAllowsTheConnection() {
        LogEntry log = new FirewallLog(date, "198.51.100.7", 22, false);

        assertEquals(SeverityLevel.LOW, log.getSeverity());
    }

    @Test
    void shouldThrowExceptionWhenStatusCodeIsNegative() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new HttpAccessLog(date, "192.168.1.10", HttpMethod.GET, "/index.html", -200)
        );
    }

    @Test
    void shouldKeepOldStatusCodeWhenNewOneIsRefused() {
        HttpAccessLog log = new HttpAccessLog(date, "192.168.1.10", HttpMethod.GET, "/index.html", 200);

        assertThrows(IllegalArgumentException.class, () -> log.setStatusCode(700));

        assertEquals(200, log.getStatusCode());
    }

    @Test
    void shouldThrowExceptionWhenIpIsInvalid() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuthLog(date, "192.168.1", "alice", AuthStatus.SUCCESS)
        );
    }

    @Test
    void shouldThrowExceptionWhenPortIsOutOfRange() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new FirewallLog(date, "198.51.100.7", 70000, true)
        );
    }
}
