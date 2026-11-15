package com.example.loganalyzer.utils;

import com.example.loganalyzer.exception.InvalidLogFormatException;
import com.example.loganalyzer.model.AuthLog;
import com.example.loganalyzer.model.FirewallLog;
import com.example.loganalyzer.model.HttpAccessLog;
import com.example.loganalyzer.model.LogEntry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogEntryFactoryTest {

    @Test
    void shouldCreateHttpLogFromValidLine() throws InvalidLogFormatException {
        // Arrange
        String line = "HTTP,2026-11-09T08:02:11,192.168.1.10,GET,/index.html,200";

        // Act
        LogEntry log = LogEntryFactory.create(line);

        // Assert
        assertTrue(log instanceof HttpAccessLog);
        assertEquals("192.168.1.10", log.getIpAddress());
    }

    @Test
    void shouldCreateAuthLogFromValidLine() throws InvalidLogFormatException {
        LogEntry log = LogEntryFactory.create("AUTH,2026-11-09T11:00:01,203.0.113.45,root,FAILED");

        assertTrue(log instanceof AuthLog);
        assertEquals(6, log.calculateRiskScore());
    }

    @Test
    void shouldCreateFirewallLogFromValidLine() throws InvalidLogFormatException {
        LogEntry log = LogEntryFactory.create("FIREWALL,2026-11-09T11:01:30,203.0.113.45,22,BLOCK");

        assertTrue(log instanceof FirewallLog);
    }

    @Test
    void shouldAcceptLowercaseType() throws InvalidLogFormatException {
        LogEntry log = LogEntryFactory.create("http,2026-11-09T08:02:11,192.168.1.10,get,/index.html,200");

        assertEquals("HTTP", log.getType());
    }

    @Test
    void shouldThrowExceptionWhenLogLineIsMalformed() {
        assertThrows(
                InvalidLogFormatException.class,
                () -> LogEntryFactory.create("this line is not a valid log")
        );
    }

    @Test
    void shouldThrowExceptionWhenLineIsEmpty() {
        assertThrows(
                InvalidLogFormatException.class,
                () -> LogEntryFactory.create("")
        );
    }

    @Test
    void shouldThrowExceptionWhenStatusCodeIsNotANumber() {
        assertThrows(
                InvalidLogFormatException.class,
                () -> LogEntryFactory.create("HTTP,2026-11-09T12:00:00,192.168.1.10,GET,/index.html,abc")
        );
    }

    @Test
    void shouldThrowExceptionWhenDateIsInvalid() {
        assertThrows(
                InvalidLogFormatException.class,
                () -> LogEntryFactory.create("AUTH,09/11/2026,203.0.113.45,root,FAILED")
        );
    }

    @Test
    void shouldThrowExceptionWhenTypeIsUnknown() {
        InvalidLogFormatException exception = assertThrows(
                InvalidLogFormatException.class,
                () -> LogEntryFactory.create("DNS,2026-11-09T12:00:00,192.168.1.10,example.com,OK")
        );

        assertEquals("Unknown log type: DNS", exception.getMessage());
    }
}
