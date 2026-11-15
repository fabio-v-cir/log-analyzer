package com.example.loganalyzer.utils;

import com.example.loganalyzer.exception.InvalidLogFormatException;
import com.example.loganalyzer.model.AuthLog;
import com.example.loganalyzer.model.AuthStatus;
import com.example.loganalyzer.model.FirewallLog;
import com.example.loganalyzer.model.HttpAccessLog;
import com.example.loganalyzer.model.HttpMethod;
import com.example.loganalyzer.model.LogEntry;

import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;

public class LogEntryFactory {

    public static LogEntry create(String line) throws InvalidLogFormatException {
        if (line == null || line.isBlank()) {
            throw new InvalidLogFormatException("The line is empty");
        }
        String[] fields = line.split(",");
        if (fields.length < 5) {
            throw new InvalidLogFormatException("Not enough fields: expected at least 5 but got " + fields.length);
        }

        String type = fields[0].trim().toUpperCase();
        try {
            LocalDateTime timestamp = LocalDateTime.parse(fields[1].trim());
            String ip = fields[2].trim();

            return switch (type) {
                case "HTTP" -> createHttpLog(fields, timestamp, ip);
                case "AUTH" -> createAuthLog(fields, timestamp, ip);
                case "FIREWALL" -> createFirewallLog(fields, timestamp, ip);
                default -> throw new InvalidLogFormatException("Unknown log type: " + type);
            };
        } catch (DateTimeParseException e) {
            throw new InvalidLogFormatException("Invalid date: " + fields[1], e);
        } catch (NumberFormatException e) {
            throw new InvalidLogFormatException("A number was expected: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            // thrown by the model validation or by valueOf() on an unknown enum value
            throw new InvalidLogFormatException("Invalid value: " + e.getMessage(), e);
        }
    }

    private static LogEntry createHttpLog(String[] fields, LocalDateTime timestamp, String ip)
            throws InvalidLogFormatException {
        if (fields.length != 6) {
            throw new InvalidLogFormatException("An HTTP log needs 6 fields but got " + fields.length);
        }
        HttpMethod method = HttpMethod.valueOf(fields[3].trim().toUpperCase());
        String url = fields[4].trim();
        int statusCode = Integer.parseInt(fields[5].trim());
        return new HttpAccessLog(timestamp, ip, method, url, statusCode);
    }

    private static LogEntry createAuthLog(String[] fields, LocalDateTime timestamp, String ip)
            throws InvalidLogFormatException {
        if (fields.length != 5) {
            throw new InvalidLogFormatException("An AUTH log needs 5 fields but got " + fields.length);
        }
        String username = fields[3].trim();
        AuthStatus status = AuthStatus.valueOf(fields[4].trim().toUpperCase());
        return new AuthLog(timestamp, ip, username, status);
    }

    private static LogEntry createFirewallLog(String[] fields, LocalDateTime timestamp, String ip)
            throws InvalidLogFormatException {
        if (fields.length != 5) {
            throw new InvalidLogFormatException("A FIREWALL log needs 5 fields but got " + fields.length);
        }
        int port = Integer.parseInt(fields[3].trim());
        String action = fields[4].trim().toUpperCase();
        if (!action.equals("BLOCK") && !action.equals("ALLOW")) {
            throw new InvalidLogFormatException("Unknown firewall action: " + action);
        }
        return new FirewallLog(timestamp, ip, port, action.equals("BLOCK"));
    }
}
