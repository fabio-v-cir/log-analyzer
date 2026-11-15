package com.example.loganalyzer.model;

import java.time.LocalDateTime;

public class HttpAccessLog extends LogEntry {

    private HttpMethod method;
    private String url;
    private int statusCode;

    public HttpAccessLog(LocalDateTime timestamp, String ipAddress, HttpMethod method, String url, int statusCode) {
        super(timestamp, ipAddress);
        if (method == null) {
            throw new IllegalArgumentException("HTTP method cannot be null");
        }
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("URL cannot be empty");
        }
        this.method = method;
        this.url = url;
        setStatusCode(statusCode);
    }

    @Override
    public int calculateRiskScore() {
        // 401 and 403 mean somebody tried to reach something he is not allowed to see
        if (statusCode == 401 || statusCode == 403) {
            return 3;
        }
        if (statusCode >= 500) {
            return 2;
        }
        if (statusCode >= 400) {
            return 1;
        }
        return 0;
    }

    @Override
    public String getType() {
        return "HTTP";
    }

    @Override
    public String getDetails() {
        return method + " " + url + " -> " + statusCode;
    }

    public HttpMethod getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        if (statusCode < 100 || statusCode > 599) {
            throw new IllegalArgumentException("Invalid HTTP status code: " + statusCode);
        }
        this.statusCode = statusCode;
    }
}
