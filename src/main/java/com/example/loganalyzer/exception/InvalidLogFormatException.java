package com.example.loganalyzer.exception;

public class InvalidLogFormatException extends Exception {

    public InvalidLogFormatException(String message) {
        super(message);
    }

    public InvalidLogFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
