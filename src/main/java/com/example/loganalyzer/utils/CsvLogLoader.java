package com.example.loganalyzer.utils;

import com.example.loganalyzer.exception.InvalidLogFormatException;
import com.example.loganalyzer.model.LogEntry;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class CsvLogLoader {

    private final List<String> rejectedLines = new ArrayList<>();

    public List<LogEntry> load(Path path) throws IOException {
        List<LogEntry> logs = new ArrayList<>();
        rejectedLines.clear();

        try (BufferedReader reader = Files.newBufferedReader(path)) {
            // the first line is the header of the CSV
            String line = reader.readLine();
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    logs.add(LogEntryFactory.create(line));
                } catch (InvalidLogFormatException e) {
                    // one bad line should not stop the loading of the whole file
                    rejectedLines.add(line + "  (" + e.getMessage() + ")");
                }
            }
        }
        return logs;
    }

    public List<String> getRejectedLines() {
        return rejectedLines;
    }
}
