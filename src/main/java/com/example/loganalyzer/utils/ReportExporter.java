package com.example.loganalyzer.utils;

import com.example.loganalyzer.model.Exportable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class ReportExporter {

    public void export(List<Exportable> reports, Path path) throws IOException {
        List<String> lines = new ArrayList<>();
        for (Exportable report : reports) {
            lines.add(report.exportReport());
        }
        Files.write(path, lines, StandardCharsets.UTF_8);
    }
}
