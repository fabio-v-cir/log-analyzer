package com.example.loganalyzer;

import com.example.loganalyzer.exception.LogAnalysisException;
import com.example.loganalyzer.model.Exportable;
import com.example.loganalyzer.model.IpReport;
import com.example.loganalyzer.model.LogEntry;
import com.example.loganalyzer.model.SeverityLevel;
import com.example.loganalyzer.model.TrafficSummary;
import com.example.loganalyzer.service.LogAnalyzerService;
import com.example.loganalyzer.utils.CsvLogLoader;
import com.example.loganalyzer.utils.ReportExporter;
import com.example.loganalyzer.utils.ReportPrinter;

import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class Application {

    private static final String LOG_FILE = "src/main/resources/logs.csv";
    private static final String REPORT_FILE = "security-report.txt";
    private static final int BRUTE_FORCE_THRESHOLD = 5;
    private static final double MAX_ERROR_RATE = 30.0;

    public static void main(String[] args) {
        CsvLogLoader loader = new CsvLogLoader();
        ReportPrinter printer = new ReportPrinter();
        ReportExporter exporter = new ReportExporter();

        try {
            List<LogEntry> logs = loader.load(Path.of(LOG_FILE));
            System.out.println(logs.size() + " logs loaded from " + LOG_FILE);
            printer.printList("Rejected lines", loader.getRejectedLines());

            LogAnalyzerService service = new LogAnalyzerService(logs);

            printer.printRiskScores(logs);

            TrafficSummary summary = service.buildTrafficSummary();
            printer.printSummary(summary, service.isHealthy(MAX_ERROR_RATE));

            List<String> attackers = service.detectBruteForceIps(BRUTE_FORCE_THRESHOLD);
            printer.printList("Brute force suspects (" + BRUTE_FORCE_THRESHOLD + " failures or more)", attackers);

            List<IpReport> ranking = service.getIpRanking();
            printer.printList("IP ranking (most dangerous first)", ranking);

            printer.printTitle("Most dangerous IP");
            Optional<IpReport> mostDangerous = service.findMostDangerousIp();
            if (mostDangerous.isPresent()) {
                System.out.println(mostDangerous.get());
            } else {
                System.out.println("No IP found");
            }

            printer.printList("Critical logs", service.filterBySeverity(SeverityLevel.CRITICAL));

            LocalDateTime start = LocalDateTime.of(2026, 11, 10, 0, 0);
            LocalDateTime end = LocalDateTime.of(2026, 11, 10, 23, 59);
            printer.printList("Logs of 2026-11-10", service.filterByDateRange(start, end));

            List<Exportable> reports = new ArrayList<>();
            reports.add(summary);
            reports.addAll(ranking);
            exporter.export(reports, Path.of(REPORT_FILE));
            printer.printTitle("Export");
            System.out.println("Report written in " + REPORT_FILE);

            showErrorHandling(service, printer);

        } catch (IOException e) {
            System.err.println("Unable to read or write a file: " + e.getMessage());
        } catch (LogAnalysisException e) {
            System.err.println("Analysis failed: " + e.getMessage());
        }
    }

    // Shows that wrong inputs are refused with a clear message instead of crashing the program.
    private static void showErrorHandling(LogAnalyzerService service, ReportPrinter printer) {
        printer.printTitle("Error handling");
        try {
            service.detectBruteForceIps(-1);
        } catch (LogAnalysisException e) {
            System.out.println("Refused: " + e.getMessage());
        }
        try {
            service.findLogsByIp("999.1.1");
        } catch (IllegalArgumentException e) {
            System.out.println("Refused: " + e.getMessage());
        }
    }
}
