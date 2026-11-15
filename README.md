# Local Server Log Analyzer

Final project - Java Object-Oriented Programming (JUNIA M1)

## 1. Purpose of the application

I run a small web agency and I regularly have to look at server logs for my clients
(who is hitting the website, are there bots, is somebody trying to log in as root...).
This console application reads a CSV file of server logs and does this job automatically:
it gives a risk score to each log, finds the IPs that look like attackers and prints
some traffic statistics.

Three kinds of logs are supported:

- HTTP access logs (method, URL, status code)
- authentication logs (username, success or failure)
- firewall logs (port, blocked or allowed)

## 2. How to run it

Requirements: Java 17 or more and Maven.

From the root of the project:

```
mvn compile exec:java
```

Or from IntelliJ: open the project and run `Application.main()`.

The program must be started from the root of the project because the log file is read
from `src/main/resources/logs.csv`.

## 3. Main features

- Loads the logs from a CSV file at startup and ignores the malformed lines (they are listed at the end of the loading)
- Calculates a risk score for each log and for each IP address
- Detects brute force attacks (IPs with too many failures)
- Calculates the error rate and says if the server looks healthy
- Filters the logs by severity or by date range
- Ranks the IPs from the most dangerous to the least dangerous
- Exports a small report in `security-report.txt`

## 4. Main classes

| Package | Class | Role |
|---|---|---|
| model | `LogEntry` | abstract parent of all the logs (timestamp + IP) |
| model | `HttpAccessLog`, `AuthLog`, `FirewallLog` | the three kinds of logs |
| model | `Exportable` | interface for what can be written in the report file |
| model | `IpReport`, `TrafficSummary` | results of the analysis, both exportable |
| model | `SeverityLevel`, `HttpMethod`, `AuthStatus` | enums |
| service | `LogAnalyzerService` | all the business logic |
| utils | `CsvLogLoader` | reads the CSV file |
| utils | `LogEntryFactory` | creates the right log object from a CSV line |
| utils | `ReportPrinter` | displays the results in the console |
| utils | `ReportExporter` | writes the report file |
| exception | `InvalidLogFormatException`, `LogAnalysisException` | custom exceptions |
| | `Application` | entry point, only connects the other classes |

## 5. Technical decisions

1. **The risk score is calculated by the log itself.** Each subclass knows its own rules
   (a 403 is worse than a 404, a failed login on root is worse than on a normal user...).
   The service just calls `calculateRiskScore()` and never needs an `instanceof`.
2. **A Simple Factory creates the logs.** `LogEntryFactory.create(line)` reads the first
   field of the line and chooses the class. The loader doesn't know the concrete classes.
3. **`InvalidLogFormatException` is checked, `LogAnalysisException` is unchecked.**
   A bad line in a file is something expected, so I want the compiler to force the
   loader to deal with it. A negative threshold is a mistake from the caller, so a
   runtime exception is enough.
4. **A bad line does not stop the loading.** The loader catches the exception line by
   line and keeps the rejected lines in a list so they can be displayed.
5. **The service receives the list of logs in its constructor.** It doesn't read the
   file itself, so it can be tested with a few logs created by hand.

## 6. Where inheritance is used

`HttpAccessLog`, `AuthLog` and `FirewallLog` extend `LogEntry`. It is a real "is-a"
relationship: each one is a log with a timestamp and an IP address. The parent
keeps the common attributes, their validation, `getSeverity()`, `isFailure()` and `toString()`.

The two custom exceptions also extend `Exception` and `RuntimeException`.

## 7. Where polymorphism is used

- `LogAnalyzerService` works with a `List<LogEntry>` and calls `calculateRiskScore()`,
  `isFailure()` and `getSeverity()` without knowing the real type (for example in
  `calculateRiskScoreForIp()` and `calculateErrorRate()`).
- `ReportPrinter.printRiskScores()` loops on the `List<LogEntry>` and calls
  `getType()` and `calculateRiskScore()`: the result depends on the real object.
- `ReportExporter.export()` receives a `List<Exportable>` containing a `TrafficSummary`
  and several `IpReport`, and calls `exportReport()` on each of them.

## 8. Where the abstract class / interface is used

- **Abstract class `LogEntry`**: a "generic" log does not exist, so it should not be
  possible to instantiate it. But all logs share state (timestamp, IP) and
  behaviour (`getSeverity()`), so an abstract class is the right tool. The abstract
  methods are `calculateRiskScore()`, `getType()` and `getDetails()`.
- **Interface `Exportable`**: `IpReport` and `TrafficSummary` have nothing in common
  except that they can be written in the report file. It is a capability, not a
  family of objects, so I used an interface and not a parent class.

## 9. Custom exceptions

- `InvalidLogFormatException` (checked): thrown by `LogEntryFactory` when a CSV line
  is empty, has the wrong number of fields, an unknown type, a wrong date, a status
  code that is not a number or a value refused by the model. The original exception
  is kept as the cause.
- `LogAnalysisException` (unchecked): thrown by `LogAnalyzerService` when the analysis
  is impossible (empty list of logs, threshold lower or equal to zero, error rate limit
  outside 0-100).

Standard exceptions are used too: `IllegalArgumentException` for the validation in the
model (invalid IP, HTTP status, port) and `IOException` for the files.

## 10. How the application loads its data

`CsvLogLoader.load()` opens `src/main/resources/logs.csv` with a `BufferedReader` in a
try-with-resources, skips the header and gives each line to `LogEntryFactory`.
The format is:

```
HTTP,timestamp,ip,method,url,statusCode
AUTH,timestamp,ip,username,SUCCESS|FAILED
FIREWALL,timestamp,ip,port,BLOCK|ALLOW
```

The file contains two wrong lines on purpose to show that they are rejected
without crashing the program.

## 11. How SOLID principles were applied

- **S - Single Responsibility**: reading the file (`CsvLogLoader`), creating objects
  (`LogEntryFactory`), business rules (`LogAnalyzerService`), display (`ReportPrinter`)
  and export (`ReportExporter`) are in different classes. `Application` only calls them.
- **O - Open/Closed**: to support a new kind of log (DNS for example), I create a new
  subclass of `LogEntry` and add one case in the factory. The service, the printer and
  the exporter don't change.
- **L - Liskov Substitution**: the three subclasses can be used everywhere a `LogEntry`
  is expected. None of them throws an exception for a method of the parent.
- **I - Interface Segregation**: `Exportable` has only one method. The logs don't
  implement it because they are not exported, so they are not forced to have a useless method.
- **D - Dependency Inversion**: `LogAnalyzerService` depends on the abstraction
  `LogEntry` and receives its data from outside (constructor). `ReportExporter` depends
  on `Exportable` and not on `IpReport` or `TrafficSummary`.

## 12. How to run the tests

```
mvn test
```

There are three test classes (JUnit 5):

- `LogAnalyzerServiceTest`: risk score, brute force detection, error rate, filters, ranking
- `LogEntryTest`: risk rules of each kind of log and validation
- `LogEntryFactoryTest`: creation from a CSV line and malformed lines
