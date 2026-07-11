# C++ Log Analyzer

A command-line tool that parses Apache web server logs, detects suspicious activity, and generates a structured report.

## What it detects
- **Brute Force** — IPs with 5+ failed authentication attempts (401/403)
- **Directory Scanning** — IPs generating 10+ 404 errors
- **SQL Injection** — URLs containing classic SQLi patterns

## How it works
1. Reads an Apache Combined Log Format file line by line
2. Parses each entry into a linked list of `LogEntry` nodes (heap allocated)
3. Runs three detection passes over the list
4. Writes flagged and clean entries to a report file

## Project structure

log_analyzer/
├── main.cpp        — entry point, parser
├── log_entry.h     — LogEntry struct (one node per log line)
├── linked_list.h   — LogList class (insert, traverse, free)
├── analyzer.h      — brute force, scan, SQLi detection
├── report.h        — report generation
└── sample.log      — test data

## Build and run
```bash
g++ -std=c++17 main.cpp -o log_analyzer
./log_analyzer
```

## Skills demonstrated
C++ classes, structs, singly linked list, dynamic memory allocation,
heap memory management, file I/O, token parsing, pattern matching