#pragma once
#include "linked_list.h"
#include <fstream>
#include <iostream>
#include <map>

void generateReport(LogList& list, const std::string& outFile) {
    ofstream report(outFile);

    if (!report.is_open()) {
        cerr << "Error: cannot write report to " << outFile << endl;
        return;
    }

    // ── Summary counts ──────────────────────────────────────────────
    int totalEntries   = 0;
    int suspiciousHits = 0;
    map<std::string, int> threatCounts;

    LogEntry* current = list.head;
    while (current != nullptr) {
        totalEntries++;
        if (current->isSuspicious) {
            suspiciousHits++;
            threatCounts[current->threat]++;
        }
        current = current->next;
    }

    report << "==============================================\n";
    report << "  LOG ANALYSIS REPORT\n";
    report << "==============================================\n\n";
    report << "Total log entries analysed : " << totalEntries   << "\n";
    report << "Suspicious entries flagged : " << suspiciousHits << "\n\n";

    report << "Threat breakdown:\n";
    for (auto& pair : threatCounts) {
        report << "  " << pair.first << " : " << pair.second << " hits\n";
    }

    // ── Flagged entries detail ──────────────────────────────────────
    report << "\n----------------------------------------------\n";
    report << "FLAGGED ENTRIES\n";
    report << "----------------------------------------------\n";

    current = list.head;
    while (current != nullptr) {
        if (current->isSuspicious) {
            report << "[" << current->threat << "] "
                   << current->ip        << " "
                   << current->timestamp << " "
                   << current->method    << " "
                   << current->url       << " "
                   << current->status_code << "\n";
        }
        current = current->next;
    }

     // ── clean entries ──────────────────────────────────────────
    report << "\n----------------------------------------------\n";
    report << "CLEAN ENTRIES\n";
    report << "----------------------------------------------\n";

    current = list.head;
    while (current != nullptr)
    {
        if (!current->isSuspicious)
        {
            report << current->ip          << " "
                   << current->method      << " "
                   << current->url         << " "
                   << current->status_code << "\n";
        }
        current = current->next;
    }

    report.close();
    std::cout << "[+] Report written to: " << outFile << "\n";
}