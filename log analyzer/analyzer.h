#pragma once
#include <map>
#include <string>
#include "linked_list.h"

void detectionBF(LogList& list, int threshold = 5)
{
    std::map<std::string, int> failCount;

    LogEntry* current = list.head;
    while (current != nullptr)
    {
        if (current->status_code == 401 || current->status_code == 403)
            failCount[current->ip]++;
        current = current->next;
    }

    current = list.head;
    while (current != nullptr)
    {
        if (failCount[current->ip] >= threshold)
        {
            current->isSuspicious = true;
            current->threat = "Brute Force";
        }
        current = current->next;
    }
}

void detectionScanning(LogList& list, int threshold = 10)
{
    std::map<std::string, int> notFoundCount;

    LogEntry* current = list.head;
    while (current != nullptr)
    {
        if (current->status_code == 404)
            notFoundCount[current->ip]++;
        current = current->next;
    }

    current = list.head;
    while (current != nullptr)
    {
        if (notFoundCount[current->ip] >= threshold)
        {
            current->isSuspicious = true;
            current->threat = "Scan";
        }
        current = current->next;
    }
}

void detectionSQLi(LogList& list)
{
    const std::string patterns[] = {
        "' OR ", "1=1", "UNION SELECT", "DROP TABLE",
        "--", "/*", "xp_cmdshell", "SLEEP(",
        "' AND ", "\" OR \""
    };
    const int patternCount = 10;

    LogEntry* current = list.head;
    while (current != nullptr)
    {
        for (int i = 0; i < patternCount; i++)
        {
            std::string url = current->url;
            std::string pattern = patterns[i];

            for (char& c : url)     c = toupper(c);
            for (char& c : pattern) c = toupper(c);

            if (url.find(pattern) != std::string::npos)
            {
                current->isSuspicious = true;
                current->threat = "SQLI";
                break;
            }
        }
        current = current->next;
    }
}