#pragma once
#include <string>

struct LogEntry {
    std::string ip;
    std::string timestamp;
    std::string method;
    std::string url;

    int  status_code;
    int  bytesSent;

    bool isSuspicious;
    std::string threat;

    LogEntry* next;

    LogEntry() : status_code(0), bytesSent(0), isSuspicious(false), next(nullptr) {}
};