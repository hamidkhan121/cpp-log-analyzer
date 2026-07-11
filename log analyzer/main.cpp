#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include "linked_list.h"
#include "log_entry.h"
#include "analyzer.h"
#include "report.h"
using namespace std;

bool parseLogFile(const string& filename, LogList& list)
{
    ifstream file(filename);
    if (!file.is_open())
    {
        cerr << "Error: cannot open file " << filename << endl;
        return false;
    }

    string line;
    int lineNum = 0;

    while (getline(file, line))
    {
        lineNum++;
        if(line.empty())
        {
            continue;
        }

        istringstream ss(line);
        LogEntry* entry = new LogEntry();
        
        string identField;
        string authUser;
        string requestField;
        char ch;

        // bare token
        ss >> entry->ip;
        ss >> identField;
        ss >> authUser;

        ss >> ch;
        getline(ss, entry->timestamp, ']');

        ss >> ch;
        getline(ss, requestField, '"');

        istringstream req(requestField);
        string protocol;

        req >> entry->method;
        req >> entry->url;
        req >> protocol;

        //INTEGRATION FIELD
        ss >> entry->status_code;
        int bytesSent;
        ss >> bytesSent;

        string referrer;
        ss >> ch;
        if (ch == '"')
        {
            getline(ss, referrer, '"');
        }

        //USER agent
        string userAgent;
        ss >> ch;
        if (ch == '"')
        {
            getline(ss, userAgent, '"');
        }

        //sanity check
        if (entry->ip.empty() || entry->status_code == 0)
        {
            delete entry;
            cerr << "Warning: skipping malformedd line" << lineNum << endl;
            continue;
        }
        list.insertAtHead(entry);
    }
    file.close();
    return true;
}

int main()
{
    string InputField;
    string OutputField;

    cout << "Log Analyzer v1.0\n";
    cout << "Enter log file path: ";
    cin  >> InputField;
    cout << "Enter report output path: ";
    cin  >> OutputField;

    LogList list;

    cout << "[*] Parsing log file..." << endl;
    if (!parseLogFile(InputField, list))
    {
        return 1;
    }
    cout << "[+] Loaded " << list.count << " entries" << endl;

    // run all three detectors
    cout << "[*] Running detection passes...\n";
    detectionBF(list, 5);
    detectionScanning(list, 10);
    detectionSQLi(list);
    generateReport(list, OutputField);
    cout << "[+] Detection complete\n";

    LogEntry* cur = list.head;
    int preview = 5;
    while (preview > 0)
    {
        cout << "IP: "    << cur->ip
             << " | TS: " << cur->timestamp
             << " | "     << cur->method
             << " "       << cur->url
             << " | "     << cur->status_code << endl;
        cur = cur->next;
        preview--;
    }

    return 0;
}
