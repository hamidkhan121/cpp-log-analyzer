#pragma once
#include "log_entry.h"
#include <iostream>
using namespace std;

class LogList
{
public:
    LogEntry* head;
    int count;

    LogList(): head(NULL), count(0) {} // constructor

        ~LogList() // destructor
    {
        LogEntry* current = head;
        while (current != NULL)
        {
            LogEntry* toDelete = current;
            current = current->next;
            delete toDelete;
        }
    }

    //Inserting at the beginning (head)
    void insertAtHead(LogEntry* entry)
    {
        entry->next = head; // new node entry points at the old node head
        head = entry; // head point is remapped towards entry
        count++;
    }

    void PrintAll()
    {
        LogEntry* current = head;
        while (current != NULL)
        {
            cout << "IP: " << current->ip << " | " << " Status_Code: " << current->status_code 
            << " | " << " url: " << current->url << endl;
            current = current->next;
        }

    }

};