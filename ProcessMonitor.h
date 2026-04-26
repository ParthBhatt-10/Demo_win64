#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

struct ProcessAction {
    std::wstring processName;
    DWORD        pid;
    bool         killed;
    std::wstring reason; // "blacklisted" | "unknown" | "whitelisted" | "system_guard"
};

class ProcessMonitor {
public:
    std::vector<ProcessAction> ScanAndEnforce(
        const std::vector<std::wstring>& blacklist,
        const std::vector<std::wstring>& whitelist,
        const std::vector<std::wstring>& systemGuard,
        bool strictMode = false
    );

private:
    bool IsBlacklisted (const std::wstring& name, const std::vector<std::wstring>& list);
    bool IsWhitelisted (const std::wstring& name, const std::vector<std::wstring>& list);
    bool IsSystemProcess(const std::wstring& name, const std::vector<std::wstring>& list);

    // NEW: Check if the process owner is a Windows system account
    bool IsOwnedBySystem(DWORD pid);

    bool KillProcessByPID(DWORD pid, const std::wstring& name);
    std::wstring ToLower(const std::wstring& str);
};