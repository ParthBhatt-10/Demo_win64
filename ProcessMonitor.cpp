#include "ProcessMonitor.h"
#include <iostream>
#include <algorithm>
#include <windows.h>      // ← SECURITY_MAX_SID_SIZE lives here
#include <sddl.h>         // ← WELL_KNOWN_SID_TYPE, CreateWellKnownSid
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "advapi32.lib")  // ← CreateWellKnownSid, EqualSid

std::vector<ProcessAction> ProcessMonitor::ScanAndEnforce(
    const std::vector<std::wstring>& blacklist,
    const std::vector<std::wstring>& whitelist,
    const std::vector<std::wstring>& systemGuard,
    bool strictMode)
{
    std::vector<ProcessAction> actions;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[ERROR] Snapshot failed. Code: " << GetLastError();
        return actions;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return actions;
    }

    do {
        std::wstring name = entry.szExeFile;
        DWORD pid         = entry.th32ProcessID;

        if (pid == 0 || pid == 4) continue;

        if (IsSystemProcess(name, systemGuard)) continue;

        if (IsOwnedBySystem(pid)) continue;

        if (IsBlacklisted(name, blacklist)) {
            bool killed = KillProcessByPID(pid, name);
            actions.push_back({ name, pid, killed, L"blacklisted" });
            continue;
        }

        if (IsWhitelisted(name, whitelist)) continue;

        if (strictMode) {
            std::wcout << L"[UNKNOWN] " << name
                       << L" (PID:" << pid
                       << L") not on whitelist." << std::endl;
            bool killed = KillProcessByPID(pid, name);
            actions.push_back({ name, pid, killed, L"unknown" });
        }

    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return actions;
}

// ── IsOwnedBySystem — FIXED ───────────────────────────────────────────
bool ProcessMonitor::IsOwnedBySystem(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return false;
    }

    bool isSystem = false;

    // Build SYSTEM SID manually — this always works without sddl.h
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID systemSid = nullptr;

    // SYSTEM — 1 subauthority: SECURITY_LOCAL_SYSTEM_RID (18)
    if (AllocateAndInitializeSid(&ntAuthority, 1,
        SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0,
        &systemSid))
    {
        BOOL isMember = FALSE;
        if (CheckTokenMembership(hToken, systemSid, &isMember) && isMember)
            isSystem = true;
        FreeSid(systemSid);
    }

    if (!isSystem) {
        // LOCAL SERVICE — subauthority value 19
        PSID localSvcSid = nullptr;
        if (AllocateAndInitializeSid(&ntAuthority, 1,
            19,   // SECURITY_LOCAL_SERVICE_RID = 19
            0, 0, 0, 0, 0, 0, 0,
            &localSvcSid))
        {
            BOOL isMember = FALSE;
            if (CheckTokenMembership(hToken, localSvcSid, &isMember) && isMember)
                isSystem = true;
            FreeSid(localSvcSid);
        }
    }

    if (!isSystem) {
        // NETWORK SERVICE — subauthority value 20
        PSID networkSvcSid = nullptr;
        if (AllocateAndInitializeSid(&ntAuthority, 1,
            20,   // SECURITY_NETWORK_SERVICE_RID = 20
            0, 0, 0, 0, 0, 0, 0,
            &networkSvcSid))
        {
            BOOL isMember = FALSE;
            if (CheckTokenMembership(hToken, networkSvcSid, &isMember) && isMember)
                isSystem = true;
            FreeSid(networkSvcSid);
        }
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return isSystem;
}
// ── Other private helpers (unchanged) ────────────────────────────────

bool ProcessMonitor::IsSystemProcess(const std::wstring& name,
                                      const std::vector<std::wstring>& list) {
    std::wstring lower = ToLower(name);
    for (const auto& e : list)
        if (lower == ToLower(e)) return true;
    return false;
}

bool ProcessMonitor::IsBlacklisted(const std::wstring& name,
                                    const std::vector<std::wstring>& list) {
    std::wstring lower = ToLower(name);
    for (const auto& e : list)
        if (lower == ToLower(e)) return true;
    return false;
}

bool ProcessMonitor::IsWhitelisted(const std::wstring& name,
                                    const std::vector<std::wstring>& list) {
    std::wstring lower = ToLower(name);
    for (const auto& e : list)
        if (lower == ToLower(e)) return true;
    return false;
}

bool ProcessMonitor::KillProcessByPID(DWORD pid, const std::wstring& name) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) {
        std::wcerr << L"[WARN] Cannot open: " << name
                   << L" Code:" << GetLastError() << std::endl;
        return false;
    }
    bool ok = TerminateProcess(h, 1);
    CloseHandle(h);
    if (ok) std::wcout << L"[BLOCKED] " << name
                       << L" (PID:" << pid << L")" << std::endl;
    return ok;
}

std::wstring ProcessMonitor::ToLower(const std::wstring& str) {
    std::wstring s = str;
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}