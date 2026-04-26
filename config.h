#pragma once
#include <windows.h>
#include <vector>
#include <string>

constexpr DWORD MONITOR_INTERVAL_MS = 3000;

// ── SYSTEM GUARD — NEVER touch these regardless of any mode ──────────
// Killing any of these will crash or destabilize Windows
const std::vector<std::wstring> SYSTEM_PROCESSES = {
    L"system",               // Windows kernel (PID 4)
    L"system idle process",  // CPU idle (PID 0)
    L"smss.exe",             // Session Manager
    L"csrss.exe",            // Client/Server Runtime (critical)
    L"wininit.exe",          // Windows Initialization
    L"winlogon.exe",         // Windows Logon
    L"lsass.exe",            // Local Security Authority (critical)
    L"lsm.exe",              // Local Session Manager
    L"services.exe",         // Service Control Manager
    L"svchost.exe",          // Generic service host (many instances)
    L"dwm.exe",              // Desktop Window Manager
    L"taskhost.exe",         // Task Host
    L"taskhostw.exe",        // Task Host (Win10+)
    L"sihost.exe",           // Shell Infrastructure Host
    L"fontdrvhost.exe",      // Font Driver Host
    L"spoolsv.exe",          // Print Spooler
    L"SearchIndexer.exe",    // Windows Search
    L"RuntimeBroker.exe",    // Runtime Broker
    L"SecurityHealthService.exe", // Windows Security
    L"MsMpEng.exe",          // Windows Defender
    L"Registry",             // Registry process (Win10+)
    L"SecureExamMonitor.exe" // Our own monitor
};

// ── BLACKLIST — Remote desktop apps, always kill ──────────────────────
const std::vector<std::wstring> BLACKLISTED_APPS = {
    L"AnyDesk.exe",
    L"TeamViewer.exe",
    L"TeamViewer_Service.exe",
    L"tv_w32.exe",    L"tv_x64.exe",
    L"RustDesk.exe",
    L"UltraVNC.exe",  L"vncviewer.exe", L"winvnc.exe",
    L"LogMeIn.exe",   L"LMIGuardianSvc.exe",
    L"RemotePC.exe",  L"rpcsuite.exe",
    L"Supremo.exe",   L"SupremoService.exe",
    L"mstsc.exe",
    L"msrdcw.exe"
};

// ── WHITELIST — Trusted exam apps, always allow ───────────────────────
const std::vector<std::wstring> WHITELISTED_APPS = {
    L"explorer.exe",
    L"chrome.exe",
    L"msedge.exe",
    L"firefox.exe",
    L"notepad.exe",
    L"Code.exe",
    L"winword.exe",
    L"excel.exe",
    L"devenv.exe",
};