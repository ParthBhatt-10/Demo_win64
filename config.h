#pragma once
#include <windows.h>
#include <vector>
#include <string>

constexpr DWORD MONITOR_INTERVAL_MS = 3000;

// ── SYSTEM GUARD — NEVER touch these ─────────────────────────────────
const std::vector<std::wstring> SYSTEM_PROCESSES = {
    L"system",
    L"system idle process",
    L"smss.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"winlogon.exe",
    L"lsass.exe",
    L"lsm.exe",
    L"services.exe",
    L"svchost.exe",
    L"dwm.exe",
    L"taskhost.exe",
    L"taskhostw.exe",
    L"sihost.exe",
    L"fontdrvhost.exe",
    L"spoolsv.exe",
    L"SearchIndexer.exe",
    L"RuntimeBroker.exe",
    L"SecurityHealthService.exe",
    L"MsMpEng.exe",
    L"Registry",
    L"SecureExamMonitor.exe",

    // ── Additional system processes needed for stability ────────────
    L"conhost.exe",          // Console host — needed for this terminal
    L"cmd.exe",              // Command prompt
    L"powershell.exe",       // PowerShell — needed during testing
    L"taskmgr.exe",          // Task Manager
    L"explorer.exe",         // Windows shell — desktop/taskbar
    L"ctfmon.exe",           // Text input service
    L"dllhost.exe",          // COM surrogate
    L"WmiPrvSE.exe",         // WMI provider
    L"audiodg.exe",          // Audio service
    L"NisSrv.exe",           // Windows Defender network
    L"SgrmBroker.exe",       // System Guard Runtime
    L"TextInputHost.exe",    // Touch keyboard
    L"StartMenuExperienceHost.exe",  // Start menu
    L"SearchHost.exe",       // Search
    L"ShellExperienceHost.exe",      // Shell UI
    L"ApplicationFrameHost.exe",     // UWP apps frame
    L"UserOOBEBroker.exe",   // OOBE broker
    L"backgroundTaskHost.exe" // Background tasks
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

// ── WHITELIST — ONLY these user apps are allowed to run ──────────────
// chrome.exe is intentionally removed — it will be terminated
const std::vector<std::wstring> WHITELISTED_APPS = {
    L"msedge.exe",           // Edge browser
    L"firefox.exe",          // Firefox
    L"notepad.exe",          // Notepad
    L"Code.exe",             // VS Code
    L"winword.exe",          // MS Word
    L"excel.exe",            // MS Excel
    L"devenv.exe",           // Visual Studio
};