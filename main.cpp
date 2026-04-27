#include <iostream>
#include <windows.h>
#include <atomic>
#include "Config.h"
#include "ProcessMonitor.h"

std::atomic<bool> g_running(true);

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        std::wcout << L"\n[INFO] Shutdown received. Stopping..." << std::endl;
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

int main() {
    std::wcout << L"======================================\n";
    std::wcout << L"   Secure Exam Monitor  -  Active     \n";
    std::wcout << L"======================================\n";

    // ── SET EXAM DURATION HERE ────────────────────────────────────────
    const int EXAM_HOURS   = 0;   // ← change this
    const int EXAM_MINUTES = 1;   // ← change this
    const int EXAM_SECONDS = 0;   // ← change this

    const DWORD EXAM_DURATION_MS =
        ((EXAM_HOURS   * 3600) +
         (EXAM_MINUTES *   60) +
          EXAM_SECONDS) * 1000;

    // ── SET THIS TO true TO ENFORCE WHITELIST ─────────────────────────
    bool strictMode = true;   // ← changed to true

    std::wcout << L"[TIME] Auto-shutdown in: "
               << EXAM_HOURS   << L"h "
               << EXAM_MINUTES << L"m "
               << EXAM_SECONDS << L"s\n";

    if (strictMode)
        std::wcout << L"[MODE] STRICT — only whitelisted apps allowed.\n";
    else
        std::wcout << L"[MODE] NORMAL — blocking known remote desktop apps only.\n";

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    ProcessMonitor monitor;
    int   cycle      = 0;
    DWORD elapsed_ms = 0;

    while (g_running) {

        // ── AUTO SHUTDOWN CHECK ───────────────────────────────────────
        if (elapsed_ms >= EXAM_DURATION_MS) {
            std::wcout << L"\n[INFO] Exam time is up! "
                       << L"Monitor shutting down automatically.\n";
            break;
        }

        // ── TIME REMAINING DISPLAY ────────────────────────────────────
        DWORD remaining_ms = EXAM_DURATION_MS - elapsed_ms;
        DWORD rem_hours    = remaining_ms / 3600000;
        DWORD rem_minutes  = (remaining_ms % 3600000) / 60000;
        DWORD rem_seconds  = (remaining_ms % 60000)   / 1000;

        std::wcout << L"\n[SCAN #" << ++cycle
                   << L"] Scanning... | Time remaining: "
                   << rem_hours   << L"h "
                   << rem_minutes << L"m "
                   << rem_seconds << L"s\n";

        // ── SCAN (unchanged) ──────────────────────────────────────────
        auto actions = monitor.ScanAndEnforce(
            BLACKLISTED_APPS,
            WHITELISTED_APPS,
            SYSTEM_PROCESSES,
            strictMode
        );

        int blacklistHits = 0, unknownHits = 0;
        for (const auto& a : actions) {
            if (a.reason == L"blacklisted") blacklistHits++;
            if (a.reason == L"unknown")     unknownHits++;
        }

        if (blacklistHits > 0)
            std::wcout << L"[ALERT] " << blacklistHits
                       << L" blacklisted app(s) terminated.\n";
        if (unknownHits > 0)
            std::wcout << L"[WARN]  " << unknownHits
                       << L" unknown app(s) terminated (strict mode).\n";
        if (blacklistHits == 0 && unknownHits == 0)
            std::wcout << L"[OK]    No threats detected.\n";

        // ── SLEEP (unchanged) ─────────────────────────────────────────
        for (int i = 0; i < 30 && g_running; i++)
            Sleep(MONITOR_INTERVAL_MS / 30);

        elapsed_ms += MONITOR_INTERVAL_MS;
    }

    std::wcout << L"[INFO] Monitor stopped cleanly.\n";
    return 0;
}