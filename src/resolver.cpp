#include <windows.h>
#include <stdio.h>
#include "syscalls.h"

// Walk ntdll's export table by hand to find a function, so the loader does not
// need an import for every syscall stub it resolves.
static FARPROC FindExport(HMODULE module, const char* funcName) {
    BYTE* base = (BYTE*)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY* exportDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir->VirtualAddress == 0)
        return NULL;

    IMAGE_EXPORT_DIRECTORY* exports =
        (IMAGE_EXPORT_DIRECTORY*)(base + exportDir->VirtualAddress);

    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);
        if (strcmp(name, funcName) == 0)
            return (FARPROC)(base + functions[ordinals[i]]);
    }
    return NULL;
}

// Read the syscall number out of a stub. Every x64 stub starts
//   4C 8B D1       mov r10, rcx
//   B8 <ssn>       mov eax, ssn
// so the number is the dword at offset 4.
static DWORD GetSyscallNumber(FARPROC func) {
    if (!func) return 0;
    BYTE* bytes = (BYTE*)func;

    // 4C 8B D1 B8 = mov r10, rcx; mov eax, <ssn>
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8)
        return *(DWORD*)(bytes + 4);

    return 0;
}

// Populate the table with the syscall numbers for the stubs this loader uses.
// Any zero means a stub did not have the expected shape, and the whole table is
// rejected rather than used with a hole in it.
bool ResolveSyscalls(SyscallTable* table) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    table->NtLoadDriver = GetSyscallNumber(FindExport(ntdll, "NtLoadDriver"));
    table->NtUnloadDriver = GetSyscallNumber(FindExport(ntdll, "NtUnloadDriver"));
    table->NtCreateFile = GetSyscallNumber(FindExport(ntdll, "NtCreateFile"));
    table->NtWriteFile = GetSyscallNumber(FindExport(ntdll, "NtWriteFile"));
    table->NtDeviceIoControlFile = GetSyscallNumber(FindExport(ntdll, "NtDeviceIoControlFile"));
    table->NtClose = GetSyscallNumber(FindExport(ntdll, "NtClose"));
    table->NtCreateKey = GetSyscallNumber(FindExport(ntdll, "NtCreateKey"));
    table->NtSetValueKey = GetSyscallNumber(FindExport(ntdll, "NtSetValueKey"));
    table->NtDeleteKey = GetSyscallNumber(FindExport(ntdll, "NtDeleteKey"));

    DWORD* numbers = (DWORD*)table;
    for (int i = 0; i < sizeof(SyscallTable) / sizeof(DWORD); i++) {
        if (numbers[i] == 0) {
            printf("[-] Failed to resolve syscall %d\n", i);
            return false;
        }
    }

    printf("[+] Syscalls resolved\n");
    return true;
}
