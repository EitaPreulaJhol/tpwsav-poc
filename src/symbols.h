#pragma once
#include <windows.h>

struct KernelOffsets {
    ULONG64 PsActiveProcessHead;
    ULONG64 PiDDBCacheTable;
    ULONG64 PiDDBCacheList;
    ULONG64 PiDDBLock;
    ULONG64 MmUnloadedDrivers;
    ULONG64 MmLastUnloadedDriver;
    ULONG64 PsInitialSystemProcess;
    ULONG64 HalpRMStub;

    ULONG64 RtlLookupElementGenericTableAvl;
    ULONG64 RtlDeleteElementGenericTableAvl;
    ULONG64 ExAcquireResourceExclusiveLite;
    ULONG64 ExReleaseResourceLite;
    ULONG64 ExFreePoolWithTag;

    ULONG DirectoryTableBase;
    ULONG UserDirectoryTableBase;
    ULONG UniqueProcessId;
    ULONG ActiveProcessLinks;
    ULONG ImageFileName;
    ULONG Protection;
    ULONG SectionBaseAddress;
    ULONG ThreadListHead;
    ULONG ThreadListEntry;
    ULONG VadRoot;

    ULONG VadStartingVpn;
    ULONG VadEndingVpn;
    ULONG VadStartingVpnHigh;
    ULONG VadEndingVpnHigh;
    ULONG VadFlags;

    ULONG VirtualSize;

    ULONG64 PsLoadedModuleList;

    ULONG LdrInLoadOrderLinks;
    ULONG LdrDllBase;
    ULONG LdrSizeOfImage;
    ULONG LdrBaseDllName;

    ULONG64 NtoskrnlBase;
};

bool ResolveKernelOffsets(KernelOffsets* offsets);

// Resolve the RVA of a single symbol from the PDB of any PE on disk.
bool ResolveSymbolRva(const char* pePath, const char* symbolName, ULONG64* rva);
