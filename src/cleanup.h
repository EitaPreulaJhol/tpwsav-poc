#pragma once
#include <windows.h>
#include "syscalls.h"
#include "symbols.h"

bool CleanPiDDBCache(HANDLE device, SyscallTable* sc,
    ULONG64 systemCr3, KernelOffsets* offsets, const wchar_t* driverFileName);

struct MmCleanupContext {
    void* mappedDriversPage;
    void* mappedIndexPage;
    ULONG64 driversPA;
    ULONG64 indexPA;
    ULONG preUnloadIndex;
    ULONG64 driversArrayPA;
    ULONG offsetInPage;
    ULONG indexOffsetInPage;
    // True when the erased slot is the previous one in the ring, in which case
    // MmLastUnloadedDriver has to be rewound onto it.
    bool rewindIndex;
};

// driverFileName is the file name we loaded (e.g. tmp1A2B3C.sys). It is used to
// identify our own entry: the ring holds other drivers' history too and those
// must not be touched.
bool PrepareMmCleanup(HANDLE device, SyscallTable* sc,
    ULONG64 systemCr3, KernelOffsets* offsets,
    const wchar_t* driverFileName, MmCleanupContext* ctx);

bool FinishMmCleanup(MmCleanupContext* ctx);
