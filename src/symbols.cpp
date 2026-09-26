#include <windows.h>
#include <stdio.h>
#include <urlmon.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <fstream>
#include <atlbase.h>
#include <dia2.h>
#include "symbols.h"

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "psapi.lib")

struct PdbInfo {
    DWORD signature;
    GUID guid;
    DWORD age;
    char pdbFileName[1];
};

struct RTL_PROCESS_MODULE_INFORMATION {
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
};

struct RTL_PROCESS_MODULES {
    ULONG Count;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
};

typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

static bool EnablePrivilege(LPCWSTR name) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(token);
    return ok && err == ERROR_SUCCESS;
}

static ULONG64 GetKernelBase() {
    // SystemModuleInformation returns an empty module list unless
    // SeDebugPrivilege is *enabled*. An elevated token has the privilege
    // present but disabled, so relying on the token alone is not enough: it
    // happened to work from an admin terminal (which had it enabled) but
    // failed when the exe was started by double-click.
    EnablePrivilege(SE_DEBUG_NAME);

    auto NtQSI = (pNtQuerySystemInformation)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    ULONG size = 0;
    NtQSI(11, NULL, 0, &size);
    if (size == 0) return 0; // query denied, required size never returned

    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) return 0;

    if (NtQSI(11, buffer, size, &size) != 0) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)buffer;
    ULONG64 base = 0;

    for (ULONG i = 0; i < modules->Count; i++) {
        const char* name = (const char*)(
            modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName);
        if (_stricmp(name, "ntoskrnl.exe") == 0 ||
            _stricmp(name, "ntkrnlmp.exe") == 0 ||
            _stricmp(name, "ntkrnlpa.exe") == 0) {
            base = (ULONG64)modules->Modules[i].ImageBase;
            break;
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    if (base) return base;

    // Fallback for builds/EDR configs where the module list comes back empty:
    // EnumDeviceDrivers still resolves ntoskrnl under KASLR.
    LPVOID drivers[1024] = {};
    DWORD needed = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed) && needed > 0)
        base = (ULONG64)drivers[0];
    return base;
}

struct PdbDownloadInfo {
    GUID guid;
    DWORD age;
    std::string pdbFileName;
    ULONG imageSize;   // SizeOfImage, used to sanity check resolved RVAs
};

static bool GetPdbInfo(const char* pePath, PdbDownloadInfo* info) {
    std::ifstream file(pePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;

    auto fileSize = file.tellg();
    file.seekg(0);
    std::vector<char> fileData((size_t)fileSize);
    file.read(fileData.data(), fileSize);
    file.close();

    BYTE* raw = (BYTE*)fileData.data();
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    std::vector<BYTE> image(imageSize, 0);
    memcpy(image.data(), raw, nt->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (UINT i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData)
            memcpy(image.data() + section->VirtualAddress,
                   raw + section->PointerToRawData, section->SizeOfRawData);
    }

    IMAGE_DATA_DIRECTORY* debugDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (!debugDir->Size) return false;

    IMAGE_DEBUG_DIRECTORY* dbgDir =
        (IMAGE_DEBUG_DIRECTORY*)(image.data() + debugDir->VirtualAddress);
    if (dbgDir->Type != IMAGE_DEBUG_TYPE_CODEVIEW) return false;

    PdbInfo* pdb = (PdbInfo*)(image.data() + dbgDir->AddressOfRawData);
    if (pdb->signature != 0x53445352) return false;

    info->guid = pdb->guid;
    info->age = pdb->age;
    info->pdbFileName = pdb->pdbFileName;
    info->imageSize = imageSize;
    return true;
}

static std::string DownloadPdb(const PdbDownloadInfo& info) {
    wchar_t wGuid[100] = {};
    StringFromGUID2(info.guid, wGuid, 100);

    char aGuid[100] = {};
    wcstombs(aGuid, wGuid, sizeof(aGuid));

    char filtered[256] = {};
    int j = 0;
    for (int i = 0; aGuid[i]; i++) {
        char c = aGuid[i];
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))
            filtered[j++] = c;
    }

    char ageStr[16] = {};
    sprintf(ageStr, "%X", info.age);

    std::string url = "https://msdl.microsoft.com/download/symbols/";
    url += info.pdbFileName + "/" + filtered + ageStr + "/" + info.pdbFileName;

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string pdbPath = std::string(tempPath) + info.pdbFileName;

    printf("[*] Downloading PDB...\n");
    if (FAILED(URLDownloadToFileA(NULL, url.c_str(), pdbPath.c_str(), 0, NULL))) {
        printf("[-] PDB download failed\n");
        return "";
    }

    std::ifstream verify(pdbPath, std::ios::binary | std::ios::ate);
    if (!verify.is_open() || verify.tellg() < 1024) {
        DeleteFileA(pdbPath.c_str());
        return "";
    }

    printf("[+] PDB downloaded\n");
    return pdbPath;
}

// Build the list of places to look for the DIA runtime. The DLL must be the
// x64 build and match the linked diaguids.lib, so prefer the copy shipped next
// to the executable (placed there by the build) over whatever happens to be on
// PATH. Falls back to a Visual Studio DIA SDK install and finally the bare name.
static void CollectDiaCandidates(std::vector<std::wstring>& out) {
    wchar_t exePath[MAX_PATH] = {};
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        std::wstring dir(exePath);
        size_t slash = dir.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            dir.resize(slash + 1);
            out.push_back(dir + L"msdia140.dll");
        }
    }

    wchar_t programFiles[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"ProgramFiles", programFiles, MAX_PATH)) {
        std::wstring pattern = std::wstring(programFiles) +
            L"\\Microsoft Visual Studio\\*\\*\\DIA SDK\\bin\\amd64\\msdia140.dll";
        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            std::wstring base = pattern.substr(0, pattern.find_last_of(L'\\') + 1);
            do {
                out.push_back(base + fd.cFileName);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    out.push_back(L"msdia140.dll");
    out.push_back(L"msdia120.dll");
    out.push_back(L"msdia110.dll");
}

static IDiaDataSource* CreateDiaSource() {
    IDiaDataSource* source = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER,
        IID_IDiaDataSource, (void**)&source);
    if (SUCCEEDED(hr)) return source;

    std::vector<std::wstring> candidates;
    CollectDiaCandidates(candidates);

    for (const auto& dll : candidates) {
        HMODULE hMod = LoadLibraryW(dll.c_str());
        if (!hMod) {
            printf("[-] DIA: could not load %ls (error %lu)\n", dll.c_str(), GetLastError());
            continue;
        }

        typedef HRESULT(WINAPI* pDllGetClassObject)(REFCLSID, REFIID, LPVOID*);
        auto getClass = (pDllGetClassObject)GetProcAddress(hMod, "DllGetClassObject");
        if (!getClass) {
            printf("[-] DIA: %ls has no DllGetClassObject\n", dll.c_str());
            continue;
        }

        IClassFactory* factory = nullptr;
        hr = getClass(CLSID_DiaSource, IID_IClassFactory, (void**)&factory);
        if (FAILED(hr) || !factory) {
            printf("[-] DIA: %ls rejected CLSID_DiaSource (0x%08lX)\n",
                   dll.c_str(), (unsigned long)hr);
            continue;
        }

        hr = factory->CreateInstance(NULL, IID_IDiaDataSource, (void**)&source);
        factory->Release();
        if (SUCCEEDED(hr)) {
            printf("[+] DIA runtime: %ls\n", dll.c_str());
            return source;
        }
    }
    return nullptr;
}

static bool DiaGetGlobalRva(IDiaSession* session, IDiaSymbol* global,
                            const char* name, ULONG64* rva, bool dataGlobal) {
    (void)session;
    wchar_t wName[256];
    mbstowcs(wName, name, 256);

    // A global variable is described by a SymTagData entry; the public symbol
    // of the same name is only a section/offset pair, and DIA will happily
    // report a plausible but wrong RVA for it. For data globals, trust the data
    // symbol and keep the public one as a fallback. Functions are the other way
    // round. When both resolve and disagree, say so - a silent disagreement is
    // how a walk ends up reading the PE header instead of a list head.
    const enum SymTagEnum tags[] = {
        dataGlobal ? SymTagData : SymTagPublicSymbol,
        dataGlobal ? SymTagPublicSymbol : SymTagData
    };
    const char* tagNames[] = { "data", "public" };

    bool have[2] = { false, false };
    ULONG64 rvas[2] = { 0, 0 };

    for (int t = 0; t < 2; t++) {
        CComPtr<IDiaEnumSymbols> enumSyms;
        HRESULT hr = global->findChildren(tags[t], wName, nsfCaseInsensitive, &enumSyms);
        if (FAILED(hr) || !enumSyms) continue;

        CComPtr<IDiaSymbol> sym;
        ULONG celt = 0;
        if (FAILED(enumSyms->Next(1, &sym, &celt)) || celt != 1 || !sym) continue;

        // findChildren matches case-insensitively, so a neighbour like
        // "PsActiveProcessHeadLock" can come back instead of the exact name.
        BSTR symName = nullptr;
        if (SUCCEEDED(sym->get_name(&symName)) && symName) {
            bool matches = lstrcmpW(symName, wName) == 0;
            if (!matches)
                printf("[-] %s: %ls symbol is not '%s', ignoring it\n",
                       name, (wchar_t*)symName, name);
            SysFreeString(symName);
            if (!matches) continue;
        }

        DWORD rvaVal = 0;
        if (FAILED(sym->get_relativeVirtualAddress(&rvaVal))) continue;
        if (rvaVal == 0) continue; // no section/offset: not a usable address

        have[t] = true;
        rvas[t] = rvaVal;
    }

    if (have[0] && have[1] && rvas[0] != rvas[1])
        printf("[!] %s: %s says 0x%llX but %s says 0x%llX - using %s\n",
               name, tagNames[0], rvas[0], tagNames[1], rvas[1], tagNames[0]);

    if (have[0]) { *rva = rvas[0]; return true; }
    if (have[1]) { *rva = rvas[1]; return true; }

    printf("[-] symbol not found: %s\n", name);
    return false;
}

static bool DiaGetMemberOffset(IDiaSymbol* global, const char* typeName,
                               const char* memberName, ULONG* offset) {
    wchar_t wType[256], wMember[256];
    mbstowcs(wType, typeName, 256);
    mbstowcs(wMember, memberName, 256);

    CComPtr<IDiaEnumSymbols> enumTypes;
    if (FAILED(global->findChildren(SymTagUDT, wType, nsfCaseInsensitive, &enumTypes))) {
        printf("[-] type not found: %s\n", typeName);
        return false;
    }

    CComPtr<IDiaSymbol> udt;
    ULONG celt = 0;
    if (FAILED(enumTypes->Next(1, &udt, &celt)) || celt != 1) {
        printf("[-] type not found: %s\n", typeName);
        return false;
    }

    CComPtr<IDiaEnumSymbols> enumMembers;
    if (FAILED(udt->findChildren(SymTagData, wMember, nsfCaseInsensitive, &enumMembers))) {
        printf("[-] member not found: %s::%s\n", typeName, memberName);
        return false;
    }

    CComPtr<IDiaSymbol> member;
    if (FAILED(enumMembers->Next(1, &member, &celt)) || celt != 1) {
        printf("[-] member not found: %s::%s\n", typeName, memberName);
        return false;
    }

    LONG off = 0;
    if (FAILED(member->get_offset(&off))) {
        printf("[-] member has no offset: %s::%s\n", typeName, memberName);
        return false;
    }

    *offset = (ULONG)off;
    return true;
}

bool ResolveKernelOffsets(KernelOffsets* offsets) {
    CoInitialize(NULL);

    printf("[*] Finding ntoskrnl base...\n");
    offsets->NtoskrnlBase = GetKernelBase();
    if (!offsets->NtoskrnlBase) {
        printf("[-] Failed to locate ntoskrnl base\n");
        return false;
    }
    printf("[+] ntoskrnl: 0x%llX\n", offsets->NtoskrnlBase);

    PdbDownloadInfo pdbInfo = {};
    if (!GetPdbInfo("C:\\Windows\\System32\\ntoskrnl.exe", &pdbInfo)) {
        printf("[-] Failed to read ntoskrnl debug directory\n");
        return false;
    }

    std::string pdbPath = DownloadPdb(pdbInfo);
    if (pdbPath.empty()) return false;

    IDiaDataSource* source = CreateDiaSource();
    if (!source) {
        printf("[-] Failed to create DIA data source (msdia140.dll not found)\n");
        DeleteFileA(pdbPath.c_str());
        return false;
    }

    wchar_t wPdbPath[MAX_PATH];
    mbstowcs(wPdbPath, pdbPath.c_str(), MAX_PATH);

    if (FAILED(source->loadDataFromPdb(wPdbPath))) {
        printf("[-] Failed to load PDB into DIA\n");
        source->Release();
        DeleteFileA(pdbPath.c_str());
        return false;
    }

    CComPtr<IDiaSession> session;
    if (FAILED(source->openSession(&session))) {
        printf("[-] Failed to open DIA session\n");
        source->Release();
        DeleteFileA(pdbPath.c_str());
        return false;
    }

    CComPtr<IDiaSymbol> global;
    if (FAILED(session->get_globalScope(&global))) {
        printf("[-] Failed to get DIA global scope\n");
        source->Release();
        DeleteFileA(pdbPath.c_str());
        return false;
    }

    bool ok = true;
    // dataGlobal = true: these are variables, so the SymTagData RVA is the
    // authoritative one. false: these are functions.
    ok &= DiaGetGlobalRva(session, global, "PsActiveProcessHead", &offsets->PsActiveProcessHead, true);
    ok &= DiaGetGlobalRva(session, global, "PiDDBCacheTable", &offsets->PiDDBCacheTable, true);
    ok &= DiaGetGlobalRva(session, global, "PiDDBCacheList", &offsets->PiDDBCacheList, true);
    ok &= DiaGetGlobalRva(session, global, "PiDDBLock", &offsets->PiDDBLock, true);
    ok &= DiaGetGlobalRva(session, global, "MmUnloadedDrivers", &offsets->MmUnloadedDrivers, true);
    ok &= DiaGetGlobalRva(session, global, "MmLastUnloadedDriver", &offsets->MmLastUnloadedDriver, true);
    ok &= DiaGetGlobalRva(session, global, "PsInitialSystemProcess", &offsets->PsInitialSystemProcess, true);
    ok &= DiaGetGlobalRva(session, global, "PsLoadedModuleList", &offsets->PsLoadedModuleList, true);
    ok &= DiaGetGlobalRva(session, global, "HalpRMStub", &offsets->HalpRMStub, false);
    ok &= DiaGetGlobalRva(session, global, "RtlLookupElementGenericTableAvl", &offsets->RtlLookupElementGenericTableAvl, false);
    ok &= DiaGetGlobalRva(session, global, "RtlDeleteElementGenericTableAvl", &offsets->RtlDeleteElementGenericTableAvl, false);
    ok &= DiaGetGlobalRva(session, global, "ExAcquireResourceExclusiveLite", &offsets->ExAcquireResourceExclusiveLite, false);
    ok &= DiaGetGlobalRva(session, global, "ExReleaseResourceLite", &offsets->ExReleaseResourceLite, false);
    ok &= DiaGetGlobalRva(session, global, "ExFreePoolWithTag", &offsets->ExFreePoolWithTag, false);

    ok &= DiaGetMemberOffset(global, "_KPROCESS", "DirectoryTableBase", &offsets->DirectoryTableBase);
    ok &= DiaGetMemberOffset(global, "_KPROCESS", "UserDirectoryTableBase", &offsets->UserDirectoryTableBase);
    ok &= DiaGetMemberOffset(global, "_KPROCESS", "ThreadListHead", &offsets->ThreadListHead);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "UniqueProcessId", &offsets->UniqueProcessId);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "ActiveProcessLinks", &offsets->ActiveProcessLinks);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "ImageFileName", &offsets->ImageFileName);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "Protection", &offsets->Protection);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "SectionBaseAddress", &offsets->SectionBaseAddress);
    ok &= DiaGetMemberOffset(global, "_KTHREAD", "ThreadListEntry", &offsets->ThreadListEntry);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "VadRoot", &offsets->VadRoot);
    ok &= DiaGetMemberOffset(global, "_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks", &offsets->LdrInLoadOrderLinks);
    ok &= DiaGetMemberOffset(global, "_LDR_DATA_TABLE_ENTRY", "DllBase", &offsets->LdrDllBase);
    ok &= DiaGetMemberOffset(global, "_LDR_DATA_TABLE_ENTRY", "SizeOfImage", &offsets->LdrSizeOfImage);
    ok &= DiaGetMemberOffset(global, "_LDR_DATA_TABLE_ENTRY", "BaseDllName", &offsets->LdrBaseDllName);

    ok &= DiaGetMemberOffset(global, "_MMVAD_SHORT", "StartingVpn", &offsets->VadStartingVpn);
    ok &= DiaGetMemberOffset(global, "_MMVAD_SHORT", "EndingVpn", &offsets->VadEndingVpn);
    ok &= DiaGetMemberOffset(global, "_MMVAD_SHORT", "StartingVpnHigh", &offsets->VadStartingVpnHigh);
    ok &= DiaGetMemberOffset(global, "_MMVAD_SHORT", "EndingVpnHigh", &offsets->VadEndingVpnHigh);
    ok &= DiaGetMemberOffset(global, "_MMVAD_SHORT", "u", &offsets->VadFlags);

    if (!DiaGetMemberOffset(global, "_EPROCESS", "VirtualSize", &offsets->VirtualSize))
        offsets->VirtualSize = 0;

    // The member is Token in most PDBs, PrimaryToken in some. Not fatal if it
    // is missing: the thread-level impersonation still works without it.
    if (!DiaGetMemberOffset(global, "_EPROCESS", "Token", &offsets->Token) &&
        !DiaGetMemberOffset(global, "_EPROCESS", "PrimaryToken", &offsets->Token)) {
        printf("[-] _EPROCESS::Token not found, process-level SYSTEM will be skipped\n");
        offsets->Token = 0;
    } else {
        printf("[+] _EPROCESS::Token        off: 0x%X\n", offsets->Token);
    }

    // The walks below fail silently on a plausible-but-wrong RVA (they read the
    // module header and give up), so show the ones that steer them and reject
    // anything that cannot possibly be inside the image.
    struct { const char* name; ULONG64 rva; } globals[] = {
        { "PsActiveProcessHead", offsets->PsActiveProcessHead },
        { "PsLoadedModuleList",   offsets->PsLoadedModuleList },
        { "PsInitialSystemProcess", offsets->PsInitialSystemProcess },
        { "PiDDBCacheList",       offsets->PiDDBCacheList },
        { "PiDDBCacheTable",      offsets->PiDDBCacheTable },
        { "MmUnloadedDrivers",    offsets->MmUnloadedDrivers },
        { "MmLastUnloadedDriver", offsets->MmLastUnloadedDriver },
    };
    for (auto& g : globals) {
        bool inRange = g.rva != 0 && g.rva < pdbInfo.imageSize;
        printf("[%c] %-22s RVA 0x%llX%s\n", inRange ? '+' : '!', g.name, g.rva,
               inRange ? "" : "  <-- outside the image, this is garbage");
        if (!inRange) ok = false;
    }
    printf("[+] ntoskrnl SizeOfImage    0x%X\n", pdbInfo.imageSize);
    printf("[+] VirtualSize           off: 0x%X\n", offsets->VirtualSize);

    global.Release();
    session.Release();
    source->Release();
    CoUninitialize();

    DeleteFileA(pdbPath.c_str());

    if (!ok) printf("[-] Some offsets failed to resolve\n");
    else printf("[+] All offsets resolved\n");

    return ok;
}

bool ResolveSymbolRva(const char* pePath, const char* symbolName, ULONG64* rva) {
    CoInitialize(NULL);

    bool ok = false;
    PdbDownloadInfo pdbInfo;
    if (!GetPdbInfo(pePath, &pdbInfo)) {
        printf("[-] Failed to read debug directory of %s\n", pePath);
        CoUninitialize();
        return false;
    }

    std::string pdbPath = DownloadPdb(pdbInfo);
    if (pdbPath.empty()) {
        CoUninitialize();
        return false;
    }

    IDiaDataSource* source = CreateDiaSource();
    if (!source) {
        printf("[-] Failed to create DIA data source (msdia140.dll not found)\n");
        DeleteFileA(pdbPath.c_str());
        CoUninitialize();
        return false;
    }

    wchar_t wPdbPath[MAX_PATH];
    mbstowcs(wPdbPath, pdbPath.c_str(), MAX_PATH);

    if (SUCCEEDED(source->loadDataFromPdb(wPdbPath))) {
        CComPtr<IDiaSession> session;
        if (SUCCEEDED(source->openSession(&session))) {
            CComPtr<IDiaSymbol> global;
            if (SUCCEEDED(session->get_globalScope(&global)))
                ok = DiaGetGlobalRva(session, global, symbolName, rva, true);
        }
    } else {
        printf("[-] Failed to load PDB into DIA\n");
    }

    source->Release();
    DeleteFileA(pdbPath.c_str());
    CoUninitialize();
    return ok;
}
