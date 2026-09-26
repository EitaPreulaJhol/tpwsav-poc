#pragma once
#include <windows.h>
#include "syscalls.h"
#include "symbols.h"

// _EPROCESS::Protection packs (signer << 4) | type:
//   type:   0x00 none, 0x01 PsProtectedType1 .. 0x04 PsProtectedType4 (highest)
//   signer: 0x00 none, 0x10 Authenticode, 0x20 Antimalware, 0x30 Lsa, 0x40 Windows
// The level shown as "WinSystem" is the highest type with the Windows signer.
// Note the previous value here was 0x31, which is PsProtectedType1 | Lsa - the
// Antimalware signer is 0x20, so 0x21 would have been the "Light Antimalware"
// level the old comment claimed.
#define PPL_FULL_WINSYSTEM 0x44   // PsProtectedType4 | PsProtectedSignerWindows

bool ImpersonateSystem();
bool LockProcessDACL();

// Bring every child process with this image name (e.g. the conhost.exe that owns
// our console) up to the same state as us: the System primary token and the same
// PPL level. CSRSS spawns the console host before any token work happens, so it
// still carries the original interactive account.
bool MatchChildToSystem(ULONG64 systemCr3, KernelOffsets* offsets, const wchar_t* imageName);

// Print the raw Protection byte of every matching child process.
void ReportChildProtection(ULONG64 systemCr3, KernelOffsets* offsets, const wchar_t* imageName);
