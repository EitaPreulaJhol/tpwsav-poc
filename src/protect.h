#pragma once
#include <windows.h>
#include "syscalls.h"
#include "symbols.h"

// _EPROCESS::Protection packs (signer << 4) | type:
//   type:   0x00 none, 0x01 PsProtectedType1 .. 0x04 PsProtectedType4 (highest)
//   signer: 0x00 none, 0x10 Authenticode, 0x20 Antimalware, 0x30 Lsa, 0x40 Windows
// "WinSystem" is the highest type with the Windows signer. (The value this
// replaced, 0x31, was Type1|Lsa, not the Light Antimalware its comment claimed -
// that would have been 0x21.)
#define PPL_FULL_WINSYSTEM 0x44   // PsProtectedType4 | PsProtectedSignerWindows

bool ImpersonateSystem();
bool LockProcessDACL();

// Bring every child with this image name (e.g. the conhost.exe that owns our
// console) up to our own state: the System primary token and the same PPL level.
// CSRSS spawns the console host before any token work happens, so it still
// carries the original interactive account.
bool MatchChildToSystem(ULONG64 systemCr3, KernelOffsets* offsets, const wchar_t* imageName);

// Print the raw Protection byte of every matching child process.
void ReportChildProtection(ULONG64 systemCr3, KernelOffsets* offsets, const wchar_t* imageName);
