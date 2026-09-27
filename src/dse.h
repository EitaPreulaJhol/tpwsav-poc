#pragma once
#include <windows.h>
#include "symbols.h"

// Resolve ci.dll!g_CiOptions' RVA, which means downloading that module's PDB and
// running DIA over it. That is by far the most memory-hungry thing the loader
// does, so it happens up front - before the physical window commits a couple of
// gigabytes - and DisableDSE() is then only a translate and a write.
bool ResolveCiOptionsRva(ULONG64* outRva);

// Zeroes ci.dll!g_CiOptions through the physical window (no driver, no ring0
// code). rva comes from ResolveCiOptionsRva; when it is unknown the variable is
// located structurally from the CI validation functions, which needs the window
// and therefore runs late.
bool DisableDSE(ULONG64 systemCr3, KernelOffsets* offsets, bool haveRva, ULONG64 rva);
