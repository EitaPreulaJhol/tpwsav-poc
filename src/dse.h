#pragma once
#include <windows.h>
#include "symbols.h"

// Resolve ci.dll!g_CiOptions' RVA: download that PDB and run DIA over it.
// Done up front, because it is the most memory-hungry step here, so DisableDSE()
// is left with just a translate and a write.
bool ResolveCiOptionsRva(ULONG64* outRva);

// Zeroes ci.dll!g_CiOptions through the physical window (no driver, no ring0
// code). rva comes from ResolveCiOptionsRva; when it is unknown the variable is
// located structurally from the CI validation functions, which needs the window
// and therefore runs late.
bool DisableDSE(ULONG64 systemCr3, KernelOffsets* offsets, bool haveRva, ULONG64 rva);
