#pragma once
#include <windows.h>
#include "symbols.h"

// Disables Driver Signature Enforcement by zeroing ci.dll!g_CiOptions
// through the physical memory window (no driver, no ring0 code).
bool DisableDSE(ULONG64 systemCr3, KernelOffsets* offsets);
