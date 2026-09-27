# tpwsav-poc

Basically a DSE disabler. It borrows a read/write window on physical memory from a
known-vulnerable, long-EOL signed driver, and uses that window to do some "usual"
stuff: hide its own memory from VAD enumeration, scrub the loader traces
it just left behind, take the SYSTEM token and mark itself and its console host
as a fully protected process, and finally sets g_CiOptions to 0.

This is a research tool. Run it on a machine you own or are authorised to
test. It patches kernel data structures and loads a driver that is vulnerable.  
It can (and will, because of PatchGuard) cause BSOD's on the running system.
You have been warned.

## The driver

`tpwsav.sys` is a legitimate signed driver by **Compal Electronic**, for the
Toshiba laptop power management (the Toshiba Power Saver package).  
The driver is embedded in the `driver_bytes.h` header so the .exe carries everything it needs in one file.

## What it does

Basically, here's the detailed overview of what the final .exe does:

1. **Self-elevate.** Relaunches via `runas` if the user isn't elevated, and
   makes sure a console exists before the first `printf`.
2. **Resolve syscalls.** Parses the ntdll stubs directly (`4C 8B D1 B8` +
   dword) instead of importing them, so nothing in the import table looks odd.
3. **Resolve kernel offsets.** Finds the ntoskrnl base, downloads its PDB from
   msdl.microsoft.com, and pulls the globals and struct members it needs out of
   DIA. Data globals prefer the `SymTagData` entry over the public symbol.
4. **Enable `SeLoadDriverPrivilege`** and drop the embedded driver into `%TEMP%`.
5. **Register and load it**, then open `\DosDevices\EBIoDispatch`.
6. **Leak a `\Device\PhysicalMemory` handle** through the driver's first
   `IOCTL_MAP_PHYS`, then use it to map physical RAM in 1 GiB chunks. It probes
   64 GiB. The mapping is lazy, so unmapped chunks cost nothing.
7. **Brute-force the System CR3** out of low physical memory: a candidate page
   has to map the kernel, map itself, and resolve the kernel base to an MZ header.
8. **Pre-fault a prefix of the window**, then truncate the MMVADs behind it so
   the mapping is invisible to `VirtualQuery` and to anything else that walks the
   VAD tree.
9. **Clean the PiDDB** entry for the driver it just loaded.
10. **Restore the VADs**, unload the driver, delete the service key.
11. **Take the SYSTEM token** - both the thread token (`SetThreadToken`) and,
    more usefully, the process's primary token via `EPROCESS::Token`, so the
    process itself reports as SYSTEM rather than just its API calls.
12. **Set PPL `0x44`** (`PsProtectedType4 | PsProtectedSignerWindows`) on itself
    *and* on the `conhost.exe` that owns its console, so the process tree doesn't
    leave a non-protected sibling behind.
13. **Disable DSE** by zeroing `ci.dll!g_CiOptions`.
14. **Lock the process DACL** (deny Everyone, grant SYSTEM) as the last step.

## How the vulnerable is loaded

All of this goes through the raw NT syscalls resolved at startup, not through `advapi32`.

1. **Enable `SeLoadDriverPrivilege`** on the process token.
2. **Write the driver bytes to `%TEMP%\tmp<tick>.sys`**, the name derived from
   `GetTickCount64` so back-to-back runs don't collide. Created with
   `NtCreateFile` as `FILE_OVERWRITE_IF | FILE_SYNCHRONOUS_IO_NONALERT`, then
   `NtWriteFile` from the embedded array.
3. **Create the service key** by hand:
   `HKLM\System\CurrentControlSet\Services\tmp<tick>` via `NtCreateKey`, then two
   `NtSetValueKey` calls. `ImagePath` (`REG_EXPAND_SZ`, the `\??\...` NT path)
   and `Type` (`REG_DWORD`, `1` = `SERVICE_KERNEL_DRIVER`).
4. **Load it** with `NtLoadDriver` on that key.
5. **Delete the file** straight away. The image is mapped and running by then,
   so the on-disk copy is only trace material.
6. **Open the device**, `\DosDevices\EBIoDispatch`, for read/write.

The service key is removed again at the end of the run, after `NtUnloadDriver`.

The first `IOCTL_MAP_PHYS` on that handle is where the driver misbehaves and
returns a usable `PhysicalMemory` handle instead of a mapped view. That leak is
what the rest of the tool is built on.

## Status

Verified on Windows 11 26100, with and without HVCI:

| | |
|---|---|
| Physical memory window | works |
| System CR3 discovery | works |
| VAD spoof + restore | works, limited to the pre-faulted prefix |
| PiDDB cleanup | works |
| SYSTEM primary + thread token | works |
| PPL `0x44`, self and conhost | works |
| DSE disable | works, but the write is **refused under HVCI** |
| `MmUnloadedDrivers` cleanup | **does not work** |

The tool prints an honest verdict for every step, including the ones that fail.
It will not write into kernel memory on a guess.

## `MmUnloadedDrivers`: the one that doesn't work

The PDB points `MmUnloadedDrivers` at something that looks like a ring (the
populated slot count tracks the ring index) but it is not a 50-entry array of
`UNLOADED_DRIVERS_ENTRY`. Across three runs and two different builds, not one of
the five qwords in a slot was a pointer to a name string. The published struct
layout was tried, the previous-slot ordering was tried, and a probe of every
8-byte word of the recent slots was tried. None of them found the entry.

So the step scans the ring, fails to find the driver by name, prints the raw
bytes of the two most recent slots so the layout is visible, and refuses to
write. A name-based search for the loader's copy of the driver name was also
tried and removed. It faulted reproducibly at the 1 GiB chunk boundary, which
suggests the window's own residency bookkeeping is sketchy independently of
anything the search did. If someone got an idea, let me know!

## Requirements

- Windows 10/11 x64
- Administrator (the .exe re-launches itself with UAC)
- Internet access on first run, for the PDB download

## Building

Visual Studio 2022/2026 (toolset v145), Release x64:

```
msbuild tpwsav.sln -p:Configuration=Release -p:Platform=x64
```

Output is `build/tpwsav.exe`. The DIA runtime (`msdia140.dll`) is copied next to
the .exe by a post-build step, so the PDB parsing works on most machines.


## Layout

```
src/main.cpp        run order, console/elevation, crash reporting
src/window.cpp      physical memory window, VAD spoof/restore, EPROCESS walks
src/physmem.cpp     driver IOCTL path, window path, page-table walks
src/cleanup.cpp     PiDDB and MmUnloadedDrivers
src/protect.cpp     tokens, DACL, child process elevation
src/dse.cpp         g_CiOptions resolution and write
src/symbols.cpp     PDB download and DIA symbol/offset resolution
src/resolver.cpp    ntdll stub parsing
src/reader.cpp      cross-process read demo, not part of the loader path
src/driver_bytes.h  the embedded driver
src/syscalls.asm    the syscall stubs
```

The crash reporter in `main.cpp` is worth knowing about if you extend this: it
tags every phase, so an unhandled exception prints where it happened and then
restores the VAD tree rather than leaving a truncated VAD behind for the section
teardown path to trip over.

## Credits

This project is based on
[physmem-driverless](https://github.com/AlamoRick/physmem-driverless) by
AlamoRick, which is where the driverless physical memory approach comes from.
