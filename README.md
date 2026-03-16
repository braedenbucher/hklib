# hklib

Experimental Windows kernel hook library using trampoline detours and atomic 16-byte inline patching. Allows authors to initialize trampolines for each detour, and restore them gracefully on driver exit.

## Environment and Workflow

OS: VMWare Workstation Windows 10/11 x64 Virtual Machine

Toolchain: Visual Studio + Windows Driver Kit (WDK)

Driver type: kernel-mode driver

Build using the Visual Studio driver project configuration.

Basic testing was performed in a virtual machine with kernel debugging enabled.
1. Build the driver with Visual Studio.
2. Boot the VM with kernel debugging enabled.
3. Load the driver.
4. Use WinDbg to inspect patched functions and verify trampoline execution.
5. Manual validation of hook installation and restoration.

Future expansions should include more structured testing. This version is experimental.

## Usage

The library exposes a small API:
```c
PHK_TRAMPOLINE trampoline;

// Initialize the library
HkInitialize();

// Apply the patch and populate the trampoline
NTSTATUS status = HkDetourFunction(TargetFunction, MyHookFunction, &trampoline);

// call the hook

// Restore the patch and free the trampoline
NTSTATUS status = HkRestoreFunction(trampoline);
NTSTATUS status = HkReleaseTrampoline(trampoline);

// Restore and release all active trampolines
HkReleaseAllHooks();
```

When a hook is installed with `HkDetourFunction`, a trampoline is populated that contains:
- The relocated instructions that were overwritten in the target function
- A jump back to the original execution flow
This entry point in the field `Trampoline->RelocatedCode` behaves like the original function.
To invoke the original implementation from a hook, cast this pointer to the original function prototype and call it normally.

Example:
```c
typedef NTSTATUS (*NtOpenProcess_t)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

PHK_TRAMPOLINE Trampoline;

NTSTATUS NtOpenProcessHook(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
)
{
    NtOpenProcess_t Original =
        (NtOpenProcess_t) Trampoline->RelocatedCode;

    return Original(
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ClientId
    );
}
```
A helper macro may be used to simplify the cast:
```c
#define HK_CALL_ORIGINAL(trampoline, type) ((type)((trampoline)->RelocatedCode))
```
Usage:
```c
return HK_CALL_ORIGINAL(Trampoline, NtOpenProcess_t)(
    ProcessHandle,
    DesiredAccess,
    ObjectAttributes,
    ClientId
);
```
The caller must still define the correct function typedef so the compiler receives the return type, parameters, and calling convention.

## Primary Utilities and Mechanisms

- Uses an external **Length Disassembler** (`ld.c`) to determine the size of instructions at the start of a target function. The detour requires a minimum overwrite size (16 bytes), so instructions are decoded without splitting.
- **Trampoline Construction** - On hook installation he overwritten instructions and another relative jump are copied into an executable buffer inside the trampoline. Execution can continue normally by jumping from this relocated block back into the original function after the patched region.
- The hook patch uses a **RIP-Relative Detour Stub** consisting of a jump instruction (`FF 25 [rip+0]`) followed by an absolute pointer to the hook. This is a standard detour technique to  jump to any 64-bit address without relying on 32-bit relative offsets.
- **Atomic 16-Byte Code Patching** - The original function is modified using a 16-byte atomic compare-and-swap via `InterlockedCompareExchange128`. This _reduces_ (not eliminates) the chance of partially written instructions being observed by another CPU during patch installation.
- Executable kernel code is typically read-only. This implementation uses an **MDL-Based Writable Mapping** to allow read-only physical memory to be modified. A separate virtual page generated from an MDL (`Memory Descriptor List`) adjusts page protection to allow writing before patching.
- Installed hooks have are tracked in a **Global Hook Table** protected by a spinlock. Each hook transitions through a simple lifecycle:
    - `HK_INACTIVE` – trampoline allocated but not installed
    - `HK_ACTIVE` – detour installed and operational
    - `HK_DRAINING` – hook removed and awaiting cleanup
- **Restoration and cleanup** - The original function bytes are stored when the hook is installed.
    - `HkRestoreFunction` atomically restores these bytes, removing the detour while leaving the trampoline structure intact for cleanup.
    - `HkReleaseAllHooks` enumerates active hooks, restores the original code, and releases trampoline memory. This provides a basic mechanism for driver unload or emergency cleanup.

## Limitations


- **No RIP-Relative Instruction Relocation** - Instructions copied into the trampoline are not rewritten if they reference memory relative to the instruction pointer. If the relocated instructions contain RIP-relative addressing, the displacement will point to an incorrect location when executed from the trampoline.
- **No Relative Branch Rewriting** - Relative branches (such as `call`, `jmp`, or conditional jumps) inside the relocated instruction block are copied exactly. If such instructions target addresses outside the relocated block, execution may behave incorrectly.
- The atomic patch routine enforces a **16-byte Alignment Requirement**. This library rejects functions not aligned, since they cannot be hooked without modifying the patch strategy.
- **No Thread Synchronization During Patching** - The implementation does not pause or synchronize other processors while patching executable code. While the write itself is atomic, another thread executing the function at the same time could theoretically observe inconsistent control flow.
- The disassembler is also experimental. Instruction decoding determines semi-accurate instruction length for many instructions, but does not account for the entire x86 instruction set. The decoder is not used to analyze semantics or relocation. This is a planned future update for the project.

This library also contains many test states such as a fixed size table and small trampoline metadata, as they were unecessary or out-of-scope. Future updates can implement dynamic resizing, duplicate detection, or a more advanced hook state machine. Additionally, this implementation was tested manually in a virutal environment using debugging tools. It has not been stress tested under concurrency or multiple kernel versions.

## License

MIT License - see [LICENSE](LICENSE) for details

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes.
