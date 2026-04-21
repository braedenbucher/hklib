# Additional Features
The initial kernel hook implementation was a great foundation for learning inline hooking mechanics, but it has a few notable limitations:
1. **The trampoline is an unstructured buffer.** The trampoline is just a flat array of bytes, and the layout is implied. The caller would have to know that the first 16 bytes are preserved code, and the rest is the relocated instructions and jump. It's fine for minimality, but if we want to expand the trampoline behavior then we have to move to a better alternative. Our first job will be replacing it with an explicit struct to hold metadata: the original and hook function pointers, named buffers for the preserved and relocated code, and state fields for the restoration to enforce valid transitions.
2. **The restore function doesn't guard against free-while-executing.** It performs the atomic write to reinstate the initial bytes, but doesn't validate the trampoline is inactive before freeing. We just wait 10ms and hope it's not in use. This is a known shortcut, but not a guarantee. We'll resolve this by splitting the restore into two phases. `HkRestorefunction` will perform the atomic patch and transition the struct into a draining state. `HkReleaseTrampoline` will free the allocation, meaning the caller decides when it's safe to release, not us.
3. **Installing, executing, and handling trampolines needs a more convenient API** For consistent library usage, exposing macros for hook creation, as well as a table to keep track of all trampolines and their states is necessary. This will involve registering trampolines with the table on install, as well as unregistering them on cleanup. Also, a method for releasing all trampolines is nice for convenience.
4. **If the hooked function is called again withing your hook's own call chain, unbounded recursion occurs.** If our hooked function triggers the hooked function again, execution will re-enter the hook before the first invocation has ended. The kernel will overflow the stack and cause a bugcheck. The plan is a per-CPU reentrancy guard stored in the trampoline: an array of flags for the active processor count, set on hook entry for the CPU and cleared on exit. If it's already set when the hook is entered, execution bypasses the hook and falls through to the trampoline immediately.

# Struct and Detour Rewrite

We will start by creating a `struct` for our trampoline. This means all fields are accessible without pointer arithmetic, and the layout is explicitly declared rather than implied. For our restoration goal, we will need a state `enum` as declared below. 

```c
typedef enum _HK_STATE {
    HK_INACTIVE = 0,
    HK_ACTIVE = 1,
    HK_DRAINING = 2,
} HK_STATE;

typedef struct _HK_TRAMPOLINE {
    PVOID OriginalFunction;
    PVOID HookFunction;
    UCHAR OriginalBytes[ATOMIC_PATCH_SIZE];
    PUCHAR RelocatedCode;
    HK_STATE State;
} HK_TRAMPOLINE, *PHK_TRAMPOLINE;
```

## Signature and Setup

```c
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkDetourFunction(
	_In_ PVOID TargetFunction,
	_In_ PVOID HookFunction,
	_Out_ PHK_TRAMPOLINE* OutTrampoline
) {
    NTSTATUS Status;
    SIZE_T CopiedCodeLength;
    UCHAR DetourPatch[ATOMIC_PATCH_SIZE];
    
    if (OutTrampoline == NULL) {
        return STATUS_INVALID_PARAMETER_4;
    }

    PHK_TRAMPOLINE Trampoline = (PHK_TRAMPOLINE) ExAllocatePool2(
	    POOL_FLAG_NON_PAGED,
	    sizeof(HK_TRAMPOLINE),
	    HK_POOL_TAG
	);
    if (Trampoline == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(Trampoline, sizeof(HK_TRAMPOLINE));
```

- We no longer need to take `CopiedCodeLength` as an input since our length disassembler will capture it.

## Populating the Struct
We start with the pointers we can immediately fill:

```c
Trampoline->OriginalFunction = TargetFunction;
Trampoline->HookFunction     = HookFunction;
Trampoline->State            = HK_INACTIVE;
```

We can copy the bytes over using `RtlCopyMemory` and `HkpGetMinimumCopyLength`:

```c
// Get instruction copy length
Status = HkpGetMinimumCopyLength(TargetFunction, &CopiedCodeLength);
if (!NT_SUCCESS(Status)) {
    ExFreePoolWithTag(Trampoline, HK_POOL_TAG);
    return Status;
}

// copy 16 bytes over
RtlCopyMemory(
	Trampoline->OriginalBytes,
	TargetFunction,
	ATOMIC_PATCH_SIZE
);

// allocate executable space for relocated code
Trampoline->RelocatedCode = ExAllocatePool2(
	POOL_FLAG_NON_PAGED_EXECUTE,
	CopiedCodeLength + FULL_DETOUR_SIZE,
	HK_POOL_TAG
);
if (Trampoline->RelocatedCode == NULL) {
    ExFreePoolWithTag(Trampoline, HK_POOL_TAG);
    return STATUS_INSUFFICIENT_RESOURCES;
}

// copy complete instructions and riprelativejump over
RtlCopyMemory(
	Trampoline->RelocatedCode,
	TargetFunction,
	CopiedCodeLength
);
HkpPlaceRipJump(
	Trampoline->RelocatedCode + CopiedCodeLength,
	(PVOID)((ULONG_PTR)TargetFunction + CopiedCodeLength)
);
```

## Placing the Patch
Lastly, building and placing the patch is identical, just updating the struct to `HK_ACTIVE` on success.

```c
HkpPlaceRipJump(DetourPatch, HookFunction);
RtlCopyMemory(
	(PUCHAR)DetourPatch + FULL_DETOUR_SIZE,
	(PUCHAR)TargetFunction + FULL_DETOUR_SIZE,
	ATOMIC_PATCH_SIZE - FULL_DETOUR_SIZE
);

Status = HkpAtomicWriteCode16Bytes(TargetFunction, DetourPatch);
if (!NT_SUCCESS(Status)) {
    ExFreePoolWithTag(Trampoline->RelocatedCode, HK_POOL_TAG);
    ExFreePoolWithTag(Trampoline, HK_POOL_TAG);
} else {
    Trampoline->State = HK_ACTIVE;
    *OutTrampoline = Trampoline;
}

return Status;
```

# Two-Part Restoration

Our currrent restoration process isn't secure because we are guessing when any thread will exit the trampoline. To avoid free-while-executing bugs, we will split our current process into two steps:
1. The first helper will only handle *rewriting the bytes back to the function*.
2. The second helper will only handle *freeing the trampoline struct*.
## Restoration

```c
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkRestoreFunction(_In_ PHK_TRAMPOLINE Trampoline) {
    if (Trampoline == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    } else if (Trampoline->State != HK_ACTIVE) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    
    NTSTATUS Status = HkpAtomicWriteCode16Bytes(
	    Trampoline->OriginalFunction,
	    Trampoline->OriginalBytes
	);
	
    if (NT_SUCCESS(Status)) {
        Trampoline->State = HK_DRAINING;
    }
    
    return Status;
}
```

We'll use a few `NTSTATUS` values if the patch cannot be fixed now. Then restore and update the state to `DRAINING` for the next helper.

## Release

```c
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkReleaseTrampoline(_In_ PHK_TRAMPOLINE Trampoline) {
    if (Trampoline == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    } else if (Trampoline->State != HK_DRAINING) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    
    ExFreePoolWithTag(Trampoline->RelocatedCode, HK_POOL_TAG);
    ExFreePoolWithTag(Trampoline, HK_POOL_TAG);

    return STATUS_SUCCESS;
}
```

Running a similar check to `HkRestoreFunction`:
- `INVALID_PARAMETER` if the trampoline pointer is null
- `INVALID_DEVICE_STATE` if the trampoline isn't draining (e.g. the patch hasn't been restored yet)
Then, we free all the fields and return.

# Hook Table

If we want a caller to be able to track multiple hooks at once, it's unsafe to expect them to keep passing the trampolines around; hooks aren't fire-and-forget. You need to release and free all hooks for clean driver unload, and that requires doing so to all active hooks. Without a table you'd either leak trampoline pointers on unload or require callers to track their own handles, which forces every single hook site into a correctness policy. The table centralizes ownership while also giving you a natural place to hang future policy: hook count limits, duplicate detection, audit logging, all without changing any call sites.

We run into a crucial problem when we simply generate a table and read-write on demand: If two threads are simultaneously scanning, find an empty slot, and write to it, only one gets truly written; the registration races. A lock will force that scan-and-claim mechanism to an atomic operation. Even if *"hooks are only installed at init time"* that future assumption might not hold, and we shouldn't bake it into the data structure.

## Design
The table itself is simple enough:

```c
typedef struct _HK_HOOK_TABLE {
    PHK_TRAMPOLINE Entries[HK_MAX_HOOKS];
    ULONG Count;
    KSPIN_LOCK Lock;
} HK_HOOK_TABLE;

static HK_HOOK_TABLE HkpHookTable;

#define HK_MAX_HOOKS 64
```

To force atomicity, we can use a lock/mutex, but which one
- `ERESOURCE`/`FAST_MUTEX` are sync primitives that support read and write acquisition, and the ability to sleep while waiting. They both require `IRQL <= APC_LEVEL`, which makes it technically viable. They're impractical for this use case because the sleeping acquisition and tracking of readers-writers is unecessary overhead for a small critical section.
- `EX_PUSH_LOCK` is similar (and lighter) lock than `ERESOURCE` that spins briefly before sleeping. This makes IRQL assumptions and is more useful when readers outnumber writers, overkill for our small table.
- `KSPIN_LOCK` is a busy-waiting lock that raises IRQL to `DISPATCH_LEVEL`, preventing DPCs from interfering. No allocation, no sleeping semantics, and minimal init process. It's the approach we will use.

Now, it makes sense to ask if *we* even need a lock at all. Since the caller has control of the threads, it's possible for them to implement the atomicity themselves. The purpose here is a design principle: 
- The goal of the table is to avoid pushing cleanup correctness outwards.
- A lock also also exists to avoid pushing atomic correctness outwards.
The lock belongs with the data structure for the same reason the table exists.

The lockless correctness is local but the *danger* of it is non-local. A compare-and-swap on a single slot is fine when isolated, but any operation that needs to reason about the table (such as a snapshotting mechanism, threshold count, duplicate detection) will need a lock anyways, or an even more complex scheme to avoid the race.

Additionally, there's no real performance gain for going lockless. The lock is in place for *microseconds* across a 64-entry scan. Hooks are installed and removed rarely, and never on a hot path. Lockless optimizations aren't justified by the existence of a shared state

## Implementation
To start, we need an **initializer** to set up the table and spin lock:
```c
_IRQL_requires_max_(APC_LEVEL)
VOID HkInitialize(VOID) {
    RtlZeroMemory(&HkpHookTable, sizeof(HK_HOOK_TABLE));
    KeInitializeSpinLock(&HkpHookTable.Lock);
}
```

Next, we'll write a regstration function our detour can use to register a trampoline with the table.

```c
_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS HkpRegisterTrampoline(_In_ PHK_TRAMPOLINE Trampoline) {
    KIRQL OldIrql;
    KeAcquireSpinLock(&HkpHookTable.Lock, &OldIrql);

    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;
    for (ULONG i = 0; i < HK_MAX_HOOKS; i++) {
        if (HkpHookTable.Entries[i] == NULL) {
            HkpHookTable.Entries[i] = Trampoline;
            HkpHookTable.Count++;
            Status = STATUS_SUCCESS;
            break;
        }
    }

    KeReleaseSpinLock(&HkpHookTable.Lock, OldIrql);
    return Status;
}
```
*We'll have to keep track of the IRQL level before locking, that way the spinlock can restore it.*

In our detour function, we will now attempt to register the newly created trampoline with the table, freeing and returning on failure:

```c
} else {
    Trampoline->State = HK_ACTIVE;
    Status = HkpRegisterTrampoline(Trampoline);
    if (!NT_SUCCESS(Status)) {
        Trampoline->State = HK_DRAINING;
        HkRestoreFunction(Trampoline);
        HkReleaseTrampoline(Trampoline);
        return Status;
    }
    *OutTrampoline = Trampoline;
}
```

Next, *before* freeing the trampoline in `HkReleaseTrampoline` we will want to reacquire the lock and remove the entry:

```c
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkReleaseTrampoline(_In_ PHK_TRAMPOLINE Trampoline) {
	// checks
	
	KIRQL OldIrql;
    KeAcquireSpinLock(&HkpHookTable.Lock, &OldIrql);
    for (ULONG i = 0; i < HK_MAX_HOOKS; i++) {
        if (HkpHookTable.Entries[i] == Trampoline) {
            HkpHookTable.Entries[i] = NULL;
            HkpHookTable.Count--;
            break;
        }
    }
    KeReleaseSpinLock(&HkpHookTable.Lock, OldIrql);
    
    // frees
}
```

And lastly, we can assemble a wrapper for authors to clear the table and restore its trampolines on driver exit:

```c
_IRQL_requires_max_(APC_LEVEL)
VOID HkReleaseAllHooks(VOID) {
    PHK_TRAMPOLINE Snapshot[HK_MAX_HOOKS];
    ULONG Count = 0;

    KIRQL OldIrql;
    KeAcquireSpinLock(&HkpHookTable.Lock, &OldIrql);
    for (ULONG i = 0; i < HK_MAX_HOOKS; i++) {
        if (HkpHookTable.Entries[i] != NULL) {
            Snapshot[Count++] = HkpHookTable.Entries[i];
        }
    }
    KeReleaseSpinLock(&HkpHookTable.Lock, OldIrql);

    for (ULONG i = 0; i < Count; i++) {
        if (Snapshot[i]->State == HK_ACTIVE) {
            HkRestoreFunction(Snapshot[i]);
        }
    }

    for (ULONG i = 0; i < Count; i++) {
        if (Snapshot[i]->State == HK_DRAINING) {
            HkReleaseTrampoline(Snapshot[i]);
        }
    }
}
```

 For the above, `HkReleaseAllHooks` can't simply iterate the table under the lock and restore each hook in place:
-  `HkReleaseTrampoline` needs to acquire the lock itself, so holding it across calls deadlocks.
-  `HkRestoreFunction` being called concurrently could result in two threads both passing the `HK_ACTIVE` state check, both calling `HkReleaseTrampoline`, and one freeing memory the other still holds.

The snapshot drops the lock before calling into either function, giving `HkReleaseTrampoline` a clean acquisition path and ensuring `HkRestoreFunction` is only called once per trampoline. The pointers are safe to dereference after the lock drops because `HkReleaseAllHooks` is the only teardown caller, so nothing else will free them out from under us.

# Macros

Now actually executing this can be verbose. Just hooking `NtOpen` would look like:

```c
#include "hk.h"

NTSTATUS (*OriginalNtClose)(_In_ HANDLE Handle);
NTSTATUS HookedNtOpen( _In_ HANDLE Handle ) {
	DbgPrintEx(0, 0, "Called NtOpen\n");
	return OriginalNtOpen(Handle);
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	HkRestoreFunction((PVOID)NtClose, (PVOID)OriginalNtClose);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING	RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = DriverUnload;
	HkDetourFunction((PVOID)NtOpen, (PVOID)HookedNtOpen, 20, (PVOID*)&OriginalNtOpen);
	return STATUS_SUCCESS;
}
```

We can actually macro a lot of this out.

```c
static inline NTSTATUS HkInstallHook(PVOID Target, PVOID Hook, PHK_TRAMPOLINE* OutTrampoline) {
    return HkDetourFunction(Target, Hook, OutTrampoline);
}

static inline void HkRemoveHook(PHK_TRAMPOLINE* Trampoline) {
    if (*Trampoline) {
        HkRestoreFunction(*Trampoline);
        HkReleaseTrampoline(*Trampoline);
        *Trampoline = NULL;
    }
}

define HK_DECLARE_TRAMPOLINE(name) \
    static PHK_TRAMPOLINE name##Trampoline = NULL

define HK_DEFINE_ORIGINAL(name, ret_type, ...) \
    static inline ret_type name##_Original(__VA_ARGS__) { \
        return ((ret_type(*)(__VA_ARGS__))(name##Trampoline->RelocatedCode))(__VA_ARGS__); \
    }

define HK_DECLARE_DEFINE(name, ret_type, ...)           \
    static PHK_TRAMPOLINE name##Trampoline = NULL;          \
    static inline ret_type name##_Original(__VA_ARGS__) {    \
        return ((ret_type(*)(__VA_ARGS__))(name##Trampoline->RelocatedCode))(__VA_ARGS__); \
    }

define HK_CALL_ORIGINAL(trampoline, type) ((type)((trampoline)->RelocatedCode))
```

- `HkInstallHook` is just a wrapper over the detour routine for consistent hook installation
- `HkRemoveHook` restores the original function, frees the trampoline, and clears the handle to prevent reuse
- `HK_DECLARE_TRAMPOLINE` declares a static trampoline pointer for a given hook.
- `HK_DEFINE_ORIGINAL` defines a *typed* wrapper that calls the original function via the trampoline’s relocated code.
- `HK_DECLARE_DEFINE` the two above macros
- `HK_CALL_ORIGINAL` casts a trampoline’s relocated code to a callable function pointer of a specified type
All of these wrappers need an *initialized* trampoline and an *exact* function signature match.

A basic pattern:
```c
HK_DECLARE_DEFINE(HookFunction, NTSTATUS, PVOID arg);

NTSTATUS HookFunction(PVOID arg) {
    return HookFunction_Original(arg);
}

HkInstallHook((PVOID) TargetFunction, (PVOID) HookFunction, &MyHookTrampoline);

HkRemoveHook(&HookFunctionTrampoline);
```
# Reentrancy Guard

Even as a proof of concept, I attempted to work around the multiple failure points kernel hooking introduces. One of the fundamental failures of kernel hooking is reentrancy, and it's one of the few failures the library itself is solely reponsible for. If a hooked function is called again while it's own hook is already executing, the hook recurses, which often reults in a kernel stack overflow and bugcheck.

A mechanically straightforward fix is a per-CPU guard that detects active execution and bypasses the hook. This avoids global locking (expensive at `DISPATCH_LEVEL` and illegal above it), but making this system fully transparent (meaning the library handles it all) introduced several constraints that compounded when I attempted to implement it.

A generic dispatcher to guard the hook needs to:
- Identify the active hook
- Preseve arbitrary arguments
- Forward those arguments through the hook's call chain
- Regain control after the hook returns to clear the guard
Upon researching how to implement these, I found out they often require per-hook assembly stubs with the embedded pointers and arguments. Then, it needed to call a shared dispatcher function using `call` rather than `jmp` so execution could return for cleanup, which meant visible stack frames and that return values needed to be stored.

The result of all this is functionally straightforward but required runtime codegen, ABI-sensitive assembly, constant bugcheck guards, and ended up blowing up in complexity beyond the rest of the library. I unfortunately did not have the time or knowledge to make this functional even as a PoC. A simple enter-exit model is more predictable, which is what I leave this project on.
