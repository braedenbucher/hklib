#pragma once
#include <ntddk.h>
#include "ld.h"
#include "hk2.h"

#define HK_POOL_TAG                 ('kHkH')

static const UCHAR HkpRipRelativeJump[] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00};
#define FULL_DETOUR_SIZE            (sizeof(HkpRipRelativeJump) + sizeof(PVOID))

typedef struct _HK_HOOK_TABLE {
    PHK_TRAMPOLINE Entries[HK_MAX_HOOKS];
    ULONG Count;
    KSPIN_LOCK Lock;
} HK_HOOK_TABLE;
static HK_HOOK_TABLE HkpHookTable;

/**
 * Writes a 14-byte RIP-relative absolute jump instruction at WriteAddress.
 *
 * The instruction sequence is:
 *     FF 25 00 00 00 00
 *     <8-byte absolute destination>
 *
 * The caller must guarantee that WriteAddress points to writable memory
 * with at least FULL_DETOUR_SIZE bytes available.
 */
_IRQL_requires_max_(APC_LEVEL)
static VOID HkpPlaceRipJump(_In_ PVOID WriteAddress, _In_ PVOID JumpDestination) {
    RtlCopyMemory((PUCHAR)WriteAddress, HkpRipRelativeJump, sizeof(HkpRipRelativeJump));
    RtlCopyMemory((PUCHAR)WriteAddress + sizeof(HkpRipRelativeJump), &JumpDestination, sizeof(PVOID));
}

/**
 * Determines the minimum number of bytes to be copied from the
 * start of TargetFunction for a detour patch of FULL_DETOUR_SIZE bytes.
 * Does not split any instruction boundaries.
 *
 * The function walks instructions using LdeGetInstructionLength until
 * the accumulated length is >= FULL_DETOUR_SIZE.
 */
_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS HkpGetMinimumCopyLength(_In_ PVOID FunctionStart, _Out_ SIZE_T* OutLength) {
    PUCHAR ptr = (PUCHAR)FunctionStart;
    SIZE_T accumulated = 0;

    while (accumulated < FULL_DETOUR_SIZE) {
        PUCHAR instr = ptr + accumulated;
        ULONG instrLen = LdeGetInstructionLength(instr);
        if (instrLen == 0) {
            return STATUS_NOT_SUPPORTED;
        }
        accumulated += (SIZE_T) instrLen;
    }

    *OutLength = accumulated;
    return STATUS_SUCCESS;
}

/**
 * Atomically replaces 16 bytes of executable code at TargetAddress.
 *
 * Maps the target page writable via a Memory Descriptor List and performs a
 * cmpxchg16b operation on the mapped virtual address.
 *
 * Requirements:
 *   - TargetAddress must be 16-byte aligned
 *   - ATOMIC_PATCH_SIZE must be 16
 *
 * The current 16 bytes must match the captured
 * comparand used by InterlockedCompareExchange128.
 */
_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS HkpAtomicWriteCode16Bytes(_In_ PVOID TargetAddress, _In_ PUCHAR ReplacementBytes) {
    if ((ULONG64)TargetAddress != ((ULONG64)TargetAddress & ~0xf)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    PMDL PageMdl = IoAllocateMdl(TargetAddress, ATOMIC_PATCH_SIZE, FALSE, FALSE, NULL);
    if (PageMdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(PageMdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(PageMdl);
        return STATUS_INVALID_ADDRESS;
    }

    PLONG64 WritableMappedAddress = MmMapLockedPagesSpecifyCache(PageMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute);
    if (WritableMappedAddress == NULL) {
        MmUnlockPages(PageMdl);
        IoFreeMdl(PageMdl);
        return STATUS_INTERNAL_ERROR;
    }

    NTSTATUS Status = MmProtectMdlSystemAddress(PageMdl, PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) {
        MmUnmapLockedPages(WritableMappedAddress, PageMdl);
        MmUnlockPages(PageMdl);
        IoFreeMdl(PageMdl);
        return Status;
    }

    LONG64 AtomicSwapComparand[2];
    AtomicSwapComparand[0] = WritableMappedAddress[0];
    AtomicSwapComparand[1] = WritableMappedAddress[1];

    InterlockedCompareExchange128(WritableMappedAddress, ((PLONG64)ReplacementBytes)[1], ((PLONG64)ReplacementBytes)[0], AtomicSwapComparand);

    MmUnmapLockedPages(WritableMappedAddress, PageMdl);
    MmUnlockPages(PageMdl);
    IoFreeMdl(PageMdl);
    return STATUS_SUCCESS;
}

/**
 * Inserts a trampoline entry into the global hook table.
 *
 * The table is protected by HkpHookTable.Lock. If the table is full
 * (HK_MAX_HOOKS entries) the function fails with
 * STATUS_INSUFFICIENT_RESOURCES.
 */
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

/**
* On startup, clears the hook table and initializes the spinlock for that table.
*/
_IRQL_requires_max_(APC_LEVEL)
VOID HkInitialize(VOID) {
    RtlZeroMemory(&HkpHookTable, sizeof(HK_HOOK_TABLE));
    KeInitializeSpinLock(&HkpHookTable.Lock);
}

/**
 * Installs a detour hook on TargetFunction.
 *
 * Replaces the first 16 bytes of TargetFunction with a RIP-relative
 * absolute jump to HookFunction. The displaced instructions are
 * copied to a an executable buffer in the trampoline which allows the
 * original function to be executed.
 *
 * On success:
 *   - a trampoline object is returned via OutTrampoline
 *   - the hook becomes active immediately
 *
 * The caller must later call HkRestoreFunction followed by
 * HkReleaseTrampoline to fully remove the hook.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkDetourFunction(_In_ PVOID TargetFunction, _In_ PVOID HookFunction, _Out_ PHK_TRAMPOLINE* OutTrampoline) {
    NTSTATUS Status;
    SIZE_T CopiedCodeLength;
    UCHAR DetourPatch[ATOMIC_PATCH_SIZE];
    
    if (OutTrampoline == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    PHK_TRAMPOLINE Trampoline = (PHK_TRAMPOLINE) ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HK_TRAMPOLINE), HK_POOL_TAG);
    if (Trampoline == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Trampoline, sizeof(HK_TRAMPOLINE));

    Trampoline->OriginalFunction = TargetFunction;
    Trampoline->HookFunction     = HookFunction;
    Trampoline->State            = HK_INACTIVE;

    Status = HkpGetMinimumCopyLength(TargetFunction, &CopiedCodeLength);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Trampoline, HK_POOL_TAG);
        return Status;
    }

    RtlCopyMemory(Trampoline->OriginalBytes, TargetFunction, ATOMIC_PATCH_SIZE);

    Trampoline->RelocatedCode = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, CopiedCodeLength + FULL_DETOUR_SIZE, HK_POOL_TAG);
    if (Trampoline->RelocatedCode == NULL) {
        ExFreePoolWithTag(Trampoline, HK_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(Trampoline->RelocatedCode, TargetFunction, CopiedCodeLength);
    HkpPlaceRipJump(Trampoline->RelocatedCode + CopiedCodeLength, (PVOID)((ULONG_PTR)TargetFunction + CopiedCodeLength));

    HkpPlaceRipJump(DetourPatch, HookFunction);
    RtlCopyMemory((PUCHAR)DetourPatch + FULL_DETOUR_SIZE, (PUCHAR)TargetFunction + FULL_DETOUR_SIZE, ATOMIC_PATCH_SIZE - FULL_DETOUR_SIZE);

    Status = HkpAtomicWriteCode16Bytes(TargetFunction, DetourPatch);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Trampoline->RelocatedCode, HK_POOL_TAG);
        ExFreePoolWithTag(Trampoline, HK_POOL_TAG);
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

    return Status;
}

/**
 * Removes the active detour patch from a function.
 *
 * The original 16 bytes saved in the trampoline are written back
 * also using cmpxchg16b. After a successful restore the trampoline
 * enters the HK_DRAINING state and may be released.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkRestoreFunction(_In_ PHK_TRAMPOLINE Trampoline) {
    if (Trampoline == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    } else if (Trampoline->State != HK_ACTIVE) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    NTSTATUS Status = HkpAtomicWriteCode16Bytes(Trampoline->OriginalFunction, Trampoline->OriginalBytes);
    
    if (NT_SUCCESS(Status)) {
        Trampoline->State = HK_DRAINING;
    }

    return Status;
}

/**
 * Frees a trampoline after the hook has been restored.
 *
 * The trampoline must be in HK_DRAINING state. The routine removes the
 * entry from the global hook table and releases all associated memory.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkReleaseTrampoline(_In_ PHK_TRAMPOLINE Trampoline) {
    if (Trampoline == NULL)
        return STATUS_INVALID_PARAMETER_1;
    if (Trampoline->State != HK_DRAINING)
        return STATUS_INVALID_DEVICE_STATE;

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

    ExFreePoolWithTag(Trampoline->RelocatedCode, HK_POOL_TAG);
    ExFreePoolWithTag(Trampoline, HK_POOL_TAG);
    return STATUS_SUCCESS;
}

/**
 * Restores and releases every hook currently registered in the
 * global hook table. A snapshot of the table is taken so hooks
 * can be safely restored outside the spinlock.
 */
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
