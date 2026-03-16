#pragma once
#include <ntddk.h>

#define ATOMIC_PATCH_SIZE (16ul)
#define HK_MAX_HOOKS 64

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

_IRQL_requires_max_(APC_LEVEL)
VOID HkInitialize(VOID);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkDetourFunction(
	_In_ PVOID	 TargetFunction,
	_In_ PVOID	 HookFunction,
	_Out_ PHK_TRAMPOLINE* OutTrampoline
);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkRestoreFunction(_In_ PHK_TRAMPOLINE Trampoline);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkReleaseTrampoline(_In_ PHK_TRAMPOLINE Trampoline);

_IRQL_requires_max_(APC_LEVEL)
VOID HkReleaseAllHooks(VOID);