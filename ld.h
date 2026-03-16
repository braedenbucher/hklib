#pragma once
#include <ntddk.h>

// Returns the length in bytes of the x64 instruction at InstructionPointer.
// Returns 0 if the opcode is unrecognized or the encoding is invalid.
_IRQL_requires_max_(APC_LEVEL)
ULONG LdeGetInstructionLength( _In_ PCVOID InstructionPointer);