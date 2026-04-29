# Instruction Components

As covered extensively in the inline hook, the trampoline requires multiple instructions up to a boundary to be copied into a buffer. The challenge is that x86-64 instructions are variable length, ranging between 1 to 15 bytes long. The **instruction name (opcode)** is only one of multiple *optional* components, all represented in bytes. The full breakdown consists of:

```
[Prefixes] [Opcode] [ModRM] [SIB] [Displacement] [Immediate]
```
 
 Our length disassembler's job is to determine which components are included, how long they are, and to sum the entire count of bytes.

# Design

We will start with a pointer to an instruction, and for each component simply walk the bytes. Now, the various prefix and opcode bytes and the immediate/displacement bytes are potentially far apart in the instruction stream. By the time we get to measuring the immediate, we've already consumed the opcode and possibly ModRM and SIB bytes. To handle this, we will stash `OperandSizeOverride`, `RexW` etc. at parsing time so that later stages can reference the conditionals without having to look backwards.

There are two approaches we could use to store persistent information:
1. A global `struct` using bits as flags for length summing. Our parser would comb through, and set the flags as needed. This would leave a simple `if-else` structure for the final sum step. Each bit indicates whether a modification is active, and our final "tally" references it for counting.

```c
typedef struct _OPCODE_INFO {
    UCHAR   ModRM   : 1;  // Has ModRM byte
    UCHAR   Imm8    : 1;  // Has 8-bit immediate
    UCHAR   Imm16   : 1;  // Has 16-bit immediate  
    UCHAR   Imm32   : 1;  // Has 32-bit immediate
    UCHAR   Rel8    : 1;  // Relative 8-bit offset
    UCHAR   Rel32   : 1;  // Relative 32-bit offset
    UCHAR   Invalid : 1;  // Invalid/unsupported opcode
    UCHAR   Group   : 1;  // Opcode group (uses ModRM reg field to distinguish)
} OPCODE_INFO;
```

2. Multiple local variables declared in the primary parsing function. This would leave us with a `switch-case` flow which pattern matches the byte patterns at every step. Before each major count, we'll create the flags, and then when a component is identified, the flags are updated and the pointer is moved.

A lookup table of `_OPCODE_INFO` structs would make the main decode logic easy to read. Instead of a 200-line switch statement you'd just do `info = opcodeTable[opcode]` and then a few `if` checks. Easier to read and extend.

The challenge is one we will break down in depth later. Parsing some special instructions and storing their attributes requires knowing information that comes *after* the current place in the byte stream. You can't really encode values that "may show up later" in a struct without overhead, and would need to come up with some `if/switch` logic to store and reference it later. Therefore, you would likely end up with a hybrid `struct/switch` anyways, and at that point it's subjective whether it's truly "cleaner" than just switch cases.

For a proof-of-concept disassembler built for an experimental hook, the lookup table approach doesn't offer a clean separation, and we would likely end up with a hybrid `struct/switch` regardless. The `switch-case` method is good enough for our purposes.

*Signature and initial declarations*
```c
#define MAX_INSTR_LEN 15

ULONG LdeGetInstructionLength( _In_ PCVOID InstructionPointer) {
    const PUCHAR p = (const PUCHAR) InstructionPointer;
    const PUCHAR start = p; // base pointer, never moved
    
    BOOLEAN OperandSizeOverride = FALSE; // 0x66
	// other flags above . . .
	ULONG   prefixCount = 0;
}
```

# Prefixes

To start, **prefixes** are modifiers that come *before* the operation code. There can be multiple prefixes, each 1 byte long. We will distinguish two kinds of prefixes:

1. Prefixes that **DON'T** affect length *(LOCK, REP, segment prefixes are all functionally different but don't affect length)*, they just count as a +1 byte, +1 prefix, and move on.
2. Prefixes that **DO** affect length. There are three prefixes that do this.
	1. `0x66` is the operand size override, which flips the operand size between 16 bit and 32 bit, changing how long the immediate field is.
	2. `0x67` is the address size override, which flips the address size down to 32 bit, changing how long the displacement field is.
	3. The REX prefix, which is exclusive to 64 bit mode. It's a byte range between `0x40` and `0x4F`, the low 4 bits are flags. The one we care about is bit 3 `REX.W`, which widens our operation to 64 bits rather than `0x66` narrowing it to 16 bits.

## Implementation
We'll start by keeping track of some prefix flags:

```c
BOOLEAN OperandSizeOverride = FALSE; // 0x66
BOOLEAN AddressSizeOverride = FALSE; // 0x67
BOOLEAN RexW = FALSE;   // 64-bit operand size
```

For this initial loop, we just want to consume until we have no more detected prefixes. Since we're storing our maximum length as a constant, we can just loop until we either:
- Detect current byte as *not* a prefix *(`goto DonePrefixes;`)*
- Run past 15 bytes *(checked by `p - start < MAX_INSTR_LEN`, something has gone wrong by this point)*
Also, rather than exporting the prefix parsing to a helper method, we'll actually use a C-standard `goto`. Gotos are notorious for being overused, but our case has a pretty natural conditional exit, so a `goto` saves some extraction overhead.

```c
// PREFIXES
while ((ULONG_PTR)(p - start) < MAX_INSTR_LEN) {
    UCHAR b = *p;
    
    switch (b) {
	    // cases
	    
    case 0x66: OperandSizeOverride = TRUE; p++; prefixCount++; continue;
    case 0x67: AddressSizeOverride = TRUE; p++; prefixCount++; continue;
    
    default:
        if (b >= 0x40 && b <= 0x4F) {
            // REX prefix
            Rex  = TRUE;
            RexW = (b & 0x08) != 0;
            p++; prefixCount++; continue;
        }
        goto DonePrefixes;
    }
}
DonePrefixes:;
```

# Opcode

The **Opcode** is the core of the instruction. These actually represent what the CPU exectures, and so we cannot just consume them. Since the opcode decides what components follow it, we must determine the instruction.

Most opcodes are 1 byte, but x86 includes many more instructions than 256 instructions, so there are **escape sequences** to indicate 2-byte or 3-byte opcodes.
These are just escape bytes, and are *included* in the byte count:
- **2-byte:** Byte 1 =  `0x0F`, next byte is included in opcode
- **3-byte:** Byte 1 = `0x0F`, Byte 2 = `0x38` / `0x3A`, next byte is included in opcode

Once we know the instruciton, we ask two questions:
1. Does it have a ModRM byte?
2. Does it have an immediate?
	- How big is the immediate?
Some opcodes have a fixed answer (no modrm, no imm), some depend on the prefix flags we stored earlier.

## Groups
As with most things in x86 encoding, an opcode byte does not always uniquely identify an instruction. Some opcode values are *shared by multiple instructions*, forming what are known as **opcode groups**.

In these cases, the actual instruction is selected by the `reg` field of the following **ModRM byte**, which effectively acts as a 3-bit sub-opcode. The full mechanics of this will be covered later.

For now, the important consequence is for length calculation. When the chosen sub-opcode determines whether an immediate is present, the final instruction length cannot be known from the opcode alone.

The most notable example is **Group 3** (`0xF6` / `0xF7`), where the ModRM `reg` field decides whether an immediate follows. Determining the instruction length therefore requires examining the ModRM byte first.

## Setup
The first job is setup. We will run a few checks, primarily:
- Did any flags change the operand size? *(`0x66`, `0x67`, REX)*
- Have we passed our `MAX_INSTR_LEN` yet? *(like prefixes, error if this is true)*
Then, we set up our flags for this section for ModRM and immediates.

```c
ULONG effOperandSize = 32; // default op size
if (RexW) effOperandSize = 64; // if RexW was set
else if (OperandSizeOverride) effOperandSize = 16; // if 0x66 prefix

if ((ULONG_PTR)(p - start) >= MAX_INSTR_LEN) return 0;
  
UCHAR opcode = *p++;
ULONG immSize = 0;
BOOLEAN hasModRM = FALSE;
ULONG modrmSize = 0;
```

To parse, we can just use large `if` and `switch` blocks:

```c
if (opcode == 0x0F) {
	if ((ULONG_PTR)(p - start) >= MAX_INSTR_LEN) return 0;
	
    UCHAR op2 = *p++;
    if (op2 == 0x38 || op2 == 0x3A) {
	    if ((ULONG_PTR)(p - start) >= MAX_INSTR_LEN) return 0;
	    // 3-byte opcodes
    } else {
	    // 2-byte opcodes
    }
} else {
	// 1-byte opcodes
}
```
*Since we are advancing the pointer every byte, we'll have to check we haven't passed the `MAX_INSTR_LEN` boundary each time as well*

## Implementation
*Opcode cases researched from [the x86 assembly reference](http://ref.x86asm.net/)

The 3-byte opcodes are the easiest. They have global attributes rather than groups:
- All `0x38` and `0x3A` opcodes use ModRM
- All `0x3A` opcodes have an `imm8` immediate

The 2-byte and 1-byte cases follow directly from the reference table. Each opcode falls into a category that determines what we set:
- ModRM only
- Immediate only, fixed size
- Immediate only, size depends on `effOperandSize`
- Both ModRM and immediate
- Neither (single-byte instruction, nothing follows)

The full mapping is sourced from the reference. The `default` branch in both switch statements returns 0, treating unknown opcodes as an error.

As we mentioned, we need to separate the 1-byte Group 3 cases. We'll account for their attributes (since they need ModRM) in the switch, but put a conditional after the switch:

```c
} else {
	// 1-byte opcode
	switch (opcode) {
	
	// rest of the cases
	
    // Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV r/m
    case 0xF6: hasModRM = TRUE; break; // TEST r/m8 has extra imm8
    case 0xF7: hasModRM = TRUE; break; // TEST r/m has extra imm
    
    default:
        return 0; // unknown
    }
    
    // Group 3: TEST subop (reg field = 0) has an immediate
}
```

At the end of this (last comment), the pointer `p` is at the start of the ModRM byte. We'll "peek" into the field inside, but to do that we must understand what the ModRM byte is. After the overview below, this conditional will be constructed and placed in this position to wrap up the opcodes.

# ModRM, SIB, Displacement

**ModRM** is a single byte following the opcode which is used to *specify the operands* packed into three fields:

```
[ mod (2 bits) | reg (3 bits) | rm (3 bits) ]
7             6 5            3 2           0
```

## Reg
In most cases, `reg`  is the easiest field to handle. It's just a register number. But remember Opcode Groups? It's where this field comes into play. Intel repurposed these 3 bits as a **sub-opcode**. For example `0xF6` alone doesn't tell us the instruction, `0xF6` + `reg=0` means TEST, `0xF6` + `reg=2` means NOT, `0xF6` + `reg=3` means NEG, and so on.

That's why Group 3 (`0xF6`/`0xF7`) is special. The immediate is only present when the sub-opcode is TEST (`reg=0` or `reg=1`). So we have to peek at the ModRM byte before we can know the full length. To do this, we build the conditional from the previous section:

*Completing the Group 3 case opened in the Opcode section*
```c
if ((opcode == 0xF6 || opcode == 0xF7) && hasModRM) {
    if ((ULONG_PTR)(p - start) < MAX_INSTR_LEN) {
        UCHAR regField = (*p >> 3) & 0x7;
        if (regField == 0 || regField == 1) { // TEST
            immSize = (opcode == 0xF6) ? 1 :
                      (effOperandSize == 16) ? 2 : 4;
        }
    }
}
```

We take the ModRM byte, shift right 3 to remove `rm`, and mask all the above bits with `0b00000111` to discard `mod` bits. This isolates `reg`.

`0xF6` is the byte-operand variant of the group, so its TEST always takes a 1-byte immediate. `0xF7` is the word/dword/qword variant, so its immediate size depends on the operand size we resolved from the prefixes earlier, 2 bytes if `0x66` was set, otherwise 4. Note it caps at 4 even for 64-bit, immediates are never 8 bytes except for the special `MOV reg, imm64` encoding.

## Mod & RM
These two describe the other operand, and it determines what follows. The `mod` field has four possible values:

| Value | Mode     | Description                                                                                      | Bytes Added |
| ----- | -------- | ------------------------------------------------------------------------------------------------ | ----------- |
| 11    | Register | RM is just a register number                                                                     | 0 bytes     |
| 00    | Memory   | Memory, no displacement.<br>- If `rm = 101`, it's rip-relative addressing w/ 32-bit displacement | 0/4 bytes   |
| 01    | Memory   | Memory with 8-bit displacement                                                                   | 1 byte      |
| 10    | Memory   | Memory with 32-bit displacement                                                                  | 4 bytes     |

When `rm = 100` in any memory mode, it indicates there is a **SIB Byte** between ModRM and the displacement. The SIB byte is covered below.

## SIB
The **SIB Byte (Scale-Index-Base)** contains three fields:

```
[ scale (2 bits) | index (3 bits) | base (3 bits) ]
7               6 5              3 2              0
```

It's always exactly 1 byte, with one special case: If `base = 101` and `mod = 00`, there is a standalone 4-byte displacement *(distinct from the 4-byte displacement when `mod = 00` and `rm = 101`)*.

## Displacement
**Displacement** is the simplest of the three. It's a raw integer baked into the instruction that gets added to a base address to form a memory location. The size is entirely determined by `mod` from the ModRM byte. The table above and SIB breakdown indicate all changes, restated here for clarity:

| Mod | Displacement            |
| --- | ----------------------- |
| 00  | 0/4 *(rm=101/base=101)* |
| 01  | 1 byte                  |
| 10  | 4 bytes                 |
| 11  | 0 bytes                 |

Just a note, displacement is always signed. 1-byte displacement `0xFF` is `-1`, not 255. This doesn't affect length, just handy to know.

## Implementation
The structure is essentially following the table we have constructed.

Isolate `mod` and`rm` (since `reg` is already handled), consume the byte. If it's not just a register, check for a SIB. If there is a SIB, check the conditions for 4-byte displacement. If no SIB, just calculate the standard displacements.

```c
if (hasModRM) {
    if ((ULONG_PTR)(p - start) >= MAX_INSTRUCTION_LENGTH) return 0;
    
    UCHAR mod = (p[0] >> 6) & 0x3;
    UCHAR rm  = (p[0] >> 0) & 0x7;
    p++; // consume ModRM
    
    if (mod != 3) { // if not reg
        if (rm == 4) { // has SIB
            UCHAR sibBase = *p & 0x7;
            p++; // consume SIB
            if (mod == 0 && sibBase == 5) p += 4;
            else if (mod == 1) p += 1;
            else if (mod == 2) p += 4;
        } else {
            if (mod == 0 && rm == 5) p += 4;
            else if (mod == 1) p += 1;
            else if (mod == 2) p += 4;
        }
    }
}
```

# Immediate and Final Sum

At this point, we have incremented our byte counter all we have needed to, and the only thing left is the immediate. Thankfully, our opcode and ModRM have already determined how long the immediate is (in bytes), so we just tally it all up and return!

```c
p += immSize;

ULONG totalLength = (ULONG_PTR)(p - start);
if (totalLength == 0 || totalLength > MAX_INSTR_LEN) return 0;

return totalLength;
```
*We sanity check the length here because something has gone wrong in either case. Every instruction should be at lease 1 byte, but never more than 15.*

# In the Kernel Hook

The kernel hook usage is easy, since we have exposed a single function to capture a complete instruction, we can now make a helper to capture the necessary instruction length to cover the hook:

```c
_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS HkpGetMinimumCopyLength(
	_In_ PVOID FunctionStart,
	_Out_ SIZE_T* OutLength
) {
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
```
