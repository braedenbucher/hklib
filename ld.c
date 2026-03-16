#include <ntddk.h>
#define MAX_INSTR_LEN 15

_IRQL_requires_max_(APC_LEVEL)
ULONG LdeGetInstructionLength( _In_ PCVOID InstructionPointer) {
    const PUCHAR p = (const PUCHAR) InstructionPointer;
    const PUCHAR start = p; // base pointer, never moved


    // PREFIXES
    BOOLEAN OperandSizeOverride = FALSE; // 0x66
    BOOLEAN AddressSizeOverride = FALSE; // 0x67
    // BOOLEAN Rex = FALSE; // triggers on end of REX check
    BOOLEAN RexW = FALSE;   // 64-bit operand size
    // BOOLEAN HasLock = FALSE; // triggers on 0xF0
    // BOOLEAN HasRep  = FALSE; // triggers on 0xF3
    // ULONG   prefixCount = 0; // triggers on 0x65, 0x66, 0x76, end of REX check

    while ((ULONG_PTR)(p - start) < MAX_INSTR_LEN) {
        UCHAR b = *p;

        switch (b) {
        case 0xF0: // LOCK
        case 0xF2: // REPNE/REPNZ
        case 0xF3: // REP/REPE
        case 0x2E: // CS / branch not taken
        case 0x36: // SS
        case 0x3E: // DS / branch taken 
        case 0x26: // ES
        case 0x64: // FS
        case 0x65: p++; continue; // GS
        case 0x66: OperandSizeOverride = TRUE; p++; continue;
        case 0x67: AddressSizeOverride = TRUE; p++; continue;
        default:
            if (b >= 0x40 && b <= 0x4F) {
                // REX prefix
                RexW = (b & 0x08) != 0;
                p++; continue;
            }
            goto DonePrefixes;
        }
    }
DonePrefixes:;

    // OPCODES
    ULONG effOperandSize = 32; // default op size
    if (RexW) effOperandSize = 64; // if RexW was set
    else if (OperandSizeOverride) effOperandSize = 16; // if 0x66 prefix

    if ((ULONG_PTR)(p - start) >= MAX_INSTR_LEN) return 0;

    UCHAR opcode = *p++;
    ULONG immSize = 0;
    BOOLEAN hasModRM = FALSE;

    // Handle 2-byte and 3-byte escape
    if (opcode == 0x0F) {
        if ((ULONG_PTR)(p - start) >= MAX_INSTR_LEN) return 0;
        UCHAR op2 = *p++;

        if (op2 == 0x38 || op2 == 0x3A) {
            // 3-byte opcode
            if ((ULONG_PTR)(p - start) >= MAX_INSTR_LEN) return 0;
            p++;

            if (op2 == 0x3A) immSize = 1; // imm8 for all 0F3Axx

            // All 0F38xx and 0F3Axx use ModRM
            hasModRM = TRUE;
        } else {
            // 2-byte opcode
            switch (op2) {
            // Jcc long forms: 0F 80..8F rel32
            case 0x80: case 0x81: case 0x82: case 0x83:
            case 0x84: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x8A: case 0x8B:
            case 0x8C: case 0x8D: case 0x8E: case 0x8F:
                immSize = 4; break;

            // SETcc, CMOVcc: ModRM, no imm
            case 0x90: case 0x91: case 0x92: case 0x93:
            case 0x94: case 0x95: case 0x96: case 0x97:
            case 0x98: case 0x99: case 0x9A: case 0x9B:
            case 0x9C: case 0x9D: case 0x9E: case 0x9F:
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                hasModRM = TRUE; break;

            // BT/BTS/BTR/BTC r/m, r
            case 0xA3: case 0xAB: case 0xB3: case 0xBB:
            // SHLD/SHRD r/m,r,imm8
            case 0xA4: immSize = 1; hasModRM = TRUE; break;
            case 0xAC: immSize = 1; hasModRM = TRUE; break;
            // SHLD/SHRD r/m,r,CL  
            case 0xA5: case 0xAD: hasModRM = TRUE; break;
            // IMUL r,r/m
            case 0xAF:
            // Bit ops
            case 0xA0: case 0xA1: case 0xA8: case 0xA9: // PUSH/POP FS/GS — no modrm
                if (op2 == 0xA0 || op2 == 0xA1 || op2 == 0xA8 || op2 == 0xA9) {
                    hasModRM = FALSE;
                } else {
                    hasModRM = TRUE;
                }
                break;
            // MOVZX / MOVSX
            case 0xB6: case 0xB7: case 0xBE: case 0xBF:
            // BSF/BSR
            case 0xBC: case 0xBD:
            // LSS/LFS/LGS
            case 0xB2: case 0xB4: case 0xB5:
                hasModRM = TRUE; break;

            // MOVAPS/MOVAPD etc (SSE): most use ModRM
            // For a kernel hook LDE you usually only need common GP instructions;
            // add SSE/AVX as needed.

            // NOP (0F 1F /0) — ModRM
            case 0x1F: hasModRM = TRUE; break;

            // SYSCALL, SYSRET, etc — no ModRM
            case 0x05: case 0x07: case 0x34: case 0x35: break;

            // XADD
            case 0xC0: hasModRM = TRUE; immSize = 0; break; // XADD r/m8,r8 — but immSize=0, byte ops
            case 0xC1: hasModRM = TRUE; break;

            // BSWAP: no ModRM (reg encoded in opcode)
            case 0xC8: case 0xC9: case 0xCA: case 0xCB:
            case 0xCC: case 0xCD: case 0xCE: case 0xCF: break;

            // CMPXCHG
            case 0xB0: case 0xB1:
            // XCHG
            case 0xC7: // CMPXCHG8B/16B — group 9
            case 0xBA: // BT/BTS/BTR/BTC r/m,imm8 — group 8
                hasModRM = TRUE;
                if (op2 == 0xBA) immSize = 1;
                break;

            // MOV CR/DR
            case 0x20: case 0x21: case 0x22: case 0x23: hasModRM = TRUE; break;

            // WRMSR, RDMSR, RDTSC, etc
            case 0x30: case 0x31: case 0x32: case 0x33: break;

            default:
                return 0; // unknown, bail
            }
        }
    } else {
        // 1-byte opcode
        switch (opcode) {
        // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP variants
        // r/m, r  or  r, r/m
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B:
            hasModRM = TRUE; break;

        // imm8 (sign-extended) forms: ADD/OR/.../CMP r/m, imm8
        case 0x04: case 0x0C: case 0x14: case 0x1C:
        case 0x24: case 0x2C: case 0x34: case 0x3C:
            immSize = 1; break; // AL, imm8

        // imm16/32 forms: ADD/... rAX, imm
        case 0x05: case 0x0D: case 0x15: case 0x1D:
        case 0x25: case 0x2D: case 0x35: case 0x3D:
            immSize = (effOperandSize == 16) ? 2 : 4; break;

        // PUSH/POP segment registers (16-bit encodings, rare in 64-bit)
        case 0x06: case 0x07: case 0x0E:
        case 0x16: case 0x17: case 0x1E: case 0x1F:
            break; // invalid in 64-bit but size=1+prefixes

        // INC/DEC r (16/32-bit forms, invalid in 64-bit, REX takes their place)
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F:
            // These were consumed as REX above; if we're here, no REX was set
            // (32-bit mode). No operand.
            break;

        // PUSH reg
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
        // POP reg
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            break;

        // PUSH imm
        case 0x68: immSize = (effOperandSize == 16) ? 2 : 4; break;
        case 0x6A: immSize = 1; break; // PUSH imm8 (sign-extended)

        // IMUL r,r/m,imm
        case 0x69: hasModRM = TRUE; immSize = (effOperandSize == 16) ? 2 : 4; break;
        case 0x6B: hasModRM = TRUE; immSize = 1; break;

        // Jcc short: rel8
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            immSize = 1; break;

        // Group 1: ADD/OR/.../CMP r/m, imm  (80 /x imm8 .. 83 /x imm8s)
        case 0x80: hasModRM = TRUE; immSize = 1; break;
        case 0x81: hasModRM = TRUE; immSize = (effOperandSize == 16) ? 2 : 4; break;
        case 0x82: hasModRM = TRUE; immSize = 1; break; // invalid in 64-bit
        case 0x83: hasModRM = TRUE; immSize = 1; break; // sign-extended imm8

        // TEST r/m, r
        case 0x84: case 0x85: hasModRM = TRUE; break;
        // XCHG r/m, r
        case 0x86: case 0x87: hasModRM = TRUE; break;
        // MOV r/m, r  /  r, r/m
        case 0x88: case 0x89: case 0x8A: case 0x8B: hasModRM = TRUE; break;
        // MOV r/m, Sreg / Sreg, r/m
        case 0x8C: case 0x8E: hasModRM = TRUE; break;
        // LEA
        case 0x8D: hasModRM = TRUE; break;
        // Group 1A: POP r/m
        case 0x8F: hasModRM = TRUE; break;

        // NOP / XCHG rAX,rAX..r15
        case 0x90: case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97: break;

        // CBW/CWDE/CDQE, CWD/CDQ/CQO
        case 0x98: case 0x99: break;
        // CALL far (obsolete in 64-bit): 2+2 or 2+4
        case 0x9A: immSize = (effOperandSize == 16) ? 4 : 6; break;
        // PUSHF/POPF, SAHF, LAHF
        case 0x9C: case 0x9D: case 0x9E: case 0x9F: break;

        // MOV AL/AX/EAX/RAX, moffs
        case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            // moffs = address size (assumes 64 bit mode; 0x67 overrides to 32 bit)
            immSize = AddressSizeOverride ? 4 : 8; break;

        // MOVS, CMPS, STOS, LODS, SCAS — no operands
        case 0xA4: case 0xA5: case 0xA6: case 0xA7:
        case 0xAA: case 0xAB: case 0xAC: case 0xAD:
        case 0xAE: case 0xAF: break;

        // TEST AL/rAX, imm
        case 0xA8: immSize = 1; break;
        case 0xA9: immSize = (effOperandSize == 16) ? 2 : 4; break;

        // MOV r8, imm8
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            immSize = 1; break;

        // MOV r16/32/64, imm
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            immSize = RexW ? 8 : (effOperandSize == 16 ? 2 : 4); break;

        // Group 2: ROL/ROR/.../SAR r/m, imm8  (C0/C1)
        case 0xC0: hasModRM = TRUE; immSize = 1; break;
        case 0xC1: hasModRM = TRUE; immSize = 1; break;

        // RET near (imm16 / no operand)
        case 0xC2: immSize = 2; break;
        case 0xC3: break;
        // RET far
        case 0xCA: immSize = 2; break;
        case 0xCB: break;

        // LES/LDS (invalid in 64-bit)
        case 0xC4: case 0xC5: hasModRM = TRUE; break;

        // MOV r/m, imm
        case 0xC6: hasModRM = TRUE; immSize = 1; break;
        case 0xC7: hasModRM = TRUE; immSize = (effOperandSize == 16) ? 2 : 4; break;

        // ENTER imm16, imm8
        case 0xC8: immSize = 3; break;
        // LEAVE
        case 0xC9: break;

        // INT 3, INT imm8, INTO, IRET
        case 0xCC: break;
        case 0xCD: immSize = 1; break;
        case 0xCE: break;
        case 0xCF: break;

        // Group 2: ROL/ROR/.../SAR r/m, 1 or CL
        case 0xD0: case 0xD1: case 0xD2: case 0xD3: hasModRM = TRUE; break;

        // AAM, AAD (imm8)
        case 0xD4: case 0xD5: immSize = 1; break;

        // XLAT
        case 0xD7: break;

        // FPU (D8..DF) — all use ModRM
        case 0xD8: case 0xD9: case 0xDA: case 0xDB:
        case 0xDC: case 0xDD: case 0xDE: case 0xDF: hasModRM = TRUE; break;

        // LOOPcc rel8, LOOP rel8, JCXZ/JECXZ/JRCXZ rel8
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: immSize = 1; break;

        // IN/OUT fixed port
        case 0xE4: case 0xE5: case 0xE6: case 0xE7: immSize = 1; break;
        // IN/OUT DX — no immediate
        case 0xEC: case 0xED: case 0xEE: case 0xEF: break;

        // CALL rel32
        case 0xE8: immSize = 4; break;
        // JMP rel32
        case 0xE9: immSize = 4; break;
        // JMP rel8
        case 0xEB: immSize = 1; break;
        // JMP far (invalid in 64-bit)
        case 0xEA: immSize = (effOperandSize == 16) ? 4 : 6; break;

        // HLT, CMC, STC, CLD, STD, CLI, STI
        case 0xF4: case 0xF5: case 0xF8: case 0xF9:
        case 0xFA: case 0xFB: case 0xFC: case 0xFD: break;

        // Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV r/m
        case 0xF6: hasModRM = TRUE; break; // TEST r/m8 has extra imm8
        case 0xF7: hasModRM = TRUE; break; // TEST r/m has extra imm

        // Group 4/5: INC/DEC r/m8, and INC/DEC/CALL/CALLF/JMP/JMPF/PUSH r/m
        case 0xFE: case 0xFF: hasModRM = TRUE; break;

        default:
            return 0; // unknown
        }

        // Group 3 TEST subop (reg field = 0) has an immediate
        if ((opcode == 0xF6 || opcode == 0xF7) && hasModRM) {
            if ((ULONG_PTR)(p - start) < MAX_INSTR_LEN) {
                UCHAR regField = (*p >> 3) & 0x7;
                if (regField == 0 || regField == 1) { // TEST
                    immSize = (opcode == 0xF6) ? 1 :
                              (effOperandSize == 16) ? 2 : 4;
                }
            }
        }
    }

    // MODRM + SIB + DISPLACEMENT
    if (hasModRM) {
        if ((ULONG_PTR)(p - start) >= MAX_INSTR_LEN) return 0;
        
        UCHAR mod = (p[0] >> 6) & 0x3;
        UCHAR rm  = (p[0] >> 0) & 0x7;
        p++; // consume ModRM
        
        if (mod != 3) { // if not reg
            if (rm == 4) { // has SIB
                UCHAR sibBase = *p & 0x7;
                p++; // consume SIB
                if (mod == 0 && sibBase == 5) p += 4; // disp32 when base=rbp/r13
                else if (mod == 1) p += 1;
                else if (mod == 2) p += 4;
            } else {
                if (mod == 0 && rm == 5) p += 4; // RIP+disp32
                else if (mod == 1) p += 1;
                else if (mod == 2) p += 4;
            }
        }
    }

    // IMMEDIATE
    p += immSize;

    ULONG totalLength = (ULONG)(p - start);
    if (totalLength == 0 || totalLength > MAX_INSTR_LEN) return 0;

    return totalLength;
}