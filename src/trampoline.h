/*
 *  MinHook - The Minimalistic API Hooking Library for x64/x86
 *  Copyright (C) 2009-2014 Tsuda Kageyu.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 *  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#pragma pack(push, 1)

// Structs for writing x86/x64 instructions.

// 8-bit relative jump.
typedef struct _JMP_REL_SHORT
{
    UINT8  opcode;
    UINT8  operand;
} JMP_REL_SHORT;

// 32-bit direct relative jump/call.
typedef struct _JMP_REL
{
    UINT8  opcode;
    UINT32 operand;
} JMP_REL, CALL_REL;

// 32-bit indirect absolute jump/call or direct relative conditional jumps.
typedef struct _JMP_ABS
{
    UINT16 opcode;
    UINT32 operand;
} JMP_ABS, CALL_ABS, JCC_REL;

// 64bit indirect absolute conditional jumps that x64 lacks.
typedef struct _JCC_ABS
{
    UINT8  opcode;    // 7* 06          J** +4
    UINT8  dummy0;
    UINT16 dummy1;    // FF25 xxxxxxxx  JMP [RIP+xxxxxxxx]
    UINT32 operand;
} JCC_ABS;

#pragma pack(pop)

typedef struct _TRAMPOLINE
{
    void      *pTarget;         // [In] Address of the target function.
    void      *pDetour;         // [In] Address of the detour function.
    void      *pTrampoline;     // [In] Buffer address for the trampoline function.
    UINT       trampolineSize;  // [In] Buffer size for the trampoline function.
#if defined _M_X64
    void      *pRelay;          // [In] Buffer address for the relay function.
    ULONG_PTR *pTable;          // [In] Buffer address for the jump address table.
    UINT       tableSize;       // [In] Buffer size for the jump address table.
#endif

    BOOL       patchAbove;      // [Out] Should use the hot patch area?
    int        nIP;             // [Out] Number of the instruction boundaries.
    UINT8      oldIPs[8];       // [Out] Instruction boundaries of the target function.
    UINT8      newIPs[8];       // [Out] Instruction boundaries of the trampoline function.
} TRAMPOLINE;

BOOL CreateTrampolineFunction(TRAMPOLINE *ct);
