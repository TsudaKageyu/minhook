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

#include <Windows.h>

#if defined _M_X64
#include "hde/hde64.h"
typedef hde64s hde_t;
#define HDE_DISASM(code, hs) hde64_disasm(code, hs)
#elif defined _M_IX86
#include "hde/hde32.h"
typedef hde32s hde_t;
#define HDE_DISASM(code, hs) hde32_disasm(code, hs)
#endif

#include "trampoline.h"
#include "buffer.h"

//-------------------------------------------------------------------------
static BOOL IsCodePadding(UINT8 *pInst, size_t size)
{
    size_t i;

    if (pInst[0] != 0x00 && pInst[0] != 0x90 && pInst[0] != 0xCC)
        return FALSE;

    for (i = 1; i < size; ++i)
    {
        if (pInst[i] != pInst[0])
            return FALSE;
    }
    return TRUE;
}

//-------------------------------------------------------------------------
BOOL CreateTrampolineFunction(CREATE_TRAMPOLINE_T *ct)
{
#if defined _M_X64
    CALL_ABS call = { 0x15FF, 0x00000000 };
    JMP_ABS  jmp  = { 0x25FF, 0x00000000 };
    JCC_ABS  jcc  = { 0x70, 0x06, 0x25FF, 0x00000000 };
#elif defined _M_IX86
    CALL_REL call = { 0xE8, 0x00000000 };
    JMP_REL  jmp  = { 0xE9, 0x00000000 };
    JCC_REL  jcc  = { 0x800F, 0x00000000 };
#endif
    size_t    oldPos   = 0;
    size_t    newPos   = 0;
    ULONG_PTR jmpDest  = 0;     // Destination address of an internal jump.
    BOOL      finished = FALSE; // Is the function completed?
#if defined _M_X64
    size_t    tableSize = 0;
    UINT8   instBuf[16];
#endif

    while (!finished)
    {
        hde_t     hs;
        UINT      copySize;
        void     *pCopySrc;
        ULONG_PTR pOldInst = (ULONG_PTR)ct->pTarget     + oldPos;
        ULONG_PTR pNewInst = (ULONG_PTR)ct->pTrampoline + newPos;

        copySize = HDE_DISASM((void *)pOldInst, &hs);
        if (hs.flags & F_ERROR)
            return FALSE;

        pCopySrc = (void *)pOldInst;
        if (oldPos >= sizeof(JMP_REL))
        {
            // The trampoline function is long enough.
            // Complete the function with the jump to the target function.
#if defined _M_X64
            if (tableSize >= ct->tableSize)
                return FALSE;

            ct->pTable[tableSize++] = pOldInst;
            jmp.operand
                = (UINT32)((ULONG_PTR)(ct->pTable + tableSize - 1) - (pNewInst + sizeof(JMP_ABS)));
#elif defined _M_IX86
            jmp.operand = (UINT32)(pOldInst - (pNewInst + sizeof(JMP_REL)));
#endif
            pCopySrc = &jmp;
            copySize = sizeof(jmp);

            finished = TRUE;
        }
#if defined _M_X64
        else if ((hs.modrm & 0xC7) == 0x05)
        {
            // Instructions using RIP relative addressing. (ModR/M = 00???101B)

            // Modify the RIP relative address.
            UINT32 *pRelAddr;

            memcpy(instBuf, (void *)pOldInst, copySize);
            pCopySrc = instBuf;

            // Relative address is stored at (instruction length - immediate value length - 4).
            pRelAddr = (PUINT32)(instBuf + hs.len - ((hs.flags & 0x3C) >> 2) - 4);
            *pRelAddr
                = (UINT32)((pOldInst + hs.len + (INT32)hs.disp.disp32) - (pNewInst + hs.len));

            // Complete the function if JMP (FF /4).
            if (hs.opcode == 0xFF && hs.modrm_reg == 4)
                finished = TRUE;
        }
#endif
        else if (hs.opcode == 0xE8)
        {
            // Direct relative CALL
            ULONG_PTR dest = pOldInst + hs.len + (INT32)hs.imm.imm32;
#if defined _M_X64
            if (tableSize >= ct->tableSize)
                return FALSE;

            ct->pTable[tableSize++] = dest;
            call.operand
                = (UINT32)((ULONG_PTR)(ct->pTable + tableSize - 1) - (pNewInst + sizeof(CALL_ABS)));
#elif defined _M_IX86
            call.operand = (UINT32)(dest - (pNewInst + hs.len));
#endif
            pCopySrc = &call;
            copySize = sizeof(call);
        }
        else if ((hs.opcode & 0xFD) == 0xE9)
        {
            // Direct relative JMP (EB or E9)
            ULONG_PTR dest = pOldInst + hs.len;

            if (hs.opcode == 0xEB) // isShort jmp
                dest += (INT8)hs.imm.imm8;
            else
                dest += (INT32)hs.imm.imm32;

            // Simply copy an internal jump.
            if ((ULONG_PTR)ct->pTarget <= dest
                && dest < ((ULONG_PTR)ct->pTarget + sizeof(JMP_REL)))
            {
                if (jmpDest < dest)
                    jmpDest = dest;
            }
            else
            {
#if defined _M_X64
                if (tableSize >= ct->tableSize)
                    return FALSE;

                ct->pTable[tableSize++] = dest;
                jmp.operand
                    = (UINT32)((ULONG_PTR)(ct->pTable + tableSize - 1) - (pNewInst + sizeof(JMP_ABS)));
#elif defined _M_IX86
                jmp.operand = (UINT32)(dest - (pNewInst + sizeof(JMP_REL)));
#endif
                pCopySrc = &jmp;
                copySize = sizeof(jmp);

                // Exit the function If it is not in the branch
                finished = (pOldInst >= jmpDest);
            }
        }
        else if ((hs.opcode & 0xF0) == 0x70
            || (hs.opcode & 0xFC) == 0xE0
            || (hs.opcode2 & 0xF0) == 0x80)
        {
            // Direct relative Jcc
            ULONG_PTR dest = pOldInst + hs.len;

            if ((hs.opcode & 0xF0) == 0x70      // Jcc
                || (hs.opcode & 0xFC) == 0xE0)  // LOOPNZ/LOOPZ/LOOP/JECXZ
                dest += (INT8)hs.imm.imm8;
            else
                dest += (INT32)hs.imm.imm32;

            // Simply copy an internal jump.
            if ((ULONG_PTR)ct->pTarget <= dest && dest < ((ULONG_PTR)ct->pTarget + sizeof(JMP_REL)))
            {
                if (jmpDest < dest)
                    jmpDest = dest;
            }
            else if ((hs.opcode & 0xFC) == 0xE0) // JCXZ/JECXZ to the outside are not supported.
            {
                // LOOPNZ/LOOPZ/LOOP/JECXZ
                return FALSE;
            }
            else
            {
#if defined _M_X64
                if (tableSize >= ct->tableSize)
                    return FALSE;

                ct->pTable[tableSize++] = dest;

                // JCC_ABS jcc = { 0x70, 0x06, 0x25FF, 0x00000000 };
                // Invert the condition.
                jcc.opcode = 0x71 ^ ((hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F);
                jcc.operand = (UINT32)((ULONG_PTR)(ct->pTable + tableSize - 1) - (pNewInst + sizeof(JCC_ABS)));
#elif defined _M_IX86
                // JCC_REL  jcc = { 0x800F, 0x00000000 };
                jcc.opcode = 0x800F | (((hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F) << 8);
                jcc.operand = (UINT32)(dest - (pNewInst + sizeof(JCC_REL)));
#endif
                pCopySrc = &jcc;
                copySize = sizeof(jcc);
            }
        }
        else if ((hs.opcode & 0xFE) == 0xC2)
        {
            // RET (C2 or C3)

            // Complete the function if not in a branch.
            finished = (pOldInst >= jmpDest);
        }

        // Can't alter the instruction length in a branch.
        if (pOldInst < jmpDest && copySize != hs.len)
            return FALSE;

        if ((newPos + copySize) > ct->trampolineSize)
            return FALSE;

        if (ct->nIP >= ARRAYSIZE(ct->oldIPs))
            return FALSE;

        ct->oldIPs[ct->nIP] = (UINT8)oldPos;
        ct->newIPs[ct->nIP] = (UINT8)newPos;
        ct->nIP++;

        memcpy((UINT8 *)ct->pTrampoline + newPos, pCopySrc, copySize);
        newPos += copySize;
        oldPos += hs.len;
    }

    // Is there enough place for a long jump?
    if (oldPos < sizeof(JMP_REL)
        && !IsCodePadding((UINT8 *)ct->pTarget + oldPos, sizeof(JMP_REL) - oldPos))
    {
        // Is there enough place for a short jump?
        if (oldPos < sizeof(JMP_REL_SHORT)
            && !IsCodePadding((UINT8 *)ct->pTarget + oldPos, sizeof(JMP_REL_SHORT) - oldPos))
        {
            return FALSE;
        }

        // Can we place the long jump above the function?
        if (!IsExecutableAddress((UINT8 *)ct->pTarget - sizeof(JMP_REL)))
            return FALSE;

        if (!IsCodePadding((UINT8 *)ct->pTarget - sizeof(JMP_REL), sizeof(JMP_REL)))
            return FALSE;

        ct->patchAbove = TRUE;
    }

    // Create a relay function.
#if defined _M_X64
    if (tableSize >= ct->tableSize)
        return FALSE;

    ct->pTable[tableSize++] = (ULONG_PTR)ct->pDetour;
    ((JMP_ABS *)ct->pRelay)->opcode = 0x25FF;
    ((JMP_ABS *)ct->pRelay)->operand
        = (UINT32)((ULONG_PTR)(ct->pTable + tableSize - 1) - ((ULONG_PTR)ct->pRelay + sizeof(JMP_ABS)));
#endif

    return TRUE;
}
