/*
 *  DarkHook - The Minimalistic API Hooking Library for x64/x86
 *  Copyright (C) 2009-2017 Tsuda Kageyu.
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

#include <windows.h>

#if defined(_MSC_VER) && !defined(MINHOOK_DISABLE_INTRINSICS)
    #define ALLOW_INTRINSICS
    #include <intrin.h>
#endif

#ifndef ARRAYSIZE
    #define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

#if defined(_M_X64) || defined(__x86_64__)
    #include "./hde/hde64.h"
    typedef hde64s HDE;
    #define HDE_DISASM(code, hs) hde64_disasm(code, hs)
#else
    #include "./hde/hde32.h"
    typedef hde32s HDE;
    #define HDE_DISASM(code, hs) hde32_disasm(code, hs)
#endif

#include "trampoline.h"
#include "buffer.h"

// Maximum size of a trampoline function.
#if defined(_M_X64) || defined(__x86_64__)
    #define TRAMPOLINE_MAX_SIZE (MEMORY_SLOT_SIZE - sizeof(jmp_abs))
#else
    #define TRAMPOLINE_MAX_SIZE MEMORY_SLOT_SIZE
#endif

//-------------------------------------------------------------------------
static BOOL is_code_padding(LPBYTE instruction, UINT size)
{
    UINT i;

    if (instruction[0] != 0x00 && instruction[0] != 0x90 && instruction[0] != 0xCC)
        return FALSE;

    for (i = 1; i < size; ++i)
    {
        if (instruction[i] != instruction[0])
            return FALSE;
    }
    return TRUE;
}

//-------------------------------------------------------------------------
BOOL create_trampoline_function(ptrampoline trampoline_data)
{
#if defined(_M_X64) || defined(__x86_64__)
    call_abs call = {
        0xFF, 0x15, 0x00000002, // FF15 00000002: CALL [RIP+8]
        0xEB, 0x08,             // EB 08:         JMP +10
        0x0000000000000000ULL   // Absolute destination address
    };
    jmp_abs jmp = {
        0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
        0x0000000000000000ULL   // Absolute destination address
    };
    jcc_abs jcc = {
        0x70, 0x0E,             // 7* 0E:         J** +16
        0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
        0x0000000000000000ULL   // Absolute destination address
    };
#else
    call_rel call = {
        0xE8,                   // E8 xxxxxxxx: CALL +5+xxxxxxxx
        0x00000000              // Relative destination address
    };
    jmp_rel jmp = {
        0xE9,                   // E9 xxxxxxxx: JMP +5+xxxxxxxx
        0x00000000              // Relative destination address
    };
    jcc_rel jcc = {
        0x0F, 0x80,             // 0F8* xxxxxxxx: J** +6+xxxxxxxx
        0x00000000              // Relative destination address
    };
#endif

    UINT8     old_pos   = 0;
    UINT8     new_pos   = 0;
    ULONG_PTR jump_dest  = 0;     // Destination address of an internal jump.
    BOOL      finished = FALSE; // Is the function completed?
#if defined(_M_X64) || defined(__x86_64__)
    UINT8     instruction_buffer[16];
#endif

    trampoline_data->patch_above = FALSE;
    trampoline_data->instruction_count        = 0;

    do
    {
        HDE       hs;
        UINT      copy_size;
        LPVOID    copy_source;
        ULONG_PTR old_inst = (ULONG_PTR)trampoline_data->target     + old_pos;
        ULONG_PTR new_inst = (ULONG_PTR)trampoline_data->trampoline + new_pos;

        copy_size = HDE_DISASM((LPVOID)old_inst, &hs);
        if (hs.flags & F_ERROR)
            return FALSE;

        copy_source = (LPVOID)old_inst;
        if (old_pos >= sizeof(jmp_rel))
        {
            // The trampoline function is long enough.
            // Complete the function with the jump to the target function.
#if defined(_M_X64) || defined(__x86_64__)
            jmp.address = old_inst;
#else
            jmp.operand = (INT32)(old_inst - (new_inst + sizeof(jmp)));
#endif
            copy_source = &jmp;
            copy_size = sizeof(jmp);

            finished = TRUE;
        }
#if defined(_M_X64) || defined(__x86_64__)
        else if ((hs.modrm & 0xC7) == 0x05)
        {
            // Instructions using RIP relative addressing. (ModR/M = 00???101B)

            // Modify the RIP relative address.
            PUINT32 rel_address;

            // Avoid using memcpy to reduce the footprint.
#ifndef ALLOW_INTRINSICS
            memcpy(instruction_buffer, (LPBYTE)old_inst, copy_size);
#else
            __movsb(instruction_buffer, (LPBYTE)old_inst, copy_size);
#endif
            copy_source = instruction_buffer;

            // Relative address is stored at (instruction length - immediate value length - 4).
            rel_address = (PUINT32)(instruction_buffer + hs.len - ((hs.flags & 0x3C) >> 2) - 4);
            *rel_address
                = (UINT32)((old_inst + hs.len + (INT32)hs.disp.disp32) - (new_inst + hs.len));

            // Complete the function if JMP (FF /4).
            if (hs.opcode == 0xFF && hs.modrm_reg == 4)
                finished = TRUE;
        }
#endif
        else if (hs.opcode == 0xE8)
        {
            // Direct relative CALL
            ULONG_PTR dest = old_inst + hs.len + (INT32)hs.imm.imm32;
#if defined(_M_X64) || defined(__x86_64__)
            call.address = dest;
#else
            call.operand = (INT32)(dest - (new_inst + sizeof(call)));
#endif
            copy_source = &call;
            copy_size = sizeof(call);
        }
        else if ((hs.opcode & 0xFD) == 0xE9)
        {
            // Direct relative JMP (EB or E9)
            ULONG_PTR dest = old_inst + hs.len;

            if (hs.opcode == 0xEB) // isShort jmp
                dest += (INT8)hs.imm.imm8;
            else
                dest += (INT32)hs.imm.imm32;

            // Simply copy an internal jump.
            if ((ULONG_PTR)trampoline_data->target <= dest
                && dest < ((ULONG_PTR)trampoline_data->target + sizeof(jmp_rel)))
            {
                if (jump_dest < dest)
                    jump_dest = dest;
            }
            else
            {
#if defined(_M_X64) || defined(__x86_64__)
                jmp.address = dest;
#else
                jmp.operand = (INT32)(dest - (new_inst + sizeof(jmp)));
#endif
                copy_source = &jmp;
                copy_size = sizeof(jmp);

                // Exit the function if it is not in the branch.
                finished = (old_inst >= jump_dest);
            }
        }
        else if ((hs.opcode & 0xF0) == 0x70
            || (hs.opcode & 0xFC) == 0xE0
            || (hs.opcode2 & 0xF0) == 0x80)
        {
            // Direct relative Jcc
            ULONG_PTR dest = old_inst + hs.len;

            if ((hs.opcode & 0xF0) == 0x70      // Jcc
                || (hs.opcode & 0xFC) == 0xE0)  // LOOPNZ/LOOPZ/LOOP/JECXZ
                dest += (INT8)hs.imm.imm8;
            else
                dest += (INT32)hs.imm.imm32;

            // Simply copy an internal jump.
            if ((ULONG_PTR)trampoline_data->target <= dest
                && dest < ((ULONG_PTR)trampoline_data->target + sizeof(jmp_rel)))
            {
                if (jump_dest < dest)
                    jump_dest = dest;
            }
            else if ((hs.opcode & 0xFC) == 0xE0)
            {
                // LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported.
                return FALSE;
            }
            else
            {
                UINT8 cond = ((hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F);
#if defined(_M_X64) || defined(__x86_64__)
                // Invert the condition in x64 mode to simplify the conditional jump logic.
                jcc.opcode  = 0x71 ^ cond;
                jcc.address = dest;
#else
                jcc.opcode1 = 0x80 | cond;
                jcc.operand = (INT32)(dest - (new_inst + sizeof(jcc)));
#endif
                copy_source = &jcc;
                copy_size = sizeof(jcc);
            }
        }
        else if ((hs.opcode & 0xFE) == 0xC2)
        {
            // RET (C2 or C3)

            // Complete the function if not in a branch.
            finished = (old_inst >= jump_dest);
        }

        // Can't alter the instruction length in a branch.
        if (old_inst < jump_dest && copy_size != hs.len)
            return FALSE;

        // Trampoline function is too large.
        if ((new_pos + copy_size) > TRAMPOLINE_MAX_SIZE)
            return FALSE;

        // Trampoline function has too many instructions.
        if (trampoline_data->instruction_count >= ARRAYSIZE(trampoline_data->old_ips))
            return FALSE;

        trampoline_data->old_ips[trampoline_data->instruction_count] = old_pos;
        trampoline_data->new_ips[trampoline_data->instruction_count] = new_pos;
        trampoline_data->instruction_count++;

        // Avoid using memcpy to reduce the footprint.
#ifndef ALLOW_INTRINSICS
        memcpy((LPBYTE)trampoline_data->trampoline + new_pos, copy_source, copy_size);
#else
        __movsb((LPBYTE)trampoline_data->trampoline + new_pos, (LPBYTE)copy_source, copy_size);
#endif
        new_pos += copy_size;
        old_pos += hs.len;
    } while (!finished);

    // Is there enough place for a long jump?
    if (old_pos < sizeof(jmp_rel)
        && !is_code_padding((LPBYTE)trampoline_data->target + old_pos, sizeof(jmp_rel) - old_pos))
    {
        // Is there enough place for a short jump?
        if (old_pos < sizeof(jmp_rel_short)
            && !is_code_padding((LPBYTE)trampoline_data->target + old_pos, sizeof(jmp_rel_short) - old_pos))
        {
            return FALSE;
        }

        // Can we place the long jump above the function?
        if (!is_executable_address((LPBYTE)trampoline_data->target - sizeof(jmp_rel)))
            return FALSE;

        if (!is_code_padding((LPBYTE)trampoline_data->target - sizeof(jmp_rel), sizeof(jmp_rel)))
            return FALSE;

        trampoline_data->patch_above = TRUE;
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Create a relay function.
    jmp.address = (ULONG_PTR)trampoline_data->detour;

    trampoline_data->relay = (LPBYTE)trampoline_data->trampoline + new_pos;
    memcpy(trampoline_data->relay, &jmp, sizeof(jmp));
#endif

    return TRUE;
}
