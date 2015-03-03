﻿/*
 *  MinHook - The Minimalistic API Hooking Library for x64/x86
 *  Copyright (C) 2009-2015 Tsuda Kageyu.
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
#include "buffer.h"

// Size of each memory block. (= page size of VirtualAlloc)
#define MEMORY_BLOCK_SIZE 0x1000

// Max range for seeking a memory block. (= 32MB)
#define MAX_MEMORY_RANGE 0x02000000

// Memory protection flags to check the executable address.
#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

// Memory slot.
typedef struct _MEMORY_SLOT
{
    union
    {
        struct _MEMORY_SLOT *pNext;
        UINT8 buffer[MEMORY_SLOT_SIZE];
    };
} MEMORY_SLOT, *PMEMORY_SLOT;

// Memory block info. Placed at the head of each block.
typedef struct _MEMORY_BLOCK
{
    struct _MEMORY_BLOCK *pNext;
    PMEMORY_SLOT pFree;         // First element of the free slot list.
    UINT usedCount;
} MEMORY_BLOCK, *PMEMORY_BLOCK;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// First element of the memory block list.
PMEMORY_BLOCK g_pMemoryBlocks;

//-------------------------------------------------------------------------
VOID InitializeBuffer(VOID)
{
    // Nothing to do for now.
}

//-------------------------------------------------------------------------
VOID UninitializeBuffer(VOID)
{
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    g_pMemoryBlocks = NULL;

    while (pBlock)
    {
        PMEMORY_BLOCK pNext = pBlock->pNext;
        VirtualFree(pBlock, 0, MEM_RELEASE);
        pBlock = pNext;
    }
}

//-------------------------------------------------------------------------
static PMEMORY_BLOCK GetMemoryBlock(LPVOID pOrigin)
{
    ULONG_PTR minAddr=NULL;
    ULONG_PTR maxAddr=NULL;
    PMEMORY_BLOCK pBlock=NULL;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
    maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;

#ifdef _M_X64
    // pOrigin ± 16MB
    if ((ULONG_PTR)pOrigin > MAX_MEMORY_RANGE)
        minAddr = max(minAddr, (ULONG_PTR)pOrigin - MAX_MEMORY_RANGE);

    maxAddr = min(maxAddr, (ULONG_PTR)pOrigin + MAX_MEMORY_RANGE);
#endif

    // Look the registered blocks for a reachable one.
    for (pBlock = g_pMemoryBlocks; pBlock != NULL; pBlock = pBlock->pNext)
    {
#ifdef _M_X64
        // Ignore the blocks too far.
        if ((ULONG_PTR)pBlock < minAddr || (ULONG_PTR)pBlock >= maxAddr)
            continue;
#endif
        // The block has at least one unused slot.
        if (pBlock->pFree != NULL)
            return pBlock;
    }

    // Alloc a new block if not found.
    {
        ULONG_PTR pStart = ((ULONG_PTR)pOrigin / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE
        ULONG_PTR PAlloc = NULL;
        for (pAlloc = pStart - MEMORY_BLOCK_SIZE; pAlloc >= minAddr; pAlloc -= MEMORY_BLOCK_SIZE)
        {
            pBlock = (PMEMORY_BLOCK)VirtualAlloc(
                (LPVOID)pAlloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pBlock != NULL)
                break;
        }
        if (pBlock == NULL)
        {
            for (pAlloc = pStart + MEMORY_BLOCK_SIZE; pAlloc < maxAddr; pAlloc += MEMORY_BLOCK_SIZE)
            {
                pBlock = (PMEMORY_BLOCK)VirtualAlloc(
                    (LPVOID)pAlloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (pBlock != NULL)
                    break;
            }
        }
    }

    if (pBlock != NULL)
    {
        // Build a linked list of all the slots.
        PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBlock + 1;
        pBlock->pFree = NULL;
        pBlock->usedCount = 0;
        do
        {
            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pSlot++;
        } while ((ULONG_PTR)pSlot - (ULONG_PTR)pBlock <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE);

        pBlock->pNext = g_pMemoryBlocks;
        g_pMemoryBlocks = pBlock;
    }

    return pBlock;
}

//-------------------------------------------------------------------------
LPVOID AllocateBuffer(LPVOID pOrigin)
{
    PMEMORY_SLOT  pSlot = NULL;
    PMEMORY_BLOCK pBlock = GetMemoryBlock(pOrigin);
    if (pBlock == NULL)
        return NULL;

    // Remove an unused slot from the list.
    pSlot = pBlock->pFree;
    pBlock->pFree = pSlot->pNext;
    pBlock->usedCount++;
#ifdef _DEBUG
    // Fill the slot with INT3 for debugging.
    memset(pSlot, 0xCC, sizeof(MEMORY_SLOT));
#endif
    return pSlot;
}

//-------------------------------------------------------------------------
VOID FreeBuffer(LPVOID pBuffer)
{
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    PMEMORY_BLOCK pPrev = NULL;
    ULONG_PTR pTargetBlock = ((ULONG_PTR)pBuffer / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;

    while (pBlock != NULL)
    {
        if ((ULONG_PTR)pBlock == pTargetBlock)
        {
            PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBuffer;
#ifdef _DEBUG
            // Clear the released slot for debugging.
            memset(pSlot, 0x00, sizeof(MEMORY_SLOT));
#endif
            // Restore the released slot to the list.
            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pBlock->usedCount--;

            // Free if unused.
            if (pBlock->usedCount == 0)
            {
                if (pPrev)
                    pPrev->pNext = pBlock->pNext;
                else
                    g_pMemoryBlocks = pBlock->pNext;

                VirtualFree(pBlock, 0, MEM_RELEASE);
            }

            break;
        }

        pPrev = pBlock;
        pBlock = pBlock->pNext;
    }
}

//-------------------------------------------------------------------------
BOOL IsExecutableAddress(LPVOID pAddress)
{
    MEMORY_BASIC_INFORMATION mi;
    VirtualQuery(pAddress, &mi, sizeof(MEMORY_BASIC_INFORMATION));

    return (mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS));
}
