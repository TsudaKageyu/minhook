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
#include <assert.h>
#include "buffer.h"

// Size of each memory block. (= page size of VirtualAlloc)
#define MH_PAGE_SIZE 0x1000

// Size of each buffer.
#if defined _M_X64
#define MH_BUFFER_SIZE 64
#elif defined _M_IX86
#define MH_BUFFER_SIZE 32
#endif

// Max use count of each memory block.
#define MH_MAX_USE_COUNT (MH_PAGE_SIZE / MH_BUFFER_SIZE - 1)

// Max range for seeking a memory block in x64 mode. (= 16MB)
#define MH_MAX_RANGE 0x01000000

// Memory block info. Placed at the head of each block.
typedef struct _MEMORY_BLOCK
{
    struct _MEMORY_BLOCK *pNext;
    size_t bufferCount;     // Number of buffers allocated.
    size_t useCount;        // Number of buffers actually used.
} MEMORY_BLOCK, *PMEMORY_BLOCK;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// Lowest memory address accessible.
ULONG_PTR g_MinAddress;

// Highest memory address accessible.
ULONG_PTR g_MaxAddress;

// First element of the memory block list.
PMEMORY_BLOCK g_pMemoryBlocks;

//-------------------------------------------------------------------------
void InitializeBuffer(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    g_MinAddress = (ULONG_PTR)si.lpMinimumApplicationAddress;
    g_MaxAddress = (ULONG_PTR)si.lpMaximumApplicationAddress;
}

//-------------------------------------------------------------------------
void UninitializeBuffer(void)
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
static PMEMORY_BLOCK GetMemoryBlock(void *pOrigin)
{
    ULONG_PTR minAddr = g_MinAddress;
    ULONG_PTR maxAddr = g_MaxAddress;
    PMEMORY_BLOCK pBlock;

#if defined _M_X64
    // pOrigin ± 16MB
    if ((ULONG_PTR)pOrigin > MH_MAX_RANGE)
        minAddr = max(minAddr, (ULONG_PTR)pOrigin - MH_MAX_RANGE);

    maxAddr = min(maxAddr, (ULONG_PTR)pOrigin + MH_MAX_RANGE);
#endif

    // Look the registered blocks for a reachable one.
    for (pBlock = g_pMemoryBlocks; pBlock != NULL; pBlock = pBlock->pNext)
    {
#if defined _M_X64
        // Ignore the blocks too far.
        if ((ULONG_PTR)pBlock < minAddr || (ULONG_PTR)pBlock >= maxAddr)
            continue;
#endif
        if (pBlock->useCount < MH_MAX_USE_COUNT && pBlock->bufferCount < MH_MAX_USE_COUNT)
            return pBlock;
    }

    // Alloc a new block if not found.
    {
        ULONG_PTR pStart = ((ULONG_PTR)pOrigin / MH_PAGE_SIZE) * MH_PAGE_SIZE;
        ULONG_PTR pAlloc;
        for (pAlloc = pStart - MH_PAGE_SIZE; pAlloc >= minAddr; pAlloc -= MH_PAGE_SIZE)
        {
            pBlock = (PMEMORY_BLOCK)VirtualAlloc(
                (void *)pAlloc, MH_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pBlock != NULL)
                break;
        }
        if (pBlock == NULL)
        {
            for (pAlloc = pStart + MH_PAGE_SIZE; pAlloc < maxAddr; pAlloc += MH_PAGE_SIZE)
            {
                pBlock = (PMEMORY_BLOCK)VirtualAlloc(
                    (void *)pAlloc, MH_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (pBlock != NULL)
                    break;
            }
        }
    }

    if (pBlock != NULL)
    {
        pBlock->pNext     = g_pMemoryBlocks;
        pBlock->bufferCount = 0;
        pBlock->useCount  = 0;
        g_pMemoryBlocks = pBlock;
    }

    return pBlock;
}

//-------------------------------------------------------------------------
static void FreeBufferLL(void *pBuffer, BOOL decrement)
{
}

//-------------------------------------------------------------------------
void* AllocateBuffer(void *pOrigin)
{
#ifdef _DEBUG
    static const char zeroBuf[MH_BUFFER_SIZE] = { 0 };
#endif
    void *pBuffer;
    PMEMORY_BLOCK pBlock = GetMemoryBlock(pOrigin);
    if (pBlock == NULL)
        return NULL;

    pBuffer = (char *)pBlock + ((pBlock->bufferCount + 1) * MH_BUFFER_SIZE);
#ifdef _DEBUG
    // Check if the buffer is not used and fill it with INT3 for debugging.
    assert(memcmp(pBuffer, zeroBuf, MH_BUFFER_SIZE) == 0);
    memset(pBuffer, 0xCC, MH_BUFFER_SIZE);
#endif
    return pBuffer;
}

//-------------------------------------------------------------------------
void FreeBuffer(void *pBuffer)
{
    PMEMORY_BLOCK pPrev  = NULL;
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    ULONG_PTR pTargetBlock = ((ULONG_PTR)pBuffer / MH_PAGE_SIZE) * MH_PAGE_SIZE;

    while (pBlock != NULL)
    {
        if ((ULONG_PTR)pBlock == pTargetBlock)
        {
            pBlock->useCount--;
            if (pBlock->useCount == 0)
            {
                if (pPrev)
                    pPrev->pNext = pBlock->pNext;
                else
                    g_pMemoryBlocks = pBlock->pNext;

                VirtualFree(pBlock, 0, MEM_RELEASE);
            }
            break;
        }
#ifdef _DEBUG
        else
        {
            // Fill the released buffer with INT3 for debugging.
            memset(pBuffer, 0xCC, MH_BUFFER_SIZE);
        }
#endif
        pPrev  = pBlock;
        pBlock = pBlock->pNext;
    }
}

//-------------------------------------------------------------------------
BOOL IsExecutableAddress(void *pAddress)
{
    // Is the address allocated and has one of these flags?
    static const DWORD PageExecuteMask
        = (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);

    MEMORY_BASIC_INFORMATION mi;
    VirtualQuery(pAddress, &mi, sizeof(MEMORY_BASIC_INFORMATION));

    return (mi.State == MEM_COMMIT && (mi.Protect & PageExecuteMask)) ? TRUE : FALSE;
}
