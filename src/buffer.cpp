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
#include "buffer.h"

// Size of each memory block. (= page size of VirtualAlloc)
#define MEMORY_BLOCK_SIZE 0x1000

// Max range for seeking a memory block. (= 1024MB)
#define MAX_MEMORY_RANGE 0x40000000

// Memory protection flags to check the executable address.
#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

// Memory slot.
typedef struct _memory_slot
{
    union
    {
        struct _memory_slot *next;
        UINT8 buffer[MEMORY_SLOT_SIZE];
    };
} memory_slot, *pmemory_slot;

// Memory block info. Placed at the head of each block.
typedef struct _memory_block
{
    struct _memory_block *next;
    pmemory_slot free_list;         // First element of the free slot list.
    UINT used_count;
} memory_block, *pmemory_block;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// First element of the memory block list.
static pmemory_block g_memory_blocks;

//-------------------------------------------------------------------------
VOID initialize_buffer(VOID)
{
    // Nothing to do for now.
}

//-------------------------------------------------------------------------
VOID uninitialize_buffer(VOID)
{
    pmemory_block block = g_memory_blocks;
    g_memory_blocks = NULL;

    while (block)
    {
        pmemory_block next = block->next;
        VirtualFree(block, 0, MEM_RELEASE);
        block = next;
    }
}

//-------------------------------------------------------------------------
#if defined(_M_X64) || defined(__x86_64__)
static LPVOID find_prev_free_region(LPVOID address, LPVOID min_address, DWORD allocation_granularity)
{
    ULONG_PTR try_address = (ULONG_PTR)address;

    // Round down to the allocation granularity.
    try_address -= try_address % allocation_granularity;

    // Start from the previous allocation granularity multiply.
    try_address -= allocation_granularity;

    while (try_address >= (ULONG_PTR)min_address)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPVOID)try_address, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_FREE)
            return (LPVOID)try_address;

        if ((ULONG_PTR)mbi.AllocationBase < allocation_granularity)
            break;

        try_address = (ULONG_PTR)mbi.AllocationBase - allocation_granularity;
    }

    return NULL;
}
#endif

//-------------------------------------------------------------------------
#if defined(_M_X64) || defined(__x86_64__)
static LPVOID find_next_free_region(LPVOID address, LPVOID max_address, DWORD allocation_granularity)
{
    ULONG_PTR try_address = (ULONG_PTR)address;

    // Round down to the allocation granularity.
    try_address -= try_address % allocation_granularity;

    // Start from the next allocation granularity multiply.
    try_address += allocation_granularity;

    while (try_address <= (ULONG_PTR)max_address)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPVOID)try_address, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_FREE)
            return (LPVOID)try_address;

        try_address = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;

        // Round up to the next allocation granularity.
        try_address += allocation_granularity - 1;
        try_address -= try_address % allocation_granularity;
    }

    return NULL;
}
#endif

//-------------------------------------------------------------------------
static pmemory_block get_memory_block(LPVOID origin)
{
    pmemory_block block;
#if defined(_M_X64) || defined(__x86_64__)
    ULONG_PTR min_address;
    ULONG_PTR max_address;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    min_address = (ULONG_PTR)si.lpMinimumApplicationAddress;
    max_address = (ULONG_PTR)si.lpMaximumApplicationAddress;

    // origin ± 512MB
    if ((ULONG_PTR)origin > MAX_MEMORY_RANGE && min_address < (ULONG_PTR)origin - MAX_MEMORY_RANGE)
        min_address = (ULONG_PTR)origin - MAX_MEMORY_RANGE;

    if (max_address > (ULONG_PTR)origin + MAX_MEMORY_RANGE)
        max_address = (ULONG_PTR)origin + MAX_MEMORY_RANGE;

    // Make room for MEMORY_BLOCK_SIZE bytes.
    max_address -= MEMORY_BLOCK_SIZE - 1;
#endif

    // Look the registered blocks for a reachable one.
    for (block = g_memory_blocks; block != NULL; block = block->next)
    {
#if defined(_M_X64) || defined(__x86_64__)
        // Ignore the blocks too far.
        if ((ULONG_PTR)block < min_address || (ULONG_PTR)block >= max_address)
            continue;
#endif
        // The block has at least one unused slot.
        if (block->free_list != NULL)
            return block;
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Alloc a new block above if not found.
    {
        LPVOID alloc = origin;
        while ((ULONG_PTR)alloc >= min_address)
        {
            alloc = find_prev_free_region(alloc, (LPVOID)min_address, si.allocation_granularity);
            if (alloc == NULL)
                break;

            block = (pmemory_block)VirtualAlloc(
                alloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (block != NULL)
                break;
        }
    }

    // Alloc a new block below if not found.
    if (block == NULL)
    {
        LPVOID alloc = origin;
        while ((ULONG_PTR)alloc <= max_address)
        {
            alloc = find_next_free_region(alloc, (LPVOID)max_address, si.allocation_granularity);
            if (alloc == NULL)
                break;

            block = (pmemory_block)VirtualAlloc(
                alloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (block != NULL)
                break;
        }
    }
#else
    // In x86 mode, a memory block can be placed anywhere.
    block = (pmemory_block)VirtualAlloc(
        NULL, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif

    if (block != NULL)
    {
        // Build a linked list of all the slots.
        pmemory_slot slot = (pmemory_slot)block + 1;
        block->free_list = NULL;
        block->used_count = 0;
        do
        {
            slot->next = block->free_list;
            block->free_list = slot;
            slot++;
        } while ((ULONG_PTR)slot - (ULONG_PTR)block <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE);

        block->next = g_memory_blocks;
        g_memory_blocks = block;
    }

    return block;
}

//-------------------------------------------------------------------------
LPVOID allocate_buffer(LPVOID origin)
{
    pmemory_slot  slot;
    pmemory_block block = get_memory_block(origin);
    if (block == NULL)
        return NULL;

    // Remove an unused slot from the list.
    slot = block->free_list;
    block->free_list = slot->next;
    block->used_count++;
#ifdef _DEBUG
    // Fill the slot with INT3 for debugging.
    memset(slot, 0xCC, sizeof(memory_slot));
#endif
    return slot;
}

//-------------------------------------------------------------------------
VOID free_buffer(LPVOID buffer)
{
    pmemory_block block = g_memory_blocks;
    pmemory_block prev = NULL;
    ULONG_PTR target_block = ((ULONG_PTR)buffer / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;

    while (block != NULL)
    {
        if ((ULONG_PTR)block == target_block)
        {
            pmemory_slot slot = (pmemory_slot)buffer;
#ifdef _DEBUG
            // Clear the released slot for debugging.
            memset(slot, 0x00, sizeof(memory_slot));
#endif
            // Restore the released slot to the list.
            slot->next = block->free_list;
            block->free_list = slot;
            block->used_count--;

            // Free if unused.
            if (block->used_count == 0)
            {
                if (prev)
                    prev->next = block->next;
                else
                    g_memory_blocks = block->next;

                VirtualFree(block, 0, MEM_RELEASE);
            }

            break;
        }

        prev = block;
        block = block->next;
    }
}

//-------------------------------------------------------------------------
BOOL is_executable_address(LPVOID address)
{
    MEMORY_BASIC_INFORMATION mi;
    VirtualQuery(address, &mi, sizeof(mi));

    return (mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS));
}
