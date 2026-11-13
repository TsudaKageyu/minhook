/*
 *  MinHook - The Minimalistic API Hooking Library for x64/x86
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


/* SAFE-FREEZE additions derive from the recorded project/donor implementation.
 * The code owner authorized BSD-2-Clause licensing on 2026-11-10.
 * Preserve the upstream BSD notices above and see LICENSE.SAFE_FREEZE and
 * SAFE_FREEZE_LICENSE_NOTICE.md for the contribution and provenance record.
 */
#include <windows.h>
#include <tlhelp32.h>
#include <limits.h>

#include "../include/MinHook.h"
#include "buffer.h"
#include "trampoline.h"

#ifndef ARRAYSIZE
    #define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

// Initial capacity of the HOOK_ENTRY buffer.
#define INITIAL_HOOK_CAPACITY   32

// Initial capacity of the thread IDs buffer.
#define INITIAL_THREAD_CAPACITY 128

// Special hook position values.
#define INVALID_HOOK_POS UINT_MAX
#define ALL_HOOKS_POS    UINT_MAX

// Freeze() action argument defines.
#define ACTION_DISABLE      0
#define ACTION_ENABLE       1
#define ACTION_APPLY_QUEUED 2

// Thread access rights for suspending/resuming threads.
#define THREAD_ACCESS \
    (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT)

// Hook information.
typedef struct _HOOK_ENTRY
{
    LPVOID pTarget;             // Address of the target function.
    LPVOID pDetour;             // Address of the detour or relay function.
    LPVOID pTrampoline;         // Address of the trampoline function.
    UINT8  backup[8];           // Original prologue of the target function.

    UINT8  patchAbove  : 1;     // Uses the hot patch area.
    UINT8  isEnabled   : 1;     // Enabled.
    UINT8  queueEnable : 1;     // Queued for enabling/disabling when != isEnabled.

    UINT   nIP : 4;             // Count of the instruction boundaries.
    UINT8  oldIPs[8];           // Instruction boundaries of the target function.
    UINT8  newIPs[8];           // Instruction boundaries of the trampoline function.
} HOOK_ENTRY, *PHOOK_ENTRY;

// Suspended threads for Freeze()/Unfreeze().
#if defined(MH_SAFE_FREEZE)
typedef struct _FROZEN_THREAD_ITEM
{
    HANDLE handle;
    BOOL   suspended;
} FROZEN_THREAD_ITEM, *PFROZEN_THREAD_ITEM;

#endif
typedef struct _FROZEN_THREADS
{
#if defined(MH_SAFE_FREEZE)
    PFROZEN_THREAD_ITEM pItems; // Exact physical owners retained until release succeeds.
    UINT                capacity;
    UINT                size;
#else
    LPDWORD pItems;         // Data heap
    UINT    capacity;       // Size of allocated data heap, items
    UINT    size;           // Actual number of data items
#endif
} FROZEN_THREADS, *PFROZEN_THREADS;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// Spin lock flag for EnterSpinLock()/LeaveSpinLock().
static volatile LONG g_isLocked = FALSE;

// Private heap handle. If not NULL, this library is initialized.
static HANDLE g_hHeap = NULL;

// Hook entries.
static struct
{
    PHOOK_ENTRY pItems;     // Data heap
    UINT        capacity;   // Size of allocated data heap, items
    UINT        size;       // Actual number of data items
} g_hooks;

//-------------------------------------------------------------------------
// Returns INVALID_HOOK_POS if not found.
static UINT FindHookEntry(LPVOID pTarget)
{
    UINT i;
    for (i = 0; i < g_hooks.size; ++i)
    {
        if ((ULONG_PTR)pTarget == (ULONG_PTR)g_hooks.pItems[i].pTarget)
            return i;
    }

    return INVALID_HOOK_POS;
}

//-------------------------------------------------------------------------
static PHOOK_ENTRY AddHookEntry()
{
    if (g_hooks.pItems == NULL)
    {
        g_hooks.capacity = INITIAL_HOOK_CAPACITY;
        g_hooks.pItems = (PHOOK_ENTRY)HeapAlloc(
            g_hHeap, 0, g_hooks.capacity * sizeof(HOOK_ENTRY));
        if (g_hooks.pItems == NULL)
            return NULL;
    }
    else if (g_hooks.size >= g_hooks.capacity)
    {
        PHOOK_ENTRY p = (PHOOK_ENTRY)HeapReAlloc(
            g_hHeap, 0, g_hooks.pItems, (g_hooks.capacity * 2) * sizeof(HOOK_ENTRY));
        if (p == NULL)
            return NULL;

        g_hooks.capacity *= 2;
        g_hooks.pItems = p;
    }

    return &g_hooks.pItems[g_hooks.size++];
}

//-------------------------------------------------------------------------
static VOID DeleteHookEntry(UINT pos)
{
    if (pos < g_hooks.size - 1)
        g_hooks.pItems[pos] = g_hooks.pItems[g_hooks.size - 1];

    g_hooks.size--;

    if (g_hooks.capacity / 2 >= INITIAL_HOOK_CAPACITY && g_hooks.capacity / 2 >= g_hooks.size)
    {
        PHOOK_ENTRY p = (PHOOK_ENTRY)HeapReAlloc(
            g_hHeap, 0, g_hooks.pItems, (g_hooks.capacity / 2) * sizeof(HOOK_ENTRY));
        if (p == NULL)
            return;

        g_hooks.capacity /= 2;
        g_hooks.pItems = p;
    }
}

//-------------------------------------------------------------------------
static DWORD_PTR FindOldIP(PHOOK_ENTRY pHook, DWORD_PTR ip)
{
    UINT i;

    if (pHook->patchAbove && ip == ((DWORD_PTR)pHook->pTarget - sizeof(JMP_REL)))
        return (DWORD_PTR)pHook->pTarget;

    for (i = 0; i < pHook->nIP; ++i)
    {
        if (ip == ((DWORD_PTR)pHook->pTrampoline + pHook->newIPs[i]))
            return (DWORD_PTR)pHook->pTarget + pHook->oldIPs[i];
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Check relay function.
    if (ip == (DWORD_PTR)pHook->pDetour)
        return (DWORD_PTR)pHook->pTarget;
#endif

    return 0;
}

//-------------------------------------------------------------------------
static DWORD_PTR FindNewIP(PHOOK_ENTRY pHook, DWORD_PTR ip)
{
    UINT i;
    for (i = 0; i < pHook->nIP; ++i)
    {
        if (ip == ((DWORD_PTR)pHook->pTarget + pHook->oldIPs[i]))
            return (DWORD_PTR)pHook->pTrampoline + pHook->newIPs[i];
    }

    return 0;
}

//-------------------------------------------------------------------------
#if defined(MH_SAFE_FREEZE)
typedef enum _PEER_PREPARATION_RESULT
#else
static VOID ProcessThreadIPs(HANDLE hThread, UINT pos, UINT action)
#endif
{
#if defined(MH_SAFE_FREEZE)
    PEER_PREPARED = 0,
    PEER_TERMINATED = 1,
    PEER_UNRESOLVED = 2
} PEER_PREPARATION_RESULT;
#else
    // If the thread suspended in the overwritten area,
    // move IP to the proper address.
#endif

#if defined(MH_SAFE_FREEZE)
static BOOL ThreadNoLongerLive(HANDLE hThread)
{
    DWORD exitCode = STILL_ACTIVE;
    if (GetExitCodeThread(hThread, &exitCode))
        return exitCode != STILL_ACTIVE;
    return GetLastError() == ERROR_INVALID_HANDLE;
}

static PEER_PREPARATION_RESULT ProcessThreadIPs(HANDLE hThread, UINT pos, UINT action)
{
#endif
    CONTEXT c;
#if defined(_M_X64) || defined(__x86_64__)
    DWORD64 *pIP = &c.Rip;
#else
    DWORD   *pIP = &c.Eip;
#endif
    UINT count;

    c.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &c))
#if defined(MH_SAFE_FREEZE)
        return ThreadNoLongerLive(hThread) ? PEER_TERMINATED : PEER_UNRESOLVED;
#else
        return;
#endif

    if (pos == ALL_HOOKS_POS)
    {
        pos = 0;
        count = g_hooks.size;
    }
    else
    {
        count = pos + 1;
    }

    for (; pos < count; ++pos)
    {
        PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
        BOOL        enable;
        DWORD_PTR   ip;

        switch (action)
        {
        case ACTION_DISABLE:
            enable = FALSE;
            break;
#if defined(MH_SAFE_FREEZE)
#else

#endif
        case ACTION_ENABLE:
            enable = TRUE;
            break;
#if defined(MH_SAFE_FREEZE)
        default:
#else

        default: // ACTION_APPLY_QUEUED
#endif
            enable = pHook->queueEnable;
            break;
        }
        if (pHook->isEnabled == enable)
            continue;

        if (enable)
            ip = FindNewIP(pHook, *pIP);
        else
            ip = FindOldIP(pHook, *pIP);

        if (ip != 0)
        {
            *pIP = ip;
#if defined(MH_SAFE_FREEZE)
            if (!SetThreadContext(hThread, &c))
                return ThreadNoLongerLive(hThread) ? PEER_TERMINATED : PEER_UNRESOLVED;
#else
            SetThreadContext(hThread, &c);
#endif
        }
    }
#if defined(MH_SAFE_FREEZE)
    return PEER_PREPARED;
#endif
}

//-------------------------------------------------------------------------
#if defined(MH_SAFE_FREEZE)
/* MH_SAFE_FREEZE_V1
 *
 * Stock MinHook enumerates peer threads with CreateToolhelp32Snapshot.
 * Strict mode uses stable owned handles and rejects unresolved peers.
 * Keep MinHook's suspend/context/IP-relocation contract, but enumerate stable
 * thread handles with NtGetNextThread instead. Callers must avoid loader lock.
 *
 * Retained ownership rule: every duplicated peer HANDLE and the backing heap array
 * remain discoverable until ResumeThread/CloseHandle/HeapFree physically
 * succeed or the handle is proven terminated/invalid. A later MinHook operation
 * retries retained cleanup before acquiring a new peer-thread set.
 */
typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PFN_NT_GET_NEXT_THREAD)(
    HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

/* Completion records outlive failed API calls. No allocation is needed while
 * peers are suspended. A seven-byte hotpatch can touch at most two pages. */
typedef struct _PATCH_PAGE
{
    LPVOID address;
    DWORD protection;
    BOOL pending;
} PATCH_PAGE;
static struct
{
    BOOL active, cachePending;
    LPBYTE target;
    SIZE_T size, pageSize;
    UINT count;
    PATCH_PAGE pages[2];
} g_patchCompletion;
static LPVOID g_retainedBuffer;
static BOOL g_shutdownPending;
static LPVOID g_retiringBuffer;
#define ACTION_RETIRE 3

static BOOL RetryPatchCompletion(VOID)
{
    UINT i;
    BOOL complete = TRUE;
    if (!g_patchCompletion.active)
        return TRUE;
    if (g_patchCompletion.cachePending)
    {
        if (FlushInstructionCache(GetCurrentProcess(), g_patchCompletion.target, g_patchCompletion.size))
            g_patchCompletion.cachePending = FALSE;
        else
            complete = FALSE;
    }
    for (i = 0; i < g_patchCompletion.count; ++i)
    {
        PATCH_PAGE *page = &g_patchCompletion.pages[i];
        if (page->pending)
        {
            DWORD ignored;
            if (VirtualProtect(page->address, g_patchCompletion.pageSize, page->protection, &ignored))
                page->pending = FALSE;
            else
                complete = FALSE;
        }
    }
    if (complete)
        memset(&g_patchCompletion, 0, sizeof(g_patchCompletion));
    return complete;
}

static BOOL IsRetiringAddress(DWORD_PTR address)
{
    if (g_retiringBuffer != NULL)
        return address >= (ULONG_PTR)g_retiringBuffer &&
            address - (ULONG_PTR)g_retiringBuffer < MEMORY_SLOT_SIZE;
    return IsBufferAddress((ULONG_PTR)address);
}

static PEER_PREPARATION_RESULT CheckRetiringThread(HANDLE thread)
{
    CONTEXT context;
    MEMORY_BASIC_INFORMATION first;
    ULONG_PTR cursor, allocation;
    SIZE_T scanned = 0;
    DWORD_PTR registers[17];
    UINT i, count;
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(thread, &context))
        return ThreadNoLongerLive(thread) ? PEER_TERMINATED : PEER_UNRESOLVED;
#if defined(_M_X64) || defined(__x86_64__)
    registers[0]=context.Rip; registers[1]=context.Rax; registers[2]=context.Rbx;
    registers[3]=context.Rcx; registers[4]=context.Rdx; registers[5]=context.Rsi;
    registers[6]=context.Rdi; registers[7]=context.Rbp; registers[8]=context.Rsp;
    registers[9]=context.R8; registers[10]=context.R9; registers[11]=context.R10;
    registers[12]=context.R11; registers[13]=context.R12; registers[14]=context.R13;
    registers[15]=context.R14; registers[16]=context.R15;
    count = 17;
    cursor = (ULONG_PTR)context.Rsp;
#else
    registers[0]=context.Eip; registers[1]=context.Eax; registers[2]=context.Ebx;
    registers[3]=context.Ecx; registers[4]=context.Edx; registers[5]=context.Esi;
    registers[6]=context.Edi; registers[7]=context.Ebp; registers[8]=context.Esp;
    count = 9;
    cursor = (ULONG_PTR)context.Esp;
#endif
    for (i = 0; i < count; ++i)
        if (IsRetiringAddress(registers[i]))
            return PEER_UNRESOLVED;
    if (!VirtualQuery((LPCVOID)cursor, &first, sizeof(first)))
        return PEER_UNRESOLVED;
    allocation = (ULONG_PTR)first.AllocationBase;
    while (scanned < 64 * 1024 * 1024)
    {
        MEMORY_BASIC_INFORMATION region;
        ULONG_PTR limit;
        if (!VirtualQuery((LPCVOID)cursor, &region, sizeof(region)))
            return PEER_UNRESOLVED;
        if ((ULONG_PTR)region.AllocationBase != allocation)
            return PEER_PREPARED;
        limit = (ULONG_PTR)region.BaseAddress + region.RegionSize;
        if (limit <= cursor || limit - cursor > 64 * 1024 * 1024 - scanned ||
            region.State != MEM_COMMIT || (region.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            return PEER_UNRESOLVED;
        while (cursor < limit)
        {
            DWORD_PTR words[64];
            SIZE_T copied = 0, bytes = limit - cursor;
            if (bytes > sizeof(words)) bytes = sizeof(words);
            if (bytes % sizeof(words[0]) != 0 ||
                !ReadProcessMemory(GetCurrentProcess(), (LPCVOID)cursor, words, bytes, &copied) || copied != bytes)
                return PEER_UNRESOLVED;
            for (i = 0; i < bytes / sizeof(words[0]); ++i)
                if (IsRetiringAddress(words[i]))
                    return PEER_UNRESOLVED;
            cursor += bytes;
            scanned += bytes;
        }
    }
    return PEER_UNRESOLVED;
}

static FROZEN_THREADS g_retainedThreads = { NULL, 0, 0 };
static FROZEN_THREAD_ITEM g_emergencyThread = { NULL, FALSE };
static FROZEN_THREAD_ITEM g_emergencyNextThread = { NULL, FALSE };

static PFN_NT_GET_NEXT_THREAD ResolveNtGetNextThread(VOID)
#else
static BOOL EnumerateThreads(PFROZEN_THREADS pThreads)
#endif
{
#if defined(MH_SAFE_FREEZE)
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL)
        return NULL;
    return (PFN_NT_GET_NEXT_THREAD)GetProcAddress(ntdll, "NtGetNextThread");
}
#else
    BOOL succeeded = FALSE;
#endif

#if defined(MH_SAFE_FREEZE)
static BOOL AppendThreadHandle(PFROZEN_THREADS pThreads, HANDLE hThread)
{
    if (pThreads->pItems == NULL)
#else
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
#endif
    {
#if defined(MH_SAFE_FREEZE)
        pThreads->capacity = INITIAL_THREAD_CAPACITY;
        pThreads->pItems = (PFROZEN_THREAD_ITEM)HeapAlloc(
            g_hHeap, HEAP_ZERO_MEMORY,
            pThreads->capacity * sizeof(FROZEN_THREAD_ITEM));
        if (pThreads->pItems == NULL)
            return FALSE;
    }
    else if (pThreads->size >= pThreads->capacity)
    {
        PFROZEN_THREAD_ITEM p;
        UINT oldCapacity = pThreads->capacity;
        pThreads->capacity *= 2;
        p = (PFROZEN_THREAD_ITEM)HeapReAlloc(
            g_hHeap, HEAP_ZERO_MEMORY, pThreads->pItems,
            pThreads->capacity * sizeof(FROZEN_THREAD_ITEM));
        if (p == NULL)
#else
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hSnapshot, &te))
#endif
        {
#if defined(MH_SAFE_FREEZE)
            pThreads->capacity = oldCapacity;
            return FALSE;
        }
        pThreads->pItems = p;
    }
    pThreads->pItems[pThreads->size].handle = hThread;
    pThreads->pItems[pThreads->size].suspended = FALSE;
    ++pThreads->size;
    return TRUE;
}

static BOOL ResumeOwnedThread(PFROZEN_THREAD_ITEM pItem)
{
    DWORD resumeResult;
    if (pItem->handle == NULL || !pItem->suspended)
        return TRUE;
    if (ThreadNoLongerLive(pItem->handle))
    {
        pItem->suspended = FALSE;
        return TRUE;
    }
    resumeResult = ResumeThread(pItem->handle);
    if (resumeResult != 0xFFFFFFFF)
    {
        pItem->suspended = FALSE;
        return TRUE;
    }
    if (GetLastError() == ERROR_INVALID_HANDLE || ThreadNoLongerLive(pItem->handle))
    {
        pItem->suspended = FALSE;
        return TRUE;
    }
    return FALSE;
}

static BOOL CloseOwnedThread(PFROZEN_THREAD_ITEM pItem)
{
    if (pItem->handle == NULL)
        return TRUE;
    if (CloseHandle(pItem->handle))
    {
        pItem->handle = NULL;
        return TRUE;
    }
    if (GetLastError() == ERROR_INVALID_HANDLE)
    {
        pItem->handle = NULL;
        return TRUE;
    }
    return FALSE;
}

static BOOL CloseOrRetainEmergency(HANDLE hThread)
{
    FROZEN_THREAD_ITEM item = { hThread, FALSE };
    if (CloseOwnedThread(&item))
        return TRUE;
    if (g_emergencyThread.handle == NULL)
    {
        g_emergencyThread = item;
        return FALSE;
    }
    if (g_emergencyNextThread.handle == NULL)
    {
        g_emergencyNextThread = item;
        return FALSE;
    }
    return FALSE;
}

static BOOL ReleaseEmergencyThreadOwnership(VOID)
{
    // One failed cursor-close can coexist with a newly returned next handle.
    // Keep two physically independent emergency owner slots until both close.
    BOOL nextReleased = ResumeOwnedThread(&g_emergencyNextThread);
    if (nextReleased)
        nextReleased = CloseOwnedThread(&g_emergencyNextThread);
    BOOL cursorReleased = ResumeOwnedThread(&g_emergencyThread);
    if (cursorReleased)
        cursorReleased = CloseOwnedThread(&g_emergencyThread);
    return nextReleased && cursorReleased;
}

static BOOL ReleaseFrozenThreadOwnership(PFROZEN_THREADS pThreads)
{
    UINT i;
    BOOL released = TRUE;
    if (pThreads->pItems == NULL)
        return TRUE;
    for (i = 0; i < pThreads->size; ++i)
    {
        PFROZEN_THREAD_ITEM pItem = &pThreads->pItems[i];
        if (!ResumeOwnedThread(pItem))
        {
            released = FALSE;
            continue;
        }
        if (!CloseOwnedThread(pItem))
            released = FALSE;
    }
    if (!released)
        return FALSE;
    if (!HeapFree(g_hHeap, 0, pThreads->pItems))
        return FALSE;
    pThreads->pItems = NULL;
    pThreads->size = 0;
    pThreads->capacity = 0;
    return TRUE;
}

static BOOL PreserveFrozenThreadOwnership(PFROZEN_THREADS pThreads)
{
    if (ReleaseFrozenThreadOwnership(pThreads))
        return TRUE;
    if (g_retainedThreads.pItems != NULL)
        return FALSE; /* Freeze drains this before creating a new owner set. */
    g_retainedThreads = *pThreads;
    pThreads->pItems = NULL;
    pThreads->size = 0;
    pThreads->capacity = 0;
    return FALSE;
}

static BOOL RetryRetainedThreadOwnership(VOID)
{
    /* Never resume peers into an instruction stream whose completion failed. */
    if (!RetryPatchCompletion())
        return FALSE;
    if (!ReleaseEmergencyThreadOwnership() || !ReleaseFrozenThreadOwnership(&g_retainedThreads))
        return FALSE;
    if (g_retainedBuffer != NULL)
    {
        if (!FreeBuffer(g_retainedBuffer))
            return FALSE;
        g_retainedBuffer = NULL;
    }
    return TRUE;
}

static BOOL HasRetainedThreadOwnership(VOID)
{
    return g_emergencyThread.handle != NULL || g_emergencyNextThread.handle != NULL || g_retainedThreads.pItems != NULL;
}

typedef enum _THREAD_ENUMERATION_RESULT
{
    THREAD_ENUMERATION_OK = 0,
    THREAD_ENUMERATION_ALLOC_FAILED = 1,
    THREAD_ENUMERATION_API_FAILED = 2,
    THREAD_ENUMERATION_OWNERSHIP_FAILED = 3
} THREAD_ENUMERATION_RESULT;

static THREAD_ENUMERATION_RESULT EnumerateThreads(PFROZEN_THREADS pThreads)
{
    PFN_NT_GET_NEXT_THREAD getNextThread = ResolveNtGetNextThread();
    HANDLE process = GetCurrentProcess();
    HANDLE cursor = NULL;
    DWORD currentThreadId = GetCurrentThreadId();
    if (getNextThread == NULL)
        return THREAD_ENUMERATION_API_FAILED;

    for (;;)
    {
        HANDLE next = NULL;
        NTSTATUS status = getNextThread(
            process, cursor, THREAD_ACCESS, 0, 0, &next);
        if (cursor != NULL && !CloseOrRetainEmergency(cursor))
        {
            // NtGetNextThread has already returned next. The failed cursor
            // close consumes the first emergency owner slot; retain next in
            // the second slot, even if it has not been suspended yet.
            if (NT_SUCCESS(status) && next != NULL)
                g_emergencyNextThread.handle = next;
            cursor = NULL;
            (void)PreserveFrozenThreadOwnership(pThreads);
            return THREAD_ENUMERATION_OWNERSHIP_FAILED;
        }
        cursor = NULL;
        if (!NT_SUCCESS(status))
        {
            if (status == STATUS_NO_MORE_ENTRIES)
                break;
            return PreserveFrozenThreadOwnership(pThreads)
                ? THREAD_ENUMERATION_API_FAILED
                : THREAD_ENUMERATION_OWNERSHIP_FAILED;
        }
        cursor = next;

        if (GetThreadId(next) != currentThreadId)
        {
            HANDLE owned = NULL;
            if (!DuplicateHandle(
                    process, next, process, &owned, 0, FALSE, DUPLICATE_SAME_ACCESS))
#else
            succeeded = TRUE;
            do
#endif
            {
#if defined(MH_SAFE_FREEZE)
                if (cursor != NULL && !CloseOrRetainEmergency(cursor))
                    cursor = NULL;
                return PreserveFrozenThreadOwnership(pThreads)
                    ? THREAD_ENUMERATION_API_FAILED
                    : THREAD_ENUMERATION_OWNERSHIP_FAILED;
            }
            if (!AppendThreadHandle(pThreads, owned))
#else
                if (te.dwSize >= (FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD))
                    && te.th32OwnerProcessID == GetCurrentProcessId()
                    && te.th32ThreadID != GetCurrentThreadId())
                {
                    if (pThreads->pItems == NULL)
                    {
                        pThreads->capacity = INITIAL_THREAD_CAPACITY;
                        pThreads->pItems
                            = (LPDWORD)HeapAlloc(g_hHeap, 0, pThreads->capacity * sizeof(DWORD));
                        if (pThreads->pItems == NULL)
                        {
                            succeeded = FALSE;
                            break;
                        }
                    }
                    else if (pThreads->size >= pThreads->capacity)
                    {
                        LPDWORD p;
                        pThreads->capacity *= 2;
                        p = (LPDWORD)HeapReAlloc(
                            g_hHeap, 0, pThreads->pItems, pThreads->capacity * sizeof(DWORD));
                        if (p == NULL)
                        {
                            succeeded = FALSE;
                            break;
                        }

                        pThreads->pItems = p;
                    }
                    pThreads->pItems[pThreads->size++] = te.th32ThreadID;
                }

                te.dwSize = sizeof(THREADENTRY32);
            } while (Thread32Next(hSnapshot, &te));

            if (succeeded && GetLastError() != ERROR_NO_MORE_FILES)
                succeeded = FALSE;

            if (!succeeded && pThreads->pItems != NULL)
#endif
            {
#if defined(MH_SAFE_FREEZE)
                BOOL cleanupOk = CloseOrRetainEmergency(owned);
                if (cursor != NULL && !CloseOrRetainEmergency(cursor))
                    cleanupOk = FALSE;
                if (!PreserveFrozenThreadOwnership(pThreads))
                    cleanupOk = FALSE;
                return cleanupOk
                    ? THREAD_ENUMERATION_ALLOC_FAILED
                    : THREAD_ENUMERATION_OWNERSHIP_FAILED;
#else
                HeapFree(g_hHeap, 0, pThreads->pItems);
                pThreads->pItems = NULL;
#endif
            }
        }
#if defined(MH_SAFE_FREEZE)
#else
        CloseHandle(hSnapshot);
#endif
    }
#if defined(MH_SAFE_FREEZE)
    if (cursor != NULL && !CloseOrRetainEmergency(cursor))
    {
        (void)PreserveFrozenThreadOwnership(pThreads);
        return THREAD_ENUMERATION_OWNERSHIP_FAILED;
    }
    return THREAD_ENUMERATION_OK;
#else

    return succeeded;
#endif
}

//-------------------------------------------------------------------------
static MH_STATUS Freeze(PFROZEN_THREADS pThreads, UINT pos, UINT action)
{
    MH_STATUS status = MH_OK;
#if defined(MH_SAFE_FREEZE)
#else

#endif
    pThreads->pItems   = NULL;
    pThreads->capacity = 0;
    pThreads->size     = 0;
#if defined(MH_SAFE_FREEZE)

    if (!RetryRetainedThreadOwnership())
        return MH_ERROR_MEMORY_PROTECT;
#else
    if (!EnumerateThreads(pThreads))
#endif
    {
#if defined(MH_SAFE_FREEZE)
        THREAD_ENUMERATION_RESULT enumeration = EnumerateThreads(pThreads);
        if (enumeration != THREAD_ENUMERATION_OK)
#else
        status = MH_ERROR_MEMORY_ALLOC;
    }
    else if (pThreads->pItems != NULL)
    {
        UINT i;
        for (i = 0; i < pThreads->size; ++i)
#endif
        {
#if defined(MH_SAFE_FREEZE)
            if (enumeration == THREAD_ENUMERATION_ALLOC_FAILED)
                return MH_ERROR_MEMORY_ALLOC;
            if (enumeration == THREAD_ENUMERATION_OWNERSHIP_FAILED ||
                HasRetainedThreadOwnership())
                return MH_ERROR_MEMORY_PROTECT;
            // OS/API enumeration failure is not allocation
            // failure. Preserve MinHook's public ABI and report its generic
            // non-allocation failure status rather than lying about memory.
            return MH_UNKNOWN;
#else
            HANDLE hThread = OpenThread(THREAD_ACCESS, FALSE, pThreads->pItems[i]);
            BOOL suspended = FALSE;
            if (hThread != NULL)
            {
                DWORD result = SuspendThread(hThread);
                if (result != 0xFFFFFFFF)
                {
                    suspended = TRUE;
                    ProcessThreadIPs(hThread, pos, action);
                }
                CloseHandle(hThread);
            }

            if (!suspended)
            {
                // Mark thread as not suspended, so it's not resumed later on.
                pThreads->pItems[i] = 0;
            }
#endif
        }
    }
#if defined(MH_SAFE_FREEZE)
#else

    return status;
}

//-------------------------------------------------------------------------
static VOID Unfreeze(PFROZEN_THREADS pThreads)
{
#endif
    if (pThreads->pItems != NULL)
    {
        UINT i;
        for (i = 0; i < pThreads->size; ++i)
        {
#if defined(MH_SAFE_FREEZE)
            PFROZEN_THREAD_ITEM pItem = &pThreads->pItems[i];
            if (pItem->handle == NULL)
                continue;
            if (SuspendThread(pItem->handle) != 0xFFFFFFFF)
#else
            DWORD threadId = pThreads->pItems[i];
            if (threadId != 0)
#endif
            {
#if defined(MH_SAFE_FREEZE)
                PEER_PREPARATION_RESULT peerResult;
                pItem->suspended = TRUE;
                peerResult = action == ACTION_RETIRE ? CheckRetiringThread(pItem->handle) : ProcessThreadIPs(pItem->handle, pos, action);
                if (peerResult == PEER_UNRESOLVED)
                    status = MH_ERROR_MEMORY_PROTECT;
            }
            else if (!ThreadNoLongerLive(pItem->handle))
            {
                status = MH_ERROR_MEMORY_PROTECT;
#else
                HANDLE hThread = OpenThread(THREAD_ACCESS, FALSE, threadId);
                if (hThread != NULL)
                {
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
#endif
            }
        }
#if defined(MH_SAFE_FREEZE)
    }
    if (status != MH_OK)
        (void)PreserveFrozenThreadOwnership(pThreads);
    return status;
}
#endif

#if defined(MH_SAFE_FREEZE)
//-------------------------------------------------------------------------
static MH_STATUS Unfreeze(PFROZEN_THREADS pThreads)
{
    return PreserveFrozenThreadOwnership(pThreads)
        ? MH_OK
        : MH_ERROR_MEMORY_PROTECT;
}

static MH_STATUS FinishFreeze(PFROZEN_THREADS pThreads, MH_STATUS status)
{
    MH_STATUS cleanupStatus;
    if (g_patchCompletion.active)
    {
        /* Freeze entered with no retained set. Transfer without resuming. */
        g_retainedThreads = *pThreads;
        memset(pThreads, 0, sizeof(*pThreads));
        return MH_ERROR_MEMORY_PROTECT;
    }
    cleanupStatus = Unfreeze(pThreads);
    return status == MH_OK ? cleanupStatus : status;
#else
        HeapFree(g_hHeap, 0, pThreads->pItems);
    }
#endif
}

//-------------------------------------------------------------------------
#if defined(MH_SAFE_FREEZE)
static MH_STATUS RetireHookEntry(UINT pos)
{
    FROZEN_THREADS threads;
    MH_STATUS status;
    g_retiringBuffer = g_hooks.pItems[pos].pTrampoline;
    status = Freeze(&threads, ALL_HOOKS_POS, ACTION_RETIRE);
    if (status == MH_OK)
    {
        if (FreeBuffer(g_hooks.pItems[pos].pTrampoline))
            DeleteHookEntry(pos);
        else
            status = MH_ERROR_MEMORY_PROTECT;
        status = FinishFreeze(&threads, status);
    }
    g_retiringBuffer = NULL;
    return status;
}

static MH_STATUS RetireAllBuffers(VOID)
{
    FROZEN_THREADS threads;
    MH_STATUS status;
    g_retiringBuffer = NULL;
    status = Freeze(&threads, ALL_HOOKS_POS, ACTION_RETIRE);
    if (status == MH_OK)
    {
        /* Some blocks may be released before a later release fails. */
        g_shutdownPending = TRUE;
        if (!UninitializeBuffer())
            status = MH_ERROR_MEMORY_PROTECT;
        status = FinishFreeze(&threads, status);
    }
    return status;
}
#endif

#if defined(MH_SAFE_FREEZE)
static MH_STATUS EnableHookLL(UINT pos, BOOL enable)
{
    PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
    SIZE_T patchSize = sizeof(JMP_REL);
    LPBYTE target = (LPBYTE)pHook->pTarget;
    SYSTEM_INFO info;
    ULONG_PTR first, last;
    UINT i;
    if (g_patchCompletion.active)
        return MH_ERROR_MEMORY_PROTECT;
    if (pHook->patchAbove)
    {
        target -= sizeof(JMP_REL);
        patchSize += sizeof(JMP_REL_SHORT);
    }
    GetSystemInfo(&info);
    if (!info.dwPageSize || patchSize > info.dwPageSize || (ULONG_PTR)target > (ULONG_PTR)-1 - patchSize)
        return MH_ERROR_MEMORY_PROTECT;
    first = (ULONG_PTR)target / info.dwPageSize * info.dwPageSize;
    last = ((ULONG_PTR)target + patchSize - 1) / info.dwPageSize * info.dwPageSize;
    memset(&g_patchCompletion, 0, sizeof(g_patchCompletion));
    g_patchCompletion.active = TRUE;
    g_patchCompletion.target = target;
    g_patchCompletion.size = patchSize;
    g_patchCompletion.pageSize = info.dwPageSize;
    g_patchCompletion.count = first == last ? 1 : 2;
    for (i = 0; i < g_patchCompletion.count; ++i)
    {
        PATCH_PAGE *page = &g_patchCompletion.pages[i];
        page->address = (LPVOID)(first + i * info.dwPageSize);
        if (!VirtualProtect(page->address, info.dwPageSize, PAGE_EXECUTE_READWRITE, &page->protection))
        {
            (void)RetryPatchCompletion();
            return MH_ERROR_MEMORY_PROTECT;
        }
        page->pending = TRUE;
    }
    if (enable)
    {
        PJMP_REL jump = (PJMP_REL)target;
        jump->opcode = 0xE9;
        jump->operand = (INT32)((LPBYTE)pHook->pDetour - (target + sizeof(JMP_REL)));
        if (pHook->patchAbove)
        {
            PJMP_REL_SHORT shortJump = (PJMP_REL_SHORT)pHook->pTarget;
            shortJump->opcode = 0xEB;
            shortJump->operand = (INT8)(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
        }
    }
    else
        memcpy(target, pHook->backup, patchSize);
    /* Reflect the bytes already written even if subsequent completion fails. */
    pHook->isEnabled = enable;
    pHook->queueEnable = enable;
    g_patchCompletion.cachePending = TRUE;
    return RetryPatchCompletion() ? MH_OK : MH_ERROR_MEMORY_PROTECT;
}
#else
static MH_STATUS EnableHookLL(UINT pos, BOOL enable)
{
    PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
    DWORD  oldProtect;
    SIZE_T patchSize    = sizeof(JMP_REL);
    LPBYTE pPatchTarget = (LPBYTE)pHook->pTarget;

    if (pHook->patchAbove)
    {
        pPatchTarget -= sizeof(JMP_REL);
        patchSize    += sizeof(JMP_REL_SHORT);
    }

    if (!VirtualProtect(pPatchTarget, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return MH_ERROR_MEMORY_PROTECT;

    if (enable)
    {
        PJMP_REL pJmp = (PJMP_REL)pPatchTarget;
        pJmp->opcode = 0xE9;
        pJmp->operand = (INT32)((LPBYTE)pHook->pDetour - (pPatchTarget + sizeof(JMP_REL)));

        if (pHook->patchAbove)
        {
            PJMP_REL_SHORT pShortJmp = (PJMP_REL_SHORT)pHook->pTarget;
            pShortJmp->opcode = 0xEB;
            pShortJmp->operand = (INT8)(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
        }
    }
    else
    {
        if (pHook->patchAbove)
            memcpy(pPatchTarget, pHook->backup, sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
        else
            memcpy(pPatchTarget, pHook->backup, sizeof(JMP_REL));
    }

    VirtualProtect(pPatchTarget, patchSize, oldProtect, &oldProtect);

    // Just-in-case measure.
    FlushInstructionCache(GetCurrentProcess(), pPatchTarget, patchSize);

    pHook->isEnabled   = enable;
    pHook->queueEnable = enable;

    return MH_OK;
}
#endif

//-------------------------------------------------------------------------
static MH_STATUS EnableAllHooksLL(BOOL enable)
{
    MH_STATUS status = MH_OK;
#if defined(MH_SAFE_FREEZE)
    if (!RetryRetainedThreadOwnership())
        return MH_ERROR_MEMORY_PROTECT;
#endif
    UINT i, first = INVALID_HOOK_POS;

    for (i = 0; i < g_hooks.size; ++i)
    {
        if (g_hooks.pItems[i].isEnabled != enable)
        {
            first = i;
            break;
        }
    }

    if (first != INVALID_HOOK_POS)
    {
        FROZEN_THREADS threads;
        status = Freeze(&threads, ALL_HOOKS_POS, enable ? ACTION_ENABLE : ACTION_DISABLE);
        if (status == MH_OK)
        {
            for (i = first; i < g_hooks.size; ++i)
            {
                if (g_hooks.pItems[i].isEnabled != enable)
                {
                    status = EnableHookLL(i, enable);
                    if (status != MH_OK)
                        break;
                }
            }

#if defined(MH_SAFE_FREEZE)
            status = FinishFreeze(&threads, status);
#else
            Unfreeze(&threads);
#endif
        }
    }

    return status;
}

//-------------------------------------------------------------------------
static VOID EnterSpinLock(VOID)
{
    SIZE_T spinCount = 0;

    // Wait until the flag is FALSE.
    while (InterlockedCompareExchange(&g_isLocked, TRUE, FALSE) != FALSE)
    {
        // No need to generate a memory barrier here, since InterlockedCompareExchange()
        // generates a full memory barrier itself.

        // Prevent the loop from being too busy.
        if (spinCount < 32)
            Sleep(0);
        else
            Sleep(1);

        spinCount++;
    }
}

//-------------------------------------------------------------------------
static VOID LeaveSpinLock(VOID)
{
    // No need to generate a memory barrier here, since InterlockedExchange()
    // generates a full memory barrier itself.

    InterlockedExchange(&g_isLocked, FALSE);
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_Initialize(VOID)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (g_hHeap == NULL)
    {
        g_hHeap = HeapCreate(0, 0, 0);
        if (g_hHeap != NULL)
        {
            // Initialize the internal function buffer.
            InitializeBuffer();
        }
        else
        {
            status = MH_ERROR_MEMORY_ALLOC;
        }
    }
    else
    {
        status = MH_ERROR_ALREADY_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
#if defined(MH_SAFE_FREEZE)
MH_STATUS WINAPI MH_Uninitialize(VOID)
{
    MH_STATUS status = MH_ERROR_NOT_INITIALIZED;
    EnterSpinLock();
    if (g_hHeap != NULL)
    {
        status = RetryRetainedThreadOwnership() ? MH_OK : MH_ERROR_MEMORY_PROTECT;
        if (status == MH_OK && !g_shutdownPending)
            status = EnableAllHooksLL(FALSE);
        if (status == MH_OK)
            status = RetireAllBuffers();
        /* Frozen arrays belong to this heap: finish/retry their cleanup before
         * destroying it. HeapDestroy also owns the hook-entry allocation. */
        if (status == MH_OK)
        {
            if (!HeapDestroy(g_hHeap))
                status = MH_ERROR_MEMORY_PROTECT;
            else
            {
                g_hHeap = NULL;
                g_hooks.pItems = NULL;
                g_hooks.size = g_hooks.capacity = 0;
                g_shutdownPending = FALSE;
            }
        }
    }
    LeaveSpinLock();
    return status;
}
#else
MH_STATUS WINAPI MH_Uninitialize(VOID)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        status = EnableAllHooksLL(FALSE);
        if (status == MH_OK)
        {
            // Free the internal function buffer.

            // HeapFree is actually not required, but some tools detect a false
            // memory leak without HeapFree.

            UninitializeBuffer();

            HeapFree(g_hHeap, 0, g_hooks.pItems);
            HeapDestroy(g_hHeap);

            g_hHeap = NULL;

            g_hooks.pItems   = NULL;
            g_hooks.capacity = 0;
            g_hooks.size     = 0;
        }
    }
    else
    {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}
#endif

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

#if defined(MH_SAFE_FREEZE)
    if (g_hHeap != NULL && (g_shutdownPending || !RetryRetainedThreadOwnership()))
    {
        LeaveSpinLock();
        return MH_ERROR_MEMORY_PROTECT;
    }

#endif
    if (g_hHeap != NULL)
    {
        if (IsExecutableAddress(pTarget) && IsExecutableAddress(pDetour))
        {
            UINT pos = FindHookEntry(pTarget);
            if (pos == INVALID_HOOK_POS)
            {
                LPVOID pBuffer = AllocateBuffer(pTarget);
                if (pBuffer != NULL)
                {
                    TRAMPOLINE ct;

                    ct.pTarget     = pTarget;
                    ct.pDetour     = pDetour;
                    ct.pTrampoline = pBuffer;
                    if (CreateTrampolineFunction(&ct))
                    {
                        #if defined(MH_SAFE_FREEZE)
                        PHOOK_ENTRY pHook = NULL;
                        if (FlushInstructionCache(GetCurrentProcess(), pBuffer, MEMORY_SLOT_SIZE))
                            pHook = AddHookEntry();
                        else
                            status = MH_ERROR_MEMORY_PROTECT;
#else
                        PHOOK_ENTRY pHook = AddHookEntry();
#endif
                        if (pHook != NULL)
                        {
                            pHook->pTarget     = ct.pTarget;
#if defined(_M_X64) || defined(__x86_64__)
                            pHook->pDetour     = ct.pRelay;
#else
                            pHook->pDetour     = ct.pDetour;
#endif
                            pHook->pTrampoline = ct.pTrampoline;
                            pHook->patchAbove  = ct.patchAbove;
                            pHook->isEnabled   = FALSE;
                            pHook->queueEnable = FALSE;
                            pHook->nIP         = ct.nIP;
                            memcpy(pHook->oldIPs, ct.oldIPs, ARRAYSIZE(ct.oldIPs));
                            memcpy(pHook->newIPs, ct.newIPs, ARRAYSIZE(ct.newIPs));

                            // Back up the target function.

                            if (ct.patchAbove)
                            {
                                memcpy(
                                    pHook->backup,
                                    (LPBYTE)pTarget - sizeof(JMP_REL),
                                    sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
                            }
                            else
                            {
                                memcpy(pHook->backup, pTarget, sizeof(JMP_REL));
                            }

                            if (ppOriginal != NULL)
                                *ppOriginal = pHook->pTrampoline;
                        }
                        else
                        {
                            #if defined(MH_SAFE_FREEZE)
                            if (status == MH_OK)
#endif
                            status = MH_ERROR_MEMORY_ALLOC;
                        }
                    }
                    else
                    {
                        status = MH_ERROR_UNSUPPORTED_FUNCTION;
                    }

                    if (status != MH_OK)
                    {
                        #if defined(MH_SAFE_FREEZE)
if (!FreeBuffer(pBuffer))
                        {
                            g_retainedBuffer = pBuffer;
                            status = MH_ERROR_MEMORY_PROTECT;
                        }
#else
FreeBuffer(pBuffer);
#endif
                    }
                }
                else
                {
                    status = MH_ERROR_MEMORY_ALLOC;
                }
            }
            else
            {
                status = MH_ERROR_ALREADY_CREATED;
            }
        }
        else
        {
            status = MH_ERROR_NOT_EXECUTABLE;
        }
    }
    else
    {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_RemoveHook(LPVOID pTarget)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

#if defined(MH_SAFE_FREEZE)
    if (g_hHeap != NULL && (g_shutdownPending || !RetryRetainedThreadOwnership()))
    {
        LeaveSpinLock();
        return MH_ERROR_MEMORY_PROTECT;
    }

#endif
    if (g_hHeap != NULL)
    {
        UINT pos = FindHookEntry(pTarget);
        if (pos != INVALID_HOOK_POS)
        {
            if (g_hooks.pItems[pos].isEnabled)
            {
                FROZEN_THREADS threads;
                status = Freeze(&threads, pos, ACTION_DISABLE);
                if (status == MH_OK)
                {
                    status = EnableHookLL(pos, FALSE);

#if defined(MH_SAFE_FREEZE)
                    status = FinishFreeze(&threads, status);
#else
                    Unfreeze(&threads);
#endif
                }
            }

            if (status == MH_OK)
            {
                #if defined(MH_SAFE_FREEZE)
status = RetireHookEntry(pos);
#else
FreeBuffer(g_hooks.pItems[pos].pTrampoline);
                DeleteHookEntry(pos);
#endif
            }
        }
        else
        {
            status = MH_ERROR_NOT_CREATED;
        }
    }
    else
    {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
static MH_STATUS EnableHook(LPVOID pTarget, BOOL enable)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

#if defined(MH_SAFE_FREEZE)
    if (g_hHeap != NULL && (g_shutdownPending || !RetryRetainedThreadOwnership()))
    {
        LeaveSpinLock();
        return MH_ERROR_MEMORY_PROTECT;
    }

#endif
    if (g_hHeap != NULL)
    {
        if (pTarget == MH_ALL_HOOKS)
        {
            status = EnableAllHooksLL(enable);
        }
        else
        {
            UINT pos = FindHookEntry(pTarget);
            if (pos != INVALID_HOOK_POS)
            {
                if (g_hooks.pItems[pos].isEnabled != enable)
                {
                    FROZEN_THREADS threads;
#if defined(MH_SAFE_FREEZE)
                    status = Freeze(&threads, pos, enable ? ACTION_ENABLE : ACTION_DISABLE);
#else
                    status = Freeze(&threads, pos, ACTION_ENABLE);
#endif
                    if (status == MH_OK)
                    {
                        status = EnableHookLL(pos, enable);

#if defined(MH_SAFE_FREEZE)
                        status = FinishFreeze(&threads, status);
#else
                        Unfreeze(&threads);
#endif
                    }
                }
                else
                {
                    status = enable ? MH_ERROR_ENABLED : MH_ERROR_DISABLED;
                }
            }
            else
            {
                status = MH_ERROR_NOT_CREATED;
            }
        }
    }
    else
    {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_EnableHook(LPVOID pTarget)
{
    return EnableHook(pTarget, TRUE);
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_DisableHook(LPVOID pTarget)
{
    return EnableHook(pTarget, FALSE);
}

//-------------------------------------------------------------------------
static MH_STATUS QueueHook(LPVOID pTarget, BOOL queueEnable)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();
#if defined(MH_SAFE_FREEZE)

    if (g_hHeap != NULL && (g_shutdownPending || !RetryRetainedThreadOwnership()))
    {
        LeaveSpinLock();
        return MH_ERROR_MEMORY_PROTECT;
    }
#endif

    if (g_hHeap != NULL)
    {
        if (pTarget == MH_ALL_HOOKS)
        {
            UINT i;
            for (i = 0; i < g_hooks.size; ++i)
                g_hooks.pItems[i].queueEnable = queueEnable;
        }
        else
        {
            UINT pos = FindHookEntry(pTarget);
            if (pos != INVALID_HOOK_POS)
            {
                g_hooks.pItems[pos].queueEnable = queueEnable;
            }
            else
            {
                status = MH_ERROR_NOT_CREATED;
            }
        }
    }
    else
    {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_QueueEnableHook(LPVOID pTarget)
{
    return QueueHook(pTarget, TRUE);
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_QueueDisableHook(LPVOID pTarget)
{
    return QueueHook(pTarget, FALSE);
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_ApplyQueued(VOID)
{
    MH_STATUS status = MH_OK;
    UINT i, first = INVALID_HOOK_POS;

    EnterSpinLock();

#if defined(MH_SAFE_FREEZE)
    if (g_hHeap != NULL && (g_shutdownPending || !RetryRetainedThreadOwnership()))
    {
        LeaveSpinLock();
        return MH_ERROR_MEMORY_PROTECT;
    }

#endif
    if (g_hHeap != NULL)
    {
        for (i = 0; i < g_hooks.size; ++i)
        {
            if (g_hooks.pItems[i].isEnabled != g_hooks.pItems[i].queueEnable)
            {
                first = i;
                break;
            }
        }

        if (first != INVALID_HOOK_POS)
        {
            FROZEN_THREADS threads;
            status = Freeze(&threads, ALL_HOOKS_POS, ACTION_APPLY_QUEUED);
            if (status == MH_OK)
            {
                for (i = first; i < g_hooks.size; ++i)
                {
                    PHOOK_ENTRY pHook = &g_hooks.pItems[i];
                    if (pHook->isEnabled != pHook->queueEnable)
                    {
                        status = EnableHookLL(i, pHook->queueEnable);
                        if (status != MH_OK)
                            break;
                    }
                }

#if defined(MH_SAFE_FREEZE)
                status = FinishFreeze(&threads, status);
#else
                Unfreeze(&threads);
#endif
            }
        }
    }
    else
    {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_CreateHookApiEx(
    LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour,
    LPVOID *ppOriginal, LPVOID *ppTarget)
{
    HMODULE hModule;
    LPVOID  pTarget;

    hModule = GetModuleHandleW(pszModule);
    if (hModule == NULL)
        return MH_ERROR_MODULE_NOT_FOUND;

    pTarget = (LPVOID)GetProcAddress(hModule, pszProcName);
    if (pTarget == NULL)
        return MH_ERROR_FUNCTION_NOT_FOUND;

    if (ppTarget != NULL)
        *ppTarget = pTarget;

    return MH_CreateHook(pTarget, pDetour, ppOriginal);
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_CreateHookApi(
    LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal)
{
    return MH_CreateHookApiEx(pszModule, pszProcName, pDetour, ppOriginal, NULL);
}

//-------------------------------------------------------------------------
const char *WINAPI MH_StatusToString(MH_STATUS status)
{
#define MH_ST2STR(x)    \
    case x:             \
        return #x;

    switch (status) {
        MH_ST2STR(MH_UNKNOWN)
        MH_ST2STR(MH_OK)
        MH_ST2STR(MH_ERROR_ALREADY_INITIALIZED)
        MH_ST2STR(MH_ERROR_NOT_INITIALIZED)
        MH_ST2STR(MH_ERROR_ALREADY_CREATED)
        MH_ST2STR(MH_ERROR_NOT_CREATED)
        MH_ST2STR(MH_ERROR_ENABLED)
        MH_ST2STR(MH_ERROR_DISABLED)
        MH_ST2STR(MH_ERROR_NOT_EXECUTABLE)
        MH_ST2STR(MH_ERROR_UNSUPPORTED_FUNCTION)
        MH_ST2STR(MH_ERROR_MEMORY_ALLOC)
        MH_ST2STR(MH_ERROR_MEMORY_PROTECT)
        MH_ST2STR(MH_ERROR_MODULE_NOT_FOUND)
        MH_ST2STR(MH_ERROR_FUNCTION_NOT_FOUND)
    }

#undef MH_ST2STR

    return "(unknown)";
}
