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

#define _WIN32_WINNT 0x0400
#include <Windows.h>
#include <TlHelp32.h>
#include <intrin.h>

#include "MinHook.h"
#include "buffer.h"
#include "trampoline.h"

// Initial capacity of the HOOK_ENTRY buffer.
#define MH_INITIAL_CAPACITY 64

// Initial capacity of the thread IDs buffer.
#define MH_INITIAL_THREAD_CAPACITY 256

// Max length of a trampoline function.
#define MH_TRAMPOLINE_SIZE 32

#if defined _M_X64

// Offset of the relay function in a 64-byte buffer.
#define MH_RELAY_OFFSET   32

// Offset of the jump table function in a 64-byte buffer.
#define MH_TABLE_OFFSET   40

// Max length of the jump table.
#define MH_TABLE_SIZE 3

#endif

// Special hook position values.
#define INVALID_HOOK_POS UINT_MAX
#define ALL_HOOKS_POS    UINT_MAX

// Freeze() action argument defines.
#define ACTION_DISABLE      0
#define ACTION_ENABLE       1
#define ACTION_APPLY_QUEUED 2

// Thread access rights for suspending/resuming threads.
#define MH_THREAD_ACCESS \
    (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT \
    | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT)

// Hook information.
typedef struct _HOOK_ENTRY
{
    LPVOID pTarget;             // Address of the target function.
    LPVOID pDetour;             // Address of the detour or relay function.
    LPVOID pTrampoline;         // Address of the trampoline function.
    UINT8  backup[8];           // Original prologue of the target function.

    BOOL   patchAbove  : 1;     // Uses the hot patch area.
    BOOL   isEnabled   : 1;     // Enabled.
    BOOL   queueEnable : 1;     // Queued for enabling/disabling when != isEnabled.

    UINT   nIP : 3;             // Count of the instruction boundaries.
    UINT8  oldIPs[8];           // Instruction boundaries of the target function.
    UINT8  newIPs[8];           // Instruction boundaries of the trampoline function.
} HOOK_ENTRY, *PHOOK_ENTRY;

// Suspended threads for Freeze()/Unfreeze().
typedef struct _FROZEN_THREADS
{
    LPDWORD pItems;         // Data heap
    UINT    capacity;       // Size of allocated data heap, items
    UINT    size;           // Actual number of data items
} FROZEN_THREADS, *PFROZEN_THREADS;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// CriticalSection.
CRITICAL_SECTION g_cs;

// Private heap handle. If not NULL, this library is initialized.
HANDLE g_hHeap = NULL;

// Hook entries.
struct
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
static PHOOK_ENTRY NewHookEntry()
{
    if (g_hooks.pItems == NULL)
    {
        g_hooks.capacity = MH_INITIAL_CAPACITY;
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
static void DelHookEntry(UINT pos)
{
    if (pos < g_hooks.size - 1)
    {
        g_hooks.pItems[pos] = g_hooks.pItems[g_hooks.size - 1];
    }
    g_hooks.size--;

    if(g_hooks.capacity / 2 >= MH_INITIAL_CAPACITY && g_hooks.capacity / 2 >= g_hooks.size)
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
static void ProcessThreadIPs(HANDLE hThread, UINT pos, UINT action)
{
    // If the thread suspended in the overwritten area,
    // move IP to the proper address.

    CONTEXT c;
#if defined _M_X64
    DWORD64 *pIP = &c.Rip;
#elif defined _M_IX86
    DWORD   *pIP = &c.Eip;
#endif
    UINT count;

    __stosb((PBYTE)&c, 0, sizeof(CONTEXT));
    c.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &c))
        return;

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

        case ACTION_ENABLE:
            enable = TRUE;
            break;

        case ACTION_APPLY_QUEUED:
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
            SetThreadContext(hThread, &c);
        }
    }
}

//-------------------------------------------------------------------------
static VOID EnumerateThreads(PFROZEN_THREADS pThreads)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        __stosb((PBYTE)&te, 0, sizeof(THREADENTRY32));
        te.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hSnapshot, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == GetCurrentProcessId()
                    && te.th32ThreadID != GetCurrentThreadId())
                {
                    if (pThreads->pItems == NULL)
                    {
                        pThreads->capacity = MH_INITIAL_THREAD_CAPACITY;
                        pThreads->pItems
                            = (LPDWORD)HeapAlloc(g_hHeap, 0, pThreads->capacity * sizeof(DWORD));
                        if (pThreads->pItems == NULL)
                            break;
                    }
                    else if (pThreads->size >= pThreads->capacity)
                    {
                        LPDWORD p = (LPDWORD)HeapReAlloc(
                            g_hHeap, 0, pThreads->pItems, (pThreads->capacity * 2) * sizeof(DWORD));
                        if (p == NULL)
                            break;

                        pThreads->capacity *= 2;
                        pThreads->pItems = p;
                    }
                    pThreads->pItems[pThreads->size++] = te.th32ThreadID;
                }
            } while (Thread32Next(hSnapshot, &te));
        }
    }
    CloseHandle(hSnapshot);
}

//-------------------------------------------------------------------------
static VOID Freeze(PFROZEN_THREADS pThreads, UINT pos, UINT action)
{
    pThreads->pItems   = NULL;
    pThreads->capacity = 0;
    pThreads->size     = 0;
    EnumerateThreads(pThreads);

    if (pThreads->pItems != NULL)
    {
        UINT i;
        for (i = 0; i < pThreads->size; ++i)
        {
            HANDLE hThread = OpenThread(MH_THREAD_ACCESS, FALSE, pThreads->pItems[i]);
            if (hThread != NULL)
            {
                SuspendThread(hThread);
                ProcessThreadIPs(hThread, pos, action);
                CloseHandle(hThread);
            }
        }
    }
}

//-------------------------------------------------------------------------
static VOID Unfreeze(PFROZEN_THREADS pThreads)
{
    if (pThreads->pItems != NULL)
    {
        UINT i;
        for (i = 0; i < pThreads->size; ++i)
        {
            HANDLE hThread = OpenThread(MH_THREAD_ACCESS, FALSE, pThreads->pItems[i]);
            if (hThread != NULL)
            {
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }

        HeapFree(g_hHeap, 0, pThreads->pItems);
        pThreads->pItems   = NULL;
        pThreads->capacity = 0;
        pThreads->size     = 0;
    }
}

//-------------------------------------------------------------------------
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
        ((PJMP_REL)pPatchTarget)->opcode = 0xE9;
        ((PJMP_REL)pPatchTarget)->operand
            = (UINT32)((LPBYTE)pHook->pDetour - (pPatchTarget + sizeof(JMP_REL)));

        if (pHook->patchAbove)
        {
            ((PJMP_REL_SHORT)pHook->pTarget)->opcode = 0xEB;
            ((PJMP_REL_SHORT)pHook->pTarget)->operand
                = (UINT8)(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
        }
    }
    else
    {
        memcpy(pPatchTarget, pHook->backup, patchSize);
    }

    VirtualProtect(pPatchTarget, patchSize, oldProtect, &oldProtect);

    pHook->isEnabled   = enable;
    pHook->queueEnable = enable;

    return MH_OK;
}

//-------------------------------------------------------------------------
static MH_STATUS EnableAllHooksLL(BOOL enable)
{
    UINT i;
    for (i = 0; i < g_hooks.size; ++i)
    {
        if (g_hooks.pItems[i].isEnabled != enable)
        {
            FROZEN_THREADS threads;
            Freeze(&threads, ALL_HOOKS_POS, enable ? ACTION_ENABLE : ACTION_DISABLE);
            __try
            {
                for (; i < g_hooks.size; ++i)
                {
                    if (g_hooks.pItems[i].isEnabled != enable)
                    {
                        MH_STATUS status = EnableHookLL(i, enable);
                        if (status != MH_OK)
                            return status;
                    }
                }
            }
            __finally
            {
                Unfreeze(&threads);
            }
        }
    }

    return MH_OK;
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_Initialize(VOID)
{
    if(g_hHeap != NULL)
        return MH_ERROR_ALREADY_INITIALIZED;

    __try
    {
        InitializeCriticalSection(&g_cs);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return MH_ERROR_MEMORY_ALLOC;
    }

    g_hHeap = HeapCreate(0, 0, 0);
    if (g_hHeap == NULL)
        return MH_ERROR_MEMORY_ALLOC;

    // Initialize the internal function buffer.
    InitializeBuffer();

    return MH_OK;
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_Uninitialize(VOID)
{
    MH_STATUS status;

    if (g_hHeap == NULL)
        return MH_ERROR_NOT_INITIALIZED;

    status = EnableAllHooksLL(FALSE);
    if (status == MH_OK)
    {
        // Free the internal function buffer.
        UninitializeBuffer();
        HeapDestroy(g_hHeap);
    }

    g_hHeap = NULL;

    g_hooks.pItems   = NULL;
    g_hooks.capacity = 0;
    g_hooks.size     = 0;

    DeleteCriticalSection(&g_cs);

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal)
{
    __try
    {
        EnterCriticalSection(&g_cs);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return MH_ERROR_NOT_INITIALIZED;
    }

    __try
    {
        __try
        {
            UINT        pos;
            LPVOID      pBuffer;
            TRAMPOLINE  ct;
            PHOOK_ENTRY pHook;

            if (g_hHeap == NULL)
                return MH_ERROR_NOT_INITIALIZED;

            if (!IsExecutableAddress(pTarget) || !IsExecutableAddress(pDetour))
                return MH_ERROR_NOT_EXECUTABLE;

            pos = FindHookEntry(pTarget);
            if (pos != INVALID_HOOK_POS)
                return MH_ERROR_ALREADY_CREATED;

            pBuffer = AllocateBuffer(pTarget);
            if (pBuffer == NULL)
                return MH_ERROR_MEMORY_ALLOC;

            __stosb((PBYTE)&ct, 0, sizeof(ct));
            ct.pTrampoline    = pBuffer;
            ct.pTarget        = pTarget;
            ct.pDetour        = pDetour;
            ct.trampolineSize = MH_TRAMPOLINE_SIZE;
#if defined _M_X64
            ct.pRelay = (char *)ct.pTrampoline + MH_RELAY_OFFSET;
            ct.pTable = (ULONG_PTR*)((char *)ct.pTrampoline + MH_TABLE_OFFSET);
            ct.tableSize = MH_TABLE_SIZE;
#endif
            if (!CreateTrampolineFunction(&ct))
            {
                FreeBuffer(pBuffer);
                return MH_ERROR_UNSUPPORTED_FUNCTION;
            }

            pHook = NewHookEntry();
            if (pHook == NULL)
            {
                FreeBuffer(pBuffer);
                return MH_ERROR_MEMORY_ALLOC;
            }

            pHook->pTarget     = pTarget;
#if defined _M_X64
            pHook->pDetour     = ct.pRelay;
#elif defined _M_IX86
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
                    (char *)pTarget - sizeof(JMP_REL),
                    sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
            }
            else
            {
                memcpy(pHook->backup, pTarget, sizeof(JMP_REL));
            }

            if (ppOriginal != NULL)
                *ppOriginal = pHook->pTrampoline;

            return MH_OK;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return MH_UNKNOWN;
        }
    }
    __finally
    {
        LeaveCriticalSection(&g_cs);
    }
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_RemoveHook(LPVOID pTarget)
{
    __try
    {
        EnterCriticalSection(&g_cs);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return MH_ERROR_NOT_INITIALIZED;
    }

    __try
    {
        UINT pos;

        if (g_hHeap == NULL)
            return MH_ERROR_NOT_INITIALIZED;

        pos = FindHookEntry(pTarget);
        if (pos == INVALID_HOOK_POS)
            return MH_ERROR_NOT_CREATED;

        if (g_hooks.pItems[pos].isEnabled)
        {
            FROZEN_THREADS threads;
            Freeze(&threads, pos, ACTION_DISABLE);
            __try
            {
                MH_STATUS status = EnableHookLL(pos, FALSE);
                if (status != MH_OK)
                    return status;
            }
            __finally
            {
                Unfreeze(&threads);
            }
        }

        FreeBuffer(g_hooks.pItems[pos].pTrampoline);
        DelHookEntry(pos);

        return MH_OK;
    }
    __finally
    {
        LeaveCriticalSection(&g_cs);
    }
}

//-------------------------------------------------------------------------
static MH_STATUS EnableHook(LPVOID pTarget, BOOL enable)
{
    __try
    {
        EnterCriticalSection(&g_cs);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return MH_ERROR_NOT_INITIALIZED;
    }

    __try
    {
        if (g_hHeap == NULL)
            return MH_ERROR_NOT_INITIALIZED;

        if (pTarget == MH_ALL_HOOKS)
        {
            return EnableAllHooksLL(enable);
        }
        else
        {
            UINT pos = FindHookEntry(pTarget);
            if (pos == INVALID_HOOK_POS)
                return MH_ERROR_NOT_CREATED;

            if (g_hooks.pItems[pos].isEnabled == enable)
                return enable ? MH_ERROR_ENABLED : MH_ERROR_DISABLED;

            FROZEN_THREADS threads;
            Freeze(&threads, pos, ACTION_ENABLE);
            __try
            {
                return EnableHookLL(pos, enable);
            }
            __finally
            {
                Unfreeze(&threads);
            }
        }
    }
    __finally
    {
        LeaveCriticalSection(&g_cs);
    }
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
    __try
    {
        EnterCriticalSection(&g_cs);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return MH_ERROR_NOT_INITIALIZED;
    }

    __try
    {
        if (g_hHeap == NULL)
            return MH_ERROR_NOT_INITIALIZED;

        if (pTarget == MH_ALL_HOOKS)
        {
            UINT i;
            for (i = 0; i < g_hooks.size; ++i)
                g_hooks.pItems[i].queueEnable = queueEnable;
        }
        else
        {
            UINT pos = FindHookEntry(pTarget);
            if (pos == INVALID_HOOK_POS)
                return MH_ERROR_NOT_CREATED;

            g_hooks.pItems[pos].queueEnable = queueEnable;
        }

        return MH_OK;
    }
    __finally
    {
        LeaveCriticalSection(&g_cs);
    }
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
    __try
    {
        EnterCriticalSection(&g_cs);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return MH_ERROR_NOT_INITIALIZED;
    }

    __try
    {
        UINT i;

        if (g_hHeap == NULL)
            return MH_ERROR_NOT_INITIALIZED;

        for (i = 0; i < g_hooks.size; ++i)
        {
            if (g_hooks.pItems[i].isEnabled != g_hooks.pItems[i].queueEnable)
            {
                FROZEN_THREADS threads;
                Freeze(&threads, ALL_HOOKS_POS, ACTION_APPLY_QUEUED);
                __try
                {
                    for (; i < g_hooks.size; ++i)
                    {
                        PHOOK_ENTRY pHook = &g_hooks.pItems[i];
                        if (pHook->isEnabled != pHook->queueEnable)
                        {
                            MH_STATUS status = EnableHookLL(i, pHook->queueEnable);
                            if (status != MH_OK)
                                return status;
                        }
                    }
                }
                __finally
                {
                    Unfreeze(&threads);
                }
            }
        }

        return MH_OK;
    }
    __finally
    {
        LeaveCriticalSection(&g_cs);
    }
}
