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

// Thread access rights for suspending/resuming threads.
#define MH_THREAD_ACCESS \
    (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT \
    | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT)

// Import RtlMoveMemory from kernel32.dll.
#ifdef RtlMoveMemory
#undef RtlMoveMemory
#endif
EXTERN_C NTSYSAPI VOID NTAPI
RtlMoveMemory(LPVOID UNALIGNED Dst, LPCVOID UNALIGNED Src, SIZE_T Length);

// Hook information.
typedef struct _HOOK_ENTRY
{
    void  *pTarget;             // Address of the target function.
    void  *pDetour;             // Address of the detour or relay function.
    void  *pTrampoline;         // Address of the trampoline function.
    UINT8  backup[8];           // Original prologue of the target function.

    BOOL   patchAbove  : 1;     // Uses the hot patch area.
    BOOL   isEnabled   : 1;     // Enabled.
    BOOL   queueEnable : 1;     // Queued for enabling/disabling when != isEnabled.

    int    nIP : 3;             // Count of the instruction boundaries.
    UINT8  oldIPs[8];           // Instruction boundaries of the target function.
    UINT8  newIPs[8];           // Instruction boundaries of the trampoline function.
} HOOK_ENTRY, *PHOOK_ENTRY;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// Spin lock flag for EnterSpinLock()/LeaveSpinLock().
volatile LONG g_isLocked = FALSE;

// Private heap handle. If not NULL, this library is initialized.
HANDLE g_hHeap = NULL;

// Hook entries.
struct
{
    PHOOK_ENTRY items;      // Data heap
    int         capacity;   // Size of allocated data heap, items
    int         size;       // Actual number of data items
} g_Hooks;

// Suspended threads for Freeze()/Unfreeze().
struct
{
    LPDWORD items;          // Data heap
    int     capacity;       // Size of allocated data heap, items
    int     size;           // Actual number of data items
} g_threads;

//-------------------------------------------------------------------------
// returns: >= 0 if the element in contained, < 0 (-insertPos-1) if not
static int FindHookEntry(void *pTarget)
{
    int left, right;

    if (g_Hooks.size == 0)
        return -1;

    // Binary search through the list
    left  = 0;
    right = g_Hooks.size - 1;

    do
    {
        const int center = (left + right) / 2;

        if ((ULONG_PTR)g_Hooks.items[center].pTarget == (ULONG_PTR)pTarget)
            return center;              // found

        if ((ULONG_PTR)g_Hooks.items[center].pTarget < (ULONG_PTR)pTarget)
            left = center + 1;          // continue right
        else
            right = center - 1;         // continue left

    } while (left <= right);

    return (0 - left - 1);  // not found, return insert position
}

//-------------------------------------------------------------------------
static PHOOK_ENTRY NewHookEntry(int pos)
{
    if (g_Hooks.items == NULL)
    {
        g_Hooks.capacity = MH_INITIAL_CAPACITY;
        g_Hooks.items = (HOOK_ENTRY *)HeapAlloc(
            g_hHeap, 0, g_Hooks.capacity * sizeof(HOOK_ENTRY));
        if (g_Hooks.items == NULL)
            return NULL;
    }
    else if (g_Hooks.size >= g_Hooks.capacity)
    {
        void *p;
        g_Hooks.capacity *= 2;
        p = HeapReAlloc(
            g_hHeap, 0, g_Hooks.items, g_Hooks.capacity * sizeof(HOOK_ENTRY));
        if (p == NULL)
            return NULL;

        g_Hooks.items = (HOOK_ENTRY *)p;
    }

    // Add the element at the correct position
    if (pos < g_Hooks.size)
    {
        RtlMoveMemory(
            &g_Hooks.items[pos + 1],
            &g_Hooks.items[pos],
            (g_Hooks.size - pos) * sizeof(HOOK_ENTRY));
    }

    g_Hooks.size++;

    return &g_Hooks.items[pos];
}

//-------------------------------------------------------------------------
static void DelHookEntry(int pos)
{
    if (pos >= 0 && pos < g_Hooks.size)
    {
        g_Hooks.size--;
        if (pos < g_Hooks.size)
        {
            RtlMoveMemory(
                &g_Hooks.items[pos],
                &g_Hooks.items[pos + 1],
                (g_Hooks.size - pos) * sizeof(HOOK_ENTRY));
        }
    }
}

//-------------------------------------------------------------------------
static DWORD_PTR FindOldIP(PHOOK_ENTRY pHook, DWORD_PTR ip)
{
    int i;

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
    int i;
    for (i = 0; i < pHook->nIP; ++i)
    {
        if (ip == ((DWORD_PTR)pHook->pTarget + pHook->oldIPs[i]))
            return (DWORD_PTR)pHook->pTrampoline + pHook->newIPs[i];
    }

    return 0;
}

//-------------------------------------------------------------------------
static void ProcessThreadIPs(HANDLE hThread, int pos, int action)
{
    // If the thread suspended in the overwritten area,
    // move IP to the proper address.

    CONTEXT c = { 0 };
#if defined _M_X64
    DWORD_PTR *pIP = &c.Rip;
#elif defined _M_IX86
    DWORD_PTR *pIP = &c.Eip;
#endif
    int count;

    c.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &c))
        return;

    if (pos < 0)
    {
        pos = 0;
        count = g_Hooks.size;
    }
    else
    {
        count = pos + 1;
    }

    for (; pos < count; ++pos)
    {
        PHOOK_ENTRY pHook = &g_Hooks.items[pos];
        BOOL      enable;
        DWORD_PTR ip;

        switch (action)
        {
        case 0:
            enable = FALSE;
            break;

        case 1:
            enable = TRUE;
            break;

        default:
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
static void EnumerateThreads(void)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te = { sizeof(THREADENTRY32) };

        if (Thread32First(hSnapshot, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == GetCurrentProcessId()
                    && te.th32ThreadID != GetCurrentThreadId())
                {
                    if (g_threads.items == NULL)
                    {
                        g_threads.capacity = MH_INITIAL_THREAD_CAPACITY;
                        g_threads.items
                            = (LPDWORD)HeapAlloc(g_hHeap, 0, g_threads.capacity * sizeof(DWORD));
                        if (g_threads.items == NULL)
                            break;
                    }
                    else if (g_threads.size >= g_threads.capacity)
                    {
                        LPDWORD p;
                        g_threads.capacity *= 2;
                        p = (LPDWORD)HeapReAlloc(
                            g_hHeap, 0, g_threads.items, g_threads.capacity * sizeof(DWORD));
                        if (p != NULL)
                            g_threads.items = p;
                        else
                            break;
                    }
                    g_threads.items[g_threads.size++] = te.th32ThreadID;
                }
            } while (Thread32Next(hSnapshot, &te));
        }
    }
    CloseHandle(hSnapshot);
}

//-------------------------------------------------------------------------
static void Freeze(int pos, int action)
{
    EnumerateThreads();

    if (g_threads.items != NULL)
    {
        int i;
        for (i = 0; i < g_threads.size; ++i)
        {
            HANDLE hThread = OpenThread(MH_THREAD_ACCESS, FALSE, g_threads.items[i]);
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
static void Unfreeze(void)
{
    if (g_threads.items != NULL)
    {
        int i;
        for (i = 0; i < g_threads.size; ++i)
        {
            HANDLE hThread = OpenThread(MH_THREAD_ACCESS, FALSE, g_threads.items[i]);
            if (hThread != NULL)
            {
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }

        HeapFree(g_hHeap, 0, g_threads.items);
        g_threads.items    = NULL;
        g_threads.capacity = 0;
        g_threads.size     = 0;
    }
}

//-------------------------------------------------------------------------
static MH_STATUS EnableHookLL(int pos)
{
    PHOOK_ENTRY pHook = &g_Hooks.items[pos];
    DWORD   oldProtect;
    size_t  patchSize = sizeof(JMP_REL);
    char   *pPatchTarget = (char *)pHook->pTarget;

    if (pHook->patchAbove)
    {
        pPatchTarget -= sizeof(JMP_REL);
        patchSize    += sizeof(JMP_REL_SHORT);
    }

    if (!VirtualProtect(pPatchTarget, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return MH_ERROR_MEMORY_PROTECT;

    ((JMP_REL *)pPatchTarget)->opcode  = 0xE9;
    ((JMP_REL *)pPatchTarget)->operand
        = (UINT32)((char *)pHook->pDetour - (pPatchTarget + sizeof(JMP_REL)));

    if (pHook->patchAbove)
    {
        ((JMP_REL_SHORT *)pHook->pTarget)->opcode  = 0xEB;
        ((JMP_REL_SHORT *)pHook->pTarget)->operand
            = (UINT8)(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
    }

    VirtualProtect(pPatchTarget, patchSize, oldProtect, &oldProtect);

    pHook->isEnabled   = TRUE;
    pHook->queueEnable = TRUE;

    return MH_OK;
}

//-------------------------------------------------------------------------
static MH_STATUS DisableHookLL(int pos)
{
    PHOOK_ENTRY pHook = &g_Hooks.items[pos];
    DWORD  oldProtect;
    size_t patchSize = sizeof(JMP_REL);
    char  *pPatchTarget = (char *)pHook->pTarget;

    if (pHook->patchAbove)
    {
        pPatchTarget -= sizeof(JMP_REL);
        patchSize    += sizeof(JMP_REL_SHORT);
    }

    if (!VirtualProtect(pPatchTarget, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return MH_ERROR_MEMORY_PROTECT;

    if (pHook->patchAbove)
        memcpy(pPatchTarget, pHook->backup, sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
    else
        memcpy(pPatchTarget, pHook->backup, sizeof(JMP_REL));

    VirtualProtect(pPatchTarget, patchSize, oldProtect, &oldProtect);

    pHook->isEnabled   = FALSE;
    pHook->queueEnable = FALSE;

    return MH_OK;
}

//-------------------------------------------------------------------------
static MH_STATUS EnableAllHooksLL(void)
{
    MH_STATUS status = MH_OK;
    int i;
    for (i = 0; i < g_Hooks.size; ++i)
    {
        if (!g_Hooks.items[i].isEnabled)
        {
            Freeze(-1, 1);
            for (; i < g_Hooks.size; ++i)
            {
                if (!g_Hooks.items[i].isEnabled)
                {
                    status = EnableHookLL(i);
                    if (status != MH_OK)
                        break;
                }
            }
            Unfreeze();
            break;
        }
    }
    return status;
}

//-------------------------------------------------------------------------
static MH_STATUS DisableAllHooksLL(void)
{
    MH_STATUS status = MH_OK;
    int i;
    for (i = 0; i < g_Hooks.size; ++i)
    {
        if (g_Hooks.items[i].isEnabled)
        {
            Freeze(-1, 0);
            for (; i < g_Hooks.size; ++i)
            {
                if (g_Hooks.items[i].isEnabled)
                {
                    status = DisableHookLL(i);
                    if (status != MH_OK)
                        break;
                }
            }
            Unfreeze();
            break;
        }
    }
    return status;
}

//-------------------------------------------------------------------------
static void EnterSpinLock(void)
{
    // Wait until the flag is FALSE.
    while (_InterlockedCompareExchange(&g_isLocked, TRUE, FALSE) != FALSE)
    {
        SwitchToThread();
    }
}

//-------------------------------------------------------------------------
static void LeaveSpinLock(void)
{
    _InterlockedExchange(&g_isLocked, FALSE);
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_Initialize(void)
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
MH_STATUS WINAPI MH_Uninitialize(void)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        // Disable all hooks.
        status = DisableAllHooksLL();
        if (status == MH_OK)
        {
            HeapDestroy(g_hHeap);

            // Free the internal function buffer.
            UninitializeBuffer();
        }

        g_hHeap = NULL;

        g_Hooks.items    = NULL;
        g_Hooks.capacity = 0;
        g_Hooks.size     = 0;

        g_threads.items    = NULL;
        g_threads.capacity = 0;
        g_threads.size     = 0;
    }
    else
    {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_CreateHook(void *pTarget, void *const pDetour, void **ppOriginal)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        if (IsExecutableAddress(pTarget) && IsExecutableAddress(pDetour))
        {
            int pos = FindHookEntry(pTarget);
            if (pos < 0)
            {
                void *pBuffer = AllocateBuffer(pTarget);
                if (pBuffer != NULL)
                {
                    CREATE_TRAMPOLINE_T ct = { 0 };
                    ct.pTrampoline    = pBuffer;
                    ct.pTarget        = pTarget;
                    ct.pDetour        = pDetour;
                    ct.trampolineSize = MH_TRAMPOLINE_SIZE;
#if defined _M_X64
                    ct.pRelay = (char *)ct.pTrampoline + MH_RELAY_OFFSET;
                    ct.pTable = (ULONG_PTR*)((char *)ct.pTrampoline + MH_TABLE_OFFSET);
                    ct.tableSize = MH_TABLE_SIZE;
#endif
                    if (CreateTrampolineFunction(&ct))
                    {
                        PHOOK_ENTRY pHook = NewHookEntry(0 - pos - 1);
                        if (pHook != NULL)
                        {
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

                            *ppOriginal = pHook->pTrampoline;
                        }
                        else // if(pHook != NULL)
                        {
                            status = MH_ERROR_MEMORY_ALLOC;
                        }
                    }
                    else // if (CreateTrampolineFunction(&ct))
                    {
                        status = MH_ERROR_UNSUPPORTED_FUNCTION;
                    }
                }
                else // if (pBuffer != NULL)
                {
                    status = MH_ERROR_MEMORY_ALLOC;
                }
            }
            else // if (pos < 0)
            {
                status = MH_ERROR_ALREADY_CREATED;
            }
        }
        else // if (IsExecutableAddress(pTarget) && IsExecutableAddress(pDetour))
        {
            status = MH_ERROR_NOT_EXECUTABLE;
        }
    }
    else // if (g_IsInitialized)
    {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_RemoveHook(void *pTarget)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        const int pos = FindHookEntry(pTarget);
        if (pos >= 0)
        {
            if (g_Hooks.items[pos].isEnabled)
            {
                Freeze(pos, 0);
                status = DisableHookLL(pos);
                Unfreeze();
            }

            if (status == MH_OK)
            {
                FreeBuffer(g_Hooks.items[pos].pTrampoline);
                DelHookEntry(pos);
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
MH_STATUS WINAPI MH_EnableHook(void *pTarget)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        if (pTarget == MH_ALL_HOOKS)
        {
            status = EnableAllHooksLL();
        }
        else
        {
            const int pos = FindHookEntry(pTarget);
            if (pos >= 0)
            {
                if (!g_Hooks.items[pos].isEnabled)
                {
                    Freeze(pos, 1);
                    status = EnableHookLL(pos);
                    Unfreeze();
                }
                else
                {
                    status = MH_ERROR_ENABLED;
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
MH_STATUS WINAPI MH_DisableHook(void *pTarget)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        if (pTarget == MH_ALL_HOOKS)
        {
            status = DisableAllHooksLL();
        }
        else
        {
            const int pos = FindHookEntry(pTarget);
            if (pos >= 0)
            {
                if (g_Hooks.items[pos].isEnabled)
                {
                    Freeze(pos, 0);
                    status = DisableHookLL(pos);
                    Unfreeze();
                }
                else
                {
                    status = MH_ERROR_DISABLED;
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
static MH_STATUS QueueHook(void *pTarget, BOOL queueEnable)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        if (pTarget == MH_ALL_HOOKS)
        {
            int i;
            for (i = 0; i < g_Hooks.size; ++i)
                g_Hooks.items[i].queueEnable = queueEnable;
        }
        else
        {
            const int pos = FindHookEntry(pTarget);
            if (pos >= 0)
                g_Hooks.items[pos].queueEnable = queueEnable;
            else
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
MH_STATUS WINAPI MH_QueueEnableHook(void *pTarget)
{
    return QueueHook(pTarget, TRUE);
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_QueueDisableHook(void *pTarget)
{
    return QueueHook(pTarget, FALSE);
}

//-------------------------------------------------------------------------
MH_STATUS WINAPI MH_ApplyQueued(void)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        int i;
        for (i = 0; i < g_Hooks.size; ++i)
        {
            if (g_Hooks.items[i].isEnabled != g_Hooks.items[i].queueEnable)
            {
                Freeze(-1, 2);
                for (; i < g_Hooks.size; ++i)
                {
                    if (g_Hooks.items[i].isEnabled != g_Hooks.items[i].queueEnable)
                    {
                        MH_STATUS status;
                        if (g_Hooks.items[i].queueEnable)
                            status = EnableHookLL(i);
                        else
                            status = DisableHookLL(i);

                        if (status != MH_OK)
                            break;
                    }
                }
                Unfreeze();
                break;
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
