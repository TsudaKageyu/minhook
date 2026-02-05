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
#include <tlhelp32.h>
#include <limits.h>

#include "../include/darkhook.h"
#include "buffer.h"
#include "trampoline.h"

#ifndef ARRAYSIZE
    #define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

// Initial capacity of the hook_entry buffer.
#define INITIAL_HOOK_CAPACITY   32

// Initial capacity of the thread IDs buffer.
#define INITIAL_THREAD_CAPACITY 128

// Special hook position values.
#define INVALID_HOOK_POS UINT_MAX
#define ALL_HOOKS_POS    UINT_MAX

// freeze_threads() action argument defines.
#define ACTION_DISABLE      0
#define ACTION_ENABLE       1
#define ACTION_APPLY_QUEUED 2

// Thread access rights for suspending/resuming threads.
#define THREAD_ACCESS \
    (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT)

// Hook information.
typedef struct _hook_entry
{
    LPVOID target;             // Address of the target function.
    LPVOID detour;             // Address of the detour or relay function.
    LPVOID trampoline;         // Address of the trampoline function.
    UINT8  backup[8];           // Original prologue of the target function.

    UINT8  patch_above  : 1;     // Uses the hot patch area.
    UINT8  is_enabled   : 1;     // Enabled.
    UINT8  queue_enable : 1;     // Queued for enabling/disabling when != is_enabled.

    UINT   instruction_count : 4;             // Count of the instruction boundaries.
    UINT8  old_ips[8];           // Instruction boundaries of the target function.
    UINT8  new_ips[8];           // Instruction boundaries of the trampoline function.
} hook_entry, *phook_entry;

// Suspended threads for freeze_threads()/unfreeze_threads().
typedef struct _frozen_threads
{
    LPDWORD items;         // Data heap
    UINT    capacity;       // Size of allocated data heap, items
    UINT    size;           // Actual number of data items
} frozen_threads, *pfrozen_threads;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// Spin lock flag for enter_spin_lock()/leave_spin_lock().
static volatile LONG g_is_locked = FALSE;

// Private heap handle. If not NULL, this library is initialized.
static HANDLE g_h_heap = NULL;

// Hook entries.
static struct
{
    phook_entry items;     // Data heap
    UINT        capacity;   // Size of allocated data heap, items
    UINT        size;       // Actual number of data items
} g_hooks;

//-------------------------------------------------------------------------
// Returns INVALID_HOOK_POS if not found.
static UINT find_hook_entry(LPVOID target)
{
    UINT i;
    for (i = 0; i < g_hooks.size; ++i)
    {
        if ((ULONG_PTR)target == (ULONG_PTR)g_hooks.items[i].target)
            return i;
    }

    return INVALID_HOOK_POS;
}

//-------------------------------------------------------------------------
static phook_entry add_hook_entry()
{
    if (g_hooks.items == NULL)
    {
        g_hooks.capacity = INITIAL_HOOK_CAPACITY;
        g_hooks.items = (phook_entry)HeapAlloc(
            g_h_heap, 0, g_hooks.capacity * sizeof(hook_entry));
        if (g_hooks.items == NULL)
            return NULL;
    }
    else if (g_hooks.size >= g_hooks.capacity)
    {
        phook_entry p = (phook_entry)HeapReAlloc(
            g_h_heap, 0, g_hooks.items, (g_hooks.capacity * 2) * sizeof(hook_entry));
        if (p == NULL)
            return NULL;

        g_hooks.capacity *= 2;
        g_hooks.items = p;
    }

    return &g_hooks.items[g_hooks.size++];
}

//-------------------------------------------------------------------------
static VOID delete_hook_entry(UINT pos)
{
    if (pos < g_hooks.size - 1)
        g_hooks.items[pos] = g_hooks.items[g_hooks.size - 1];

    g_hooks.size--;

    if (g_hooks.capacity / 2 >= INITIAL_HOOK_CAPACITY && g_hooks.capacity / 2 >= g_hooks.size)
    {
        phook_entry p = (phook_entry)HeapReAlloc(
            g_h_heap, 0, g_hooks.items, (g_hooks.capacity / 2) * sizeof(hook_entry));
        if (p == NULL)
            return;

        g_hooks.capacity /= 2;
        g_hooks.items = p;
    }
}

//-------------------------------------------------------------------------
static DWORD_PTR find_old_ip(phook_entry hook, DWORD_PTR ip)
{
    UINT i;

    if (hook->patch_above && ip == ((DWORD_PTR)hook->target - sizeof(jmp_rel)))
        return (DWORD_PTR)hook->target;

    for (i = 0; i < hook->instruction_count; ++i)
    {
        if (ip == ((DWORD_PTR)hook->trampoline + hook->new_ips[i]))
            return (DWORD_PTR)hook->target + hook->old_ips[i];
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Check relay function.
    if (ip == (DWORD_PTR)hook->detour)
        return (DWORD_PTR)hook->target;
#endif

    return 0;
}

//-------------------------------------------------------------------------
static DWORD_PTR find_new_ip(phook_entry hook, DWORD_PTR ip)
{
    UINT i;
    for (i = 0; i < hook->instruction_count; ++i)
    {
        if (ip == ((DWORD_PTR)hook->target + hook->old_ips[i]))
            return (DWORD_PTR)hook->trampoline + hook->new_ips[i];
    }

    return 0;
}

//-------------------------------------------------------------------------
static VOID process_thread_ips(HANDLE thread_handle, UINT pos, UINT action)
{
    // If the thread suspended in the overwritten area,
    // move IP to the proper address.

    CONTEXT c;
#if defined(_M_X64) || defined(__x86_64__)
    DWORD64 *instruction_pointer = &c.Rip;
#else
    DWORD   *instruction_pointer = &c.Eip;
#endif
    UINT count;

    c.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread_handle, &c))
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
        phook_entry hook = &g_hooks.items[pos];
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

        default: // ACTION_APPLY_QUEUED
            enable = hook->queue_enable;
            break;
        }
        if (hook->is_enabled == enable)
            continue;

        if (enable)
            ip = find_new_ip(hook, *instruction_pointer);
        else
            ip = find_old_ip(hook, *instruction_pointer);

        if (ip != 0)
        {
            *instruction_pointer = ip;
            SetThreadContext(thread_handle, &c);
        }
    }
}

//-------------------------------------------------------------------------
static BOOL enumerate_threads(pfrozen_threads threads)
{
    BOOL succeeded = FALSE;

    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot_handle != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(snapshot_handle, &te))
        {
            succeeded = TRUE;
            do
            {
                if (te.dwSize >= (FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD))
                    && te.th32OwnerProcessID == GetCurrentProcessId()
                    && te.th32ThreadID != GetCurrentThreadId())
                {
                    if (threads->items == NULL)
                    {
                        threads->capacity = INITIAL_THREAD_CAPACITY;
                        threads->items
                            = (LPDWORD)HeapAlloc(g_h_heap, 0, threads->capacity * sizeof(DWORD));
                        if (threads->items == NULL)
                        {
                            succeeded = FALSE;
                            break;
                        }
                    }
                    else if (threads->size >= threads->capacity)
                    {
                        LPDWORD p;
                        threads->capacity *= 2;
                        p = (LPDWORD)HeapReAlloc(
                            g_h_heap, 0, threads->items, threads->capacity * sizeof(DWORD));
                        if (p == NULL)
                        {
                            succeeded = FALSE;
                            break;
                        }

                        threads->items = p;
                    }
                    threads->items[threads->size++] = te.th32ThreadID;
                }

                te.dwSize = sizeof(THREADENTRY32);
            } while (Thread32Next(snapshot_handle, &te));

            if (succeeded && GetLastError() != ERROR_NO_MORE_FILES)
                succeeded = FALSE;

            if (!succeeded && threads->items != NULL)
            {
                HeapFree(g_h_heap, 0, threads->items);
                threads->items = NULL;
            }
        }
        CloseHandle(snapshot_handle);
    }

    return succeeded;
}

//-------------------------------------------------------------------------
static dh_status freeze_threads(pfrozen_threads threads, UINT pos, UINT action)
{
    dh_status status = DH_OK;

    threads->items   = NULL;
    threads->capacity = 0;
    threads->size     = 0;
    if (!enumerate_threads(threads))
    {
        status = DH_ERROR_MEMORY_ALLOC;
    }
    else if (threads->items != NULL)
    {
        UINT i;
        for (i = 0; i < threads->size; ++i)
        {
            HANDLE thread_handle = OpenThread(THREAD_ACCESS, FALSE, threads->items[i]);
            BOOL suspended = FALSE;
            if (thread_handle != NULL)
            {
                DWORD result = SuspendThread(thread_handle);
                if (result != 0xFFFFFFFF)
                {
                    suspended = TRUE;
                    process_thread_ips(thread_handle, pos, action);
                }
                CloseHandle(thread_handle);
            }

            if (!suspended)
            {
                // Mark thread as not suspended, so it's not resumed later on.
                threads->items[i] = 0;
            }
        }
    }

    return status;
}

//-------------------------------------------------------------------------
static VOID unfreeze_threads(pfrozen_threads threads)
{
    if (threads->items != NULL)
    {
        UINT i;
        for (i = 0; i < threads->size; ++i)
        {
            DWORD thread_id = threads->items[i];
            if (thread_id != 0)
            {
                HANDLE thread_handle = OpenThread(THREAD_ACCESS, FALSE, thread_id);
                if (thread_handle != NULL)
                {
                    ResumeThread(thread_handle);
                    CloseHandle(thread_handle);
                }
            }
        }

        HeapFree(g_h_heap, 0, threads->items);
    }
}

//-------------------------------------------------------------------------
static dh_status enable_hook_low_level(UINT pos, BOOL enable)
{
    phook_entry hook = &g_hooks.items[pos];
    DWORD  old_protect;
    SIZE_T patch_size    = sizeof(jmp_rel);
    LPBYTE patch_target = (LPBYTE)hook->target;

    if (hook->patch_above)
    {
        patch_target -= sizeof(jmp_rel);
        patch_size    += sizeof(jmp_rel_short);
    }

    if (!VirtualProtect(patch_target, patch_size, PAGE_EXECUTE_READWRITE, &old_protect))
        return DH_ERROR_MEMORY_PROTECT;

    if (enable)
    {
        pjmp_rel jump_patch = (pjmp_rel)patch_target;
        jump_patch->opcode = 0xE9;
        jump_patch->operand = (INT32)((LPBYTE)hook->detour - (patch_target + sizeof(jmp_rel)));

        if (hook->patch_above)
        {
            pjmp_rel_short short_jump = (pjmp_rel_short)hook->target;
            short_jump->opcode = 0xEB;
            short_jump->operand = (INT8)(0 - (sizeof(jmp_rel_short) + sizeof(jmp_rel)));
        }
    }
    else
    {
        if (hook->patch_above)
            memcpy(patch_target, hook->backup, sizeof(jmp_rel) + sizeof(jmp_rel_short));
        else
            memcpy(patch_target, hook->backup, sizeof(jmp_rel));
    }

    VirtualProtect(patch_target, patch_size, old_protect, &old_protect);

    // Just-in-case measure.
    FlushInstructionCache(GetCurrentProcess(), patch_target, patch_size);

    hook->is_enabled   = enable;
    hook->queue_enable = enable;

    return DH_OK;
}

//-------------------------------------------------------------------------
static dh_status enable_all_hooks_low_level(BOOL enable)
{
    dh_status status = DH_OK;
    UINT i, first = INVALID_HOOK_POS;

    for (i = 0; i < g_hooks.size; ++i)
    {
        if (g_hooks.items[i].is_enabled != enable)
        {
            first = i;
            break;
        }
    }

    if (first != INVALID_HOOK_POS)
    {
        frozen_threads threads;
        status = freeze_threads(&threads, ALL_HOOKS_POS, enable ? ACTION_ENABLE : ACTION_DISABLE);
        if (status == DH_OK)
        {
            for (i = first; i < g_hooks.size; ++i)
            {
                if (g_hooks.items[i].is_enabled != enable)
                {
                    status = enable_hook_low_level(i, enable);
                    if (status != DH_OK)
                        break;
                }
            }

            unfreeze_threads(&threads);
        }
    }

    return status;
}

//-------------------------------------------------------------------------
static VOID enter_spin_lock(VOID)
{
    SIZE_T spin_count = 0;

    // Wait until the flag is FALSE.
    while (InterlockedCompareExchange(&g_is_locked, TRUE, FALSE) != FALSE)
    {
        // No need to generate a memory barrier here, since InterlockedCompareExchange()
        // generates a full memory barrier itself.

        // Prevent the loop from being too busy.
        if (spin_count < 32)
            Sleep(0);
        else
            Sleep(1);

        spin_count++;
    }
}

//-------------------------------------------------------------------------
static VOID leave_spin_lock(VOID)
{
    // No need to generate a memory barrier here, since InterlockedExchange()
    // generates a full memory barrier itself.

    InterlockedExchange(&g_is_locked, FALSE);
}

//-------------------------------------------------------------------------
dh_status WINAPI dh_initialize(VOID)
{
    dh_status status = DH_OK;

    enter_spin_lock();

    if (g_h_heap == NULL)
    {
        g_h_heap = HeapCreate(0, 0, 0);
        if (g_h_heap != NULL)
        {
            // Initialize the internal function buffer.
            initialize_buffer();
        }
        else
        {
            status = DH_ERROR_MEMORY_ALLOC;
        }
    }
    else
    {
        status = DH_ERROR_ALREADY_INITIALIZED;
    }

    leave_spin_lock();

    return status;
}

//-------------------------------------------------------------------------
dh_status WINAPI dh_uninitialize(VOID)
{
    dh_status status = DH_OK;

    enter_spin_lock();

    if (g_h_heap != NULL)
    {
        status = enable_all_hooks_low_level(FALSE);
        if (status == DH_OK)
        {
            // Free the internal function buffer.

            // HeapFree is actually not required, but some tools detect a false
            // memory leak without HeapFree.

            uninitialize_buffer();

            HeapFree(g_h_heap, 0, g_hooks.items);
            HeapDestroy(g_h_heap);

            g_h_heap = NULL;

            g_hooks.items   = NULL;
            g_hooks.capacity = 0;
            g_hooks.size     = 0;
        }
    }
    else
    {
        status = DH_ERROR_NOT_INITIALIZED;
    }

    leave_spin_lock();

    return status;
}

//-------------------------------------------------------------------------
dh_status WINAPI dh_create_hook(LPVOID target, LPVOID detour, LPVOID *original)
{
    dh_status status = DH_OK;

    enter_spin_lock();

    if (g_h_heap != NULL)
    {
        if (is_executable_address(target) && is_executable_address(detour))
        {
            UINT pos = find_hook_entry(target);
            if (pos == INVALID_HOOK_POS)
            {
                LPVOID buffer = allocate_buffer(target);
                if (buffer != NULL)
                {
                    trampoline trampoline_data;

                    trampoline_data.target     = target;
                    trampoline_data.detour     = detour;
                    trampoline_data.trampoline = buffer;
                    if (create_trampoline_function(&trampoline_data))
                    {
                        phook_entry hook = add_hook_entry();
                        if (hook != NULL)
                        {
                            hook->target     = trampoline_data.target;
#if defined(_M_X64) || defined(__x86_64__)
                            hook->detour     = trampoline_data.relay;
#else
                            hook->detour     = trampoline_data.detour;
#endif
                            hook->trampoline = trampoline_data.trampoline;
                            hook->patch_above  = trampoline_data.patch_above;
                            hook->is_enabled   = FALSE;
                            hook->queue_enable = FALSE;
                            hook->instruction_count         = trampoline_data.instruction_count;
                            memcpy(hook->old_ips, trampoline_data.old_ips, ARRAYSIZE(trampoline_data.old_ips));
                            memcpy(hook->new_ips, trampoline_data.new_ips, ARRAYSIZE(trampoline_data.new_ips));

                            // Back up the target function.

                            if (trampoline_data.patch_above)
                            {
                                memcpy(
                                    hook->backup,
                                    (LPBYTE)target - sizeof(jmp_rel),
                                    sizeof(jmp_rel) + sizeof(jmp_rel_short));
                            }
                            else
                            {
                                memcpy(hook->backup, target, sizeof(jmp_rel));
                            }

                            if (original != NULL)
                                *original = hook->trampoline;
                        }
                        else
                        {
                            status = DH_ERROR_MEMORY_ALLOC;
                        }
                    }
                    else
                    {
                        status = DH_ERROR_UNSUPPORTED_FUNCTION;
                    }

                    if (status != DH_OK)
                    {
                        free_buffer(buffer);
                    }
                }
                else
                {
                    status = DH_ERROR_MEMORY_ALLOC;
                }
            }
            else
            {
                status = DH_ERROR_ALREADY_CREATED;
            }
        }
        else
        {
            status = DH_ERROR_NOT_EXECUTABLE;
        }
    }
    else
    {
        status = DH_ERROR_NOT_INITIALIZED;
    }

    leave_spin_lock();

    return status;
}

//-------------------------------------------------------------------------
dh_status WINAPI dh_remove_hook(LPVOID target)
{
    dh_status status = DH_OK;

    enter_spin_lock();

    if (g_h_heap != NULL)
    {
        UINT pos = find_hook_entry(target);
        if (pos != INVALID_HOOK_POS)
        {
            if (g_hooks.items[pos].is_enabled)
            {
                frozen_threads threads;
                status = freeze_threads(&threads, pos, ACTION_DISABLE);
                if (status == DH_OK)
                {
                    status = enable_hook_low_level(pos, FALSE);

                    unfreeze_threads(&threads);
                }
            }

            if (status == DH_OK)
            {
                free_buffer(g_hooks.items[pos].trampoline);
                delete_hook_entry(pos);
            }
        }
        else
        {
            status = DH_ERROR_NOT_CREATED;
        }
    }
    else
    {
        status = DH_ERROR_NOT_INITIALIZED;
    }

    leave_spin_lock();

    return status;
}

//-------------------------------------------------------------------------
static dh_status enable_hook(LPVOID target, BOOL enable)
{
    dh_status status = DH_OK;

    enter_spin_lock();

    if (g_h_heap != NULL)
    {
        if (target == DH_ALL_HOOKS)
        {
            status = enable_all_hooks_low_level(enable);
        }
        else
        {
            UINT pos = find_hook_entry(target);
            if (pos != INVALID_HOOK_POS)
            {
                if (g_hooks.items[pos].is_enabled != enable)
                {
                    frozen_threads threads;
                    status = freeze_threads(&threads, pos, ACTION_ENABLE);
                    if (status == DH_OK)
                    {
                        status = enable_hook_low_level(pos, enable);

                        unfreeze_threads(&threads);
                    }
                }
                else
                {
                    status = enable ? DH_ERROR_ENABLED : DH_ERROR_DISABLED;
                }
            }
            else
            {
                status = DH_ERROR_NOT_CREATED;
            }
        }
    }
    else
    {
        status = DH_ERROR_NOT_INITIALIZED;
    }

    leave_spin_lock();

    return status;
}

//-------------------------------------------------------------------------
dh_status WINAPI dh_enable_hook(LPVOID target)
{
    return enable_hook(target, TRUE);
}

//-------------------------------------------------------------------------
dh_status WINAPI dh_disable_hook(LPVOID target)
{
    return enable_hook(target, FALSE);
}

//-------------------------------------------------------------------------
static dh_status queue_hook(LPVOID target, BOOL queue_enable)
{
    dh_status status = DH_OK;

    enter_spin_lock();

    if (g_h_heap != NULL)
    {
        if (target == DH_ALL_HOOKS)
        {
            UINT i;
            for (i = 0; i < g_hooks.size; ++i)
                g_hooks.items[i].queue_enable = queue_enable;
        }
        else
        {
            UINT pos = find_hook_entry(target);
            if (pos != INVALID_HOOK_POS)
            {
                g_hooks.items[pos].queue_enable = queue_enable;
            }
            else
            {
                status = DH_ERROR_NOT_CREATED;
            }
        }
    }
    else
    {
        status = DH_ERROR_NOT_INITIALIZED;
    }

    leave_spin_lock();

    return status;
}

//-------------------------------------------------------------------------
dh_status WINAPI dh_queue_enable_hook(LPVOID target)
{
    return queue_hook(target, TRUE);
}

//-------------------------------------------------------------------------
dh_status WINAPI dh_queue_disable_hook(LPVOID target)
{
    return queue_hook(target, FALSE);
}

//-------------------------------------------------------------------------
dh_status WINAPI dh_apply_queued(VOID)
{
    dh_status status = DH_OK;
    UINT i, first = INVALID_HOOK_POS;

    enter_spin_lock();

    if (g_h_heap != NULL)
    {
        for (i = 0; i < g_hooks.size; ++i)
        {
            if (g_hooks.items[i].is_enabled != g_hooks.items[i].queue_enable)
            {
                first = i;
                break;
            }
        }

        if (first != INVALID_HOOK_POS)
        {
            frozen_threads threads;
            status = freeze_threads(&threads, ALL_HOOKS_POS, ACTION_APPLY_QUEUED);
            if (status == DH_OK)
            {
                for (i = first; i < g_hooks.size; ++i)
                {
                    phook_entry hook = &g_hooks.items[i];
                    if (hook->is_enabled != hook->queue_enable)
                    {
                        status = enable_hook_low_level(i, hook->queue_enable);
                        if (status != DH_OK)
                            break;
                    }
                }

                unfreeze_threads(&threads);
            }
        }
    }
    else
    {
        status = DH_ERROR_NOT_INITIALIZED;
    }

    leave_spin_lock();

    return status;
}

//-------------------------------------------------------------------------
dh_status WINAPI dh_create_hook_api_ex(
    LPCWSTR module_name, LPCSTR proc_name, LPVOID detour,
    LPVOID *original, LPVOID *target_out)
{
    HMODULE module_handle;
    LPVOID  target;

    module_handle = GetModuleHandleW(module_name);
    if (module_handle == NULL)
        return DH_ERROR_MODULE_NOT_FOUND;

    target = (LPVOID)GetProcAddress(module_handle, proc_name);
    if (target == NULL)
        return DH_ERROR_FUNCTION_NOT_FOUND;

    if (target_out != NULL)
        *target_out = target;

    return dh_create_hook(target, detour, original);
}

//-------------------------------------------------------------------------
dh_status WINAPI dh_create_hook_api(
    LPCWSTR module_name, LPCSTR proc_name, LPVOID detour, LPVOID *original)
{
    return dh_create_hook_api_ex(module_name, proc_name, detour, original, NULL);
}

//-------------------------------------------------------------------------
const char *WINAPI dh_status_to_string(dh_status status)
{
#define DH_ST2STR(x)    \
    case x:             \
        return #x;

    switch (status) {
        DH_ST2STR(DH_UNKNOWN)
        DH_ST2STR(DH_OK)
        DH_ST2STR(DH_ERROR_ALREADY_INITIALIZED)
        DH_ST2STR(DH_ERROR_NOT_INITIALIZED)
        DH_ST2STR(DH_ERROR_ALREADY_CREATED)
        DH_ST2STR(DH_ERROR_NOT_CREATED)
        DH_ST2STR(DH_ERROR_ENABLED)
        DH_ST2STR(DH_ERROR_DISABLED)
        DH_ST2STR(DH_ERROR_NOT_EXECUTABLE)
        DH_ST2STR(DH_ERROR_UNSUPPORTED_FUNCTION)
        DH_ST2STR(DH_ERROR_MEMORY_ALLOC)
        DH_ST2STR(DH_ERROR_MEMORY_PROTECT)
        DH_ST2STR(DH_ERROR_MODULE_NOT_FOUND)
        DH_ST2STR(DH_ERROR_FUNCTION_NOT_FOUND)
    }

#undef DH_ST2STR

    return "(unknown)";
}
