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

#pragma once

#if !(defined _M_IX86) && !(defined _M_X64) && !(defined __i386__) &&
    !(defined __x86_64__)
    #error DarkHook supports only x86 and x64 systems.
#endif

#include <windows.h>

// DarkHook error codes.
typedef enum dh_status {
    // Unknown error. Should not be returned.
    DH_UNKNOWN = -1,

    // Successful.
    DH_OK = 0,

    // DarkHook is already initialized.
    DH_ERROR_ALREADY_INITIALIZED,

    // DarkHook is not initialized yet, or already uninitialized.
    DH_ERROR_NOT_INITIALIZED,

    // The hook for the specified target function is already created.
    DH_ERROR_ALREADY_CREATED,

    // The hook for the specified target function is not created yet.
    DH_ERROR_NOT_CREATED,

    // The hook for the specified target function is already enabled.
    DH_ERROR_ENABLED,

    // The hook for the specified target function is not enabled yet, or already
    // disabled.
    DH_ERROR_DISABLED,

    // The specified pointer is invalid. It points the address of non-allocated
    // and/or non-executable region.
    DH_ERROR_NOT_EXECUTABLE,

    // The specified target function cannot be hooked.
    DH_ERROR_UNSUPPORTED_FUNCTION,

    // Failed to allocate memory.
    DH_ERROR_MEMORY_ALLOC,

    // Failed to change the memory protection.
    DH_ERROR_MEMORY_PROTECT,

    // The specified module is not loaded.
    DH_ERROR_MODULE_NOT_FOUND,

    // The specified function is not found.
    DH_ERROR_FUNCTION_NOT_FOUND
} dh_status;

// Can be passed as a parameter to dh_enable_hook, dh_disable_hook,
// dh_queue_enable_hook or dh_queue_disable_hook.
#define DH_ALL_HOOKS NULL

#ifdef __cplusplus
extern "C" {
#endif

    // Initialize the DarkHook library. You must call this function EXACTLY ONCE
    // at the beginning of your program.
    dh_status WINAPI dh_initialize(void);

    // Uninitialize the DarkHook library. You must call this function EXACTLY
    // ONCE at the end of your program.
    dh_status WINAPI dh_uninitialize(void);

    // Creates a hook for the specified target function, in disabled state.
    // Parameters:
    //   target     [in]  A pointer to the target function, which will be
    //                    overridden by the detour function.
    //   detour     [in]  A pointer to the detour function, which will override
    //                    the target function.
    //   original   [out] A pointer to the trampoline function, which will be
    //                    used to call the original target function.
    //                    This parameter can be NULL.
    dh_status WINAPI dh_create_hook(LPVOID target, LPVOID detour,
                                    LPVOID *original);

    // Creates a hook for the specified API function, in disabled state.
    // Parameters:
    //   module_name [in]  A pointer to the loaded module name which contains the
    //                     target function.
    //   proc_name   [in]  A pointer to the target function name, which will be
    //                     overridden by the detour function.
    //   detour      [in]  A pointer to the detour function, which will override
    //                     the target function.
    //   original    [out] A pointer to the trampoline function, which will be
    //                     used to call the original target function.
    //                     This parameter can be NULL.
    dh_status WINAPI dh_create_hook_api(
        LPCWSTR module_name, LPCSTR proc_name, LPVOID detour, LPVOID *original);

    // Creates a hook for the specified API function, in disabled state.
    // Parameters:
    //   module_name [in]  A pointer to the loaded module name which contains the
    //                     target function.
    //   proc_name   [in]  A pointer to the target function name, which will be
    //                     overridden by the detour function.
    //   detour      [in]  A pointer to the detour function, which will override
    //                     the target function.
    //   original    [out] A pointer to the trampoline function, which will be
    //                     used to call the original target function.
    //                     This parameter can be NULL.
    //   target      [out] A pointer to the target function, which will be used
    //                     with other functions.
    //                     This parameter can be NULL.
    dh_status WINAPI dh_create_hook_api_ex(
        LPCWSTR module_name, LPCSTR proc_name, LPVOID detour, LPVOID *original,
        LPVOID *target);

    // Removes an already created hook.
    // Parameters:
    //   target [in] A pointer to the target function.
    dh_status WINAPI dh_remove_hook(LPVOID target);

    // Enables an already created hook.
    // Parameters:
    //   target [in] A pointer to the target function.
    //               If this parameter is DH_ALL_HOOKS, all created hooks are
    //               enabled in one go.
    dh_status WINAPI dh_enable_hook(LPVOID target);

    // Disables an already created hook.
    // Parameters:
    //   target [in] A pointer to the target function.
    //               If this parameter is DH_ALL_HOOKS, all created hooks are
    //               disabled in one go.
    dh_status WINAPI dh_disable_hook(LPVOID target);

    // Queues to enable an already created hook.
    // Parameters:
    //   target [in] A pointer to the target function.
    //               If this parameter is DH_ALL_HOOKS, all created hooks are
    //               queued to be enabled.
    dh_status WINAPI dh_queue_enable_hook(LPVOID target);

    // Queues to disable an already created hook.
    // Parameters:
    //   target [in] A pointer to the target function.
    //               If this parameter is DH_ALL_HOOKS, all created hooks are
    //               queued to be disabled.
    dh_status WINAPI dh_queue_disable_hook(LPVOID target);

    // Applies all queued changes in one go.
    dh_status WINAPI dh_apply_queued(void);

    // Translates the dh_status to its name as a string.
    const char *WINAPI dh_status_to_string(dh_status status);

#ifdef __cplusplus
}
#endif
