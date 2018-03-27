#pragma once

#include <windows.h>
#include <TlHelp32.h>

BOOL WINAPI MyHeapFree(
    _In_ HANDLE hHeap,
    _In_ DWORD  dwFlags,
    _In_ LPVOID lpMem);

HANDLE WINAPI MyHeapCreate(
    _In_ DWORD  flOptions,
    _In_ SIZE_T dwInitialSize,
    _In_ SIZE_T dwMaximumSize
);

LPVOID WINAPI MyHeapAlloc(
    _In_ HANDLE hHeap,
    _In_ DWORD  dwFlags,
    _In_ SIZE_T dwBytes
);

LPVOID WINAPI MyHeapReAlloc(
    _In_ HANDLE hHeap,
    _In_ DWORD  dwFlags,
    _In_ LPVOID lpMem,
    _In_ SIZE_T dwBytes
);

BOOL WINAPI MyHeapDestroy(
    _In_ HANDLE hHeap
);

BOOL WINAPI MyCloseHandle(
    _In_ HANDLE hObject
);

VOID WINAPI MySleep(
    _In_ DWORD dwMilliseconds
);

SIZE_T WINAPI MyVirtualQuery(
    _In_opt_ LPCVOID                   lpAddress,
    _Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
    _In_     SIZE_T                    dwLength
);

BOOL WINAPI MyVirtualFree(
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD  dwFreeType
);

LPVOID WINAPI MyVirtualAlloc(
    _In_opt_ LPVOID lpAddress,
    _In_     SIZE_T dwSize,
    _In_     DWORD  flAllocationType,
    _In_     DWORD  flProtect
);

HANDLE WINAPI MyGetCurrentProcess(void);

DWORD WINAPI MyGetProcessId(
    _In_ HANDLE Process
);

DWORD WINAPI MyGetCurrentProcessId(void);

DWORD WINAPI MyGetThreadId(
    _In_ HANDLE Thread
);

DWORD WINAPI MyGetCurrentThreadId(void);

HANDLE WINAPI MyOpenThread(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL  bInheritHandle,
    _In_ DWORD dwThreadId
);

DWORD WINAPI MySuspendThread(
    _In_ HANDLE hThread
);

DWORD WINAPI MyResumeThread(
    _In_ HANDLE hThread
);


BOOL WINAPI MyGetThreadContext(
    _In_    HANDLE    hThread,
    _Inout_ LPCONTEXT lpContext
);

BOOL WINAPI MySetThreadContext(
    _In_       HANDLE  hThread,
    _In_ const CONTEXT *lpContext
);

BOOL WINAPI MyFlushInstructionCache(
    _In_ HANDLE  hProcess,
    _In_ LPCVOID lpBaseAddress,
    _In_ SIZE_T  dwSize
);

BOOL WINAPI MyVirtualProtect(
    _In_  LPVOID lpAddress,
    _In_  SIZE_T dwSize,
    _In_  DWORD  flNewProtect,
    _Out_ PDWORD lpflOldProtect
);

HMODULE WINAPI MyGetModuleHandleW(
    _In_opt_ LPCWSTR lpModuleName
);

FARPROC WINAPI MyGetProcAddress(
    _In_ HMODULE hModule,
    _In_ LPCSTR  lpProcName
);

void WINAPI MyGetSystemInfo(
    _Out_ LPSYSTEM_INFO lpSystemInfo
);

HANDLE WINAPI MyCreateToolhelp32Snapshot(
    _In_ DWORD dwFlags,
    _In_ DWORD th32ProcessID
);

BOOL WINAPI MyThread32First(
    _In_    HANDLE          hSnapshot,
    _Inout_ LPTHREADENTRY32 lpte
);

BOOL WINAPI MyThread32Next(
    _In_  HANDLE          hSnapshot,
    _Out_ LPTHREADENTRY32 lpte
);