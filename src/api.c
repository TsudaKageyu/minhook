#include "api.h"
#include <windows.h>
#include <TlHelp32.h>
#include <winternl.h>

typedef ULONG LOGICAL;

#if WDK_NTDDI_VERSION <= NTDDI_WIN10_RS2
// As of the RS3 SDK (16299), winternl.h declares struct CLIENT_ID. It did not do so before.
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
#endif
typedef CLIENT_ID *PCLIENT_ID;

typedef LONG KPRIORITY;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION;


#pragma optimize( "", off )
// Unless used, the compiler will try to replaced this with 'memset'
void * my_memset(void *s, int c, size_t n)
{
    unsigned char* p = s;
    while (n--)
        *p++ = (unsigned char)c;
    return s;
}

void* my_memcpy(void* destination, void* source, size_t num)
{
    int i;
    char* d = destination;
    char* s = source;
    for (i = 0; i < num; i++) {
        d[i] = s[i];
    }
    return destination;
}
#pragma optimize( "", on ) 

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandle(
    _In_opt_ PWORD pwPath,
    _In_opt_ PVOID Unused,
    _In_ PUNICODE_STRING ModuleFileName,
    _Out_ PHANDLE pHModule
);

NTSTATUS
NTAPI
LdrGetProcedureAddress(
    _In_ HMODULE ModuleHandle,
    _In_opt_ PANSI_STRING FunctionName,
    _In_opt_ WORD Oridinal,
    _Out_ PVOID *FunctionAddress
);

NTSTATUS NTAPI NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _Outptr_result_buffer_(*RegionSize) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

NTSTATUS NTAPI NtOpenThread(
    _Out_ PHANDLE            ThreadHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes,
    _In_  PCLIENT_ID         ClientId
);

NTSTATUS
NTAPI
NtSuspendThread(
    _In_ HANDLE               ThreadHandle,
    _Out_opt_ PULONG              PreviousSuspendCount);

NTSTATUS
NTAPI
NtResumeThread(
    _In_ HANDLE               ThreadHandle,
    _Out_opt_ PULONG              SuspendCount);

NTSTATUS
NTAPI
NtGetContextThread(
    _In_ HANDLE               ThreadHandle,
    _Out_ PCONTEXT            pContext);

NTSTATUS
NTAPI
NtSetContextThread(
    _In_ HANDLE               ThreadHandle,
    _In_ PCONTEXT             Context);

NTSTATUS
NTAPI
NtFlushInstructionCache(
    _In_ HANDLE               ProcessHandle,
    _In_ PVOID                BaseAddress,
    _In_ SIZE_T                NumberOfBytesToFlush);

BOOL WINAPI RtlFreeHeap(
    _In_ HANDLE hHeap,
    _In_ DWORD  dwFlags,
    _In_ LPVOID lpMem);

LPVOID WINAPI RtlAllocateHeap(
    _In_ HANDLE hHeap,
    _In_ DWORD dwFlags,
    _In_ SIZE_T dwBytes);

LPVOID WINAPI RtlReAllocateHeap(
    _In_ HANDLE hHeap,
    _In_ DWORD  dwFlags,
    _In_ LPVOID lpMem,
    _In_ SIZE_T dwBytes
);

NTSTATUS
NTAPI
NtProtectVirtualMemory(
    _In_ HANDLE               ProcessHandle,
    _Inout_ PVOID            *BaseAddress,
    _Inout_ PSIZE_T           NumberOfBytesToProtect,
    _In_ ULONG                NewAccessProtection,
    _Out_ PULONG              OldAccessProtection);

typedef
NTSTATUS
NTAPI
RTL_HEAP_COMMIT_ROUTINE(
    _In_ PVOID Base,
    _Inout_ PVOID *CommitAddress,
    _Inout_ PSIZE_T CommitSize
);
typedef RTL_HEAP_COMMIT_ROUTINE *PRTL_HEAP_COMMIT_ROUTINE;

typedef struct _RTL_HEAP_PARAMETERS {
    ULONG Length;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T MaximumAllocationSize;
    SIZE_T VirtualMemoryThreshold;
    SIZE_T InitialCommit;
    SIZE_T InitialReserve;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

PVOID
NTAPI
RtlCreateHeap(
    _In_     ULONG Flags,
    _In_opt_ PVOID HeapBase,
    _In_opt_ SIZE_T ReserveSize,
    _In_opt_ SIZE_T CommitSize,
    _In_opt_ PVOID Lock,
    _In_opt_ PRTL_HEAP_PARAMETERS Parameters
);

PVOID
NTAPI
RtlDestroyHeap(
    _In_ _Post_invalid_ PVOID HeapHandle
);

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

NTSTATUS
NTAPI
NtQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

NTSTATUS
NTAPI
NtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
);

//////////////////////////////////////////////////////////////////////////

BOOL WINAPI MyHeapFree(
    _In_ HANDLE hHeap,
    _In_ DWORD  dwFlags,
    _In_ LPVOID lpMem)
{
    return RtlFreeHeap(hHeap, dwFlags, lpMem);
}

HANDLE WINAPI MyHeapCreate(
    _In_ DWORD  flOptions,
    _In_ SIZE_T dwInitialSize,
    _In_ SIZE_T dwMaximumSize
)
{
    HANDLE hRet;
    ULONG Flags;

    /* Remove non-Win32 flags and tag this allocation */
    Flags = flOptions;

    /* Check if heap is growable and ensure max size is correct */
    if (dwMaximumSize == 0)
        Flags |= HEAP_GROWABLE;

    /* Call RTL Heap */
    hRet = RtlCreateHeap(Flags,
        NULL,
        dwMaximumSize,
        dwInitialSize,
        NULL,
        NULL);

    return hRet;
}

LPVOID WINAPI MyHeapAlloc(
    _In_ HANDLE hHeap,
    _In_ DWORD dwFlags,
    _In_ SIZE_T dwBytes)
{
    return RtlAllocateHeap(hHeap, dwFlags, dwBytes);
}

LPVOID WINAPI MyHeapReAlloc(
    _In_ HANDLE hHeap,
    _In_ DWORD  dwFlags,
    _In_ LPVOID lpMem,
    _In_ SIZE_T dwBytes
)
{
    return RtlReAllocateHeap(hHeap, dwFlags, lpMem, dwBytes);
}

BOOL WINAPI MyHeapDestroy(
    _In_ HANDLE hHeap
)
{
    if (!RtlDestroyHeap(hHeap)) return TRUE;

    return FALSE;
}

BOOL WINAPI MyCloseHandle(
    _In_ HANDLE hObject
)
{
    NTSTATUS status;

    status = NtClose(hObject);

    if (NT_SUCCESS(status)) {
        return TRUE;
    }

    return FALSE;
}

VOID WINAPI MySleep(
    _In_ DWORD dwMilliseconds
)
{
    // Unimplemented.
    return;
}

SIZE_T WINAPI MyVirtualQuery(
    _In_opt_ LPCVOID                   lpAddress,
    _Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
    _In_     SIZE_T                    dwLength
)
{
    NTSTATUS Status;
    SIZE_T ResultLength;

    Status = NtQueryVirtualMemory(MyGetCurrentProcess(),
                                 (LPVOID)lpAddress,
                                 MemoryBasicInformation,
                                 lpBuffer,
                                 dwLength,
                                 &ResultLength);

    if (!NT_SUCCESS(Status)) {
        return 0;
    }

    return ResultLength;
}

BOOL WINAPI MyVirtualFree(
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD  dwFreeType
)
{
    NTSTATUS Status;

    Status = NtFreeVirtualMemory(MyGetCurrentProcess(),
                                 &lpAddress,
                                 &dwSize,
                                 dwFreeType);

    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    return TRUE;
}

LPVOID WINAPI MyVirtualAlloc(
    _In_opt_ LPVOID lpAddress,
    _In_     SIZE_T dwSize,
    _In_     DWORD  flAllocationType,
    _In_     DWORD  flProtect
)
{
    NTSTATUS status;

    status = NtAllocateVirtualMemory(MyGetCurrentProcess(),
                                     &lpAddress,
                                     0,
                                     &dwSize,
                                     flAllocationType,
                                     flProtect);
    
    if (NT_SUCCESS(status)) {
        return lpAddress;
    }

    return NULL;
}

HANDLE WINAPI MyGetCurrentProcess(void)
{
    return ((HANDLE)(LONG_PTR)-1);
}

DWORD WINAPI MyGetProcessId(
    _In_ HANDLE Process
)
{
    PROCESS_BASIC_INFORMATION ProcessBasic;
    NTSTATUS Status;

    Status = NtQueryInformationProcess(Process,
                                       ProcessBasicInformation,
                                       &ProcessBasic,
                                       sizeof(ProcessBasic),
                                       NULL);
    if (!NT_SUCCESS(Status)) {
        return 0;
    }

    return (DWORD)ProcessBasic.UniqueProcessId;
}

DWORD WINAPI MyGetCurrentProcessId(void)
{
    return MyGetProcessId(MyGetCurrentProcess());
}

HANDLE WINAPI MyGetCurrentThread(void)
{
    return ((HANDLE)(LONG_PTR)-2);
}

DWORD WINAPI MyGetThreadId(
    _In_ HANDLE Thread
)
{
    enum {
        ThreadBasicInformation = 0
    };

    THREAD_BASIC_INFORMATION threadInfo;
    ULONG returnLength;
    NTSTATUS status;
    
    status = NtQueryInformationThread(Thread, (THREADINFOCLASS)(ThreadBasicInformation), &threadInfo, sizeof(threadInfo), &returnLength);
    if (!NT_SUCCESS(status)) {
        return 0;
    }

    return (DWORD)((ULONG_PTR)(threadInfo.ClientId.UniqueThread));
}

DWORD WINAPI MyGetCurrentThreadId(void)
{
    return MyGetThreadId(MyGetCurrentThread());
}

HANDLE WINAPI MyOpenThread(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL  bInheritHandle,
    _In_ DWORD dwThreadId
)
{
    HANDLE ThreadHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;
    NTSTATUS status;

    ClientId.UniqueProcess = 0;
    ClientId.UniqueThread = UlongToHandle(dwThreadId);

    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               (bInheritHandle ? OBJ_INHERIT : 0),
                               NULL,
                               NULL);

    status = NtOpenThread(&ThreadHandle, dwDesiredAccess, &ObjectAttributes, &ClientId);
    if (!NT_SUCCESS(status)) {
        return NULL;
    }

    return ThreadHandle;
}

DWORD WINAPI MySuspendThread(
    _In_ HANDLE hThread
)
{
    ULONG PreviousSuspendCount;
    NTSTATUS Status;

    Status = NtSuspendThread(hThread, &PreviousSuspendCount);
    if (!NT_SUCCESS(Status))
    {
        return -1;
    }

    return PreviousSuspendCount;
}

DWORD WINAPI MyResumeThread(
    _In_ HANDLE hThread
)
{
    ULONG PreviousResumeCount;
    NTSTATUS Status;

    Status = NtResumeThread(hThread, &PreviousResumeCount);
    if (!NT_SUCCESS(Status))
    {
        return -1;
    }

    return PreviousResumeCount;
}

BOOL WINAPI MyGetThreadContext(
    _In_    HANDLE    hThread,
    _Inout_ LPCONTEXT lpContext
)
{
    NTSTATUS Status;

    Status = NtGetContextThread(hThread, lpContext);
    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL WINAPI MySetThreadContext(
    _In_       HANDLE  hThread,
    _In_ const CONTEXT *lpContext
)
{
    NTSTATUS Status;

    Status = NtSetContextThread(hThread, (PCONTEXT)lpContext);
    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL WINAPI MyFlushInstructionCache(
    _In_ HANDLE  hProcess,
    _In_ LPCVOID lpBaseAddress,
    _In_ SIZE_T  dwSize
)
{
    NTSTATUS Status;

    Status = NtFlushInstructionCache(hProcess, (PVOID)lpBaseAddress, dwSize);
    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL WINAPI MyVirtualProtect(
    _In_  LPVOID lpAddress,
    _In_  SIZE_T dwSize,
    _In_  DWORD  flNewProtect,
    _Out_ PDWORD lpflOldProtect
)
{
    NTSTATUS Status;

    Status = NtProtectVirtualMemory(MyGetCurrentProcess(),
                                    &lpAddress,
                                    &dwSize,
                                    flNewProtect,
                                    (PULONG)lpflOldProtect);
    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    return TRUE;
}

HMODULE WINAPI MyGetModuleHandleW(
    _In_opt_ LPCWSTR lpModuleName
)
{
    UNICODE_STRING usModuleName;
    HANDLE hModule;
    NTSTATUS status;

    RtlInitUnicodeString(&usModuleName, lpModuleName);
    status = LdrGetDllHandle(NULL, NULL, &usModuleName, &hModule);

    if (NT_SUCCESS(status)) {
        return (HMODULE)hModule;
    }

    return NULL;
}

FARPROC WINAPI MyGetProcAddress(
    _In_ HMODULE hModule,
    _In_ LPCSTR  lpProcName
)
{
    ANSI_STRING procNameAnsi;
    RtlInitAnsiString(&procNameAnsi, lpProcName);

    FARPROC procAddress = NULL;
    NTSTATUS status = LdrGetProcedureAddress(hModule, &procNameAnsi, 0, (PVOID *)(&procAddress));
    return (NT_SUCCESS(status)) ? (procAddress) : (NULL);
}

void WINAPI MyGetSystemInfo(
    _Out_ LPSYSTEM_INFO lpSystemInfo
)
{
    my_memset(lpSystemInfo, 0x00, sizeof(*lpSystemInfo));

    // Only initialize the members of SYSTEM_INFO that will actually be used by MinHook.
    lpSystemInfo->dwAllocationGranularity = 64 * 1024;
    lpSystemInfo->lpMinimumApplicationAddress = 0;
    lpSystemInfo->lpMaximumApplicationAddress = (LPVOID)0x7fffffff; // 2 GB
}

HANDLE WINAPI MyCreateToolhelp32Snapshot(
    _In_ DWORD dwFlags,
    _In_ DWORD th32ProcessID
)
{
    // Unimplemented.
    return INVALID_HANDLE_VALUE;
}

BOOL WINAPI MyThread32First(
    _In_    HANDLE          hSnapshot,
    _Inout_ LPTHREADENTRY32 lpte
)
{
    // Unimplemented.
    return FALSE;
}

BOOL WINAPI MyThread32Next(
    _In_  HANDLE          hSnapshot,
    _Out_ LPTHREADENTRY32 lpte
)
{
    // Unimplemented.
    return FALSE;
}
