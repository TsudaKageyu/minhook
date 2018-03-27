#include "../include/MinHook.h"
#include "api.h"
#include <windows.h>
#include <winternl.h>

ULONG_PTR GetCurrentNestingLevel();
VOID IncrementCurrentNestingLevel();
VOID DecrementCurrentNestingLevel();

PTEB GetCurrentTeb64()
{
    return (PTEB)__readgsqword(offsetof(NT_TIB64, Self));
}

PULONG_PTR GetCurrentNestingLevelPtr()
{
    // We don't have TLS APIs at our disposal, so using thread-local variables is a bit tricky.
    // Luckily, we can use some members of the TEB (which is already instantiated on a per-thread basis) for our advantage.
    // In this particular case where we only want to store a single integer value (the nesting level), we chose to "abuse"
    // the last slot in the TlsSlots array, since we know it is currently not used by any other 64-bit modules in WoW64 processes.
    return (PULONG_PTR)&GetCurrentTeb64()->TlsSlots[63];
}

ULONG_PTR GetCurrentNestingLevel()
{
    return *GetCurrentNestingLevelPtr();
}

VOID IncrementCurrentNestingLevel()
{
    (*GetCurrentNestingLevelPtr())++;
}

VOID DecrementCurrentNestingLevel()
{
    (*GetCurrentNestingLevelPtr())--;
}

typedef NTSTATUS(NTAPI *NTALLOCATEVIRTUALMEMORY)(HANDLE, PVOID *, ULONG, PULONG, ULONG, ULONG);
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG, PULONG, ULONG, ULONG);

// Pointer for calling original MessageBoxW.
NTALLOCATEVIRTUALMEMORY fpNtAllocateVirtualMemory = NULL;
NTALLOCATEVIRTUALMEMORY fpNtAllocateVirtualMemoryOrig = NULL;

NTSTATUS NTAPI DetourNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect)
{
    IncrementCurrentNestingLevel();

    do {
        if (GetCurrentNestingLevel() > 1) {
            break;
        }
        // Insert your code here.
    } while (FALSE);

    DecrementCurrentNestingLevel();
    return fpNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

HMODULE ntdll;

BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        ntdll = MyGetModuleHandleW(L"ntdll.dll");
        fpNtAllocateVirtualMemoryOrig = (NTALLOCATEVIRTUALMEMORY)(MyGetProcAddress(ntdll, "NtAllocateVirtualMemory"));

        // Initialize MinHook.
        if (MH_Initialize() != MH_OK)
        {
            return FALSE;
        }

        if (MH_CreateHook(fpNtAllocateVirtualMemoryOrig, &DetourNtAllocateVirtualMemory,
            (LPVOID*)(&fpNtAllocateVirtualMemory)) != MH_OK)
        {
            return FALSE;
        }

        // Enable the hook for MessageBoxW.
        if (MH_EnableHook(fpNtAllocateVirtualMemoryOrig) != MH_OK)
        {
            return FALSE;
        }
    }

    return TRUE;
}