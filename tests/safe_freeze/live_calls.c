// SPDX-License-Identifier: BSD-2-Clause
// Real WINAPI calls on owned executable fixtures. Join callers before removal.
#include <windows.h>
#include <MinHook.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef int (WINAPI *FIXTURE_FUNCTION)(int);
typedef struct _CALLER
{
    FIXTURE_FUNCTION target,original;
    HANDLE ready,stop;
    volatile LONG calls,bad;
} CALLER;
static unsigned checks;
static void check(BOOL ok,const char *message)
{
    ++checks;
    if(!ok){fprintf(stderr,"FAIL: %s error=%lu\n",message,GetLastError());ExitProcess(1);}
}
static DWORD handle_count(void)
{
    DWORD n;check(GetProcessHandleCount(GetCurrentProcess(),&n),"handle observation");return n;
}
static DWORD WINAPI caller(void *parameter)
{
    CALLER *state=(CALLER*)parameter;
    if(!SetEvent(state->ready))return 2;
    while(WaitForSingleObject(state->stop,0)==WAIT_TIMEOUT)
    {
        int result=state->target(5);
        if((result!=12&&result!=47)||state->original(5)!=12)
        {
            InterlockedExchange(&state->bad,1);return 3;
        }
        InterlockedIncrement(&state->calls);
        if((state->calls&255)==0)SwitchToThread();
    }
    return 0x53;
}
static void results(CALLER *state,int expected)
{
    check(state->target(5)==expected,"actual target return value");
    check(state->original(5)==12,"actual original trampoline return value");
    check(state->bad==0,"concurrent caller observed only valid results");
}
int main(void)
{
    unsigned session,cycle;DWORD initial;
    unsigned long long calls=0;
    unsigned char *arena;
    puts("LIVE_CALLS: actual target/original calls with owned caller quiescence");
    initial=handle_count();
    arena=VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    check(arena!=NULL,"allocate executable fixtures");memset(arena,0x90,4096);
#if defined(_M_X64) || defined(__x86_64__)
    {const unsigned char target[]={0x8d,0x41,0x07,0xc3};
     const unsigned char detour[]={0x8d,0x41,0x2a,0xc3};
     memcpy(arena,target,sizeof target);memcpy(arena+64,detour,sizeof detour);}
#else
    {const unsigned char target[]={0x8b,0x44,0x24,0x04,0x83,0xc0,0x07,0xc2,0x04,0x00};
     const unsigned char detour[]={0x8b,0x44,0x24,0x04,0x83,0xc0,0x2a,0xc2,0x04,0x00};
     memcpy(arena,target,sizeof target);memcpy(arena+64,detour,sizeof detour);}
#endif
    check(FlushInstructionCache(GetCurrentProcess(),arena,4096),"flush executable fixtures");
    for(session=0;session<20;++session)
    {
        CALLER state;void *original=NULL;HANDLE thread;DWORD started,code;
        unsigned char bytes[16];memcpy(bytes,arena,sizeof bytes);memset(&state,0,sizeof state);
        state.target=(FIXTURE_FUNCTION)arena;
        check(state.target(5)==12,"unhooked WINAPI caller");
        check(MH_Initialize()==MH_OK,"initialize caller session");
        check(MH_CreateHook(arena,arena+64,&original)==MH_OK&&original!=NULL,"create actual original trampoline");
        state.original=(FIXTURE_FUNCTION)original;
        state.ready=CreateEventW(NULL,TRUE,FALSE,NULL);state.stop=CreateEventW(NULL,TRUE,FALSE,NULL);
        check(state.ready&&state.stop,"owned caller events");
        thread=CreateThread(NULL,0,caller,&state,0,NULL);check(thread!=NULL,"owned active caller");
        check(WaitForSingleObject(state.ready,5000)==WAIT_OBJECT_0,"caller completed loader startup");
        started=GetTickCount();while(state.calls<256&&state.bad==0&&GetTickCount()-started<5000)Sleep(1);
        check(state.calls>=256&&state.bad==0,"real calls executed before patch transitions");
        for(cycle=0;cycle<10;++cycle)
        {
            check(MH_EnableHook(arena)==MH_OK,"single enable with active calls");results(&state,47);
            check(MH_DisableHook(arena)==MH_OK,"single disable with active calls");results(&state,12);
            check(MH_QueueEnableHook(arena)==MH_OK&&MH_ApplyQueued()==MH_OK,"queued enable with active calls");results(&state,47);
            check(MH_QueueDisableHook(arena)==MH_OK&&MH_ApplyQueued()==MH_OK,"queued disable with active calls");results(&state,12);
        }
        check(SetEvent(state.stop),"request caller quiescence");
        check(WaitForSingleObject(thread,5000)==WAIT_OBJECT_0,"join before trampoline removal");
        check(GetExitCodeThread(thread,&code)&&code==0x53&&state.bad==0,"all actual caller results valid");
        calls+=(unsigned long)state.calls;
        check(CloseHandle(thread)&&CloseHandle(state.ready)&&CloseHandle(state.stop),"close exact caller owners");
        check(MH_EnableHook(arena)==MH_OK&&state.target(5)==47,"enable before quiescent removal");
        check(MH_RemoveHook(arena)==MH_OK&&state.target(5)==12,"remove only after caller drain");
        check(memcmp(bytes,arena,sizeof bytes)==0,"exact target bytes after removal");
        original=NULL;check(MH_CreateHook(arena,arena+64,&original)==MH_OK,"recreate before active uninitialize");
        check(MH_EnableHook(arena)==MH_OK&&state.target(5)==47,"actual call before uninitialize");
        check(MH_Uninitialize()==MH_OK&&state.target(5)==12,"uninitialize restores executable target");
        check(MH_DisableHook(arena)==MH_ERROR_NOT_INITIALIZED,"engine ownership retired");
        check(memcmp(bytes,arena,sizeof bytes)==0,"exact target bytes after uninitialize");
    }
    check(VirtualFree(arena,0,MEM_RELEASE),"release code only after all callers and engines retire");
    check(handle_count()==initial,"zero residual caller/engine handles");
    printf("{\"scenario\":\"actual_winapi_target_and_original_calls\",\"architecture_bits\":%u,\"sessions\":20,\"patch_transitions\":800,\"checks\":%u,\"actual_calls\":%llu,\"bad_results\":0,\"residual_handles\":0}\n",(unsigned)(8*sizeof(void*)),checks,calls);
    return 0;
}
