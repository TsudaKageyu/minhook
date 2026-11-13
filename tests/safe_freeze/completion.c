// SPDX-License-Identifier: BSD-2-Clause

/* Actual strict engine with deterministic failure boundaries. Targets and
 * projected peers are never executed. Real page protection is checked below. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <MinHook.h>

#if defined(_M_X64) || defined(__x86_64__)
#define PEER_IP(c) ((c)->Rip)
#define PEER_SP(c) ((c)->Rsp)
#define PEER_REGISTER(c) ((c)->Rax)
#else
#define PEER_IP(c) ((c)->Eip)
#define PEER_SP(c) ((c)->Esp)
#define PEER_REGISTER(c) ((c)->Eax)
#endif

static BOOL fail_restore, fail_write_protect, fail_flush, fail_free, fail_destroy;
static BOOL two_peers,fail_second_context,fail_stack_read,short_stack_read;
static unsigned fail_write_call,write_calls;
static unsigned fail_free_after,free_calls;
static unsigned checks, enumerations, resumes;
static DWORD_PTR peer_ip, peer_register;
static DWORD_PTR peer_stack[4];
static HANDLE cursor = (HANDLE)(ULONG_PTR)0x6781;
static HANDLE peer = (HANDLE)(ULONG_PTR)0x6782;
static HANDLE cursor2 = (HANDLE)(ULONG_PTR)0x6783;
static HANDLE peer2 = (HANDLE)(ULONG_PTR)0x6784;
static void require(BOOL ok, const char* why) {
    ++checks;
    if (!ok) { fprintf(stderr,"FAIL: %s\n",why); exit(1); }
}
static LONG NTAPI next_peer(HANDLE process,HANDLE previous,ACCESS_MASK access,ULONG attributes,ULONG flags,PHANDLE next) {
    (void)process;(void)access;(void)attributes;(void)flags;++enumerations;
    *next = !previous ? cursor : two_peers && previous==cursor ? cursor2 : NULL;
    return *next ? 0 : (LONG)0x8000001AL;
}
static FARPROC WINAPI lookup(HMODULE module,LPCSTR name) {
    return !strcmp(name,"NtGetNextThread") ? (FARPROC)next_peer : GetProcAddress(module,name);
}
static DWORD WINAPI thread_id(HANDLE h) { return h==cursor || h==cursor2 ? GetCurrentThreadId()+1 : GetThreadId(h); }
static BOOL WINAPI duplicate(HANDLE a,HANDLE h,HANDLE b,LPHANDLE out,DWORD access,BOOL inherit,DWORD flags) {
    if(h==cursor || h==cursor2){*out=h==cursor?peer:peer2;return TRUE;}return DuplicateHandle(a,h,b,out,access,inherit,flags);
}
static DWORD WINAPI suspend_peer(HANDLE h) { return h==peer || h==peer2 ? 0 : SuspendThread(h); }
static DWORD WINAPI resume_peer(HANDLE h) { if(h==peer || h==peer2){++resumes;return 1;}return ResumeThread(h); }
static BOOL WINAPI close_peer(HANDLE h) { return h==peer || h==cursor || h==peer2 || h==cursor2 ? TRUE : CloseHandle(h); }
static BOOL WINAPI exit_code(HANDLE h,LPDWORD out) { if(h==peer || h==peer2){*out=STILL_ACTIVE;return TRUE;}return GetExitCodeThread(h,out); }
static BOOL WINAPI context_peer(HANDLE h,LPCONTEXT out) {
    if(h==peer || h==peer2){DWORD flags=out->ContextFlags;
        if(h==peer2 && fail_second_context){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
        memset(out,0,sizeof(*out));out->ContextFlags=flags;
        PEER_IP(out)=h==peer?peer_ip:0;PEER_REGISTER(out)=peer_register;PEER_SP(out)=(DWORD_PTR)(ULONG_PTR)peer_stack;return TRUE;}
    return GetThreadContext(h,out);
}
static BOOL WINAPI set_context_peer(HANDLE h,const CONTEXT* in) {
    if(h==peer || h==peer2){if(h==peer)peer_ip=PEER_IP(in);return TRUE;}return SetThreadContext(h,in);
}
static SIZE_T WINAPI query(LPCVOID address,PMEMORY_BASIC_INFORMATION out,SIZE_T size) {
    ULONG_PTR at=(ULONG_PTR)address,start=(ULONG_PTR)peer_stack,end=start+sizeof(peer_stack);
    if(at>=start && at<=end){memset(out,0,sizeof(*out));out->BaseAddress=(LPVOID)(at==end?end:start);
        out->AllocationBase=out->BaseAddress;out->RegionSize=at==end?8:sizeof(peer_stack);
        out->State=MEM_COMMIT;out->Protect=PAGE_READWRITE;return sizeof(*out);}
    return VirtualQuery(address,out,size);
}
static BOOL WINAPI protect(LPVOID p,SIZE_T n,DWORD mode,PDWORD old) {
    if(mode==PAGE_EXECUTE_READWRITE)++write_calls;
    if((fail_restore && mode!=PAGE_EXECUTE_READWRITE) || (fail_write_protect && mode==PAGE_EXECUTE_READWRITE) ||
        (fail_write_call && write_calls==fail_write_call && mode==PAGE_EXECUTE_READWRITE)){
        SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return VirtualProtect(p,n,mode,old);
}
static BOOL WINAPI read_stack(HANDLE process,LPCVOID p,LPVOID out,SIZE_T n,SIZE_T* copied) {
    if((ULONG_PTR)p>=(ULONG_PTR)peer_stack && (ULONG_PTR)p<(ULONG_PTR)peer_stack+sizeof(peer_stack)){
        if(fail_stack_read){*copied=0;return FALSE;}
        if(short_stack_read){memcpy(out,p,n);*copied=n-1;return TRUE;}}
    return ReadProcessMemory(process,p,out,n,copied);
}
static BOOL WINAPI flush(HANDLE process,LPCVOID p,SIZE_T n) {
    if(fail_flush){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return FlushInstructionCache(process,p,n);
}
static BOOL WINAPI release(LPVOID p,SIZE_T n,DWORD mode) {
    ++free_calls;
    if(fail_free || (fail_free_after && free_calls>fail_free_after)){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return VirtualFree(p,n,mode);
}
static BOOL WINAPI destroy(HANDLE h) {
    if(fail_destroy){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return HeapDestroy(h);
}
#define GetProcAddress lookup
#define GetThreadId thread_id
#define DuplicateHandle duplicate
#define SuspendThread suspend_peer
#define ResumeThread resume_peer
#define CloseHandle close_peer
#define GetExitCodeThread exit_code
#define GetThreadContext context_peer
#define SetThreadContext set_context_peer
#define VirtualQuery query
#define VirtualProtect protect
#define FlushInstructionCache flush
#define VirtualFree release
#define HeapDestroy destroy
#define ReadProcessMemory read_stack
#include "buffer.c"
#include "hook.c"
#undef VirtualProtect
#undef VirtualFree

static unsigned char* target;
static void setup(void) {
    DWORD old;
    fail_restore=fail_write_protect=fail_flush=fail_free=fail_destroy=FALSE;
    two_peers=fail_second_context=fail_stack_read=short_stack_read=FALSE;
    fail_write_call=write_calls=0;
    fail_free_after=free_calls=0;
    peer_ip=peer_register=0;memset(peer_stack,0,sizeof peer_stack);
    require(MH_Initialize()==MH_OK,"initialize completion fixture");
    target=(unsigned char*)VirtualAlloc(NULL,8192,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    require(target!=NULL,"allocate two-page target");memset(target,0x90,8192);target[32]=target[96]=0xc3;
    require(VirtualProtect(target,8192,PAGE_EXECUTE_READ,&old),"protect target RX");
}
static LPVOID create_at(unsigned offset) {
    LPVOID original=NULL;
    require(MH_CreateHook(target+offset,target+96,&original)==MH_OK && original!=NULL,"create completion hook");
    return original;
}
static void finish(void) {
    require(MH_Uninitialize()==MH_OK,"completion fixture shutdown");
    require(VirtualFree(target,0,MEM_RELEASE),"release completion target");target=NULL;
}
static void completion_retry(BOOL cache) {
    LPVOID original;unsigned before;
    setup();original=create_at(0);(void)original;
    fail_flush=cache;fail_restore=!cache;
    before=resumes;
    require(MH_EnableHook(target)==MH_ERROR_MEMORY_PROTECT,"post-write completion failure must not report success");
    require(resumes==before,"incomplete instruction stream cannot resume owned peers");
    before=enumerations;
    require(MH_ApplyQueued()==MH_ERROR_MEMORY_PROTECT && enumerations==before,"pending completion blocks even no-op apply without acquiring peers");
    require(MH_EnableHook(target)==MH_ERROR_MEMORY_PROTECT,"already-enabled request cannot hide incomplete completion");
    require(MH_QueueDisableHook(target)==MH_ERROR_MEMORY_PROTECT,"pending completion preserves queued intent");
    require(MH_RemoveHook(target)==MH_ERROR_MEMORY_PROTECT,"pending completion retains hook storage");
    fail_flush=fail_restore=FALSE;
    require(MH_DisableHook(target)==MH_OK,"retry completes prior write before disabling");
    require(target[0]==0x90,"retry restores exact target bytes");finish();
}
static void prewrite_retirement(void) {
    LPVOID original;setup();original=create_at(0);peer_ip=(DWORD_PTR)(ULONG_PTR)target;
    fail_write_protect=TRUE;
    require(MH_EnableHook(target)==MH_ERROR_MEMORY_PROTECT && target[0]==0x90,"pre-write failure leaves target unchanged");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)original,"preparation already redirected projected peer");
    fail_write_protect=FALSE;
    require(MH_RemoveHook(target)==MH_ERROR_MEMORY_PROTECT,"disabled removal retains trampoline occupied by projected peer");
    require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT,"uninitialize retains trampoline occupied by projected peer");
    peer_ip=0;peer_stack[0]=(DWORD_PTR)(ULONG_PTR)original;
    require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT,"trampoline return address retains allocation");
    peer_stack[0]=0;peer_register=(DWORD_PTR)(ULONG_PTR)original;
    require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT,"trampoline address in register retains allocation");
    peer_register=0;finish();
}
static void release_retry(BOOL heap) {
    HANDLE owner;setup();create_at(0);owner=g_hHeap;
    fail_destroy=heap;fail_free=!heap;
    require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT && g_hHeap==owner,"failed retirement keeps exact engine owner");
    require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT && g_hHeap==owner,"persistent retirement failure stays retryable");
    require(MH_EnableHook(target)==MH_ERROR_MEMORY_PROTECT,"partial retirement prohibits mutations");
    fail_destroy=fail_free=FALSE;finish();
}
static void page_protections(void) {
    DWORD old;MEMORY_BASIC_INFORMATION first,second;setup();
    require(VirtualProtect(target+4096,4096,PAGE_EXECUTE_READWRITE,&old),"different second-page protection");
    create_at(4094);
    require(MH_EnableHook(target+4094)==MH_OK,"enable cross-page target");
    require(VirtualQuery(target,&first,sizeof first) && VirtualQuery(target+4096,&second,sizeof second),"query actual page protections");
    require(first.Protect==PAGE_EXECUTE_READ && second.Protect==PAGE_EXECUTE_READWRITE,"restore each page's own protection");
    require(MH_DisableHook(target+4094)==MH_OK,"disable cross-page target");
    require(VirtualQuery(target+4096,&second,sizeof second) && second.Protect==PAGE_EXECUTE_READWRITE,"disable preserves second-page protection");finish();
}
static void unpublished_failure(void) {
    LPVOID original=(LPVOID)(ULONG_PTR)0x1234;setup();fail_flush=fail_free=TRUE;
    require(MH_CreateHook(target,target+96,&original)==MH_ERROR_MEMORY_PROTECT && original==(LPVOID)(ULONG_PTR)0x1234,"failed generated-code flush never publishes original");
    require(MH_ApplyQueued()==MH_ERROR_MEMORY_PROTECT,"failed unpublished-buffer release retains owner");
    fail_flush=fail_free=FALSE;create_at(0);finish();
}
static void partial_batch(void) {
    LPVOID second;setup();create_at(0);second=create_at(64);
    require(MH_QueueEnableHook(target)==MH_OK && MH_QueueEnableHook(target+64)==MH_OK,"queue two-target batch");
    peer_ip=(DWORD_PTR)(ULONG_PTR)(target+64);fail_write_call=2;
    require(MH_ApplyQueued()==MH_ERROR_MEMORY_PROTECT && target[0]==0xe9 && target[64]==0x90,"second-target failure preserves physical partial-batch state");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)second,"unwritten batch target can already have redirected peer");
    fail_write_call=0;
    require(MH_DisableHook(MH_ALL_HOOKS)==MH_OK && target[0]==0x90 && target[64]==0x90,"explicit rollback restores written prefix");
    require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT,"rollback still retains unwritten target trampoline with redirected peer");
    peer_ip=0;finish();
}
static void partial_preparation(void) {
    LPVOID original;setup();original=create_at(0);two_peers=fail_second_context=TRUE;peer_ip=(DWORD_PTR)(ULONG_PTR)target;
    require(MH_EnableHook(target)==MH_ERROR_MEMORY_PROTECT && target[0]==0x90,"later peer preparation failure rejects target mutation");
    require(peer_ip==(DWORD_PTR)(ULONG_PTR)original,"earlier successful IP update remains accounted for");
    fail_second_context=FALSE;
    require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT,"partial peer preparation cannot release occupied trampoline");
    peer_ip=0;finish();
}
static void stack_failures(void) {
    setup();create_at(0);fail_stack_read=TRUE;
    require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT,"unreadable peer stack rejects retirement");
    fail_stack_read=FALSE;short_stack_read=TRUE;
    require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT,"short stack read rejects retirement");
    short_stack_read=FALSE;finish();
}
static void patch_above_pages(void) {
    DWORD old;LPVOID original;MEMORY_BASIC_INFORMATION region;setup();
    require(VirtualProtect(target,8192,PAGE_EXECUTE_READWRITE,&old),"prepare hotpatch fixture");
    target[4097]=0xc3;target[4098]=0x90;target[4099]=1;
    require(VirtualProtect(target,4096,PAGE_EXECUTE_READ,&old),"first hotpatch page RX");
    original=create_at(4097);(void)original;
    require(g_hooks.pItems[FindHookEntry(target+4097)].patchAbove,"fixture selects seven-byte patch-above range");
    require(MH_EnableHook(target+4097)==MH_OK && target[4092]==0xe9 && target[4097]==0xeb,"enable cross-page hotpatch");
    require(VirtualQuery(target+4096,&region,sizeof region) && region.Protect==PAGE_EXECUTE_READWRITE,"hotpatch preserves second-page protection");
    require(MH_DisableHook(target+4097)==MH_OK && target[4092]==0x90 && target[4097]==0xc3,"disable restores hotpatch bytes");finish();
}
static void partial_block_retirement(void) {
    HANDLE owner;unsigned i;setup();
    for(i=0;i<MEMORY_BLOCK_SIZE/MEMORY_SLOT_SIZE+6;++i)create_at(i*32);
    owner=g_hHeap;fail_free_after=1;
    require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT && free_calls==2,"second block-release failure follows one successful release");
    require(g_hHeap==owner && g_pMemoryBlocks!=NULL && g_pMemoryBlocks->pNext==NULL,"partial retirement keeps the sole remaining block and heap");
    require(MH_QueueEnableHook(target)==MH_ERROR_MEMORY_PROTECT,"partial retirement prohibits reusing stale hook entries");
    require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT && free_calls==3,"retry touches only the remaining block");
    fail_free_after=0;finish();
}
int main(int argc,char** argv) {
    const char* mode=argc>1?argv[1]:"all";
    if(!strcmp(mode,"all")||!strcmp(mode,"restore"))completion_retry(FALSE);
    if(!strcmp(mode,"all")||!strcmp(mode,"cache"))completion_retry(TRUE);
    if(!strcmp(mode,"all")||!strcmp(mode,"prewrite"))prewrite_retirement();
    if(!strcmp(mode,"all")||!strcmp(mode,"free"))release_retry(FALSE);
    if(!strcmp(mode,"all")||!strcmp(mode,"heap"))release_retry(TRUE);
    if(!strcmp(mode,"all")||!strcmp(mode,"pages"))page_protections();
    if(!strcmp(mode,"all")||!strcmp(mode,"unpublished"))unpublished_failure();
    if(!strcmp(mode,"all")){partial_batch();partial_preparation();stack_failures();patch_above_pages();partial_block_retirement();}
    require(checks!=0,"known completion test mode required");
    printf("PASS: %u completion, control-flow, retirement and page checks (projected peers)\n",checks);
    return 0;
}
