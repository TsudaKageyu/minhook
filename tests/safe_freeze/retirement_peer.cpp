// SPDX-License-Identifier: BSD-2-Clause

// A genuine Windows peer remains externally suspended throughout each edited
// context/stack case. It never executes a fixture target or trampoline.
#define NOMINMAX
#include <windows.h>
#include <MinHook.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>

#if defined(_M_X64) || defined(__x86_64__)
#define PEER_IP(c) ((c).Rip)
#define PEER_SP(c) ((c).Rsp)
#define PEER_REGISTER(c) ((c).Rax)
#else
#define PEER_IP(c) ((c).Eip)
#define PEER_SP(c) ((c).Esp)
#define PEER_REGISTER(c) ((c).Eax)
#endif

namespace {
unsigned checks;
void require(bool value,const char* why){++checks;if(!value)throw std::runtime_error(why);}
DWORD WINAPI worker(void*){return 0;}
void still_owned(void* original){
    MEMORY_BASIC_INFORMATION region{};
    require(VirtualQuery(original,&region,sizeof region)!=0 && region.State==MEM_COMMIT,
            "busy retirement preserves actual trampoline allocation");
}
}
int main(){
    try{
        require(MH_Initialize()==MH_OK,"initialize actual retirement engine");
        auto* target=static_cast<unsigned char*>(VirtualAlloc(nullptr,128,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE));
        require(target!=nullptr,"allocate retirement target");
        std::memset(target,0x90,128);target[16]=target[64]=0xc3;
        void* original=nullptr;
        require(MH_CreateHook(target,target+64,&original)==MH_OK && original,"create actual disabled trampoline");
        const HANDLE peer=CreateThread(nullptr,0,worker,nullptr,CREATE_SUSPENDED,nullptr);
        require(peer!=nullptr,"create externally suspended actual peer");
        CONTEXT saved{};saved.ContextFlags=CONTEXT_FULL;
        require(GetThreadContext(peer,&saved)!=FALSE,"save real peer context");
        auto edited=saved;PEER_IP(edited)=reinterpret_cast<std::uintptr_t>(original);
        require(SetThreadContext(peer,&edited)!=FALSE,"place suspended peer IP in actual trampoline");
        require(MH_RemoveHook(target)==MH_ERROR_MEMORY_PROTECT,"real trampoline IP blocks disabled removal");
        require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT,"real trampoline IP blocks uninitialize");still_owned(original);
        require(SuspendThread(peer)==1,"retirement preserves external suspension count");
        require(ResumeThread(peer)==2,"repay only test's inspection suspension");
        edited=saved;PEER_REGISTER(edited)=reinterpret_cast<std::uintptr_t>(original);
        require(SetThreadContext(peer,&edited)!=FALSE,"place generated-code address in real register");
        require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT,"real register address blocks retirement");still_owned(original);
        require(SetThreadContext(peer,&saved)!=FALSE,"restore real context before stack case");
        std::uintptr_t backup=0,value=reinterpret_cast<std::uintptr_t>(original);SIZE_T copied=0;
        auto* slot=reinterpret_cast<void*>(PEER_SP(saved));
        require(ReadProcessMemory(GetCurrentProcess(),slot,&backup,sizeof backup,&copied)!=FALSE && copied==sizeof backup,
                "save real suspended stack word");
        require(WriteProcessMemory(GetCurrentProcess(),slot,&value,sizeof value,&copied)!=FALSE && copied==sizeof value,
                "place generated-code return address in real suspended stack");
        require(MH_Uninitialize()==MH_ERROR_MEMORY_PROTECT,"real stack address blocks retirement");still_owned(original);
        require(WriteProcessMemory(GetCurrentProcess(),slot,&backup,sizeof backup,&copied)!=FALSE && copied==sizeof backup,
                "restore exact original stack word before peer executes");
        require(SetThreadContext(peer,&saved)!=FALSE,"restore exact original context before peer executes");
        require(ResumeThread(peer)==1,"resume only external suspension after restoration");
        require(WaitForSingleObject(peer,10000)==WAIT_OBJECT_0,"join actual peer");
        require(CloseHandle(peer)!=FALSE,"release actual peer handle");
        require(MH_RemoveHook(target)==MH_OK,"quiescent disabled hook retires");
        require(MH_Uninitialize()==MH_OK,"quiescent engine releases heap");
        require(VirtualFree(target,0,MEM_RELEASE)!=FALSE,"release fixture target");
        std::cout<<"PASS: "<<checks<<" actual Windows peer retirement checks; no fixture code executed\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}
}
