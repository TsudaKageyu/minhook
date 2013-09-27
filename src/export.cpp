/* 
 *  MinHook - Minimalistic API Hook Library	
 *  Copyright (C) 2009 Tsuda Kageyu. All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. The name of the author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 *  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <Windows.h>
#include "MinHook.h"
#include "hook.h"

using namespace MinHook;

MH_STATUS WINAPI MH_Initialize()
{
	return Initialize();
}

MH_STATUS WINAPI MH_Uninitialize()
{
	return Uninitialize();
}

MH_STATUS WINAPI MH_CreateHook(void* pTarget, void* const pDetour, void** ppOriginal)
{
	return CreateHook(pTarget, pDetour, ppOriginal);
}

MH_STATUS WINAPI MH_RemoveHook(void* pTarget)
{
	return RemoveHook(pTarget);
}

MH_STATUS WINAPI MH_EnableHook(void* pTarget)
{
	return EnableHook(pTarget);
}

MH_STATUS WINAPI MH_DisableHook(void* pTarget)
{
	return DisableHook(pTarget);
}

MH_STATUS WINAPI MH_QueueEnableHook(void* pTarget)
{
	return QueueEnableHook(pTarget);
}

MH_STATUS WINAPI MH_QueueDisableHook(void* pTarget)
{
	return QueueDisableHook(pTarget);
}

MH_STATUS WINAPI MH_ApplyQueued()
{
	return ApplyQueued();
}
