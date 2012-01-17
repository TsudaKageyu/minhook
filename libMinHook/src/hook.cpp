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

#include <cassert>
#include <vector>
#include <algorithm>
#include <functional>
#include <boost/scope_exit.hpp>
#include <boost/foreach.hpp>
#include <Windows.h>
#include "pstdint.h"

#include "../MinHook.h"
#include "hook.h"
#include "buffer.h"
#include "trampoline.h"
#include "thread.h"

namespace MinHook { namespace
{
	struct HOOK_ENTRY
	{
		void*	pTarget;
		void*	pDetour;
#if defined _M_X64
		void*	pRelay;
#endif
		void*	pTrampoline;
		void*	pBackup;
		bool	isEnabled;
		std::vector<uintptr_t>	oldIPs;
		std::vector<uintptr_t>	newIPs;
	};

	// 命令書き込み用構造体
#pragma pack(push, 1)
	struct JMP_REL
	{
		uint8_t		opcode;
		uint32_t	operand;
	};

	struct JMP_ABS
	{
		uint16_t	opcode;
		uint32_t	operand;
	};
#pragma pack(pop)

	HOOK_ENTRY* FindHook(void* const pTarget);
	bool		IsExecutableAddress(void* pAddress);
	void		WriteRelativeJump(void* pFrom, void* const pTo);
	void		WriteAbsoluteJump(void* pFrom, void* const pTo, void* pTable);

	template <typename T>
	bool operator <(const HOOK_ENTRY& lhs, const T& rhs) ;
	template <typename T>
	bool operator <(const T& lhs, const HOOK_ENTRY& rhs) ;
	bool operator <(const HOOK_ENTRY& lhs, const HOOK_ENTRY& rhs);

	CriticalSection gCS;
	std::vector<HOOK_ENTRY> gHooks;
	bool gIsInitialized = false;
}}

namespace MinHook
{
	MH_STATUS Initialize()
	{
		CriticalSection::ScopedLock lock(gCS);

		if (gIsInitialized)
		{
			return MH_ERROR_ALREADY_INITIALIZED;
		}

		// 内部関数バッファの初期化
		InitializeBuffer();

		gIsInitialized = true;
		return MH_OK;
	}

	MH_STATUS Uninitialize()
	{
		CriticalSection::ScopedLock lock(gCS);

		if (!gIsInitialized)
		{
			return MH_ERROR_NOT_INITIALIZED;
		}

		// すべてのフックを解除
		BOOST_FOREACH (const HOOK_ENTRY& hook, gHooks)
		{
			if (!hook.isEnabled)
			{
				continue;
			}
			
			MH_STATUS status = DisableHook(hook.pTarget);
			if (status != MH_OK)
			{
				return status;
			}
		}

		std::vector<HOOK_ENTRY> v;
		gHooks.swap(v);

		// 内部関数バッファの開放
		UninitializeBuffer();

		gIsInitialized = false;
		return MH_OK;
	}

	MH_STATUS CreateHook(void* pTarget, void* const pDetour, void** ppOriginal)
	{
		CriticalSection::ScopedLock lock(gCS);

		if (!gIsInitialized)
		{
			return MH_ERROR_NOT_INITIALIZED;
		}

		HOOK_ENTRY *pHook = FindHook(pTarget);
		if (pHook != NULL)
		{
			return MH_ERROR_ALREADY_CREATED;
		}

		if (!IsExecutableAddress(pTarget) || !IsExecutableAddress(pDetour))
		{
			return MH_ERROR_NOT_EXECUTABLE;
		}

		if (pHook == NULL)
		{
			bool committed = false;
			BOOST_SCOPE_EXIT((&committed))
			{
				if (!committed)
				{
					RollbackBuffer();
				}
			}
			BOOST_SCOPE_EXIT_END;

			// トランポリン関数を作成する
			CREATE_TREMPOLINE_T ct = { 0 };
			ct.pTarget = pTarget;
			if (!CreateTrampolineFunction(ct))
			{
				return MH_ERROR_UNSUPPORTED_FUNCTION;
			}

			void* pTrampoline = AllocateCodeBuffer(pTarget, ct.trampoline.size());
			if (pTrampoline == NULL)
			{
				return MH_ERROR_MEMORY_ALLOC;
			}
#if defined _M_X64
			void* pTable = AllocateDataBuffer(pTrampoline, (ct.table.size() + 1) * sizeof(uintptr_t));
			if (pTable == NULL)
			{
				return MH_ERROR_MEMORY_ALLOC;
			}
#endif

			ct.pTrampoline = pTrampoline;
#if defined _M_X64
			ct.pTable = pTable;
#endif
			if (!ResolveTemporaryAddresses(ct))
			{
				return MH_ERROR_UNSUPPORTED_FUNCTION;
			}

			memcpy(pTrampoline, &ct.trampoline[ 0 ], ct.trampoline.size());
#if defined _M_X64
			if (ct.table.size() != 0)
			{
				memcpy(pTable, &ct.table[ 0 ], ct.table.size() * sizeof(uintptr_t));
			}
#endif

			// ターゲット関数のバックアップをとる
			void* pBackup = AllocateDataBuffer(NULL, sizeof(JMP_REL));
			if (pBackup == NULL)
			{
				return MH_ERROR_MEMORY_ALLOC;
			}

			memcpy(pBackup, pTarget, sizeof(JMP_REL));

			// 中継関数を作成する
#if defined _M_X64
			void* pRelay = AllocateCodeBuffer(pTarget, sizeof(JMP_ABS));
			if (pRelay == NULL)
			{
				return MH_ERROR_MEMORY_ALLOC;
			}

			WriteAbsoluteJump(pRelay, pDetour, reinterpret_cast<uintptr_t*>(pTable) + ct.table.size());
#endif
			CommitBuffer();
			committed = true;

			// フック情報の登録
			HOOK_ENTRY hook = { 0 };
			hook.pTarget = pTarget;
			hook.pDetour = pDetour;
#if defined _M_X64
			hook.pRelay  = pRelay;
#endif
			hook.pTrampoline = pTrampoline;
			hook.pBackup = pBackup;
			hook.isEnabled = false;
			hook.oldIPs = ct.oldIPs;
			hook.newIPs = ct.newIPs;

			std::vector<HOOK_ENTRY>::iterator i	= std::lower_bound(gHooks.begin(), gHooks.end(), hook);
			i = gHooks.insert(i, hook);
			pHook = &(*i);

		}

		// OUT引数の処理
		*ppOriginal = pHook->pTrampoline;
		
		return MH_OK;
	}

	MH_STATUS EnableHook(void* pTarget)
	{
		CriticalSection::ScopedLock lock(gCS);

		if (!gIsInitialized)
		{
			return MH_ERROR_NOT_INITIALIZED;
		}

		HOOK_ENTRY *pHook = FindHook(pTarget);
		if (pHook == NULL)
		{
			return MH_ERROR_NOT_CREATED;
		}

		if (pHook->isEnabled)
		{
			return MH_ERROR_ENABLED;
		}

		// ターゲット関数の冒頭に、中継関数またはフック関数へのジャンプを書き込む
		{
			ScopedThreadExclusive tex(pHook->oldIPs, pHook->newIPs);

			DWORD oldProtect;
			if (!VirtualProtect(pHook->pTarget, sizeof(JMP_REL), PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				return MH_ERROR_MEMORY_PROTECT;
			}

#if defined _M_X64
			WriteRelativeJump(pHook->pTarget, pHook->pRelay);
#elif defined _M_IX86
			WriteRelativeJump(pHook->pTarget, pHook->pDetour);
#endif
			VirtualProtect(pHook->pTarget, sizeof(JMP_REL), oldProtect, &oldProtect);
		}

		pHook->isEnabled = true;

		return MH_OK;
	}

	MH_STATUS DisableHook(void* pTarget)
	{
		CriticalSection::ScopedLock lock(gCS);

		if (!gIsInitialized)
		{
			return MH_ERROR_NOT_INITIALIZED;
		}

		HOOK_ENTRY *pHook = FindHook(pTarget);
		if (pHook == NULL)
		{
			return MH_ERROR_NOT_CREATED;
		}

		if (!pHook->isEnabled)
		{
			return MH_ERROR_DISABLED;
		}

		// ターゲット関数の冒頭を書き戻すだけ。他は再利用のため残しておく
		{
			ScopedThreadExclusive tex(pHook->oldIPs, pHook->newIPs);

			DWORD oldProtect;
			if (!VirtualProtect(pHook->pTarget, sizeof(JMP_REL), PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				return MH_ERROR_MEMORY_PROTECT;
			}

			memcpy(pHook->pTarget, pHook->pBackup, sizeof(JMP_REL));

			VirtualProtect(pHook->pTarget, sizeof(JMP_REL), oldProtect, &oldProtect);
		}

		pHook->isEnabled = false;

		return MH_OK;
	}
}
namespace MinHook { namespace
{
	HOOK_ENTRY* FindHook(void* const pTarget)
	{
		std::vector<HOOK_ENTRY>::iterator i 
			= std::lower_bound(gHooks.begin(), gHooks.end(), pTarget);
		if (i != gHooks.end() && i->pTarget == pTarget)
		{
			return &(*i);
		}

		return NULL;
	}

	bool IsExecutableAddress(void* pAddress)
	{
		static const DWORD PageExecuteMask 
			= (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY); 

		// 未割り当てや実行不可能な領域をチェック
		MEMORY_BASIC_INFORMATION mi = { 0 };
		VirtualQuery(pAddress, &mi, sizeof(mi));

		return ((mi.Protect & PageExecuteMask) != 0);
	}

	void WriteRelativeJump(void* pFrom, void* const pTo)
	{
		JMP_REL jmp;
		jmp.opcode  = 0xE9;
		jmp.operand = static_cast<uint32_t>(reinterpret_cast<char*>(pTo) - (reinterpret_cast<char*>(pFrom) + sizeof(jmp)));

		memcpy(pFrom, &jmp, sizeof(jmp));
	}

	void WriteAbsoluteJump(void* pFrom, void* const pTo, void* pTable)
	{
		JMP_ABS jmp;
		jmp.opcode  = 0x25FF;
		jmp.operand = static_cast<uint32_t>(reinterpret_cast<char*>(pTable) - (reinterpret_cast<char*>(pFrom) + sizeof(jmp)));

		memcpy(pFrom,  &jmp, sizeof(jmp));
		memcpy(pTable, &pTo, sizeof(pTo));
	}

	template <typename T>
	bool operator <(const HOOK_ENTRY& lhs, const T& rhs) 
	{ 
		return lhs.pTarget < reinterpret_cast<void*>(rhs); 
	}

	template <typename T>
	bool operator <(const T& lhs, const HOOK_ENTRY& rhs) 
	{ 
		return reinterpret_cast<void*>(lhs) < rhs.pTarget; 
	}

	bool operator <(const HOOK_ENTRY& lhs, const HOOK_ENTRY& rhs)
	{ 
		return lhs.pTarget < rhs.pTarget;
	}
}}
