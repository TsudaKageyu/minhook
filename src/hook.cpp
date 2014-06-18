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
#include <Windows.h>
#include "pstdint.h"

#include "MinHook.h"
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
		void*	pTable;
		void*	pRelay;
#endif
		void*	pTrampoline;
		void*	pBackup;
		bool	patchAbove;
		bool	isEnabled;
		bool	queueEnable;
		std::vector<uintptr_t>	oldIPs;
		std::vector<uintptr_t>	newIPs;
	};

	// Structs for writing x86/x64 instcutions.
#pragma pack(push, 1)
	struct JMP_REL_SHORT
	{
		uint8_t		opcode;
		uint8_t		operand;
	};

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

	MH_STATUS	EnableHookLL(HOOK_ENTRY *pHook);
	MH_STATUS	DisableHookLL(HOOK_ENTRY *pHook);
	MH_STATUS	EnableAllHooksLL();
	MH_STATUS	DisableAllHooksLL();
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

		// Initialize the internal function buffer.
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

		// Disable all hooks.
		MH_STATUS status = DisableAllHooksLL();
		if (status != MH_OK)
		{
			return status;
		}

		std::vector<HOOK_ENTRY> v;
		gHooks.swap(v);

		// Free the internal function buffer.
		UninitializeBuffer();

		gIsInitialized = false;
		return MH_OK;
	}

	struct RollbackIfNotCommitted
	{
		bool* committed_;
		RollbackIfNotCommitted(bool* committed)
		 : committed_(committed)
		{
		}
		~RollbackIfNotCommitted()
		{
			if (!*committed_)
			{
				RollbackBuffer();
			}
		}
	};

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

		{
			bool committed = false;
			RollbackIfNotCommitted scopedRollback(&committed);

			// Create a trampoline function.
			CREATE_TREMPOLINE_T ct = { 0 };
			ct.pTarget = pTarget;
			if (!CreateTrampolineFunction(ct))
			{
				return MH_ERROR_UNSUPPORTED_FUNCTION;
			}

			void* pJmpPtr = pTarget;
			if (ct.patchAbove)
			{
				pJmpPtr = reinterpret_cast<char*>(pJmpPtr) - sizeof(JMP_REL);
			}

			void* pTrampoline = AllocateCodeBuffer(pJmpPtr, ct.trampoline.size());
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

			// Back up the target function.
			size_t backupSize = sizeof(JMP_REL);
			if (ct.patchAbove)
			{
				backupSize += sizeof(JMP_REL_SHORT);
			}

			void* pBackup = AllocateDataBuffer(NULL, backupSize);
			if (pBackup == NULL)
			{
				return MH_ERROR_MEMORY_ALLOC;
			}

			memcpy(pBackup, pJmpPtr, backupSize);

			// Create a relay function.
#if defined _M_X64
			void* pRelay = AllocateCodeBuffer(pJmpPtr, sizeof(JMP_ABS));
			if (pRelay == NULL)
			{
				return MH_ERROR_MEMORY_ALLOC;
			}

			WriteAbsoluteJump(pRelay, pDetour, reinterpret_cast<uintptr_t*>(pTable) + ct.table.size());
#endif
			CommitBuffer();
			committed = true;

			// Register the new hook entry.
			HOOK_ENTRY hook = { 0 };
			hook.pTarget = pTarget;
			hook.pDetour = pDetour;
#if defined _M_X64
			hook.pTable  = pTable;
			hook.pRelay  = pRelay;
#endif
			hook.pTrampoline = pTrampoline;
			hook.pBackup = pBackup;
			hook.patchAbove = ct.patchAbove;
			hook.isEnabled = false;
			hook.queueEnable = false;
			hook.oldIPs = ct.oldIPs;
			hook.newIPs = ct.newIPs;

			std::vector<HOOK_ENTRY>::iterator i	= std::lower_bound(gHooks.begin(), gHooks.end(), hook);
			i = gHooks.insert(i, hook);
			pHook = &(*i);
		}

		*ppOriginal = pHook->pTrampoline;

		return MH_OK;
	}

	MH_STATUS RemoveHook(void* pTarget)
	{
		CriticalSection::ScopedLock lock(gCS);

		if (!gIsInitialized)
		{
			return MH_ERROR_NOT_INITIALIZED;
		}

		std::vector<HOOK_ENTRY>::iterator i
			= std::lower_bound(gHooks.begin(), gHooks.end(), pTarget);
		if (i == gHooks.end() || i->pTarget != pTarget)
			return MH_ERROR_NOT_CREATED;

		HOOK_ENTRY *pHook = &(*i);

		if (pHook->isEnabled)
		{
			ScopedThreadExclusive tex(pHook->newIPs, pHook->oldIPs);

			MH_STATUS status = DisableHookLL(pHook);
			if (status != MH_OK)
			{
				return status;
			}
		}

		FreeBuffer(pHook->pTrampoline);

#if defined _M_X64
		FreeBuffer(pHook->pTable);
#endif

		FreeBuffer(pHook->pBackup);

#if defined _M_X64
		FreeBuffer(pHook->pRelay);
#endif

		gHooks.erase(i);

		return MH_OK;
	}

	MH_STATUS EnableHook(void* pTarget)
	{
		CriticalSection::ScopedLock lock(gCS);

		if (!gIsInitialized)
		{
			return MH_ERROR_NOT_INITIALIZED;
		}

		if (pTarget == MH_ALL_HOOKS)
		{
			return EnableAllHooksLL();
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

		// Overwrite the prologue of the target function with a jump to the relay or hook function.
		{
			ScopedThreadExclusive tex(pHook->oldIPs, pHook->newIPs);

			MH_STATUS status = EnableHookLL(pHook);
			if (status != MH_OK)
			{
				return status;
			}
		}

		return MH_OK;
	}

	MH_STATUS DisableHook(void* pTarget)
	{
		CriticalSection::ScopedLock lock(gCS);

		if (!gIsInitialized)
		{
			return MH_ERROR_NOT_INITIALIZED;
		}

		if (pTarget == MH_ALL_HOOKS)
		{
			return DisableAllHooksLL();
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

		// Write back the prologue of the target function. Preserve other stuff to reuse.
		{
			ScopedThreadExclusive tex(pHook->newIPs, pHook->oldIPs);

			MH_STATUS status = DisableHookLL(pHook);
			if (status != MH_OK)
			{
				return status;
			}
		}

		return MH_OK;
	}

	MH_STATUS QueueEnableHook(void* pTarget)
	{
		CriticalSection::ScopedLock lock(gCS);

		if (!gIsInitialized)
		{
			return MH_ERROR_NOT_INITIALIZED;
		}

		if (pTarget == MH_ALL_HOOKS)
		{
			for (size_t i = 0, count = gHooks.size(); i < count; ++i)
			{
				HOOK_ENTRY& hook = gHooks[i];
				hook.queueEnable = true;
			}

			return MH_OK;
		}

		HOOK_ENTRY *pHook = FindHook(pTarget);
		if (pHook == NULL)
		{
			return MH_ERROR_NOT_CREATED;
		}

		pHook->queueEnable = true;

		return MH_OK;
	}

	MH_STATUS QueueDisableHook(void* pTarget)
	{
		CriticalSection::ScopedLock lock(gCS);

		if (!gIsInitialized)
		{
			return MH_ERROR_NOT_INITIALIZED;
		}

		if (pTarget == MH_ALL_HOOKS)
		{
			for (size_t i = 0, count = gHooks.size(); i < count; ++i)
			{
				HOOK_ENTRY& hook = gHooks[i];
				hook.queueEnable = false;
			}

			return MH_OK;
		}

		HOOK_ENTRY *pHook = FindHook(pTarget);
		if (pHook == NULL)
		{
			return MH_ERROR_NOT_CREATED;
		}

		pHook->queueEnable = false;

		return MH_OK;
	}

	MH_STATUS ApplyQueued()
	{
		CriticalSection::ScopedLock lock(gCS);

		if (!gIsInitialized)
		{
			return MH_ERROR_NOT_INITIALIZED;
		}

		std::vector<uintptr_t> oldIPs;
		std::vector<uintptr_t> newIPs;

		for (size_t i = 0, count = gHooks.size(); i < count; ++i)
		{
			HOOK_ENTRY& hook = gHooks[i];
			if (hook.isEnabled != hook.queueEnable)
			{
				if (hook.queueEnable)
				{
					oldIPs.insert(oldIPs.end(), hook.oldIPs.begin(), hook.oldIPs.end());
					newIPs.insert(newIPs.end(), hook.newIPs.begin(), hook.newIPs.end());
				}
				else
				{
					oldIPs.insert(oldIPs.end(), hook.newIPs.begin(), hook.newIPs.end());
					newIPs.insert(newIPs.end(), hook.oldIPs.begin(), hook.oldIPs.end());
				}
			}
		}

		if (oldIPs.size() > 0)
		{
			ScopedThreadExclusive tex(oldIPs, newIPs);

			for (size_t i = 0, count = gHooks.size(); i < count; ++i)
			{
				HOOK_ENTRY& hook = gHooks[i];
				if (hook.isEnabled != hook.queueEnable)
				{
					MH_STATUS status;
					if (hook.queueEnable)
					{
						status = EnableHookLL(&hook);
					}
					else
					{
						status = DisableHookLL(&hook);
					}

					if (status != MH_OK)
					{
						return status;
					}
				}
			}
		}

		return MH_OK;
	}

}
namespace MinHook { namespace
{
	MH_STATUS EnableHookLL(HOOK_ENTRY *pHook)
	{
		void* pPatchTarget = pHook->pTarget;
		size_t patchSize = sizeof(JMP_REL);
		if (pHook->patchAbove)
		{
			pPatchTarget = reinterpret_cast<char*>(pPatchTarget) - sizeof(JMP_REL);
			patchSize += sizeof(JMP_REL_SHORT);
		}

		DWORD oldProtect;
		if (!VirtualProtect(pPatchTarget, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			return MH_ERROR_MEMORY_PROTECT;
		}

#if defined _M_X64
		WriteRelativeJump(pPatchTarget, pHook->pRelay);
#elif defined _M_IX86
		WriteRelativeJump(pPatchTarget, pHook->pDetour);
#endif

		if (pHook->patchAbove)
		{
			JMP_REL_SHORT jmpAbove;
			jmpAbove.opcode  = 0xEB;
			jmpAbove.operand = 0 - static_cast<uint8_t>(sizeof(JMP_REL_SHORT) + sizeof(JMP_REL));

			memcpy(pHook->pTarget, &jmpAbove, sizeof(jmpAbove));
		}

		VirtualProtect(pPatchTarget, patchSize, oldProtect, &oldProtect);

		pHook->isEnabled = true;
		pHook->queueEnable = true;

		return MH_OK;
	}

	MH_STATUS DisableHookLL(HOOK_ENTRY *pHook)
	{
		void* pPatchTarget = pHook->pTarget;
		size_t patchSize = sizeof(JMP_REL);
		if (pHook->patchAbove)
		{
			pPatchTarget = reinterpret_cast<char*>(pPatchTarget) - sizeof(JMP_REL);
			patchSize += sizeof(JMP_REL_SHORT);
		}

		DWORD oldProtect;
		if (!VirtualProtect(pPatchTarget, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			return MH_ERROR_MEMORY_PROTECT;
		}

		memcpy(pPatchTarget, pHook->pBackup, patchSize);

		VirtualProtect(pPatchTarget, patchSize, oldProtect, &oldProtect);

		pHook->isEnabled = false;
		pHook->queueEnable = false;

		return MH_OK;
	}

	MH_STATUS EnableAllHooksLL()
	{
		std::vector<uintptr_t> oldIPs;
		std::vector<uintptr_t> newIPs;

		for (size_t i = 0, count = gHooks.size(); i < count; ++i)
		{
			HOOK_ENTRY& hook = gHooks[i];
			if (!hook.isEnabled)
			{
				oldIPs.insert(oldIPs.end(), hook.oldIPs.begin(), hook.oldIPs.end());
				newIPs.insert(newIPs.end(), hook.newIPs.begin(), hook.newIPs.end());
			}
		}

		if (oldIPs.size() > 0)
		{
			ScopedThreadExclusive tex(oldIPs, newIPs);

			for (size_t i = 0, count = gHooks.size(); i < count; ++i)
			{
				HOOK_ENTRY& hook = gHooks[i];
				if (!hook.isEnabled)
				{
					MH_STATUS status = EnableHookLL(&hook);
					if (status != MH_OK)
					{
						return status;
					}
				}
			}
		}

		return MH_OK;
	}

	MH_STATUS DisableAllHooksLL()
	{
		std::vector<uintptr_t> oldIPs;
		std::vector<uintptr_t> newIPs;

		for (size_t i = 0, count = gHooks.size(); i < count; ++i)
		{
			HOOK_ENTRY& hook = gHooks[i];
			if (hook.isEnabled)
			{
				oldIPs.insert(oldIPs.end(), hook.oldIPs.begin(), hook.oldIPs.end());
				newIPs.insert(newIPs.end(), hook.newIPs.begin(), hook.newIPs.end());
			}
		}

		if (oldIPs.size() > 0)
		{
			ScopedThreadExclusive tex(newIPs, oldIPs);

			for (size_t i = 0, count = gHooks.size(); i < count; ++i)
			{
				HOOK_ENTRY& hook = gHooks[i];
				if (hook.isEnabled)
				{
					MH_STATUS status = DisableHookLL(&hook);
					if (status != MH_OK)
					{
						return status;
					}
				}
			}
		}

		return MH_OK;
	}

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

		// Is the address is allocated and executable?
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
