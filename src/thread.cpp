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
#include <windows.h>
#include <TlHelp32.h>

#include "thread.h"

namespace MinHook { namespace
{
	// 自動的にCloseHandleされるWindowsハンドル
	class ScopedHandle
	{
		ScopedHandle(const ScopedHandle&);
		void operator=(const ScopedHandle&);
	private:
		HANDLE handle_;
	public:
		ScopedHandle(HANDLE handle)
			: handle_(handle)
		{
		}

		~ScopedHandle()
		{
			CloseHandle(handle_);
		}

		operator HANDLE() const
		{
			return handle_;
		}
	};

}}

// CriticalSection, CriticalSection::ScopedLock の実装
namespace MinHook
{
	CriticalSection::CriticalSection()
	{
		InitializeCriticalSection(&cs_);
	}

	CriticalSection::~CriticalSection()
	{
		DeleteCriticalSection(&cs_);
	}

	void CriticalSection::enter()
	{
		EnterCriticalSection(&cs_);
	}

	void CriticalSection::leave()
	{
		LeaveCriticalSection(&cs_);
	}

	CriticalSection::ScopedLock::ScopedLock(CriticalSection& cs)
		: cs_(cs)
	{
		cs_.enter();
	}

	CriticalSection::ScopedLock::~ScopedLock()
	{
		cs_.leave();
	}
}

// ScopedThreadExclusive の実装
namespace MinHook
{
	ScopedThreadExclusive::ScopedThreadExclusive(const std::vector<uintptr_t>& oldIPs, const std::vector<uintptr_t>& newIPs)
	{
		assert(("ScopedThreadExclusive::ctor", (oldIPs.size() == newIPs.size())));

		GetThreads(threads_);
		Freeze(threads_, oldIPs, newIPs);
	}

	ScopedThreadExclusive::~ScopedThreadExclusive()
	{
		Unfreeze(threads_);
	}

	void ScopedThreadExclusive::GetThreads(std::vector<DWORD>& threads)
	{
		ScopedHandle hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
		{
			return;
		}

		THREADENTRY32 te = { sizeof(te) };
		if (Thread32First(hSnapshot, &te))
		{
			do
			{
				if (te.th32OwnerProcessID == GetCurrentProcessId()
					&& te.th32ThreadID != GetCurrentThreadId())
				{
					threads.push_back(te.th32ThreadID);
				}
			}
			while (Thread32Next(hSnapshot, &te));
		}
	}

	void ScopedThreadExclusive::Freeze(
		const std::vector<DWORD>& threads, const std::vector<uintptr_t>& oldIPs, const std::vector<uintptr_t>& newIPs)
	{
		assert(("ScopedThreadExclusive::freeze", (oldIPs.size() == newIPs.size())));

		static const DWORD ThreadAccess 
			= THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT;

		for (size_t i = 0, count = threads.size(); i < count; ++i)
		{
			DWORD tid = threads[i];
			ScopedHandle hThread = OpenThread(ThreadAccess, FALSE, tid);
			SuspendThread(hThread);

			// 書き換え範囲内でスレッドが停止した場合は、トランポリン関数に制御を移す
			CONTEXT c = { 0 };
			c.ContextFlags = CONTEXT_CONTROL;
			if (!GetThreadContext(hThread, &c))
			{
				return;
			}

#if defined _M_X64
			DWORD64& ip = c.Rip;
#elif defined _M_IX86
			DWORD& ip = c.Eip;
#endif
			for (size_t i = 0; i < oldIPs.size(); ++i)
			{
				if (ip == oldIPs[ i ])
				{
					ip = newIPs[ i ];
					SetThreadContext(hThread, &c);
					break;
				}
			}
		}
	}

	void ScopedThreadExclusive::Unfreeze(const std::vector<DWORD>& threads)
	{
		for (size_t i = 0, count = threads.size(); i < count; ++i)
		{
			DWORD tid = threads[i];
			ScopedHandle hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
			ResumeThread(hThread);
		}
	}
}

