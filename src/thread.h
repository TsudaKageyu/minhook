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

#pragma once

#include <vector>
#include <windows.h>

#include "trampoline.h"

namespace MinHook
{
	// CriticalSection with scoped lock feature.
	class CriticalSection
	{
		CriticalSection(const CriticalSection&);
		void operator=(const CriticalSection&);
	public:
		class ScopedLock
		{
			ScopedLock(const ScopedLock&);
			void operator=(const ScopedLock&);
		private:
			CriticalSection& cs_;
		public:
			ScopedLock(CriticalSection& cs);
			~ScopedLock();
		};

	private:
		CRITICAL_SECTION cs_;
	public:
		CriticalSection();
		~CriticalSection();
		void enter();
		void leave();
	};

	// Halt all other threads in the running process.
	class ScopedThreadExclusive
	{
	private:
		std::vector<DWORD> threads_;
	public:
		ScopedThreadExclusive(const std::vector<uintptr_t>& oldIPs, const std::vector<uintptr_t>& newIPs);
		~ScopedThreadExclusive();
	private:
		static void GetThreads(std::vector<DWORD>& threads);
		static void Freeze(
			const std::vector<DWORD>& threads, const std::vector<uintptr_t>& oldIPs, const std::vector<uintptr_t>& newIPs);
		static void Unfreeze(const std::vector<DWORD>& threads);
	};
}

