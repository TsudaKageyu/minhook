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

namespace MinHook
{
	struct TEMP_ADDR
	{
		uintptr_t	address;
		size_t		position;
		size_t		pc;
	};

	struct CREATE_TREMPOLINE_T
	{
		void*					pTarget;
		void*					pTrampoline;
		bool					patchAbove;
		std::vector<char>		trampoline;
		std::vector<TEMP_ADDR>	tempAddr;
#if defined _M_X64
		void*					pTable;
		std::vector<uintptr_t>	table;
#endif
		std::vector<uintptr_t>	oldIPs;
		std::vector<uintptr_t>	newIPs;
	};

	bool CreateTrampolineFunction(CREATE_TREMPOLINE_T& ct);
	bool ResolveTemporaryAddresses(CREATE_TREMPOLINE_T& ct);
}