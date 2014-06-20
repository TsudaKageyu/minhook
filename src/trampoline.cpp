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
#include <Windows.h>
#include "pstdint.h"

#if defined _M_X64
#include "hde64/include/hde64.h"
#elif defined _M_IX86
#include "hde32/hde32.h"
#endif

#include "trampoline.h"

namespace MinHook { namespace
{
#if defined _M_X64
	typedef hde64s hde_t;
	inline unsigned int hde_disasm(const void* code, hde_t* hs) { return hde64_disasm(code, hs); }
#elif defined _M_IX86
	typedef hde32s hde_t;
	inline unsigned int hde_disasm(const void* code, hde_t* hs) { return hde32_disasm(code, hs); }
#endif

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
	typedef JMP_REL CALL_REL;

	struct JMP_ABS
	{
		uint16_t	opcode;
		uint32_t	operand;
	};
	typedef JMP_ABS CALL_ABS, JCC_REL;

	// 32/64bit indirect absolute conditional jump that x86/x64 lacks.
	struct JCC_ABS
	{
		uint8_t		opcode;		// 7* 02			J** +4
		uint8_t		dummy0;
		uint8_t		dummy1;		// EB 06			JMP +8
		uint8_t		dummy2;
		uint16_t	dummy3;		// FF25 xxxxxxxx	JMP [RIP+xxxxxxxx]
		uint32_t	operand;
	};
#pragma pack(pop)

	uintptr_t	GetRelativeBranchDestination(uint8_t* pInst, const hde_t& hs, bool isShort);
	inline bool	IsInternalJump(void* pTarget, uintptr_t dest);
	template <typename T>
	void		AppendTempAddress(uintptr_t address, size_t pos, const T& inst, CREATE_TREMPOLINE_T& ct);
#if defined _M_X64
	void		AppendRipRelativeAddress(uint8_t* pInst, size_t pos, const hde_t& hs, CREATE_TREMPOLINE_T& ct);
#endif
	inline void	SetJccOpcode(const hde_t& hs, JCC_REL& inst);
	inline void	SetJccOpcode(const hde_t& hs, JCC_ABS& inst);
	bool		IsCodePadding(uint8_t* pInst, size_t size);
	bool		IsExecutableAddress(void* pAddress);
}}

namespace MinHook
{
	bool CreateTrampolineFunction(CREATE_TREMPOLINE_T& ct)
	{
		assert(("CreateTrampolineFunction", ct.pTarget != NULL));

#if defined _M_X64
		CALL_ABS call = { 0x15FF, 0x00000000 };
		JMP_ABS  jmp  = { 0x25FF, 0x00000000 };
		JCC_ABS  jcc  = { 0x70, 0x02, 0xEB, 0x06, 0x25FF, 0x00000000 };
#elif defined _M_IX86
		CALL_REL call = { 0xE8, 0x00000000 };
		JMP_REL  jmp  = { 0xE9, 0x00000000 };
		JCC_REL  jcc  = { 0x800F, 0x00000000 };
#endif

		size_t    oldPos = 0;
		size_t    newPos = 0;
		uintptr_t jmpDest = 0;		// Destination address of an internal jump.
		bool      finished = false;	// Is the function completed?
		while (!finished)
		{
			uint8_t *pInst = reinterpret_cast<uint8_t*>(ct.pTarget) + oldPos;
			hde_t hs;
			hde_disasm(pInst, &hs);
			if ((hs.flags & F_ERROR) == F_ERROR)
			{
				return false;
			}

			void*  pCopySrc = pInst;
			size_t copySize = hs.len;

			if (pInst - reinterpret_cast<uint8_t*>(ct.pTarget) >= sizeof(JMP_REL))
			{
				// The trampoline function is long enough.
				// Complete the function with the jump to the target function.
				AppendTempAddress(reinterpret_cast<uintptr_t>(pInst), newPos, jmp, ct);

				pCopySrc = &jmp;
				copySize = sizeof(jmp);

				finished = true;
			}
#if defined _M_X64
			else if ((hs.modrm & 0xC7) == 0x05)
			{
				// Instructions using RIP relative addressing. (ModR/M = 00???101B)

				// Modify only RIP relative address.
				AppendRipRelativeAddress(pInst, newPos, hs, ct);

				// Complete the function if JMP (FF /4).
				if (hs.opcode == 0xFF && hs.modrm_reg == 4)
				{
					finished = true;
				}
			}
#endif
			else if (hs.opcode == 0xE8)
			{
				// Direct relative CALL

				AppendTempAddress(GetRelativeBranchDestination(pInst, hs, false), newPos, call, ct);
				pCopySrc = &call;
				copySize = sizeof(call);
			}
			else if ((hs.opcode & 0xFD) == 0xE9)
			{
				// Direct relative JMP (EB or E9)

				uintptr_t dest = GetRelativeBranchDestination(pInst, hs, hs.opcode == 0xEB);

				// Simply copy an internal jump.
				if (IsInternalJump(ct.pTarget, dest))
				{
					jmpDest = std::max<uintptr_t>(jmpDest, dest);
				}
				else
				{
					AppendTempAddress(dest, newPos, jmp, ct);
					pCopySrc = &jmp;
					copySize = sizeof(jmp);

					// 分岐中でなければ関数を終了
					finished = (reinterpret_cast<uintptr_t>(pInst) >= jmpDest);
				}
			}
			else if ((hs.opcode & 0xF0) == 0x70 || (hs.opcode & 0xFC) == 0xE0 || (hs.opcode2 & 0xF0) == 0x80)
			{
				// Direct relative Jcc

				uintptr_t dest = GetRelativeBranchDestination(pInst, hs, (hs.opcode & 0xF0) == 0x70 || (hs.opcode & 0xFC) == 0xE0);

				// Simply copy an internal jump.
				if (IsInternalJump(ct.pTarget, dest))
				{
					jmpDest = std::max<uintptr_t>(jmpDest, dest);
				}
				else if ((hs.opcode & 0xFC) == 0xE0) // JCXZ/JECXZ to the outside are not supported.
				{
					return false;
				}
				else
				{
					AppendTempAddress(dest, newPos, jcc, ct);
					SetJccOpcode(hs, jcc);
					pCopySrc = &jcc;
					copySize = sizeof(jcc);
				}
			}
			else if ((hs.opcode & 0xFE) == 0xC2)
			{
				// RET (C2 or C3)

				// Complete the function if not in a branch.
				finished = (reinterpret_cast<uintptr_t>(pInst) >= jmpDest);
			}

			// Can't alter the instruction length in a branch.
			if (reinterpret_cast<uintptr_t>(pInst) < jmpDest && copySize != hs.len)
			{
				return false;
			}

			ct.trampoline.resize(newPos + copySize);
			memcpy(&ct.trampoline[ newPos ], pCopySrc, copySize);

			ct.oldIPs.push_back(oldPos);
			oldPos += hs.len;
			ct.newIPs.push_back(newPos);
			newPos += copySize;
		}

		// Is there enough place for a long jump?
		if (oldPos < sizeof(JMP_REL) && !IsCodePadding(reinterpret_cast<uint8_t*>(ct.pTarget) + oldPos, sizeof(JMP_REL) - oldPos))
		{
			// Is there enough place for a short jump?
			if (oldPos < sizeof(JMP_REL_SHORT) && !IsCodePadding(reinterpret_cast<uint8_t*>(ct.pTarget) + oldPos, sizeof(JMP_REL_SHORT) - oldPos))
			{
				return false;
			}

			// Can we place the long jump above the function?
			if (!IsExecutableAddress(reinterpret_cast<uint8_t*>(ct.pTarget) - sizeof(JMP_REL)))
			{
				return false;
			}

			if (!IsCodePadding(reinterpret_cast<uint8_t*>(ct.pTarget) - sizeof(JMP_REL), sizeof(JMP_REL)))
			{
				return false;
			}

			ct.patchAbove = true;
		}

		return true;
	}

	bool ResolveTemporaryAddresses(CREATE_TREMPOLINE_T& ct)
	{
		assert(("ResolveTemporaryAddresses", ct.pTrampoline != NULL));
#if defined _M_X64
		assert(("ResolveTemporaryAddresses", (ct.table.empty() || ct.pTable != NULL)));
#endif

#if defined _M_X64
		uintptr_t* pt = reinterpret_cast<uintptr_t*>(ct.pTable);
#endif
		for (size_t i = 0, count = ct.tempAddr.size(); i < count; ++i)
		{
			const TEMP_ADDR& ta = ct.tempAddr[i];
			if (ta.position > ct.trampoline.size() - sizeof(uint32_t))
			{
				return false;
			}

			uintptr_t addr;
#if defined _M_X64
			if (ta.address < 0x10000)	// Table index when < 0x10000, otherwise RIP relative address.
			{
				addr = reinterpret_cast<uintptr_t>(pt++);
			}
			else
#endif
			{
				addr = ta.address;
			}

			*reinterpret_cast<uint32_t*>(&ct.trampoline[ ta.position ])
				= static_cast<uint32_t>(addr - (reinterpret_cast<uintptr_t>(ct.pTrampoline) + ta.pc));
		}

		for (size_t i = 0; i < ct.oldIPs.size(); ++i)
		{
			ct.oldIPs[ i ] += reinterpret_cast<uintptr_t>(ct.pTarget);
			ct.newIPs[ i ] += reinterpret_cast<uintptr_t>(ct.pTrampoline);
		}

		if (ct.patchAbove)
		{
			ct.oldIPs.push_back(reinterpret_cast<uintptr_t>(ct.pTarget));
			ct.newIPs.push_back(reinterpret_cast<uintptr_t>(ct.pTarget) - sizeof(JMP_REL));
		}

		return true;
	}
}

namespace MinHook { namespace
{
	inline uintptr_t GetRelativeBranchDestination(uint8_t* pInst, const hde_t& hs, bool isShort)
	{
		int32_t imm = isShort ? static_cast<int8_t>(hs.imm.imm8) : static_cast<int32_t>(hs.imm.imm32);
		return reinterpret_cast<uintptr_t>(pInst) + hs.len + imm;
	}

	inline bool IsInternalJump(void* pTarget, uintptr_t dest)
	{
		uintptr_t pt = reinterpret_cast<uintptr_t>(pTarget);
		return (pt <= dest && dest <= pt + sizeof(JMP_REL));
	}

	template <typename T>
	void AppendTempAddress(uintptr_t address, size_t pos, const T& inst, CREATE_TREMPOLINE_T& ct)
	{
		TEMP_ADDR ta;
#if defined _M_X64
		ta.address  = ct.table.size();
		ct.table.push_back(address);
#elif defined _M_IX86
		ta.address  = address;
#endif
		ta.position = pos + (reinterpret_cast<uintptr_t>(&inst.operand) - reinterpret_cast<uintptr_t>(&inst));
		ta.pc       = pos + sizeof(inst);

		ct.tempAddr.push_back(ta);
	}

#if defined _M_X64
	void AppendRipRelativeAddress(uint8_t* pInst, size_t pos, const hde_t& hs, CREATE_TREMPOLINE_T& ct)
	{
		TEMP_ADDR ta;
		ta.address  = reinterpret_cast<uintptr_t>(pInst) + hs.len + static_cast<int32_t>(hs.disp.disp32);
		ta.position = pos + hs.len - ((hs.flags & 0x3C) >> 2) - 4; // pos + instruction length - immediate value length - 4
		ta.pc       = pos + hs.len;

		ct.tempAddr.push_back(ta);
	}
#endif

	inline void SetJccOpcode(const hde_t& hs, JCC_REL& inst)
	{
		uint8_t n = ((hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F);
		inst.opcode = 0x800F | (n << 8);
	}

	inline void SetJccOpcode(const hde_t& hs, JCC_ABS& inst)
	{
		uint8_t n = ((hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F);
		inst.opcode = 0x70 | n;
	}

	bool IsCodePadding(uint8_t* pInst, size_t size)
	{
		uint8_t paddingByte = pInst[0];
		switch (paddingByte)
		{
		case 0x00:
		case 0x90: // NOP
		case 0xCC: // INT3
			for (size_t i = 1; i < size; ++i)
			{
				if (pInst[i] != paddingByte)
				{
					return false;
				}
			}
			return true;

		default:
			return false;
		}
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
}}


