/*
 * Hacker Disassembler Engine 64 C
 * Copyright (c) 2008-2009, Vyacheslav Patkov.
 * All rights reserved.
 *
 */

#if defined(_M_X64) || defined(__x86_64__)

#include <string.h>
#include "hde64.h"
#include "table64.h"

/* An instruction is at most 15 bytes long, so the bytes past that may not be
 * mapped: a decode that would run over the limit stops instead of reading. */
#define NEED(n) do { if (limit - p < (n)) goto error_length; } while (0)

unsigned int hde64_disasm(const void *code, hde64s *hs)
{
    uint8_t x, c = 0, *p = (uint8_t *)code, cflags, opcode, pref = 0;
    uint8_t *ht = hde64_table, m_mod, m_reg, m_rm, disp_size = 0;
    uint8_t op64 = 0, rex = 0, ext = 0;
    uint8_t *limit = (uint8_t *)code + 15;

    memset(hs, 0, sizeof(hde64s));

    for (x = 15; x; x--)
        switch (c = *p++) {
            case 0xf3:
                hs->p_rep = c;
                pref |= PRE_F3;
                rex = 0;
                break;
            case 0xf2:
                hs->p_rep = c;
                pref |= PRE_F2;
                rex = 0;
                break;
            case 0xf0:
                hs->p_lock = c;
                pref |= PRE_LOCK;
                rex = 0;
                break;
            case 0x26: case 0x2e: case 0x36:
            case 0x3e: case 0x64: case 0x65:
                hs->p_seg = c;
                pref |= PRE_SEG;
                rex = 0;
                break;
            case 0x66:
                hs->p_66 = c;
                pref |= PRE_66;
                rex = 0;
                break;
            case 0x67:
                hs->p_67 = c;
                pref |= PRE_67;
                rex = 0;
                break;
            default:
                if ((c & 0xf0) != 0x40)
                    goto pref_done;
                /* REX counts only as the last prefix before the opcode: a
                 * legacy prefix after it, or a further REX, discards it. */
                rex = c;
                break;
        }
    goto error_length;          /* 15 prefixes leave no room for an opcode */

  pref_done:

    hs->flags = (uint32_t)pref << 23;

    if (!pref)
        pref |= PRE_NONE;

    if (rex) {
        hs->flags |= F_PREFIX_REX;
        hs->rex = rex;
        hs->rex_w = (rex & 0xf) >> 3;
        hs->rex_r = (rex & 7) >> 2;
        hs->rex_x = (rex & 3) >> 1;
        hs->rex_b = rex & 1;
        if (hs->rex_w && (c & 0xf8) == 0xb8)
            op64++;
    }

    /* VEX, EVEX and XOP. C4, C5 and 62 are always escapes in long mode; 8F is
     * one only from map 8 upwards, which leaves 8F /0 as POP. The header names
     * the opcode map, the map decides the immediate, and every instruction
     * reached this way has a ModR/M byte. */
    if (c == 0xc4 || c == 0xc5 || c == 0x62 ||
        (c == 0x8f && p < limit && (*p & 0x1f) >= 8)) {
        uint8_t map;

        hs->opcode = c;
        if (c == 0xc5) {
            NEED(3);
            map = 1;
            p++;
        } else if (c == 0x62) {
            NEED(5);
            map = *p & 0x07;            /* the bit above the map is APX's B4 */
            p += 3;
        } else {
            NEED(4);
            map = *p & 0x1f;
            p += 2;
        }
        hs->opcode2 = opcode = *p++;

        /* The escape carries the operand size and the register extensions
         * itself, so a 66, F2, F3, LOCK or REX in front of it is invalid. A
         * segment or 67 prefix still applies. */
        if (rex || (pref & (PRE_66 | PRE_F2 | PRE_F3 | PRE_LOCK)))
            hs->flags |= F_ERROR | F_ERROR_OPCODE;
        pref &= ~PRE_66;

        cflags = C_MODRM;
        if (c == 0x8f) {
            switch (map) {
                case 8:                 /* every XOP8 opcode takes an imm8 */
                    cflags |= C_IMM8;
                    break;
                case 9:                 /* no XOP9 opcode takes one */
                    break;
                case 10:                /* bextr and the lwp forms: imm32 */
                    cflags |= C_IMM_P66;
                    break;
                default:
                    hs->flags |= F_ERROR | F_ERROR_OPCODE;
                    break;
            }
        } else switch (map) {
            case 1:                     /* 0F map */
                if (opcode == 0x70 || (opcode >= 0x71 && opcode <= 0x73) ||
                    opcode == 0xc2 || (opcode >= 0xc4 && opcode <= 0xc6))
                    cflags |= C_IMM8;
                else if (c != 0x62 && opcode == 0x77)
                    cflags = C_NONE;    /* vzeroupper and vzeroall: no ModR/M */
                else if (c != 0x62 && (opcode == 0x84 || opcode == 0x85))
                    cflags = C_REL32;   /* jkzd and jknzd: rel32, no ModR/M */
                break;
            case 2:                     /* 0F 38 map: never an immediate */
                break;
            case 3:                     /* 0F 3A map: always an imm8 */
                cflags |= C_IMM8;
                break;
            case 5: case 6:             /* half-precision maps, EVEX only */
                if (c != 0x62)
                    hs->flags |= F_ERROR | F_ERROR_OPCODE;
                else if (map == 5 && (opcode == 0x08 || opcode == 0x0a ||
                                      opcode == 0x26 || opcode == 0x27 ||
                                      opcode == 0x56 || opcode == 0x57 ||
                                      opcode == 0x66 || opcode == 0x67 ||
                                      opcode == 0xc2))
                    cflags |= C_IMM8;   /* the 0F 3A forms of that map */
                break;
            default:
                hs->flags |= F_ERROR | F_ERROR_OPCODE;
                break;
        }
        ext = 1;
        x = 0;
        goto modrm;
    }

    if ((hs->opcode = c) == 0x0f) {
        NEED(1);
        hs->opcode2 = c = *p++;
        if (c == 0x38 || c == 0x3a) {
            /* Three-byte maps: the opcode follows and always has a ModR/M
             * byte. Every 0F 3A opcode takes an imm8, no 0F 38 one does, and
             * none of them is lockable. */
            NEED(2);
            opcode = *p++;
            cflags = (c == 0x3a) ? (C_MODRM | C_IMM8) : C_MODRM;
            if (pref & PRE_LOCK)
                hs->flags |= F_ERROR | F_ERROR_LOCK;
            ext = 1;
            x = 0;
            goto modrm;
        }
        ht += DELTA_OPCODES;
    } else if (c >= 0xa0 && c <= 0xa3) {
        /* moffs: the absolute address is as wide as the address size, so
         * eight bytes unless 67 selects 32-bit addressing. */
        if (!(pref & PRE_67))
            op64++;
        pref &= ~PRE_66;
    }

    opcode = c;
    cflags = ht[ht[opcode / 4] + (opcode % 4)];

    if (cflags == C_ERROR) {
        hs->flags |= F_ERROR | F_ERROR_OPCODE;
        /* An unknown opcode is still measured when its shape is known: 0F 24
         * and 0F 26 (test registers), 0F A6 and 0F A7 (PadLock), 0F B9 (ud1)
         * and 0F FF (ud0) all take a ModR/M byte. */
        cflags = 0;
        if ((opcode & -3) == 0x24 || opcode == 0xa6 || opcode == 0xa7 ||
            opcode == 0xb9 || opcode == 0xff)
            cflags = C_MODRM;
    }

    x = 0;
    if (cflags & C_GROUP) {
        uint16_t t;
        t = *(uint16_t *)(ht + (cflags & 0x7f));
        cflags = (uint8_t)t;
        x = (uint8_t)(t >> 8);
    }

    if (hs->opcode2) {
        ht = hde64_table + DELTA_PREFIXES;
        if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
            hs->flags |= F_ERROR | F_ERROR_OPCODE;
        /* vmread, vmwrite and popcnt take a ModR/M byte that the table cannot
         * give them: their entries share a row with opcodes that take none. */
        if (opcode == 0x78 || opcode == 0x79 || opcode == 0xb8)
            cflags |= C_MODRM;
    }

  modrm:
    if (cflags & C_MODRM) {
        hs->flags |= F_MODRM;
        NEED(1);
        hs->modrm = c = *p++;
        hs->modrm_mod = m_mod = c >> 6;
        hs->modrm_rm = m_rm = c & 7;
        hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

        if (x && ((x << m_reg) & 0x80))
            hs->flags |= F_ERROR | F_ERROR_OPCODE;

        if (ext)
            goto no_error_operand;      /* no legacy operand rule applies */

        if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
            uint8_t t = opcode - 0xd9;
            if (m_mod == 3) {
                ht = hde64_table + DELTA_FPU_MODRM + t*8;
                t = ht[m_reg] << m_rm;
            } else {
                ht = hde64_table + DELTA_FPU_REG;
                t = ht[t] << m_reg;
            }
            if (t & 0x80)
                hs->flags |= F_ERROR | F_ERROR_OPCODE;
        }

        if (pref & PRE_LOCK) {
            if (m_mod == 3) {
                hs->flags |= F_ERROR | F_ERROR_LOCK;
            } else {
                uint8_t *table_end, op = opcode;
                if (hs->opcode2) {
                    ht = hde64_table + DELTA_OP2_LOCK_OK;
                    table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
                } else {
                    ht = hde64_table + DELTA_OP_LOCK_OK;
                    table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
                    op &= -2;
                }
                for (; ht != table_end; ht++)
                    if (*ht++ == op) {
                        if (!((*ht << m_reg) & 0x80))
                            goto no_lock_error;
                        else
                            break;
                    }
                hs->flags |= F_ERROR | F_ERROR_LOCK;
              no_lock_error:
                ;
            }
        }

        if (hs->opcode2) {
            switch (opcode) {
                case 0x20: case 0x22:
                    m_mod = 3;
                    if (m_reg > 4 || m_reg == 1)
                        goto error_operand;
                    else
                        goto no_error_operand;
                case 0x21: case 0x23:
                    m_mod = 3;
                    if (m_reg == 4 || m_reg == 5)
                        goto error_operand;
                    else
                        goto no_error_operand;
            }
        } else {
            switch (opcode) {
                case 0x8c:
                    if (m_reg > 5)
                        goto error_operand;
                    else
                        goto no_error_operand;
                case 0x8e:
                    if (m_reg == 1 || m_reg > 5)
                        goto error_operand;
                    else
                        goto no_error_operand;
            }
        }

        if (m_mod == 3) {
            uint8_t *table_end;
            if (hs->opcode2) {
                ht = hde64_table + DELTA_OP2_ONLY_MEM;
                table_end = ht + sizeof(hde64_table) - DELTA_OP2_ONLY_MEM;
            } else {
                ht = hde64_table + DELTA_OP_ONLY_MEM;
                table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
            }
            for (; ht != table_end; ht += 2)
                if (*ht++ == opcode) {
                    if ((*ht++ & pref) && !((*ht << m_reg) & 0x80))
                        goto error_operand;
                    else
                        break;
                }
            goto no_error_operand;
        } else if (hs->opcode2) {
            switch (opcode) {
                case 0x50: case 0xd7: case 0xf7:
                    if (pref & (PRE_NONE | PRE_66))
                        goto error_operand;
                    break;
                case 0xd6:
                    if (pref & (PRE_F2 | PRE_F3))
                        goto error_operand;
                    break;
                case 0xc5:
                    goto error_operand;
            }
            goto no_error_operand;
        } else
            goto no_error_operand;

      error_operand:
        hs->flags |= F_ERROR | F_ERROR_OPERAND;
      no_error_operand:

        /* Group 3: F6 /0 and /1 take an imm8, F7 /0 and /1 an imm32 or imm16.
         * The rule belongs to the one-byte map; 0F F6 and 0F F7 are psadbw
         * and maskmovq, which take neither. */
        if (!ext && !hs->opcode2 && m_reg <= 1) {
            if (opcode == 0xf6)
                cflags |= C_IMM8;
            else if (opcode == 0xf7)
                cflags |= C_IMM_P66;
        }
        /* C7 /7 is xbegin, whose immediate is a displacement. */
        if (!ext && !hs->opcode2 && opcode == 0xc7 && m_reg == 7)
            hs->flags |= F_RELATIVE;
        /* extrq and insertq take two imm8 operands where vmread takes none. */
        if (!ext && hs->opcode2 == 0x78 && (pref & (PRE_66 | PRE_F2)))
            cflags |= C_IMM16;

        switch (m_mod) {
            case 0:
                if (m_rm == 5)
                    disp_size = 4;
                break;
            case 1:
                disp_size = 1;
                break;
            case 2:
                disp_size = 4;
                break;
        }

        if (m_mod != 3 && m_rm == 4) {
            hs->flags |= F_SIB;
            NEED(1);
            hs->sib = c = *p++;
            hs->sib_scale = c >> 6;
            hs->sib_index = (c & 0x3f) >> 3;
            if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
                disp_size = 4;
        }

        if (disp_size) {
            NEED(disp_size);
            if (disp_size == 1) {
                hs->flags |= F_DISP8;
                hs->disp.disp8 = *p;
            } else {
                hs->flags |= F_DISP32;
                hs->disp.disp32 = *(uint32_t *)p;
            }
            p += disp_size;
        }
    } else if (pref & PRE_LOCK)
        hs->flags |= F_ERROR | F_ERROR_LOCK;

    /* An operand-size dependent immediate is 32 bits wide, 16 under a 66
     * prefix, and 32 again when a REX.W overrides that prefix. */
    if (cflags & C_IMM_P66) {
        if (cflags & C_REL32) {
            if ((pref & PRE_66) && !hs->rex_w) {
                NEED(2);
                hs->flags |= F_IMM16 | F_RELATIVE;
                hs->imm.imm16 = *(uint16_t *)p;
                p += 2;
                goto disasm_done;
            }
            goto rel32_ok;
        }
        if (op64) {
            NEED(8);
            hs->flags |= F_IMM64;
            hs->imm.imm64 = *(uint64_t *)p;
            p += 8;
        } else if (!(pref & PRE_66) || hs->rex_w) {
            NEED(4);
            hs->flags |= F_IMM32;
            hs->imm.imm32 = *(uint32_t *)p;
            p += 4;
        } else
            goto imm16_ok;
    }


    if (cflags & C_IMM16) {
      imm16_ok:
        NEED(2);
        hs->flags |= F_IMM16;
        hs->imm.imm16 = *(uint16_t *)p;
        p += 2;
    }
    if (cflags & C_IMM8) {
        NEED(1);
        hs->flags |= F_IMM8;
        if (hs->flags & F_IMM16)
            hs->disp.disp8 = *p++;      /* enter: the union holds the imm16 */
        else
            hs->imm.imm8 = *p++;
    }

    if (cflags & C_REL32) {
      rel32_ok:
        NEED(4);
        hs->flags |= F_IMM32 | F_RELATIVE;
        hs->imm.imm32 = *(uint32_t *)p;
        p += 4;
    } else if (cflags & C_REL8) {
        NEED(1);
        hs->flags |= F_IMM8 | F_RELATIVE;
        hs->imm.imm8 = *p++;
    }

  disasm_done:

    hs->len = (uint8_t)(p - (uint8_t *)code);
    return (unsigned int)hs->len;

  error_length:

    hs->flags |= F_ERROR | F_ERROR_LENGTH;
    hs->len = 15;
    return 15;
}

#undef NEED

#endif // defined(_M_X64) || defined(__x86_64__)
