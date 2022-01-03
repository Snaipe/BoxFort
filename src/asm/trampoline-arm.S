/*
 * The MIT License (MIT)
 *
 * Copyright © 2016 Franklin "Snaipe" Mathieu <http://snai.pe/>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "config.h"
#include "mangling.h"

.arm

#ifdef ASSEMBLER_SUPPORTS_HIDDEN
.hidden MANGLE(bxfi_trampoline)
#endif
.globl MANGLE(bxfi_trampoline)
MANGLE(bxfi_trampoline):
    ldr     r3, addr_data
    bx      r3

.align 2

#ifdef ASSEMBLER_SUPPORTS_HIDDEN
.hidden MANGLE(bxfi_trampoline_addr)
#endif
.globl MANGLE(bxfi_trampoline_addr)
MANGLE(bxfi_trampoline_addr):
addr_data:
.fill 4, 1, 0

#ifdef ASSEMBLER_SUPPORTS_HIDDEN
.hidden MANGLE(bxfi_trampoline_end)
#endif
.globl MANGLE(bxfi_trampoline_end)
MANGLE(bxfi_trampoline_end):


/* ARM Thumb mode */

.syntax unified
.thumb

/* carefully aligned, so that the following LDR pseudo-instruction will be
 * word-aligned, which is important because the same instruction on a
 * halfword-aligned address generates a jump with a different PC-relative offset
 */
.align 2

#ifdef ASSEMBLER_SUPPORTS_HIDDEN
.hidden MANGLE(bxfi_trampoline_thumb)
#endif
.globl MANGLE(bxfi_trampoline_thumb)
MANGLE(bxfi_trampoline_thumb):
    ldr     r3, addr_data_thumb
    bx      r3

.align 2

#ifdef ASSEMBLER_SUPPORTS_HIDDEN
.hidden MANGLE(bxfi_trampoline_thumb_addr)
#endif
.globl MANGLE(bxfi_trampoline_thumb_addr)
MANGLE(bxfi_trampoline_thumb_addr):
addr_data_thumb:
.fill 4, 1, 0

#ifdef ASSEMBLER_SUPPORTS_HIDDEN
.hidden MANGLE(bxfi_trampoline_thumb_end)
#endif
.globl MANGLE(bxfi_trampoline_thumb_end)
MANGLE(bxfi_trampoline_thumb_end):

.align 2

#ifdef ASSEMBLER_SUPPORTS_HIDDEN
.hidden MANGLE(bxfi_trampoline_thumb_nop)
#endif
.globl MANGLE(bxfi_trampoline_thumb_nop)
MANGLE(bxfi_trampoline_thumb_nop):
    nop

#ifdef ASSEMBLER_SUPPORTS_HIDDEN
.hidden MANGLE(bxfi_trampoline_thumb_nop_end)
#endif
.globl MANGLE(bxfi_trampoline_thumb_nop_end)
MANGLE(bxfi_trampoline_thumb_nop_end):

#include "stackfix.h"
