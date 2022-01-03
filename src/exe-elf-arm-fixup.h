/*
 * The MIT License (MIT)
 *
 * Copyright © 2022 László "MrAnno" Várady
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

#ifndef EXE_ELF_ARM_FIXUP_H_
#define EXE_ELF_ARM_FIXUP_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern void *bxfi_trampoline_thumb;
extern void *bxfi_trampoline_thumb_addr;
extern void *bxfi_trampoline_thumb_end;

static inline int bxfi_exe_is_arm_thumb_func(void *func_addr)
{
    return (uintptr_t) func_addr & 0x1U;
}

/* The returned address should not be called, it is meant to be used for patching */
static inline void bxfi_exe_fix_func_addr_if_in_arm_thumb_mode(void **addr)
{
    *addr = (void *) (uintptr_t) ((uintptr_t) *addr & ~0x1ULL);
}

static inline void bxfi_exe_trampoline_fixup(void **func_to_patch, void **trampoline,
        void **trampoline_end, void **trampoline_addr)
{
    if (bxfi_exe_is_arm_thumb_func(*func_to_patch)) {
        *trampoline = &bxfi_trampoline_thumb;
        *trampoline_end = &bxfi_trampoline_thumb_end;
        *trampoline_addr = &bxfi_trampoline_thumb_addr;
    }

    bxfi_exe_fix_func_addr_if_in_arm_thumb_mode(func_to_patch);
}

static inline size_t bxfi_exe_inject_prelude(void *func_to_patch)
{
    return 0;
}

#endif /* !EXE_ELF_ARM_FIXUP_H_ */
