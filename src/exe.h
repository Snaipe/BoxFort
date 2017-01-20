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
#ifndef PLT_H_
#define PLT_H_

#include <stddef.h>

#include "config.h"

#if defined BXF_EXE_FMT_ELF
# include "exe-elf.h"
#elif defined BXF_EXE_FMT_PE
# include "exe-pe.h"
#elif defined BXF_EXE_FMT_MACH_O
# include "exe-mach-o.h"
#endif

int bxfi_exe_patch_main(bxfi_exe_fn *new_main);
uintptr_t bxfi_slide_from_addr(const void *addr, const char **name, size_t *seg);
uintptr_t bxfi_slide_from_name(const char *name, size_t seg);
const char *bxfi_lib_name(bxfi_exe_lib lib);
void bxfi_lib_name_term(const char *str);
size_t bxfi_exe_get_vmslide(bxfi_exe_lib lib);

#endif /* !PLT_H_ */
