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
#include <stddef.h>
#include <stdint.h>
#include <errno.h>

#include "addr.h"
#include "exe.h"

int bxfi_normalize_addr(void *addr, struct bxfi_addr *to)
{
    bxfi_exe_lib lib = bxfi_lib_from_addr(addr);
    if (lib == BXFI_INVALID_LIB)
        return -EINVAL;
    uintptr_t slide = bxfi_exe_get_vmslide(lib);

    to->addr = (char *) addr - slide;
    to->soname = bxfi_lib_name(lib);

    if (to->soname == NULL)
        return -EINVAL;
    return 0;
}

void *bxfi_denormalize_addr(struct bxfi_addr *addr)
{
    bxfi_exe_lib lib = bxfi_lib_from_name(addr->soname);
    if (lib == BXFI_INVALID_LIB)
        return NULL;
    uintptr_t slide = bxfi_exe_get_vmslide(lib);

    return (char *) addr->addr + slide;
}
