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
#ifndef ADDR_H_
#define ADDR_H_

#include "boxfort.h"
#include "common.h"

struct bxfi_addr {
    const char *soname;
    const void *addr;
    size_t seg;
};

int bxfi_normalize_addr(const void *addr, struct bxfi_addr *to);
void *bxfi_denormalize_addr(struct bxfi_addr *addr);
void bxfi_addr_term(struct bxfi_addr *addr);

static inline int bxfi_normalize_fnaddr(bxf_fn *addr, struct bxfi_addr *to)
{
    return bxfi_normalize_addr(nonstd (void *) addr, to);
}

static inline bxf_fn *bxfi_denormalize_fnaddr(struct bxfi_addr *addr)
{
    return nonstd (bxf_fn *) bxfi_denormalize_addr(addr);
}

#endif /* !ADDR_H_ */
