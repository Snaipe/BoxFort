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
#ifndef CONTEXT_H_
#define CONTEXT_H_

#include "addr.h"
#include "arena.h"

struct bxf_context_s {
    bxf_arena arena;
};

enum bxfi_ctx_tag {
    BXFI_TAG_STATIC,
    BXFI_TAG_ARENA,
    BXFI_TAG_OBJECT,
    BXFI_TAG_FHANDLE,
};

struct bxfi_ctx_static {
    enum bxfi_ctx_tag tag;
    const void *addr;
    size_t seg;
    size_t size;
    char data[];
};

struct bxfi_ctx_arena {
    enum bxfi_ctx_tag tag;
    int flags;
    void *base;

#ifdef BXF_ARENA_REOPEN_SHM
    char name[BXFI_ARENA_NAME_SIZE];
#else
    bxf_fhandle handle;
#endif
};

struct bxfi_ctx_object {
    enum bxfi_ctx_tag tag;
    size_t namesz;
    char data[];
};

struct bxfi_ctx_fhandle {
    enum bxfi_ctx_tag tag;
    bxf_fhandle handle;
};

typedef int (bxf_fhandle_fn)(bxf_fhandle, void *);

bxf_fhandle bxfi_context_gethandle(bxf_context ctx);
int bxfi_context_prepare(bxf_context ctx, bxf_fhandle_fn *fn, void *user);

int bxfi_context_inherit(struct bxfi_ctx_arena *ctx);

#endif /* !CONTEXT_H_ */
