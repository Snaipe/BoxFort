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
#ifndef ARENA_H_
#define ARENA_H_

#ifdef _WIN32
# include <windows.h>
#endif
#include <stdint.h>

#include "boxfort.h"
#include "config.h"

struct bxfi_arena_chunk {
    intptr_t addr;
    size_t size;
    intptr_t next;
};

#ifdef BXF_ARENA_REOPEN_SHM
# ifdef BXF_ARENA_FILE_BACKED
#  define BXFI_ARENA_NAME_SIZE (sizeof ("/tmp/bxf_arena__") + 31)
# else
#  define BXFI_ARENA_NAME_SIZE (sizeof ("/bxf_arena__") + 31)
# endif
#else
# ifdef BXF_ARENA_FILE_BACKED
#  define BXFI_ARENA_NAME_SIZE (sizeof ("/tmp/bxf_arena_") + 11)
# else
#  define BXFI_ARENA_NAME_SIZE (sizeof ("/bxf_arena_") + 11)
# endif
#endif

struct bxf_arena_s {
    void *addr;
    size_t size;
    intptr_t free_chunks;
    int flags;
    bxf_fhandle handle;

#ifdef BXF_ARENA_REOPEN_SHM
    char name[BXFI_ARENA_NAME_SIZE];
#endif
};

int bxfi_arena_inherit(bxf_fhandle hndl, int flags, bxf_arena *arena);

#endif /* !ARENA_H_ */
