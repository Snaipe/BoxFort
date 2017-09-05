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
#ifndef SANDBOX_WINDOWS_H_
#define SANDBOX_WINDOWS_H_

#include <windows.h>
#include "context.h"

struct bxfi_context {
    size_t total_sz;
    const void *fn;
    size_t seg;
    struct bxfi_ctx_arena context;
    size_t fn_soname_sz;
    HANDLE sync;
    int suspend;
};

struct bxfi_map {
    struct bxfi_context *ctx;
    HANDLE handle;
    TCHAR map_name[sizeof ("bxfi_") + 21];
};

struct bxfi_sandbox {
    struct bxf_instance_s props;
    HANDLE proc;
    HANDLE mainthread;

    /* A sandbox is said to be mantled if there is an unique instance
       managing its memory. */
    int mantled;

    /* The monotonic timestamp representing the start of the sandbox instance.
     * Only used to calculate more accurate run times */
    uint64_t start_monotonic;

    void *user;
    bxf_dtor *user_dtor;

    HANDLE waited;
};

#endif /* !SANDBOX_WINDOWS_H_ */
