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
#ifndef SANDBOX_H_
#define SANDBOX_H_

#include "boxfort.h"
#include "config.h"

/* *INDENT-OFF* - formatters try to add spaces here */
#include BXFI_STR(sandbox-BXF_OS_FAMILY.h)
/* *INDENT-ON* */

int bxfi_exec(bxf_instance **out, bxf_sandbox *sandbox,
        int mantled, bxf_fn *fn, bxf_preexec *preexec, bxf_callback *callback,
        void *user, bxf_dtor user_dtor);
int bxfi_check_sandbox_ctx(void);
int bxfi_init_sandbox_ctx(struct bxfi_map *map);
int bxfi_term_sandbox_ctx(struct bxfi_map *map);

#if defined (_MSC_VER)
# define BXFI_INITIALIZER_(Fn, Prefix)                              \
    static void Fn(void);                                           \
    __pragma(section(".CRT$XCU", read))                             \
    __declspec(allocate(".CRT$XCU")) void(*Fn ## _init)(void) = Fn; \
    __pragma(comment(linker, "/include:" Prefix #Fn "_init"))
# ifdef _WIN64
#  define BXFI_INITIALIZER(Fn) BXFI_INITIALIZER_(Fn, "")
# else
#  define BXFI_INITIALIZER(Fn) BXFI_INITIALIZER_(Fn, "_")
# endif
#elif defined (__GNUC__)
# define BXFI_INITIALIZER(...) __attribute__((constructor))
#else
# error Compiler not supported
#endif

#endif /* !SANDBOX_H_ */
