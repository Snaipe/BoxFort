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
#ifndef COMMON_H_
#define COMMON_H_

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifdef __GNUC__
# define nonstd __extension__
#else
# define nonstd
#endif

#ifdef _WIN32
# include <windows.h>
#else
# include <unistd.h>
#endif

#define align2_down(v, d) ((v) & ~((d) - 1))
#define align2_up(v, d) ((((v) - 1) & ~((d) - 1)) + (d))

#define bxfi_cont(Var, Type, Member) \
    (Var ? ((Type *) (((char *) Var) - offsetof(Type, Member))) : NULL)

static inline size_t pagesize(void) {
    static size_t cached;
    if (!cached) {
#ifdef _WIN32
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        cached = (size_t) si.dwPageSize;
#else
        cached = (size_t) sysconf(_SC_PAGESIZE);
#endif
    }
    return cached;
}

#define PAGE_SIZE (pagesize())

#define bug(...) do {                               \
        fprintf(stderr, __VA_ARGS__);               \
        fprintf(stderr, ": %s\n"                    \
            "This is a bug; please report it "      \
            "on the repository's issue tracker.\n", \
            strerror(errno));                       \
        abort();                                    \
    } while (0)

#endif /* !COMMON_H_ */
