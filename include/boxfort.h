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
#ifndef BOXFORT_H_
# define BOXFORT_H_

# include <stddef.h>

typedef unsigned long long bxf_pid;
typedef int (bxf_fn)(void);
typedef void (bxf_callback)(void);

struct bxf_quotas {
    size_t memory;
    size_t subprocesses;
    size_t files;
};

struct bxf_inheritance {
    int files   : 1;
    int data    : 1;
};

# define BXFI_SANDBOX_FIELDS        \
    struct bxf_quotas quotas;       \
    struct bxf_quotas iquotas;      \
    struct bxf_inheritance inherit;

struct bxf_sandbox {
    BXFI_SANDBOX_FIELDS
};

typedef const struct bxf_sandbox bxf_sandbox;

struct bxf_instance {
    bxf_sandbox *sandbox;
    bxf_pid pid;
};

typedef const struct bxf_instance bxf_instance;

struct bxf_run_params {
    bxf_fn *fn;
    bxf_callback *callback;
    BXFI_SANDBOX_FIELDS
};

typedef const struct bxf_run_params *bxf_run_params;

bxf_instance *bxf_start(bxf_sandbox *sandbox, bxf_fn *fn);
int bxf_term(bxf_instance *instance);
int bxf_wait(bxf_instance *instance, size_t timeout);

# define bxf_run(...) (bxf_run_impl(&(struct bxf_run_params) { __VA_ARGS__ }))
bxf_instance *bxf_run_impl(bxf_run_params params);

#endif /* !BOXFORT_H_ */
