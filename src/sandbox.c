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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "addr.h"
#include "context.h"
#include "exe.h"
#include "sandbox.h"

static int bxfi_main(void)
{
    struct bxfi_map local_ctx;

    if (bxfi_init_sandbox_ctx(&local_ctx) < 0)
        abort();

    struct bxfi_addr addr = {
        .soname = (char *) (local_ctx.ctx + 1),
        .addr   = local_ctx.ctx->fn,
        .seg    = local_ctx.ctx->seg,
    };
    bxf_fn *fn = bxfi_denormalize_fnaddr(&addr);

    if (!fn)
        abort();

    if (bxfi_context_inherit(&local_ctx.ctx->context) < 0)
        abort();

    if (bxfi_term_sandbox_ctx(&local_ctx) < 0)
        abort();

    return fn();
}

BXFI_INITIALIZER(patch_main)
static void patch_main(void)
{
    if (!bxfi_check_sandbox_ctx())
        return;

    if (bxfi_exe_patch_main((bxfi_exe_fn *) bxfi_main) < 0)
        abort();
}

int bxf_spawn_struct(bxf_instance **out, bxf_spawn_params params)
{
    if (!params->fn)
        return -EINVAL;

    struct bxf_sandbox_s *sandbox = calloc(1, sizeof (*sandbox));
    if (!sandbox)
        return -ENOMEM;

    /* 2nd parameter must be the start of the BXFI_SANDBOX_FIELDS in the
       parameter structure */
    memcpy(sandbox, &params->callback + 1, sizeof (*sandbox));

    int rc;
    if ((rc = bxfi_exec(out, sandbox, 1, params->fn,
                    params->preexec, params->callback,
                    params->user, params->user_dtor)))
        free(sandbox);
    return rc;
}

int bxf_run_struct(bxf_spawn_params params)
{
    bxf_instance *box;
    int rc;

    if ((rc = bxf_spawn_struct(&box, params)))
        return rc;

    rc = bxf_wait(box, BXF_FOREVER);
    bxf_term(box);
    return rc;
}

int bxf_start_struct(bxf_instance **out, bxf_sandbox *sandbox,
        bxf_start_params params)
{
    return bxfi_exec(out, sandbox, 0, params->fn,
            params->preexec, params->callback,
            params->user, params->user_dtor);
}
