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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/signal.h>
#include <sys/wait.h>

#include "addr.h"
#include "boxfort.h"
#include "plt.h"

struct bxfi_sandbox {
    struct bxf_sandbox props;
};

struct bxfi_context {
    bxf_fn *fn;
};

struct bxfi_map {
    struct bxfi_context *ctx;
    int fd;
};

static int bxfi_map_local_ctx(struct bxfi_map *map, const char *name, int create)
{
    if (create)
        shm_unlink(name);

    int flags = O_RDWR | (create ? O_CREAT | O_EXCL : 0);
    int fd = shm_open(name, flags, 0600);
    if (fd == -1)
        goto error;

    if (create && ftruncate(fd, sizeof (struct bxfi_context)))
        goto error;

    struct bxfi_context *ctx = mmap(NULL,
            sizeof (struct bxfi_context),
            PROT_READ | PROT_WRITE,
            MAP_SHARED, fd, 0);

    if (ctx == MAP_FAILED)
        goto error;

    *map = (struct bxfi_map) { ctx, fd };
    return 0;

error:;
    int err = errno;
    if (create)
        shm_unlink(name);
    if (fd != -1)
        close(fd);
    return -err;
}

static int bxfi_unmap_local_ctx(struct bxfi_map *map, const char *name, int destroy)
{
    munmap(map->ctx, sizeof (struct bxfi_context));
    close(map->fd);

    if (destroy && shm_unlink(name) == -1)
        return -errno;

    return 0;
}

extern char *__progname;

static int bxfi_main(void)
{
    char map_name[sizeof ("bxfi_") + 21];
    snprintf(map_name, sizeof (map_name), "bxfi_%d", getpid());

    struct bxfi_map local_ctx;
    if (bxfi_map_local_ctx(&local_ctx, map_name, 0) < 0)
        abort();

    bxf_fn *fn = bxfi_denormalize_fnaddr(local_ctx.ctx->fn);

    int rc = fn();

    bxfi_unmap_local_ctx(&local_ctx, map_name, 1);
    return rc;
}

__attribute__((constructor(65535)))
static void patch_main(void)
{
    if (strcmp(__progname, "boxfort-worker"))
        return;

    if (bxfi_plt_patch_main((bxfi_plt_fn *) bxfi_main) < 0)
        abort();
}

int bxf_run_impl(bxf_sandbox *ctx, bxf_run_params params)
{
    const char *self = "/proc/self/exe";

    bxf_fn *fn = bxfi_normalize_fnaddr(params->fn);

    pid_t pid = fork();
    if (pid == -1) {
        return -errno;
    } else if (pid) {
        struct bxfi_sandbox *sandbox = malloc(sizeof (*sandbox));

        int status, rc;
        for (;;) {
            rc = waitpid(pid, &status, WUNTRACED);
            if (rc != -1 || errno != EINTR)
                break;
        }
        if (rc == -1)
            return -errno;

        if (!WIFSTOPPED(status))
            return -EPROTO;

        sandbox->props = (struct bxf_sandbox) {
            .pid = pid,
        };

        char map_name[sizeof ("bxfi_") + 21];
        snprintf(map_name, sizeof (map_name), "bxfi_%d", pid);

        struct bxfi_map local_ctx;
        rc = bxfi_map_local_ctx(&local_ctx, map_name, 1);

        if (rc < 0) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            return -EPROTO;
        }

        local_ctx.ctx->fn = fn;

        kill(pid, SIGCONT);
        *ctx = &sandbox->props;

        bxfi_unmap_local_ctx(&local_ctx, map_name, 0);
        return 0;
    }

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    raise(SIGSTOP);

    execl(self, "boxfort-worker", NULL);
    _exit(errno);
}

bxf_sandbox bxf_getself(void)
{
    return NULL;
}

int bxf_wait(bxf_sandbox ctx, size_t timeout)
{
    (void) timeout;
    int status;
    if (waitpid(ctx->pid, &status, 0) == -1)
        return -errno;
    return 0;
}
