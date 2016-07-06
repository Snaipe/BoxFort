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
#include <limits.h>
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
#include "exe.h"

struct bxfi_sandbox {
    struct bxf_sandbox props;
};

struct bxfi_context {
    size_t total_sz;
    void *fn;
    size_t fn_soname_sz;
    int ok;
};

struct bxfi_map {
    struct bxfi_context *ctx;
    int fd;
};

static int bxfi_create_local_ctx(struct bxfi_map *map,
        const char *name, size_t sz)
{
    shm_unlink(name);

    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd == -1)
        goto error;

    ftruncate(fd, sizeof (struct bxfi_context) + sz);

    struct bxfi_context *ctx = mmap(NULL,
            sizeof (struct bxfi_context) + sz,
            PROT_READ | PROT_WRITE,
            MAP_SHARED, fd, 0);

    if (ctx == MAP_FAILED)
        goto error;

    ctx->total_sz = sizeof (struct bxfi_context) + sz;

    *map = (struct bxfi_map) { ctx, fd };
    return 0;

error:;
    int err = errno;
    shm_unlink(name);
    if (fd != -1)
        close(fd);
    return -err;
}

static int bxfi_check_local_ctx(const char *name)
{
    int fd = shm_open(name, O_RDONLY, 0600);
    if (fd != -1)
        close(fd);
    return fd != -1;
}

static int bxfi_map_local_ctx(struct bxfi_map *map, const char *name)
{
    int fd = shm_open(name, O_RDWR, 0600);
    if (fd == -1)
        goto error;

    size_t total_sz;

    if (read(fd, &total_sz, sizeof (size_t)) < (ssize_t) sizeof (size_t))
        goto error;

    if (lseek(fd, 0, SEEK_SET) == -1)
        goto error;

    struct bxfi_context *ctx = mmap(NULL,
            total_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (ctx == MAP_FAILED)
        goto error;

    *map = (struct bxfi_map) { ctx, fd };
    return 0;

error:;
    int err = errno;
    if (fd != -1)
        close(fd);
    return -err;
}

static int bxfi_unmap_local_ctx(struct bxfi_map *map, const char *name, int destroy)
{
    size_t sz = map->ctx->total_sz;
    munmap(map->ctx, sz);
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
    if (bxfi_map_local_ctx(&local_ctx, map_name) < 0)
        abort();

    struct bxfi_addr addr = {
        .soname = (char *)(local_ctx.ctx + 1),
        .addr   = local_ctx.ctx->fn,
    };
    bxf_fn *fn = bxfi_denormalize_fnaddr(&addr);

    if (!fn)
        abort();

    local_ctx.ctx->ok = 1;
    bxfi_unmap_local_ctx(&local_ctx, map_name, 1);

    raise(SIGSTOP);

    return fn();
}

__attribute__((constructor(65535)))
static void patch_main(void)
{
    char map_name[sizeof ("bxfi_") + 21];
    snprintf(map_name, sizeof (map_name), "bxfi_%d", getpid());

    if (!bxfi_check_local_ctx(map_name))
        return;

    if (bxfi_exe_patch_main((bxfi_exe_fn *) bxfi_main) < 0)
        abort();
}

int get_exe_path(char *buf, size_t sz)
{
    const char *self = "/proc/self/exe";

    /* We can't just use /proc/self/exe or equivalent to re-exec the
       executable, because tools like valgrind use this path to open
       and map the ELF file -- which would point to the valgrind binary. */
    ssize_t rc = readlink(self, buf, sz);
    if (rc == -1)
        return -errno;
    if ((size_t) rc == sz)
        return -ENAMETOOLONG;
    memset(buf + rc, 0, sz - rc);
    return 0;
}

int bxf_run_impl(bxf_sandbox *ctx, bxf_run_params params)
{
    static char exe[PATH_MAX + 1];

    int rc;
    if (!exe[0] && (rc = get_exe_path(exe, sizeof (exe))) < 0)
        return rc;

    struct bxfi_addr addr;
    if (bxfi_normalize_fnaddr(params->fn, &addr) < 0)
        return -EINVAL;

    pid_t pid = fork();
    if (pid == -1) {
        return -errno;
    } else if (pid) {
        struct bxfi_sandbox *sandbox = malloc(sizeof (*sandbox));
        char map_name[sizeof ("bxfi_") + 21];
        int status, map_rc;

        for (;;) {
            rc = waitpid(pid, &status, WUNTRACED);
            if (rc != -1 || errno != EINTR)
                break;
        }
        if (rc == -1)
            return -errno;

        if (!WIFSTOPPED(status))
            goto err;

        sandbox->props = (struct bxf_sandbox) {
            .pid = pid,
        };

        snprintf(map_name, sizeof (map_name), "bxfi_%d", pid);

        size_t len = strlen(addr.soname);

        struct bxfi_map local_ctx;
        map_rc = bxfi_create_local_ctx(&local_ctx, map_name, len + 1);

        if (map_rc < 0)
            goto err_kill;

        local_ctx.ctx->ok = 0;
        local_ctx.ctx->fn = addr.addr;
        memcpy(local_ctx.ctx + 1, addr.soname, len + 1);
        local_ctx.ctx->fn_soname_sz = len + 1;

        kill(pid, SIGCONT);
        waitpid(pid, &status, WUNTRACED);

        if (!WIFSTOPPED(status))
            goto err;

        if (!local_ctx.ctx->ok)
            goto err_kill;

        kill(pid, SIGCONT);
        *ctx = &sandbox->props;

        bxfi_unmap_local_ctx(&local_ctx, map_name, 0);
        return 0;

err_kill:
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
err:
        if (!map_rc)
            shm_unlink(map_name);
        return -EPROTO;
    }

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    raise(SIGSTOP);

    execl(exe, "boxfort-worker", NULL);
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

    /* Enforce the deletion of the shm file */
    if (!WIFSTOPPED(status)) {
        char map_name[sizeof ("bxfi_") + 21];
        snprintf(map_name, sizeof (map_name), "bxfi_%d", getpid());

        shm_unlink(map_name);
    }
    return 0;
}
