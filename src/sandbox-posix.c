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
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/wait.h>

#include "addr.h"
#include "boxfort.h"
#include "sandbox.h"

struct bxfi_sandbox {
    struct bxf_instance props;

    /* A sandbox is said to be mantled if there is an unique instance
       managing its memory. */
    int mantled;
};

#define bxfi_cont(Var, Type, Member) \
    (Var ? ((Type*) (((char*) Var) - offsetof(Type, Member))) : NULL)

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

    *map = (struct bxfi_map) { .ctx = ctx, .fd = fd };
    return 0;

error:;
    int err = errno;
    shm_unlink(name);
    if (fd != -1)
        close(fd);
    return -err;
}

static void bxfi_unmap_local_ctx(struct bxfi_map *map)
{
    size_t sz = map->ctx->total_sz;
    munmap(map->ctx, sz);
    close(map->fd);
}

int bxfi_check_sandbox_ctx(void)
{
    char name[sizeof ("bxfi_") + 21];
    snprintf(name, sizeof (name), "bxfi_%d", getpid());

    int fd = shm_open(name, O_RDONLY, 0600);
    if (fd != -1)
        close(fd);
    return fd != -1;
}

int bxfi_init_sandbox_ctx(struct bxfi_map *map)
{
    char name[sizeof ("bxfi_") + 21];
    snprintf(name, sizeof (name), "bxfi_%d", getpid());

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

    *map = (struct bxfi_map) { .ctx = ctx, .fd = fd };
    memcpy(map->map_name, name, sizeof (name));
    return 0;

error:;
    int err = errno;
    if (fd != -1)
        close(fd);
    return -err;
}

int bxfi_term_sandbox_ctx(struct bxfi_map *map)
{
    map->ctx->ok = 1;
    bxfi_unmap_local_ctx(map);

    if (shm_unlink(map->map_name) == -1)
        return -errno;

    /* Wait for the parent to finalize initialization */
    raise(SIGSTOP);
    return 0;
}

static int get_exe_path(char *buf, size_t sz)
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

static pid_t wait_stop(pid_t pid)
{
    int status;
    pid_t rc;

    for (;;) {
        rc = waitpid(pid, &status, WUNTRACED);
        if (rc != -1 || errno != EINTR)
            break;
    }
    if (rc == -1)
        return -pid;

    if (!WIFSTOPPED(status))
        return 0;

    return pid;
}

static int setup_limit(int limit, size_t iquota, size_t quota)
{
    if (!quota && !iquota)
        return 0;

    struct rlimit rl;
    if (getrlimit(limit, &rl) < 0)
        return -errno;

    if (quota)
        rl.rlim_max = quota;

    if (iquota)
        rl.rlim_cur = iquota;
    else if (quota)
        rl.rlim_cur = quota;

    if (setrlimit(limit, &rl) < 0)
        return -errno;
    return 0;
}

#define setup_limit(Limit, Quota)   \
        (setup_limit((Limit),       \
            sandbox->iquotas.Quota, \
            sandbox->quotas.Quota))

static int setup_limits(bxf_sandbox *sandbox)
{
    int errnum;

    errnum = setup_limit(RLIMIT_AS, memory);
    if (errnum < 0)
        return errnum;

    errnum = setup_limit(RLIMIT_NOFILE, files);
    if (errnum < 0)
        return errnum;

    errnum = setup_limit(RLIMIT_NPROC, subprocesses);
    if (errnum < 0)
        return errnum;

    return 0;
}

static int setup_inheritance(bxf_sandbox *sandbox)
{
    if (!sandbox->inherit.files) {
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
            return -errno;
        for (int fd = 3; fd < (int) rl.rlim_cur; ++fd)
            close(fd);
    }
    return 0;
}


bxf_instance *bxf_start(bxf_sandbox *sandbox, bxf_fn *fn)
{
    static char exe[PATH_MAX + 1];

    char map_name[sizeof ("bxfi_") + 21];
    struct bxfi_sandbox *instance = NULL;
    pid_t pid = 0;

    intptr_t errnum;
    int map_rc;

    if (!exe[0] && (errnum = get_exe_path(exe, sizeof (exe))) < 0)
        return (bxf_instance *) errnum;

    struct bxfi_addr addr;
    if (bxfi_normalize_fnaddr(fn, &addr) < 0)
        return (bxf_instance *) -EINVAL;

    errnum = -ENOMEM;

    instance = malloc(sizeof (*instance));
    if (!instance)
        goto err;
    instance->mantled = 1;

    pid = fork();
    if (pid == -1) {
        errnum = -errno;
        goto err;
    } else if (pid) {

        if ((pid = wait_stop(pid)) <= 0)
            goto err;

        instance->props = (struct bxf_instance) {
            .sandbox = sandbox,
            .pid = pid,
        };

        snprintf(map_name, sizeof (map_name), "bxfi_%d", pid);

        size_t len = strlen(addr.soname);

        struct bxfi_map local_ctx;
        map_rc = bxfi_create_local_ctx(&local_ctx, map_name, len + 1);

        if (map_rc < 0)
            goto err;

        local_ctx.ctx->ok = 0;
        local_ctx.ctx->fn = addr.addr;
        memcpy(local_ctx.ctx + 1, addr.soname, len + 1);
        local_ctx.ctx->fn_soname_sz = len + 1;

        kill(pid, SIGCONT);
        if ((pid = wait_stop(pid)) <= 0)
            goto err;

        if (!local_ctx.ctx->ok)
            goto err;

        kill(pid, SIGCONT);

        bxfi_unmap_local_ctx(&local_ctx);
        return &instance->props;
    }

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    if (setup_limits(sandbox) < 0)
        abort();

    if (setup_inheritance(sandbox) < 0)
        abort();

    raise(SIGSTOP);

    execl(exe, "boxfort-worker", NULL);
    _exit(errno);

err:
    if (pid) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }

    if (!map_rc)
        shm_unlink(map_name);

    return (bxf_instance *) errnum;
}

bxf_instance *bxf_run_impl(bxf_run_params params)
{
    if (!params->fn)
        return (bxf_instance *) -EINVAL;

    struct bxf_sandbox *sandbox = calloc(1, sizeof (*sandbox));
    if (!sandbox)
        return (bxf_instance *) -ENOMEM;

    sandbox->quotas  = params->quotas;
    sandbox->iquotas = params->iquotas;
    sandbox->inherit = params->inherit;

    bxf_instance *instance = bxf_start(sandbox, params->fn);
    if ((intptr_t) instance < 0)
        free(sandbox);

    return instance;
}

int bxf_term(bxf_instance *instance)
{
    struct bxfi_sandbox *sb = bxfi_cont(instance, struct bxfi_sandbox, props);
    if (sb->mantled)
        free((void *) instance->sandbox);
    free(sb);
    return 0;
}

int bxf_wait(bxf_instance *ctx, size_t timeout)
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
