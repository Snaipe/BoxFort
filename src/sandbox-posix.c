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
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/wait.h>

#include "addr.h"
#include "boxfort.h"
#include "sandbox.h"

#if defined (HAVE_PR_SET_PDEATHSIG)
# include <sys/prctl.h>
#endif

#if defined (__APPLE__)
# include <mach-o/dyld.h>
#endif

struct bxfi_sandbox {
    struct bxf_instance props;

    /* A sandbox is said to be mantled if there is an unique instance
       managing its memory. */
    int mantled;

    pthread_mutex_t sync;
    pthread_cond_t cond;
    bxf_callback *callback;
    struct bxfi_sandbox *next;
};

static struct {
    struct bxfi_sandbox *alive;
    struct bxfi_sandbox *dead;
    pthread_mutex_t sync;
    pthread_cond_t cond;

    pthread_t child_pump;
    int child_pump_active;
} self = {
    .sync = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
};

static struct bxfi_sandbox *reap_child(pid_t pid)
{
    struct bxfi_sandbox *s;

    pthread_mutex_lock(&self.sync);
    for (s = self.alive; s; s = s->next) {
        if (s->props.pid == (bxf_pid) pid)
            break;
    }
    if (!s) {
        pthread_mutex_unlock(&self.sync);
        return NULL;
    }
    pthread_mutex_unlock(&self.sync);

    int status;
    pid_t rc = waitpid(pid, &status, WNOHANG);
    if (rc != pid)
        return NULL;

    pthread_mutex_lock(&s->sync);
    if (WIFEXITED(status))
        s->props.status.exit = WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        s->props.status.signal = WTERMSIG(status);
    s->props.status.stopped = WIFSTOPPED(status);
    s->props.status.alive = WIFSTOPPED(status);
    pthread_cond_broadcast(&s->cond);
    pthread_mutex_unlock(&s->sync);

    return s;
}

static void *child_pump_fn(void *nil)
{
    int wflags = WEXITED | WNOWAIT;
    for (;;) {
        pthread_mutex_lock(&self.sync);
        while (!self.alive)
            pthread_cond_wait(&self.cond, &self.sync);
        pthread_mutex_unlock(&self.sync);

        siginfo_t infop = {0};
        int rc;
        for (;;) {
            rc = waitid(P_ALL, 0, &infop, wflags);
            if (rc != -1 || errno == EINTR)
                break;
        }
        if (rc)
            continue;

        for (;;) {
            memset(&infop, 0, sizeof (infop));
            if (waitid(P_ALL, 0, &infop, wflags | WNOHANG) == -1)
                break;
            if (!infop.si_pid)
                break;

            struct bxfi_sandbox *instance = reap_child(infop.si_pid);
            if (!instance)
                continue;
            if (!instance->props.status.alive && instance->callback)
                instance->callback(&instance->props);

            pthread_mutex_lock(&self.sync);
            struct bxfi_sandbox **prev = &self.alive;
            for (struct bxfi_sandbox *s = self.alive; s; s = s->next) {
                if (s->props.pid == (bxf_pid) infop.si_pid) {
                    *prev = s->next;
                    s->next = self.dead;
                    self.dead = s;
                    break;
                }
                prev = &s->next;
            }
            if (!self.alive)
                goto end;
            pthread_mutex_unlock(&self.sync);
        }
    }
    pthread_mutex_lock(&self.sync);
end:
    pthread_mutex_unlock(&self.sync);
    return nil;
}

static int bxfi_create_local_ctx(struct bxfi_map *map,
        const char *name, size_t sz)
{
    shm_unlink(name);

    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd == -1)
        goto error;

    if (ftruncate(fd, sizeof (struct bxfi_context) + sz) == -1)
        goto error;

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
    size_t *sz = mmap(NULL,
            sizeof (total_sz), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (sz == MAP_FAILED)
        goto error;

    total_sz = *sz;
    munmap(sz, sizeof (total_sz));

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
#if defined(__linux__)
    const char *self = "/proc/self/exe";
#elif defined __NetBSD__
    const char *self = "/proc/curproc/exe";
#elif defined __FreeBSD__
    const char *self = "/proc/curproc/file";

    int fd = open(self, O_RDONLY);
    /* Fallback */
    char path[PATH_MAX];
    if (fd == -1 && errno == ENOENT) {
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
        char path[PATH_MAX];
        size_t cb = sizeof (path);
        sysctl(mib, sizeof (mib) / sizeof (int), path, &cb, NULL, 0);
        self = path;
    }
    if (fd != -1)
        close(fd);
#elif defined __OpenBSD__ || defined __DragonFly__
    const char *self = "/proc/curproc/file";
#elif defined (__APPLE__)
    uint32_t size = sz;
    if (_NSGetExecutablePath(buf, &size) == -1)
        return -ENAMETOOLONG;
    /* _NSGetExecutablePath already returns the correct path */
    char *self;
    (void) self;
    return 0;
#else
# error Platform not supported
#endif

    /* We can't just use /proc/self/exe or equivalent to re-exec the
       executable, because tools like valgrind use this path to open
       and map the ELF file -- which would point to the valgrind binary. */
    ssize_t rc = readlink(self, buf, sz);
    if (rc == -1) {
        if (errno == EINVAL) {
            strncpy(buf, self, sz);
            return 0;
        }
        return -errno;
    }
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

    if (!WIFSTOPPED(status)) {
        errno = EPROTO;
        return 0;
    }

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

static void prefork(void)
{
    pthread_mutex_lock(&self.sync);
    for (struct bxfi_sandbox *s = self.alive; s; s = s->next)
        pthread_mutex_lock(&s->sync);
    for (struct bxfi_sandbox *s = self.dead; s; s = s->next)
        pthread_mutex_lock(&s->sync);
}

static void postfork_parent(void)
{
    for (struct bxfi_sandbox *s = self.dead; s; s = s->next)
        pthread_mutex_unlock(&s->sync);
    for (struct bxfi_sandbox *s = self.alive; s; s = s->next)
        pthread_mutex_unlock(&s->sync);
    pthread_mutex_unlock(&self.sync);
}

static void postfork_child(void)
{
    postfork_parent();

    pthread_cond_t nil = PTHREAD_COND_INITIALIZER;
    memcpy(&self.cond, &nil, sizeof (nil));

    if (self.alive)
        pthread_join(self.child_pump, NULL);

    for (struct bxfi_sandbox *s = self.alive; s; s = s->next) {
        memset((void*)&s->props.status, 0, sizeof (s->props.status));
        s->next = self.dead;
        self.dead = s;
    }

    self.alive = NULL;
}

static void init_atfork(void)
{
    pthread_atfork(prefork, postfork_parent, postfork_child);
}

static void init_child_pump(pid_t pid)
{
    if (pthread_create(&self.child_pump, NULL, child_pump_fn, NULL))
        goto thread_err;
    self.child_pump_active = 1;
    return;

thread_err:
    perror("boxfort: could not initialize child pump");
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    abort();
}

static void term_child_pump(void)
{
    if (self.child_pump_active) {
        pthread_join(self.child_pump, NULL);
        self.child_pump_active = 0;
    }
}

int bxfi_exec(bxf_instance **out, bxf_sandbox *sandbox,
        int mantled, bxf_fn *fn, bxf_preexec *preexec, bxf_callback *callback)
{
    static char exe[PATH_MAX + 1];
    static pthread_once_t atfork = PTHREAD_ONCE_INIT;

    pthread_once(&atfork, init_atfork);

    char map_name[sizeof ("bxfi_") + 21];
    struct bxfi_sandbox *instance = NULL;
    struct bxfi_map local_ctx = { 0 };
    pid_t pid = 0;

    intptr_t errnum;
    int map_rc = -1;

    if (!exe[0] && (errnum = get_exe_path(exe, sizeof (exe))) < 0)
        return errnum;

    struct bxfi_addr addr;
    if (bxfi_normalize_fnaddr(fn, &addr) < 0)
        return -EINVAL;

    errnum = -ENOMEM;

    instance = malloc(sizeof (*instance));
    if (!instance)
        goto err;
    *instance = (struct bxfi_sandbox) {
        .mantled = mantled,
        .callback = callback,
    };
    if ((errnum = -pthread_mutex_init(&instance->sync, NULL)))
        goto err;
    if ((errnum = -pthread_cond_init(&instance->cond, NULL)))
        goto err;

    pid = fork();
    if (pid == -1) {
        errnum = -errno;
        goto err;
    } else if (pid) {

        instance->props = (struct bxf_instance) {
            .sandbox = sandbox,
            .pid = pid,
            .status.alive = 1,
        };

        if ((pid = wait_stop(pid)) <= 0) {
            errnum = -errno;
            goto err;
        }

        snprintf(map_name, sizeof (map_name), "bxfi_%d", pid);

        size_t len = strlen(addr.soname);

        map_rc = bxfi_create_local_ctx(&local_ctx, map_name, len + 1);
        errnum = map_rc;

        if (map_rc < 0)
            goto err;

        local_ctx.ctx->ok = 0;
        local_ctx.ctx->fn = addr.addr;
        memcpy(local_ctx.ctx + 1, addr.soname, len + 1);
        local_ctx.ctx->fn_soname_sz = len + 1;

        kill(pid, SIGCONT);
        if ((pid = wait_stop(pid)) <= 0) {
            errnum = -errno;
            goto err;
        }

        if (!local_ctx.ctx->ok)
            goto err;

        pthread_mutex_lock(&self.sync);
        /* spawn a wait thread if no sandboxes are alive right now */
        if (!self.alive) {
            term_child_pump();
            init_child_pump(pid);
        }

        instance->next = self.alive;
        self.alive = instance;
        pthread_cond_broadcast(&self.cond);
        pthread_mutex_unlock(&self.sync);

        bxfi_unmap_local_ctx(&local_ctx);

        kill(pid, SIGCONT);

        *out = &instance->props;
        return 0;
    }

#if defined (HAVE_PR_SET_PDEATHSIG)
    prctl(PR_SET_PDEATHSIG, SIGKILL);
#endif

    instance->props = (struct bxf_instance) {
        .sandbox = sandbox,
        .pid = getpid(),
    };

    if (preexec && preexec(&instance->props) < 0)
        abort();

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

    if (!map_rc) {
        bxfi_unmap_local_ctx(&local_ctx);
        shm_unlink(map_name);
    }

    return errnum;
}

int bxf_term(bxf_instance *instance)
{
    if (instance->status.alive)
        return -EINVAL;

    struct bxfi_sandbox *sb = bxfi_cont(instance, struct bxfi_sandbox, props);
    struct bxfi_sandbox **prev = &self.dead;

    pthread_mutex_lock(&self.sync);
    for (struct bxfi_sandbox *s = self.dead; s; s = s->next) {
        if (s == sb) {
            *prev = s->next;
            break;
        }
        prev = &s->next;
    }
    pthread_mutex_unlock(&self.sync);

    if (sb->mantled)
        free((void *) instance->sandbox);
    pthread_mutex_destroy(&sb->sync);
    pthread_cond_destroy(&sb->cond);
    free(sb);
    return 0;
}

int bxf_wait(bxf_instance *instance, size_t timeout)
{
    if (!instance->status.alive)
        return 0;

    struct timespec timeo = {
        .tv_sec = timeout / 1000000000,
        .tv_nsec = timeout % 1000000000
    };

    struct bxfi_sandbox *sb = bxfi_cont(instance, struct bxfi_sandbox, props);
    pthread_mutex_lock(&sb->sync);
    while (instance->status.alive && !instance->status.stopped) {
        pthread_cond_timedwait(&sb->cond, &sb->sync, &timeo);
    }
    pthread_mutex_unlock(&sb->sync);

    pthread_mutex_lock(&self.sync);
    if (!self.alive)
        term_child_pump();
    pthread_mutex_unlock(&self.sync);

    /* Enforce the deletion of the shm file */
    if (!instance->status.alive) {
        char map_name[sizeof ("bxfi_") + 21];
        snprintf(map_name, sizeof (map_name), "bxfi_%d", (int) instance->pid);

        shm_unlink(map_name);
    }
    return 0;
}
