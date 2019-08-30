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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifdef __FreeBSD__
# include <sys/sysctl.h>
#endif

#if defined (HAVE_CLOCK_GETTIME)
# include <time.h>
#elif defined (HAVE_GETTIMEOFDAY)
# include <sys/time.h>
#endif

#include "addr.h"
#include "boxfort.h"
#include "context.h"
#include "sandbox.h"
#include "timestamp.h"
#include "timeout.h"

#if defined (HAVE_PR_SET_PDEATHSIG)
# include <sys/prctl.h>
#endif

#if defined (__APPLE__)
# include <mach-o/dyld.h>
#endif

#ifndef HAVE_ENVIRON
# ifdef __APPLE__
#  include <crt_externs.h>
#  define environ (*_NSGetEnviron())
# else
extern char **environ;
# endif
#endif

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

static struct bxfi_sandbox *reap_child(pid_t pid,
        uint64_t ts_end, uint64_t mts_end)
{
    struct bxfi_sandbox *s;

    pthread_mutex_lock(&self.sync);
    for (s = self.alive; s; s = s->next) {
        if (s->wait_pid == pid)
            break;
    }
    if (!s) {
        pthread_mutex_unlock(&self.sync);
        return NULL;
    }
    pthread_mutex_unlock(&self.sync);

    bxfi_cancel_timeout(s);

    int status;
    pid_t rc = waitpid(pid, &status, WNOHANG);
    if (rc != pid)
        return NULL;

    pthread_mutex_lock(&s->sync);
    s->props.time.end = ts_end;
    s->props.time.elapsed = mts_end - s->start_monotonic;

    if (WIFEXITED(status))
        s->props.status.exit = WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        s->props.status.signal = WTERMSIG(status);
    s->props.status.stopped = WIFSTOPPED(status);
    s->props.status.alive   = WIFSTOPPED(status);

    if (!s->props.status.alive && s->callback)
        s->callback(&s->props);

    pthread_mutex_unlock(&s->sync);

    return s;
}

static void remove_alive_by_pid(bxf_pid pid)
{
    struct bxfi_sandbox **prev = &self.alive;

    for (struct bxfi_sandbox *s = self.alive; s; s = s->next) {
        if (s->wait_pid == (pid_t) pid) {
            *prev     = s->next;
            s->next   = self.dead;
            self.dead = s;
            break;
        }
        prev = &s->next;
    }
}

static void *child_pump_fn(void *nil)
{
    int wflags = WEXITED | WNOWAIT;

    for (;;) {
        pthread_mutex_lock(&self.sync);
        while (!self.alive)
            pthread_cond_wait(&self.cond, &self.sync);
        pthread_mutex_unlock(&self.sync);

        siginfo_t infop;
        memset(&infop, 0, sizeof (infop));

        int rc;
        for (;;) {
            rc = waitid(P_ALL, 0, &infop, wflags);
            if (rc != -1 || errno == EINTR)
                break;
        }
        if (rc)
            continue;

        uint64_t mts_end = bxfi_timestamp_monotonic();
        uint64_t ts_end  = bxfi_timestamp();

        for (;;) {
            memset(&infop, 0, sizeof (infop));
            if (waitid(P_ALL, 0, &infop, wflags | WNOHANG) == -1)
                break;
            if (!infop.si_pid)
                break;

            struct bxfi_sandbox *instance = reap_child(infop.si_pid,
                    ts_end, mts_end);
            if (!instance)
                continue;

            int alive;
            pthread_mutex_lock(&self.sync);
            remove_alive_by_pid((bxf_pid) infop.si_pid);
            alive = !!self.alive;
            pthread_mutex_unlock(&self.sync);

            pthread_mutex_lock(&instance->sync);
            instance->waited = 1;
            pthread_cond_broadcast(&instance->cond);
            pthread_mutex_unlock(&instance->sync);

            if (!alive)
                goto end;
        }
    }
end:
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
    return !!getenv("BXFI_MAP");
}

int bxfi_init_sandbox_ctx(struct bxfi_map *map)
{
    const char *ctx_path = getenv("BXFI_MAP");

    int fd = shm_open(ctx_path, O_RDWR, 0600);

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
    return 0;

error:;
    int err = errno;
    if (fd != -1)
        close(fd);
    return -err;
}

int bxfi_term_sandbox_ctx(struct bxfi_map *map)
{
    /* This is either our PID or the debugging server's PID */
    pid_t control_pid = map->ctx->pid;

    int suspend = map->ctx->suspend;

    map->ctx->ok  = 1;
    map->ctx->pid = getpid();
    bxfi_unmap_local_ctx(map);

    const char *ctx_path = getenv("BXFI_MAP");

    if (shm_unlink(ctx_path) == -1)
        return -errno;

    /* Notify the parent to finalize initialization */
    kill(control_pid, SIGSTOP);

    if (suspend)
        raise(SIGSTOP);
    return 0;
}

static int get_exe_path(char *buf, size_t sz)
{
#if defined (__linux__)
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

#define setup_limit(Limit, Quota) \
    (setup_limit((Limit),         \
    sandbox->iquotas.Quota,       \
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

static int nocloexec_fd(bxf_fhandle fd, void *ctx)
{
    (void) ctx;

    int flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return -errno;
    flags &= ~FD_CLOEXEC;
    int rc = fcntl(fd, F_SETFD, flags);
    if (rc < 0)
        return -errno;
    return 0;
}

static int inherit_fd(bxf_fhandle fd, void *ctx)
{
    int rc = nocloexec_fd(fd, NULL);

    if (rc < 0)
        return rc;

    uint8_t *do_close = ctx;
    do_close[fd] = 0;
    return 0;
}

static int setup_inheritance(bxf_sandbox *sandbox)
{
    bxf_context ctx = sandbox->inherit.context;

    if (sandbox->inherit.files) {
        int rc = 0;
        if (ctx)
            rc = bxfi_context_prepare(ctx, nocloexec_fd, NULL);
        return rc;
    } else {
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
            return -errno;

        uint8_t *do_close = malloc(rl.rlim_cur);
        if (!do_close)
            return -errno;

        memset(do_close, 1, rl.rlim_cur);
        do_close[STDIN_FILENO]  = 0;
        do_close[STDOUT_FILENO] = 0;
        do_close[STDERR_FILENO] = 0;

        if (ctx) {
            int rc = bxfi_context_prepare(ctx, inherit_fd, do_close);
            if (rc < 0) {
                free(do_close);
                return rc;
            }
        }

        /* /dev/fd is somewhat more common than /proc/self/fd; we'll handle
           special cases later. */
        int fds = open("/dev/fd", O_RDONLY | O_DIRECTORY);

        if (fds >= 0) {
            /* this is somewhat problematic, as fdopendir/readdir are not
               signal-safe, and thus not fork-safe. We can thread the needle
               here by assuming deadlocks are going to be extremely unlikely,
               but not using these APIs and rolling with a custom-made readdir
               might be a better choice for the unforseeable future. */
            DIR *dirfd = fdopendir(fds);

            /* we have a shortcut; iterate through the directory entries */

            struct dirent *dir;
            while ((dir = readdir(dirfd)) != NULL) {
                errno = 0;
                long fd = strtol(dir->d_name, NULL, 10);
                if (errno != 0 || fd < 0 || fd > (long) rl.rlim_cur || !do_close[fd])
                    continue;
                close(fd);
            }

            return 0;
        } else {
            for (int fd = 0; fd < (int) rl.rlim_cur; ++fd) {
                if (!do_close[fd])
                    continue;
                int flags = fcntl(fd, F_GETFD);
                if (flags > 0 && !(flags & FD_CLOEXEC))
                    close(fd);
            }
        }
        free(do_close);
    }
    return 0;
}

#ifdef BXF_FORK_RESILIENCE
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

    for (struct bxfi_sandbox *s = self.alive; s; s = self.alive) {
        memset((void *) &s->props.status, 0, sizeof (s->props.status));
        self.alive = s->next;
        s->next    = self.dead;
        self.dead  = s;
    }

    bxfi_reset_timeout_killer();
}

static void init_atfork(void)
{
    pthread_atfork(prefork, postfork_parent, postfork_child);
}
#endif

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

static int find_exe(const char *progname, char *out, size_t size)
{
    char *sptr = NULL;
    char *path = strdup(getenv("PATH"));
    char *p    = strtok_r(path, ":", &sptr);

    while (p) {
        snprintf(out, size, "%s/%s", *p ? p : ".", progname);

        struct stat sb;
        int rc = stat(out, &sb);
        if (!rc && (S_ISREG(sb.st_mode) || S_ISLNK(sb.st_mode)))
            break;

        p = strtok_r(NULL, ":", &sptr);
    }

    free(path);
    if (!p)
        return -ENOENT;
    return 0;
}

static char **dupenv(char **concat)
{
    size_t len = 0, clen = 0;

    for (char **e = environ; *e; ++e, ++len) ;
    for (char **e = concat; *e; ++e, ++clen) ;

    char **dupe = malloc(sizeof (void *) * (len + clen + 1));
    memcpy(dupe, environ, (len + 1) * sizeof (void *));

    char **d = dupe + len;
    for (char **e = concat; *e; ++e) {
        char **de = dupe;
        for (; *de; ++de) {
            char *eq1 = strchr(*e, '='), *eq2 = strchr(*de, '=');
            if (!eq1 || !eq2)
                continue;

            size_t l1 = (size_t)(eq1 - *e), l2 = (size_t)(eq2 - *de);
            if (l1 != l2)
                continue;

            if (!strncmp(*e, *de, l1)) {
                *de = *e;
                break;
            }
        }
        if (!*de) {
            *d++ = *e;
            *d = NULL;
        }
    }

    return dupe;
}

int bxfi_exec(bxf_instance **out, bxf_sandbox *sandbox,
        int mantled, bxf_fn *fn, bxf_preexec *preexec, bxf_callback *callback,
        void *user, bxf_dtor user_dtor)
{
    static char exe[PATH_MAX + 1];

#ifdef BXF_FORK_RESILIENCE
    static pthread_once_t atfork = PTHREAD_ONCE_INIT;
    pthread_once(&atfork, init_atfork);
#endif

    char map_name[sizeof ("/bxfi_") + 21];
    struct bxfi_sandbox *instance = NULL;
    struct bxfi_map local_ctx;
    pid_t pid = 0;

    memset(&local_ctx, 0, sizeof (local_ctx));

    intptr_t errnum;
    int map_rc = -1;

    if (!exe[0] && (errnum = get_exe_path(exe, sizeof (exe))) < 0)
        return errnum;

    struct bxfi_addr addr;
    if (bxfi_normalize_fnaddr(fn, &addr) < 0)
        return -EINVAL;

    char dbg_full[PATH_MAX];
    if (sandbox->debug.debugger) {
        const char *dbg = NULL;
        switch (sandbox->debug.debugger) {
            case BXF_DBG_GDB:   dbg = "gdbserver"; break;
            case BXF_DBG_LLDB:  dbg = "lldb-server"; break;
            default:
                return -EINVAL;
        }

        if (find_exe(dbg, dbg_full, sizeof (dbg_full)) < 0)
            return -ENOENT;
    }

    errnum = -ENOMEM;

    instance = malloc(sizeof (*instance));
    if (!instance)
        goto err;
    *instance = (struct bxfi_sandbox) {
        .mantled  = mantled,
        .callback = callback,
        .user = user,
        .user_dtor = user_dtor,
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
        instance->start_monotonic = bxfi_timestamp_monotonic();
        instance->wait_pid = pid;

        instance->props = (struct bxf_instance_s) {
            .sandbox = sandbox,
            .pid = pid,
            .status.alive = 1,
            .time.start   = bxfi_timestamp(),
            .user = instance->user,
        };

        if ((pid = wait_stop(pid)) <= 0) {
            errnum = -errno;
            goto err;
        }

        snprintf(map_name, sizeof (map_name), "/bxfi_%d", pid);

        size_t len = strlen(addr.soname);

        map_rc = bxfi_create_local_ctx(&local_ctx, map_name, len + 1);
        errnum = map_rc;

        if (map_rc < 0)
            goto err;

        local_ctx.ctx->ok       = 0;
        local_ctx.ctx->fn       = addr.addr;
        local_ctx.ctx->seg      = addr.seg;
        local_ctx.ctx->pid      = pid;
        local_ctx.ctx->suspend  = sandbox->suspended;
        bxf_context ictx = sandbox->inherit.context;
        if (ictx) {
#ifdef BXF_ARENA_REOPEN_SHM
            strcpy(local_ctx.ctx->context.name, ictx->arena->name);
#else
            local_ctx.ctx->context.handle = ictx->arena->handle;
#endif
        }
        memcpy(local_ctx.ctx + 1, addr.soname, len + 1);
        local_ctx.ctx->fn_soname_sz = len + 1;

        kill(pid, SIGCONT);
        if ((pid = wait_stop(pid)) <= 0) {
            errnum = -errno;
            goto err;
        }

        if (!local_ctx.ctx->ok)
            goto err;

        instance->props.pid = local_ctx.ctx->pid;

        if (sandbox->quotas.runtime > 0)
            if (bxfi_push_timeout(instance, sandbox->quotas.runtime) < 0)
                goto err;


        if (sandbox->iquotas.runtime > 0)
            if (bxfi_push_timeout(instance, sandbox->iquotas.runtime) < 0)
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

        if (sandbox->suspended)
            instance->props.status.stopped = 1;

        *out = &instance->props;
        return 0;
    }

#if defined (HAVE_PR_SET_PDEATHSIG)
    int pdeathsig = sandbox->debug.debugger ? SIGTERM : SIGKILL;
    prctl(PR_SET_PDEATHSIG, pdeathsig);
#endif

    pid = getpid();

    instance->props = (struct bxf_instance_s) {
        .sandbox = sandbox,
        .pid = pid,
    };

    if (preexec && preexec(&instance->props) < 0)
        abort();

    if (setup_limits(sandbox) < 0)
        abort();

    if (setup_inheritance(sandbox) < 0)
        abort();

    setsid();

    raise(SIGSTOP);

    snprintf(map_name, sizeof (map_name), "/bxfi_%d", pid);

    char env_map[sizeof ("BXFI_MAP=") + sizeof (map_name)];
    snprintf(env_map, sizeof (env_map), "BXFI_MAP=%s", map_name);

    char **env = dupenv((char *[]) { env_map, "GMON_OUT_PREFIX=sandbox-gmon", NULL });

    char *fullpath = exe;
    char *argv[16] = { "boxfort-worker" };
    size_t argc = 1;

    if (sandbox->debug.debugger) {
        char port[11];

        switch (sandbox->debug.debugger) {
            case BXF_DBG_GDB:
                snprintf(port, sizeof (port), ":%d", sandbox->debug.tcp);
                break;
            case BXF_DBG_LLDB:
                argv[argc++] = "gdbserver";
                snprintf(port, sizeof (port), "*:%d", sandbox->debug.tcp);
                break;
            default:
                abort();
        }

        argv[argc++] = port;
        argv[argc++] = exe;

        fullpath = dbg_full;
    }
    argv[argc++] = NULL;

    execve(fullpath, argv, env);
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

    free(instance);

    return errnum;
}

int bxf_term(bxf_instance *instance)
{
    if (instance->status.alive)
        return -EINVAL;

    struct bxfi_sandbox *sb = bxfi_cont(instance, struct bxfi_sandbox, props);

    if (!sb->waited)
        return -EINVAL;

    pthread_mutex_lock(&self.sync);
    struct bxfi_sandbox **prev = &self.dead;
    int ok = 0;
    for (struct bxfi_sandbox *s = self.dead; s; s = s->next) {
        if (s == sb) {
            *prev = s->next;
            ok    = 1;
            break;
        }
        prev = &s->next;
    }
    pthread_mutex_unlock(&self.sync);
    if (!ok)
        return -EINVAL;

    if (sb->user && sb->user_dtor)
        sb->user_dtor(instance, sb->user);

    if (sb->mantled)
        free((void *) instance->sandbox);
    pthread_mutex_destroy(&sb->sync);
    pthread_cond_destroy(&sb->cond);
    free(sb);
    return 0;
}

int bxf_wait(bxf_instance *instance, double timeout)
{
    if (timeout < 0)
        timeout = 0;

    static const size_t nanosecs = 1000000000;

    size_t to_ns = (timeout - (size_t) timeout) * nanosecs;
    size_t to_s  = timeout;

    struct timespec timeo;

#if defined (HAVE_PTHREAD_COND_TIMEDWAIT_RELATIVE_NP)
    timeo = (struct timespec) { .tv_sec = to_ns, .tv_nsec = to_s };

    typedef int (*const f_timedwait)(pthread_cond_t *cond,
            pthread_mutex_t *mutex,
            const struct timespec *abstime);

    static f_timedwait pthread_cond_timedwait =
            pthread_cond_timedwait_relative_np;
#elif defined (HAVE_CLOCK_GETTIME)
    clock_gettime(CLOCK_REALTIME, &timeo);
    size_t new_nsec = (timeo.tv_nsec + to_ns) % nanosecs;
    timeo.tv_sec += to_s + (timeo.tv_nsec + to_ns) / nanosecs;
    timeo.tv_nsec = new_nsec;
#elif defined (HAVE_GETTIMEOFDAY)
    struct timeval tv;
    gettimeofday(&tv, NULL);

    timeo = (struct timespec) {
        .tv_sec  = tv.tv_sec + to_s + (tv.tv_usec * 1000 + to_ns) / nanosecs,
        .tv_nsec = (tv.tv_usec * 1000 + to_ns) % nanosecs,
    };
#else
# error bxf_wait needs a way to get the current time.
#endif

    struct bxfi_sandbox *sb = bxfi_cont(instance, struct bxfi_sandbox, props);
    pthread_mutex_lock(&sb->sync);
    int rc = 0;
    while (!sb->waited) {
        if (timeout == BXF_FOREVER || !isfinite(timeout))
            rc = pthread_cond_wait(&sb->cond, &sb->sync);
        else
            rc = pthread_cond_timedwait(&sb->cond, &sb->sync, &timeo);
        if (!rc || rc == ETIMEDOUT)
            break;
    }
    if (!rc)
        sb->waited = 1;
    pthread_mutex_unlock(&sb->sync);

    if (rc)
        return -rc;

    pthread_mutex_lock(&self.sync);
    if (!self.alive)
        term_child_pump();
    pthread_mutex_unlock(&self.sync);

    /* Enforce the deletion of the shm file */
    if (!instance->status.alive) {
        char map_name[sizeof ("/bxfi_") + 21];
        snprintf(map_name, sizeof (map_name), "/bxfi_%d", (int) instance->pid);

        shm_unlink(map_name);
    }
    return 0;
}

void bxf_suspend(bxf_instance *instance)
{
    kill((pid_t) instance->pid, SIGSTOP);
}

void bxf_resume(bxf_instance *instance)
{
    kill((pid_t) instance->pid, SIGCONT);
}
