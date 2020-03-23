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
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "sandbox.h"

struct bxfi_timeout_request {
    struct timespec timeout;
    pid_t pid;
    struct bxfi_sandbox *sb;
    int cancelled;
    struct bxfi_timeout_request *next;
};

static struct {
    struct bxfi_timeout_request *volatile requests;
    struct bxfi_timeout_request *volatile cancelled;
    pthread_t thread;
    int thread_active;
    pthread_mutex_t sync;
    pthread_cond_t cond;
} self = {
    .sync = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
};

static int timespec_cmp(struct timespec *a, struct timespec *b)
{
    if (a->tv_sec < b->tv_sec)
        return -1;
    if (a->tv_sec > b->tv_sec)
        return 1;
    if (a->tv_nsec < b->tv_nsec)
        return -1;
    if (a->tv_nsec > b->tv_nsec)
        return 1;
    return 0;
}

static void to_timespec(double timeout, struct timespec *timeo)
{
    static const uint64_t nanosecs = 1000000000;

    uint64_t to_ns = (timeout - (uint64_t) timeout) * nanosecs;
    uint64_t to_s  = timeout;

#if defined (HAVE_CLOCK_GETTIME)
    clock_gettime(CLOCK_REALTIME, timeo);
    uint64_t new_nsec = (timeo->tv_nsec + to_ns) % nanosecs;
    timeo->tv_sec += to_s + (timeo->tv_nsec + to_ns) / nanosecs;
    timeo->tv_nsec = new_nsec;
#elif defined (HAVE_GETTIMEOFDAY)
    struct timeval tv;
    gettimeofday(&tv, NULL);

    *timeo = (struct timespec) {
        .tv_sec  = tv.tv_sec + to_s + (tv.tv_usec * 1000 + to_ns) / nanosecs,
        .tv_nsec = (tv.tv_usec * 1000 + to_ns) % nanosecs,
    };
#else
# error No way to get a viable timespec.
#endif
}

static void *timeout_killer_fn(void *nil)
{
    pthread_mutex_lock(&self.sync);

    struct bxfi_timeout_request *req;
    for (;;) {
        while (self.cancelled) {
            req = self.cancelled;
            self.cancelled = req->next;
            free(req);
        }

        req = self.requests;
        if (!req)
            goto end;
        int rc = pthread_cond_timedwait(&self.cond, &self.sync, &req->timeout);
        if (!rc || req->cancelled)
            continue;

        assert(rc == ETIMEDOUT);
        kill(req->pid, SIGPROF);

        pthread_mutex_lock(&req->sb->sync);
        req->sb->props.status.timed_out = 1;
        pthread_mutex_unlock(&req->sb->sync);

        self.requests = req->next;
        free(req);
    }
end:
    self.thread_active = 0;
    pthread_mutex_unlock(&self.sync);
    return nil;
}

void bxfi_reset_timeout_killer(void)
{
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond   = PTHREAD_COND_INITIALIZER;

    memcpy(&self.sync, &mutex, sizeof (mutex));
    memcpy(&self.cond, &cond, sizeof (cond));
}

int bxfi_push_timeout(struct bxfi_sandbox *instance, double timeout)
{
    int rc;

    struct bxfi_timeout_request *req = calloc(1, sizeof (*req));

    if (!req)
        return -ENOMEM;

    to_timespec(timeout, &req->timeout);

    req->sb  = instance;
    req->pid = instance->props.pid;

    pthread_mutex_lock(&self.sync);
    if (!self.requests) {
        pthread_attr_t attrs;
        if ((rc = pthread_attr_init(&attrs)) == -1) {
            rc = -errno;
            goto error;
        }
        pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED);

        self.thread_active = 1;
        rc = -pthread_create(&self.thread, &attrs, timeout_killer_fn, NULL);
        pthread_attr_destroy(&attrs);
        if (rc)
            goto error;
    }

    struct bxfi_timeout_request *volatile *nptr = &self.requests;
    for (struct bxfi_timeout_request *r = self.requests; r; r = r->next) {
        if (timespec_cmp(&r->timeout, &req->timeout) > 0)
            break;
        nptr = &r->next;
    }

    *nptr = req;

    pthread_cond_broadcast(&self.cond);
    pthread_mutex_unlock(&self.sync);
    return 0;

error:
    pthread_mutex_unlock(&self.sync);
    free(req);
    return rc;
}

void bxfi_cancel_timeout(struct bxfi_sandbox *instance)
{
    pthread_mutex_lock(&self.sync);
    int cancelled = 0;

    struct bxfi_timeout_request *volatile *nptr = &self.requests;
    for (struct bxfi_timeout_request *r = self.requests; r; r = r->next) {
        if (r->pid == (pid_t) instance->props.pid) {
            *nptr   = r->next;
            r->next = self.cancelled;
            self.cancelled = r;
            r->cancelled   = cancelled = 1;
        }
        nptr = &r->next;
    }
    if (cancelled) {
        pthread_cond_broadcast(&self.cond);
    }
    pthread_mutex_unlock(&self.sync);
}
