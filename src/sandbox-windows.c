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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <tchar.h>

#include "addr.h"
#include "context.h"
#include "sandbox.h"
#include "timestamp.h"
#include "timeout.h"

int bxfi_check_sandbox_ctx(void)
{
    int is_sandbox = !!_tcsstr(GetCommandLine(), TEXT("BXFI_MAP="));

    /* If we are a sandbox, first thing we do is disable the crash dialog */
    if (is_sandbox)
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

    return is_sandbox;
}

static int bxfi_create_local_ctx(struct bxfi_map *map, LPTCH name, size_t sz)
{
    HANDLE shm = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
            PAGE_READWRITE, 0, sz, name);

    if (!shm || GetLastError() == ERROR_ALREADY_EXISTS)
        return -EEXIST;

    struct bxfi_context *ctx = MapViewOfFile(shm, FILE_MAP_ALL_ACCESS,
            0, 0, sizeof (struct bxfi_context) + sz);

    if (!ctx)
        return -ENOMEM;

    *map = (struct bxfi_map) { .ctx = ctx, .handle = shm };
    memcpy(map->map_name, name, (_tcslen(name) + 1) * sizeof (TCHAR));
    return 0;
}

int bxfi_init_sandbox_ctx(struct bxfi_map *map)
{
    TCHAR *env  = _tcsstr(GetCommandLine(), TEXT("BXFI_MAP="));
    TCHAR *name = env + sizeof ("BXFI_MAP=") - 1;

    HANDLE shm = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, name);

    if (!shm)
        return -ENOENT;

    struct bxfi_context *ctx = MapViewOfFile(shm, FILE_MAP_ALL_ACCESS,
            0, 0, sizeof (struct bxfi_context));

    errno = -ENOMEM;
    if (!ctx)
        goto error;

    DWORD size = ctx->total_sz;

    errno = -EINVAL;
    if (!UnmapViewOfFile(ctx))
        goto error;

    ctx = MapViewOfFile(shm, FILE_MAP_ALL_ACCESS, 0, 0, size);

    errno = -ENOMEM;
    if (!ctx)
        goto error;

    *map = (struct bxfi_map) { .ctx = ctx, .handle = shm };
    memcpy(map->map_name, name, (_tcslen(name) + 1) * sizeof (TCHAR));
    return 0;

error:
    if (shm)
        CloseHandle(shm);
    return -errno;
}

int bxfi_unmap_local_ctx(struct bxfi_map *map)
{
    UnmapViewOfFile(map->ctx);
    CloseHandle(map->handle);
    return 0;
}

int bxfi_term_sandbox_ctx(struct bxfi_map *map)
{
    HANDLE sync = map->ctx->sync;
    int waitfordebugger = map->ctx->suspend;
    int rc = bxfi_unmap_local_ctx(map);

    SetEvent(sync);

    if (waitfordebugger) {
        while (!IsDebuggerPresent())
            Sleep(100);
    }
    return rc;
}

struct callback_ctx {
    HANDLE whandle;
    bxf_callback *callback;
    struct bxfi_sandbox *instance;
};

#ifndef STATUS_BAD_STACK
# define STATUS_BAD_STACK 0xC0000028L
#endif

/*
 *  NTSTATUS specification, from ntstatus.h:
 *
 *  > Values are 32 bit values laid out as follows:
 *  >
 *  >  3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *  >  1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *  > +---+-+-+-----------------------+-------------------------------+
 *  > |Sev|C|R|     Facility          |               Code            |
 *  > +---+-+-+-----------------------+-------------------------------+
 *  >
 *  > where
 *  >
 *  >     Sev - is the severity code
 *  >
 *  >         00 - Success
 *  >         01 - Informational
 *  >         10 - Warning
 *  >         11 - Error
 *  >
 *  >     C - is the Customer code flag
 *  >
 *  >     R - is a reserved bit
 *  >
 *  >     Facility - is the facility code
 *  >
 *  >     Code - is the facility's status code
 *
 *  We consider that all exit codes with error severity bits that cannot
 *  be directly translated to translate to SIGSYS.
 *
 */
static void get_status(HANDLE handle, struct bxf_instance_s *instance)
{
    DWORD exit_code;

    GetExitCodeProcess(handle, &exit_code);
    unsigned int sig = 0;
    switch (exit_code) {
        case STATUS_FLOAT_DENORMAL_OPERAND:
        case STATUS_FLOAT_DIVIDE_BY_ZERO:
        case STATUS_FLOAT_INEXACT_RESULT:
        case STATUS_FLOAT_INVALID_OPERATION:
        case STATUS_FLOAT_OVERFLOW:
        case STATUS_FLOAT_STACK_CHECK:
        case STATUS_FLOAT_UNDERFLOW:
        case STATUS_INTEGER_DIVIDE_BY_ZERO:
        case STATUS_INTEGER_OVERFLOW:           sig = SIGFPE;
            break;

        case STATUS_ILLEGAL_INSTRUCTION:
        case STATUS_PRIVILEGED_INSTRUCTION:
        case STATUS_NONCONTINUABLE_EXCEPTION:   sig = SIGILL;
            break;

        case STATUS_ACCESS_VIOLATION:
        case STATUS_DATATYPE_MISALIGNMENT:
        case STATUS_ARRAY_BOUNDS_EXCEEDED:
        case STATUS_GUARD_PAGE_VIOLATION:
        case STATUS_IN_PAGE_ERROR:
        case STATUS_NO_MEMORY:
        case STATUS_INVALID_DISPOSITION:
        case STATUS_BAD_STACK:
        case STATUS_STACK_OVERFLOW:             sig = SIGSEGV;
            break;

        case STATUS_CONTROL_C_EXIT:             sig = SIGINT;
            break;

        default: break;
    }
    if (!sig && exit_code & 0xC0000000)
        sig = SIGABRT;
    instance->status.signal = sig;
    instance->status.exit   = exit_code;
    instance->status.alive  = 0;
}

static void CALLBACK handle_child_terminated(PVOID lpParameter,
        BOOLEAN TimerOrWaitFired)
{
    (void) TimerOrWaitFired;

    uint64_t mts_end = bxfi_timestamp_monotonic();
    uint64_t ts_end  = bxfi_timestamp();

    struct callback_ctx *ctx = lpParameter;
    struct bxfi_sandbox *instance = ctx->instance;
    bxf_callback *callback = ctx->callback;

    bxfi_cancel_timeout(instance);

    get_status(instance->proc, &instance->props);

    instance->props.time.end = ts_end;
    instance->props.time.elapsed = mts_end - instance->start_monotonic;

    HANDLE whandle = ctx->whandle;
    free(lpParameter);
    UnregisterWaitEx(whandle, NULL);

    if (callback)
        callback(&instance->props);

    SetEvent(instance->waited);
}

struct bxfi_prepare_ctx {
    HANDLE *handles;
    uint8_t *inherited;
    size_t size;
    size_t capacity;
    LPPROC_THREAD_ATTRIBUTE_LIST attr;
};

static void prepare_ctx_term(struct bxfi_prepare_ctx *ctx)
{
    for (size_t i = 0; i < ctx->size; ++i) {
        if (!ctx->inherited[i]) {
            if (!SetHandleInformation(ctx->handles[i], HANDLE_FLAG_INHERIT, 0))
                continue;
        }
    }
    free(ctx->handles);
    free(ctx->inherited);
    if (ctx->attr)
        free(ctx->attr);
    ctx->capacity = 0;
}

static int do_inherit_handle(bxf_fhandle handle, void *user)
{
    struct bxfi_prepare_ctx *ctx = user;

    if (!ctx->handles) {
        ctx->handles   = malloc(32 * sizeof (HANDLE));
        ctx->inherited = malloc(32);
        ctx->capacity  = 32;
    }

    /* Reserve a slot for the sync event handle */
    if (ctx->size + 2 >= ctx->capacity) {
        ctx->capacity *= 1.61;
        ctx->handles   = realloc(ctx->handles, ctx->capacity);
        ctx->inherited = realloc(ctx->inherited, ctx->capacity);
    }

    ctx->handles[ctx->size++] = handle;
    ctx->inherited[ctx->size - 1] = 1;

    DWORD info;
    if (!GetHandleInformation(handle, &info))
        return -EINVAL;

    if (info & HANDLE_FLAG_INHERIT)
        return 0;

    if (!SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
        return -EINVAL;

    ctx->inherited[ctx->size - 1] = 0;
    return 0;
}

static int prepare_context(bxf_context ictx, bxf_sandbox *sandbox,
        HANDLE sync, STARTUPINFOEX *si,
        struct bxfi_prepare_ctx *prep)
{
    if (ictx) {
        if (bxfi_context_prepare(ictx, do_inherit_handle, prep) < 0)
            return 0;
    }

    if (!prep->handles) {
        prep->handles   = malloc(sizeof (HANDLE));
        *prep->handles  = sync;
        prep->size      = 1;
    } else {
        prep->handles[prep->size++] = sync;
    }

    if (!sandbox->inherit.files) {
        SIZE_T attrsz = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attrsz);

        LPPROC_THREAD_ATTRIBUTE_LIST attr = malloc(attrsz);
        if (!attr)
            return 0;
        BOOL ok = InitializeProcThreadAttributeList(attr, 1, 0, &attrsz);
        if (!ok)
            return 0;

        si->lpAttributeList = attr;

        ok = UpdateProcThreadAttribute(attr, 0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, prep->handles,
                prep->size * sizeof (HANDLE), NULL, NULL);
        prep->attr = attr;
        if (!ok)
            return 0;
    }
    return 1;
}

int bxfi_exec(bxf_instance **out, bxf_sandbox *sandbox,
        int mantled, bxf_fn *fn, bxf_preexec *preexec, bxf_callback *callback,
        void *user, bxf_dtor user_dtor)
{
    int errnum = 0;
    struct bxfi_sandbox *instance = NULL;
    BOOL success = FALSE;

    struct bxfi_prepare_ctx prep = {
        .handles = NULL,
    };

    /* Process params and allocate relevant ressources */

    struct bxfi_addr addr;

    if (bxfi_normalize_fnaddr(fn, &addr) < 0)
        return -EINVAL;

    errnum   = -ENOMEM;
    instance = malloc(sizeof (*instance));
    if (!instance)
        goto error;
    instance->mantled   = mantled;
    instance->user      = user;
    instance->user_dtor = user_dtor;

    instance->waited = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!instance->waited)
        goto error;

    PROCESS_INFORMATION info;
    STARTUPINFOEX si = { .StartupInfo.cb = sizeof (si) };

    ZeroMemory(&info, sizeof (info));

    SECURITY_ATTRIBUTES inherit_handle = {
        .nLength        = sizeof (SECURITY_ATTRIBUTES),
        .bInheritHandle = TRUE
    };

    HANDLE sync = CreateEvent(&inherit_handle, FALSE, FALSE, NULL);
    errnum = -EPROTO;
    if (!sync)
        goto error;

    /* Process initialization */

    bxf_context ictx = sandbox->inherit.context;

    if (!prepare_context(ictx, sandbox, sync, &si, &prep))
        goto error;

    TCHAR filename[MAX_PATH];
    GetModuleFileName(NULL, filename, MAX_PATH);

    uint64_t ts_start  = bxfi_timestamp();
    uint64_t mts_start = bxfi_timestamp_monotonic();

    TCHAR map_name[sizeof ("Local\\bxfi_") + 21];
    _sntprintf(map_name, sizeof (map_name), TEXT("Local\\bxfi_%lu"), (unsigned long)GetCurrentProcessId());

    TCHAR env_map[sizeof ("BXFI_MAP=") + sizeof (map_name) + 2];
    memset(env_map, 0, sizeof (env_map));
    _sntprintf(env_map, sizeof (env_map), "BXFI_MAP=%s", map_name);

    if (sandbox->debug.debugger) {
        TCHAR *dbg = NULL;
        TCHAR *cmdline = NULL;
        SIZE_T size;

        switch (sandbox->debug.debugger) {
            case BXF_DBG_WINDBG: {
                dbg = TEXT("windbg");
                TCHAR *fmt = TEXT("boxfort-worker -server tcp:port=%d %s %s");

                size = _sctprintf(fmt, sandbox->debug.tcp, filename,
                        env_map);
                cmdline = malloc(sizeof (TCHAR) * (size + 1));
                _sntprintf(cmdline, size, fmt, sandbox->debug.tcp, filename,
                        env_map);
            } break;
            case BXF_DBG_GDB: {
                dbg = TEXT("gdbserver");
                TCHAR *fmt = TEXT("boxfort-worker :%d %s %s");

                size = _sctprintf(fmt, sandbox->debug.tcp, filename,
                        env_map);
                cmdline = malloc(sizeof (TCHAR) * size);
                _sntprintf(cmdline, size, fmt, sandbox->debug.tcp, filename,
                        env_map);
            } break;
            case BXF_DBG_LLDB: {
                dbg = TEXT("lldb-server");
                TCHAR *fmt = TEXT("boxfort-worker gdbserver *:%d %s %s");

                size = _sctprintf(fmt, sandbox->debug.tcp, filename,
                        env_map);
                cmdline = malloc(sizeof (TCHAR) * size);
                _sntprintf(cmdline, size, fmt, sandbox->debug.tcp, filename,
                        env_map);
            } break;
            default:
                errnum = -EINVAL;
                goto error;
        }

        /* _sntprinf does not null-terminate its output */
        cmdline[size] = '\0';

        DWORD pathsz    = GetEnvironmentVariable(TEXT("PATH"), NULL, 0);
        TCHAR *path     = malloc(pathsz * sizeof (TCHAR));
        TCHAR *dbg_full = NULL;

        GetEnvironmentVariable(TEXT("PATH"), path, pathsz);

        pathsz = SearchPath(path, dbg, TEXT(".exe"), 0, NULL, NULL);
        if (!pathsz)
            goto file_not_found;

        dbg_full = malloc(pathsz * sizeof (TCHAR));
        pathsz   = SearchPath(path, dbg, TEXT(".exe"), pathsz, dbg_full, NULL);

        if (!pathsz) {
file_not_found:
            free(dbg_full);
            free(path);
            free(cmdline);
            errnum = -ENOENT;
            goto error;
        }

        success = CreateProcess(dbg_full, cmdline, NULL,
                NULL, TRUE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                NULL, NULL, &si.StartupInfo, &info);

        free(dbg_full);
        free(path);
        free(cmdline);
    } else {
        TCHAR *fmt     = TEXT("boxfort-worker %s");
        SIZE_T size    = _sctprintf(fmt, filename, env_map);
        TCHAR *cmdline = malloc(sizeof (TCHAR) * size);
        _sntprintf(cmdline, size, fmt, env_map);

        success = CreateProcess(filename, cmdline, NULL,
                NULL, TRUE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                NULL, NULL, &si.StartupInfo, &info);

        free(cmdline);
    }

    errnum = -EPROTO;
    if (!success)
        goto error;

    if (si.lpAttributeList)
        DeleteProcThreadAttributeList(si.lpAttributeList);

    instance->props = (struct bxf_instance_s) {
        .sandbox = sandbox,
        .pid = info.dwProcessId,
        .status.alive = 1,
        .time.start   = ts_start,
        .user = instance->user,
    };

    instance->start_monotonic = mts_start;

    if (sandbox->quotas.runtime > 0)
        if (bxfi_push_timeout(instance, sandbox->quotas.runtime) < 0)
            goto error;


    if (sandbox->iquotas.runtime > 0)
        if (bxfi_push_timeout(instance, sandbox->iquotas.runtime) < 0)
            goto error;


    if (preexec && preexec(&instance->props) < 0)
        goto error;

    if (prep.capacity)
        prepare_ctx_term(&prep);

    instance->proc = info.hProcess;
    size_t len = strlen(addr.soname);

    struct bxfi_map map;
    if ((errnum = bxfi_create_local_ctx(&map, map_name, len + 1)) < 0)
        goto error;

    map.ctx->sync    = sync;
    map.ctx->suspend = sandbox->suspended;
    map.ctx->fn      = addr.addr;
    map.ctx->seg     = addr.seg;
    if (ictx)
        map.ctx->context.handle = bxfi_context_gethandle(ictx);
    memcpy(map.ctx + 1, addr.soname, len + 1);
    map.ctx->fn_soname_sz = len + 1;

    errnum = -ECHILD;
    if (ResumeThread(info.hThread) == (DWORD) -1)
        goto error;

    /* wait until the child has initialized itself */
    HANDLE handles[] = { info.hProcess, sync };
    DWORD wres = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
    if (wres == WAIT_OBJECT_0)
        goto error;

    instance->mainthread = info.hThread;
    CloseHandle(sync);

    struct callback_ctx *wctx = malloc(sizeof (*wctx));
    *wctx = (struct callback_ctx) {
        .instance = instance,
        .callback = callback,
    };

    RegisterWaitForSingleObject(
            &wctx->whandle,
            info.hProcess,
            handle_child_terminated,
            wctx,
            INFINITE,
            WT_EXECUTELONGFUNCTION | WT_EXECUTEONLYONCE);

    bxfi_unmap_local_ctx(&map);
    bxfi_addr_term(&addr);

    if (sandbox->suspended)
        instance->props.status.stopped = 1;

    *out = &instance->props;
    return 0;

error:
    if (prep.capacity)
        prepare_ctx_term(&prep);
    if (si.lpAttributeList)
        DeleteProcThreadAttributeList(si.lpAttributeList);
    if (sync)
        CloseHandle(sync);
    if (success) {
        CloseHandle(info.hThread);
        TerminateProcess(info.hProcess, 3);
        CloseHandle(info.hProcess);
    }
    bxfi_addr_term(&addr);
    return errnum;
}

int bxf_term(bxf_instance *instance)
{
    struct bxfi_sandbox *sb = bxfi_cont(instance, struct bxfi_sandbox, props);

    if (sb->user && sb->user_dtor)
        sb->user_dtor(instance, sb->user);
    if (sb->mantled)
        free((void *) instance->sandbox);
    CloseHandle(sb->proc);
    CloseHandle(sb->mainthread);
    CloseHandle(sb->waited);
    free(sb);
    return 0;
}

int bxf_wait(bxf_instance *instance, double timeout)
{
    DWORD dwtimeout;

    if (timeout == BXF_FOREVER || !isfinite(timeout))
        dwtimeout = INFINITE;
    else
        dwtimeout = timeout * 1000;

    struct bxfi_sandbox *sb = bxfi_cont(instance, struct bxfi_sandbox, props);
    if (WaitForSingleObject(sb->waited, dwtimeout) != WAIT_OBJECT_0)
        return -ECHILD;
    return 0;
}

void bxf_suspend(bxf_instance *instance)
{
    struct bxfi_sandbox *sb = bxfi_cont(instance, struct bxfi_sandbox, props);
    SuspendThread(sb->mainthread);
}

void bxf_resume(bxf_instance *instance)
{
    struct bxfi_sandbox *sb = bxfi_cont(instance, struct bxfi_sandbox, props);
    ResumeThread(sb->mainthread);
}
