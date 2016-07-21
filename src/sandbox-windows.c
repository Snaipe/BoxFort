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
#include <tchar.h>

#include "addr.h"
#include "sandbox.h"

struct bxfi_sandbox {
    struct bxf_instance props;
    HANDLE proc;

    /* A sandbox is said to be mantled if there is an unique instance
       managing its memory. */
    int mantled;
};

int bxfi_check_sandbox_ctx(void)
{
    TCHAR name[sizeof ("Local\\bxfi_") + 21];
    _sntprintf(name, sizeof (name), TEXT("Local\\bxfi_%lu"), GetCurrentProcessId());

    HANDLE shm = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (!shm)
        return 0;
    CloseHandle(shm);
    return 1;
}

static int bxfi_create_local_ctx(struct bxfi_map *map, bxf_pid pid, size_t sz)
{
    TCHAR name[sizeof ("Local\\bxfi_") + 21];
    _sntprintf(name, sizeof (name), TEXT("Local\\bxfi_%lu"), pid);

    HANDLE shm = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
            PAGE_READWRITE, 0, sz, name);

    if (!shm || GetLastError() == ERROR_ALREADY_EXISTS)
        return -EEXIST;

    struct bxfi_context *ctx = MapViewOfFile(shm, FILE_MAP_ALL_ACCESS,
            0, 0, sizeof (struct bxfi_context) + sz);

    if (!ctx)
        return -ENOMEM;

    *map = (struct bxfi_map) { .ctx = ctx, .handle = shm };
    memcpy(map->map_name, name, sizeof (name));
    return 0;
}

int bxfi_init_sandbox_ctx(struct bxfi_map *map)
{
    TCHAR name[sizeof ("Local\\bxfi_") + 21];
    _sntprintf(name, sizeof (name), TEXT("Local\\bxfi_%lu"), GetCurrentProcessId());

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
    memcpy(map->map_name, name, sizeof (name));
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
    int rc = bxfi_unmap_local_ctx(map);
    SetEvent(sync);
    return rc;
}

int bxfi_exec(bxf_instance **out, bxf_sandbox *sandbox,
        int mantled, bxf_fn *fn, bxf_preexec *preexec)
{
    int errnum = 0;
    struct bxfi_sandbox *instance = NULL;
    BOOL success = FALSE;

    /* Process params and allocate relevant ressources */

    struct bxfi_addr addr;
    if (bxfi_normalize_fnaddr(fn, &addr) < 0)
        return -EINVAL;

    errnum = -ENOMEM;
    instance = malloc(sizeof (*instance));
    if (!instance)
        goto error;
    instance->mantled = mantled;

    PROCESS_INFORMATION info;
    STARTUPINFO si = { .cb = sizeof (STARTUPINFO) };

    ZeroMemory(&info, sizeof (info));

    SECURITY_ATTRIBUTES inherit_handle = {
        .nLength = sizeof (SECURITY_ATTRIBUTES),
        .bInheritHandle = TRUE
    };

    HANDLE sync = CreateEvent(&inherit_handle, FALSE, FALSE, NULL);
    errnum = -EPROTO;
    if (!sync)
        goto error;

    /* Process initialization */

    TCHAR filename[MAX_PATH];
    GetModuleFileName(NULL, filename, MAX_PATH);

    success = CreateProcess(filename, TEXT("boxfort-worker"),
            NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &info);

    errnum = -EPROTO;
    if (!success)
        goto error;

    instance->props = (struct bxf_instance) {
        .sandbox = sandbox,
        .pid = info.dwProcessId,
    };

    if (preexec && preexec(&instance->props) < 0)
        goto error;

    instance->proc = info.hProcess;
    size_t len = strlen(addr.soname);

    struct bxfi_map map;
    if ((errnum = bxfi_create_local_ctx(&map, info.dwProcessId, len + 1)) < 0)
        goto error;

    map.ctx->sync = sync;
    map.ctx->fn = addr.addr;
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

    CloseHandle(info.hThread);
    CloseHandle(sync);

    bxfi_unmap_local_ctx(&map);
    *out = &instance->props;
    return 0;

error:
    if (sync)
        CloseHandle(sync);
    if (!success) {
        CloseHandle(info.hThread);
        TerminateProcess(info.hProcess, 3);
        CloseHandle(info.hProcess);
    }
    return errnum;
}

int bxf_term(bxf_instance *instance)
{
    struct bxfi_sandbox *sb = bxfi_cont(instance, struct bxfi_sandbox, props);
    if (sb->mantled)
        free((void *) instance->sandbox);
    CloseHandle(sb->proc);
    free(sb);
    return 0;
}

int bxf_wait(bxf_instance *instance, size_t timeout)
{
    struct bxfi_sandbox *sb = bxfi_cont(instance, struct bxfi_sandbox, props);
    if (WaitForSingleObject(sb->proc, timeout) != WAIT_OBJECT_0)
        return -ECHILD;
    return 0;
}
