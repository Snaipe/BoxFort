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

#include "arena.h"
#include "boxfort.h"
#include "context.h"

#ifdef _WIN32
# include <io.h>
#endif

#ifdef BXF_ARENA_REOPEN_SHM
# include <sys/mman.h>
# include <fcntl.h>
#endif

int bxf_context_init(bxf_context *ctx)
{
    struct bxf_context_s *nctx = malloc(sizeof (*nctx));

    if (!nctx)
        return -ENOMEM;

    int rc = bxf_arena_init(0,
            BXF_ARENA_RESIZE | BXF_ARENA_MAYMOVE,
            &nctx->arena);
    if (!rc)
        *ctx = nctx;
    return rc;
}

int bxf_context_addstatic(bxf_context ctx, const void *ptr, size_t size)
{
    struct bxfi_ctx_static *elt;

    struct bxfi_addr addr;
    int rc = bxfi_normalize_addr(ptr, &addr);

    if (rc < 0)
        return rc;

    bxf_ptr p = bxf_arena_alloc(&ctx->arena,
            sizeof (*elt) + size + strlen(addr.soname) + 1);
    if (p < 0)
        return p;

    elt = bxf_arena_ptr(ctx->arena, p);

    elt->tag  = BXFI_TAG_STATIC;
    elt->addr = addr.addr;
    elt->seg  = addr.seg;
    elt->size = size;
    strcpy(&elt->data[size], addr.soname);

    return 0;
}

int bxf_context_addarena(bxf_context ctx, bxf_arena arena)
{
    struct bxfi_ctx_arena *elt;

    bxf_ptr p = bxf_arena_alloc(&ctx->arena, sizeof (*elt));

    if (p < 0)
        return p;

    elt = bxf_arena_ptr(ctx->arena, p);

    elt->tag   = BXFI_TAG_ARENA;
    elt->flags = arena->flags;
    elt->base  = arena->flags & BXF_ARENA_IDENTITY ? arena : NULL;

#ifdef BXF_ARENA_REOPEN_SHM
    strcpy(elt->name, arena->name);
#else
    elt->handle = arena->handle;
#endif
    return 0;
}

int bxf_context_addobject(bxf_context ctx, const char *name,
        const void *ptr, size_t size)
{
    struct bxfi_ctx_object *elt;

    size_t len = strlen(name) + 1;

    bxf_ptr p = bxf_arena_alloc(&ctx->arena, sizeof (*elt) + len + size);

    if (p < 0)
        return p;

    elt = bxf_arena_ptr(ctx->arena, p);

    elt->tag    = BXFI_TAG_OBJECT;
    elt->namesz = len;
    memcpy(&elt->data, name, len);
    memcpy(&elt->data[elt->namesz], ptr, size);
    return 0;
}

struct bxfi_find_ctx {
    const char *name;
    void *result;
};

static int find_obj(void *ptr, size_t size, void *user)
{
    (void) size;

    struct bxfi_find_ctx *ctx = user;

    enum bxfi_ctx_tag *tag = ptr;
    if (*tag != BXFI_TAG_OBJECT)
        return 0;

    struct bxfi_ctx_object *obj = ptr;
    if (!strcmp(obj->data, ctx->name)) {
        ctx->result = &obj->data[obj->namesz];
        return 1;
    }
    return 0;
}

int bxf_context_getobject(bxf_context ctx, const char *name, void **ptr)
{
    struct bxfi_find_ctx fctx = { .name = name };
    int found = bxf_arena_iter(ctx->arena, find_obj, &fctx);

    if (found)
        *ptr = fctx.result;
    return found;
}

int bxf_context_addaddr(bxf_context ctx, const char *name, const void *addr)
{
    struct bxfi_addr norm;
    int rc = bxfi_normalize_addr(addr, &norm);

    if (rc < 0)
        return rc;

    struct bxfi_ctx_object *elt;

    size_t sonamelen = strlen(norm.soname) + 1;
    size_t size = sizeof (void *) + sizeof (norm.seg) + sonamelen;
    size_t len  = strlen(name) + 1;

    bxf_ptr p = bxf_arena_alloc(&ctx->arena, sizeof (*elt) + len + size);
    if (p < 0)
        return p;

    elt = bxf_arena_ptr(ctx->arena, p);

    elt->tag    = BXFI_TAG_OBJECT;
    elt->namesz = len;

    size_t i = 0;
    memcpy(&elt->data[i], name, len);
    i += elt->namesz;
    memcpy(&elt->data[i], &norm.addr, sizeof (void *));
    i += sizeof (void *);
    memcpy(&elt->data[i], &norm.seg, sizeof (norm.seg));
    i += sizeof (norm.seg);
    memcpy(&elt->data[i], norm.soname, sonamelen);
    return 0;
}

int bxf_context_getaddr(bxf_context ctx, const char *name, void **addr)
{
    struct {
        void *addr;
        size_t seg;
        const char soname[];
    } *serialized;

    int rc = bxf_context_getobject(ctx, name, (void **) &serialized);
    if (rc > 0) {
        struct bxfi_addr norm = {
            .addr   = serialized->addr,
            .soname = serialized->soname,
            .seg    = serialized->seg,
        };
        *addr = bxfi_denormalize_addr(&norm);
    }
    return rc;
}

int bxf_context_addfnaddr(bxf_context ctx, const char *name, void (*fn)(void))
{
    return bxf_context_addaddr(ctx, name, nonstd (void *) fn);
}

int bxf_context_getfnaddr(bxf_context ctx, const char *name, void(**fn)(void))
{
    return bxf_context_getaddr(ctx, name, nonstd (void **) fn);
}

int bxf_context_addfhandle(bxf_context ctx, bxf_fhandle hndl)
{
    struct bxfi_ctx_fhandle *elt;

    bxf_ptr p = bxf_arena_alloc(&ctx->arena, sizeof (*elt));

    if (p < 0)
        return p;

    elt = bxf_arena_ptr(ctx->arena, p);

    elt->tag    = BXFI_TAG_FHANDLE;
    elt->handle = hndl;
    return 0;
}

int bxf_context_addfile(bxf_context ctx, const char *name, FILE *file)
{
#ifdef _WIN32
    HANDLE hndl = (HANDLE) _get_osfhandle(_fileno(file));
    int rc = bxf_context_addfhandle(ctx, hndl);
    if (!rc)
        rc = bxf_context_addobject(ctx, name, &hndl, sizeof (hndl));
#else
    int fd = fileno(file);
    int rc = bxf_context_addfhandle(ctx, fd);
    if (!rc)
        rc = bxf_context_addobject(ctx, name, &fd, sizeof (int));
#endif
    return rc;
}

int bxf_context_getfile(bxf_context ctx, const char *name, FILE **file)
{
#ifdef _WIN32
    HANDLE *hndl;
    int rc = bxf_context_getobject(ctx, name, (void **) &hndl);
    if (rc > 0)
        *file = _fdopen(_open_osfhandle((intptr_t) *hndl, 0), "r+");
#else
    int *fd;
    int rc = bxf_context_getobject(ctx, name, (void **) &fd);
    if (rc > 0)
        *file = fdopen(*fd, "r+");
#endif
    return rc;
}

int bxf_context_term(bxf_context ctx)
{
    int rc = bxf_arena_term(&ctx->arena);

    free(ctx);
    return rc;
}

bxf_fhandle bxfi_context_gethandle(bxf_context ctx)
{
    return ctx->arena->handle;
}

struct bxfi_prepare_ctx {
    bxf_fhandle_fn *fn;
    void *user;
};

static int prepare_elt(void *ptr, size_t size, void *user)
{
    (void) size;
    struct bxfi_prepare_ctx *ctx = user;

    enum bxfi_ctx_tag *tag = ptr;
    switch (*tag) {
        case BXFI_TAG_STATIC: {
            struct bxfi_ctx_static *elt = ptr;

            struct bxfi_addr a = {
                .addr   = elt->addr,
                .soname = &elt->data[elt->size],
                .seg    = elt->seg,
            };
            void *addr = bxfi_denormalize_addr(&a);
            if (!addr)
                return -EINVAL;

            memcpy(elt->data, addr, elt->size);
        } break;
#ifndef BXF_ARENA_REOPEN_SHM
        case BXFI_TAG_ARENA: {
            struct bxfi_ctx_arena *elt = ptr;
            if (ctx->fn)
                return ctx->fn(elt->handle, ctx->user);
        } break;
#endif
        case BXFI_TAG_FHANDLE: {
            struct bxfi_ctx_fhandle *elt = ptr;
            if (ctx->fn)
                return ctx->fn(elt->handle, ctx->user);
        } break;
        default: break;
    }
    return 0;
}

int bxfi_context_prepare(bxf_context ctx, bxf_fhandle_fn *fn, void *user)
{
    struct bxfi_prepare_ctx uctx = {
        .fn   = fn,
        .user = user,
    };

    if (fn) {
        int rc = fn(ctx->arena->handle, user);
        if (rc < 0)
            return rc;
    }
    return bxf_arena_iter(ctx->arena, prepare_elt, &uctx);
}

static int inherit_elt(void *ptr, size_t size, void *user)
{
    (void) size, (void) user;

    enum bxfi_ctx_tag *tag = ptr;
    switch (*tag) {
        case BXFI_TAG_STATIC: {
            struct bxfi_ctx_static *elt = ptr;

            struct bxfi_addr a = {
                .addr   = elt->addr,
                .soname = &elt->data[elt->size],
                .seg    = elt->seg,
            };
            void *addr = bxfi_denormalize_addr(&a);
            if (!addr)
                return -EINVAL;

            memcpy(addr, elt->data, elt->size);
        } break;
        case BXFI_TAG_ARENA: {
            struct bxfi_ctx_arena *elt = ptr;
            bxf_arena arena = elt->base;

#ifdef BXF_ARENA_REOPEN_SHM
# ifdef BXF_ARENA_FILE_BACKED
            int hndl = open(elt->name, O_RDONLY, 0600);
# else
            int hndl = shm_open(elt->name, O_RDONLY, 0600);
# endif
            if (hndl < 0)
                return -errno;
#else
            bxf_fhandle hndl = elt->handle;
#endif
            bxfi_arena_inherit(hndl, elt->flags, &arena);
        } break;
        default: break;
    }
    return 0;
}

static struct bxf_context_s current_ctx;

int bxfi_context_inherit(struct bxfi_ctx_arena *ctx)
{
#ifdef BXF_ARENA_REOPEN_SHM
    if (!ctx->name[0])
        return 0;

# ifdef BXF_ARENA_FILE_BACKED
    int hndl = open(ctx->name, O_RDONLY, 0600);
# else
    int hndl = shm_open(ctx->name, O_RDONLY, 0600);
# endif
    if (hndl < 0)
        return -errno;
#else
    bxf_fhandle hndl = ctx->handle;
    if (!hndl)
        return 0;
#endif

    bxf_arena arena = NULL;
    int rc = bxfi_arena_inherit(hndl, 0, &arena);
    if (rc < 0)
        return rc;

    current_ctx.arena = arena;
    return bxf_arena_iter(arena, inherit_elt, NULL);
}

bxf_context bxf_context_current(void)
{
    if (!current_ctx.arena)
        return NULL;
    return &current_ctx;
}
