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
#ifndef BOXFORT_H_
#define BOXFORT_H_

#include <stdio.h>
#include <stddef.h>
#include <math.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined BXF_STATIC_LIB && !defined BXF_API
# if defined _WIN32 || defined __CYGWIN__
#  ifdef BXF_BUILDING_LIB
#   ifdef __GNUC__
#    define BXF_API __attribute__((dllexport))
#   else
#    define BXF_API __declspec(dllexport)
#   endif
#  else
#   ifdef __GNUC__
#    define BXF_API __attribute__((dllimport))
#   else
#    define BXF_API __declspec(dllimport)
#   endif
#  endif
# else
#  if __GNUC__ >= 4
#   define BXF_API __attribute__((visibility("default")))
#  else
#   define BXF_API
#  endif
# endif
#elif !defined BXF_API
# define BXF_API
#endif

/* Arena API */

/**
 * The opaque handle type representing a BoxFort memory arena.
 */
typedef struct bxf_arena_s *bxf_arena;

enum {
    /**
     * Allow the arena to be resized during allocations.
     */
    BXF_ARENA_RESIZE = (1 << 0),

    /**
     * Memory may be reclaimed with bxf_arena_free.
     */
    BXF_ARENA_DYNAMIC = (1 << 1),

    /**
     * If BXF_ARENA_RESIZE is specified, allow the arena to be moved in
     * memory.
     *
     * All allocation operations invalidate virtual addresses inside the arena.
     */
    BXF_ARENA_MAYMOVE = (1 << 2),

    /**
     * Map 1:1 the arena in the sandbox instance, exactly where the arena
     * exists in the parent's address space.
     *
     * All virtual pointers used by the parent are kept valid in the sandbox
     * instance.
     */
    BXF_ARENA_IDENTITY = (1 << 3),

    /**
     * The arena in the sandbox instance is mapped read-only. All write
     * accesses to memory allocated inside the arena result in a segmentation
     * fault.
     */
    BXF_ARENA_IMMUTABLE = (1 << 4),

    /**
     * The arena in the parent is not unmapped upon termination. All related
     * shared memory resources are still cleaned up.
     *
     * This is necessary for special languages semantics like C++ destructors
     * of static objects that assume that the heap is still mapped before
     * a call free().
     */
    BXF_ARENA_KEEPMAPPED = (1 << 5),
};

typedef intptr_t bxf_ptr;

typedef int (bxf_arena_fn)(void *, size_t, void *);

BXF_API int bxf_arena_init(size_t initial, int flags, bxf_arena *arena);

BXF_API int bxf_arena_copy(bxf_arena orig, int flags, bxf_arena *arena);

BXF_API int bxf_arena_term(bxf_arena *arena);

BXF_API bxf_ptr bxf_arena_alloc(bxf_arena *arena, size_t size);

BXF_API bxf_ptr bxf_arena_realloc(bxf_arena *arena, bxf_ptr ptr,
        size_t newsize);

BXF_API int bxf_arena_grow(bxf_arena *arena, bxf_ptr ptr, size_t newsize);

BXF_API int bxf_arena_free(bxf_arena *arena, bxf_ptr ptr);

BXF_API int bxf_arena_iter(bxf_arena arena, bxf_arena_fn *fn, void *user);

BXF_API void *bxf_arena_ptr(bxf_arena arena, bxf_ptr ptr);

/* Resource context API */

#ifdef _WIN32
typedef void *bxf_fhandle;
#else
typedef int bxf_fhandle;
#endif

typedef struct bxf_context_s *bxf_context;

BXF_API int bxf_context_init(bxf_context *ctx);

BXF_API int bxf_context_term(bxf_context ctx);

BXF_API int bxf_context_addstatic(bxf_context ctx, const void *ptr,
        size_t size);

BXF_API int bxf_context_addarena(bxf_context ctx, bxf_arena arena);

BXF_API int bxf_context_addobject(bxf_context ctx, const char *name,
        const void *ptr, size_t size);

BXF_API int bxf_context_getobject(bxf_context ctx, const char *name,
        void **ptr);

BXF_API int bxf_context_addaddr(bxf_context ctx, const char *name,
        const void *addr);

BXF_API int bxf_context_getaddr(bxf_context ctx, const char *name,
        void **addr);

BXF_API int bxf_context_addfnaddr(bxf_context ctx, const char *name,
        void (*fn)(void));

BXF_API int bxf_context_getfnaddr(bxf_context ctx, const char *name,
        void(**fn)(void));

BXF_API int bxf_context_addfhandle(bxf_context ctx, bxf_fhandle hndl);

BXF_API int bxf_context_addfile(bxf_context ctx, const char *name, FILE *file);

BXF_API int bxf_context_getfile(bxf_context ctx, const char *name, FILE **file);

BXF_API bxf_context bxf_context_current(void);

/* Sandbox API */

typedef unsigned long long bxf_pid;
typedef int (bxf_fn)(void);

struct bxf_quotas {
    size_t memory;
    size_t subprocesses;
    size_t files;
    double runtime;
};

struct bxf_inheritance {
    unsigned files   : 1;
    unsigned data    : 1;
    bxf_context context;
};

enum bxf_debugger {
    BXF_DBG_NONE, /* Do not debug the sandbox */
    BXF_DBG_GDB, /* Spawn with gdbserver */
    BXF_DBG_LLDB, /* Spawn with lldb-server */
    BXF_DBG_WINDBG, /* Spawn with windbg (Windows only) */
};

#if defined (__clang__)
# define BXF_DBG_NATIVE BXF_DBG_LLDB
#elif defined (__GNUC__)
# define BXF_DBG_NATIVE BXF_DBG_GDB
#elif defined (_WIN32)
# define BXF_DBG_NATIVE BXF_DBG_WINDBG
#endif

struct bxf_debug {
    enum bxf_debugger debugger;
    int tcp;
};

#define BXFI_SANDBOX_FIELDS         \
    int suspended;                  \
    struct bxf_quotas quotas;       \
    struct bxf_quotas iquotas;      \
    struct bxf_inheritance inherit; \
    struct bxf_debug debug;

struct bxf_sandbox_s {
    BXFI_SANDBOX_FIELDS
};

typedef const struct bxf_sandbox_s bxf_sandbox;

struct bxf_instance_s {
    bxf_sandbox *sandbox;
    bxf_pid pid;

    volatile struct {
        int signal;
        int exit;
        int alive;
        int stopped;
        int timed_out;
    } status;

    volatile struct {
        uint64_t start;
        uint64_t end;
        uint64_t elapsed;
    } time;

    void *user;
};

typedef const struct bxf_instance_s bxf_instance;

typedef void (bxf_callback)(bxf_instance *);
typedef int (bxf_preexec)(bxf_instance *);
typedef void (bxf_dtor)(bxf_instance *, void *);

struct bxf_spawn_params_s {
    int bxfi_sentinel_; /* Reserved */
    bxf_fn *fn;
    bxf_preexec *preexec;
    void *user;
    bxf_dtor *user_dtor;
    bxf_callback *callback;
    BXFI_SANDBOX_FIELDS
};

typedef const struct bxf_spawn_params_s *bxf_spawn_params;

struct bxf_start_params_s {
    int bxfi_sentinel_; /* Reserved */
    bxf_fn *fn;
    bxf_preexec *preexec;
    void *user;
    bxf_dtor *user_dtor;
    bxf_callback *callback;
};

#define BXF_FOREVER INFINITY

typedef const struct bxf_start_params_s *bxf_start_params;

#define bxf_start(Instance, Sandbox, ...) \
    (bxf_start_struct((Instance),         \
    (Sandbox),                            \
    &(struct bxf_start_params_s) { .bxfi_sentinel_ = 0, __VA_ARGS__ }))
BXF_API int bxf_start_struct(bxf_instance **instance,
        bxf_sandbox *sandbox, bxf_start_params params);

BXF_API int bxf_term(bxf_instance *instance);
BXF_API int bxf_wait(bxf_instance *instance, double timeout);

#define bxf_spawn(Instance, ...)  \
    (bxf_spawn_struct((Instance), \
    &(struct bxf_spawn_params_s) { .bxfi_sentinel_ = 0, __VA_ARGS__ }))
BXF_API int bxf_spawn_struct(bxf_instance **instance, bxf_spawn_params params);

#define bxf_run(...) \
    (bxf_run_struct( \
    &(struct bxf_spawn_params_s) { .bxfi_sentinel_ = 0, __VA_ARGS__ }))
BXF_API int bxf_run_struct(bxf_spawn_params params);

BXF_API void bxf_suspend(bxf_instance *instance);
BXF_API void bxf_resume(bxf_instance *instance);

#ifdef __cplusplus
}
#endif

#endif /* !BOXFORT_H_ */
