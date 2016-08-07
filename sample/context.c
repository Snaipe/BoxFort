#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "boxfort.h"

#define _assert(Cond) do { if (!(Cond)) abort(); } while (0)

#ifdef _WIN32
# define EXPORT __declspec(dllexport)
#else
# define EXPORT
#endif

static int *my_int;

static int child(void)
{
    bxf_context ctx = bxf_context_current();

    long *my_long = NULL;
    bxf_context_getobject(ctx, "long_id", (void **)&my_long);

    printf("my_int = %d\n", *my_int);
    printf("my_long = %ld\n", *my_long);
    return 0;
}

EXPORT int main(void)
{
    bxf_context ctx;
    _assert(!bxf_context_init(&ctx));

    /* The value of the `my_int` global variable shall be inherited */
    _assert(!bxf_context_addstatic(ctx, &my_int, sizeof (my_int)));

    /* We create an arena that shall be mapped 1:1 */
    bxf_arena arena;
    _assert(!bxf_arena_init(0, BXF_ARENA_IDENTITY, &arena));

    /* The newly created arena shall also be inherited. */
    _assert(!bxf_context_addarena(ctx, arena));

    bxf_ptr intp = bxf_arena_alloc(&arena, sizeof (int));
    _assert(intp > 0);

    my_int = bxf_arena_ptr(arena, intp);
    *my_int = 42;

    long my_long = 24;
    _assert(!bxf_context_addobject(ctx, "long_id", &my_long, sizeof (my_long)));

    /* We run the child function with the created context */
    _assert(!bxf_run(child, .inherit.context = ctx));

    _assert(!bxf_arena_term(&arena));

    _assert(!bxf_context_term(ctx));
    return 0;
}

