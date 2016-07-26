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

static int child(void)
{
    for (volatile size_t i = 0; i < 1000000000; ++i);
    return 0;
}

EXPORT int main(void)
{
    bxf_instance *box;
    _assert(!bxf_spawn(&box, child));
    bxf_wait(box, 1);
    printf("Timed out after 1sec\n");
    bxf_wait(box, BXF_FOREVER);
    bxf_term(box);
    return 0;
}
