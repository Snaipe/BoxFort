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
    for (;;);
    return 0;
}

EXPORT int main(void)
{
    bxf_instance *box;
    _assert(!bxf_spawn(&box, child, .quotas.runtime = 2.0));
    bxf_wait(box, 1.0);
    printf("Wait timed out after 1 second\n");
    bxf_wait(box, BXF_FOREVER);
    printf("Process killed after %.1f seconds\n", box->time.elapsed / 1000000000.);
    bxf_term(box);

    return 0;
}
