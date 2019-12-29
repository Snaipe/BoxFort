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

int second(void)
{
    printf("I am a nested worker!\n");
    fflush(stdout);
    return 0;
}

int first(void)
{
    printf("I am a worker!\n");
    fflush(stdout);

    _assert(!bxf_run(second));
    return 0;
}

EXPORT int main(void)
{
    _assert(!bxf_run(first));
    return 0;
}
