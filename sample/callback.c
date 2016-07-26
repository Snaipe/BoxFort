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

static volatile int called;

static int child(void)
{
    return 5;
}

static void callback(bxf_instance *instance)
{
    printf("Child exited with code %d\n", instance->status.exit);
    called = 1;
}

EXPORT int main(void)
{
    _assert(!bxf_run(child, .callback = callback));
    while (!called);
    return 0;
}
