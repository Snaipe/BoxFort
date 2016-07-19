#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "boxfort.h"

#define _assert(Cond) do { if (!(Cond)) abort(); } while (0)

int second(void)
{
    printf("I am a nested worker!\n");
    return 0;
}

int first(void)
{
    printf("I am a worker!\n");

    _assert(!bxf_run(second));
    return 0;
}

int main(void)
{
    _assert(!bxf_run(first));
    return 0;
}
