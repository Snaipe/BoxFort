#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "boxfort.h"

int second(void)
{
    printf("I am a nested worker!\n");
    return 0;
}

int first(void)
{
    printf("I am a worker!\n");

    assert(!bxf_run(second));
    return 0;
}

int main(void)
{
    assert(!bxf_run(first));
    return 0;
}
