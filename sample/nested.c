#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "boxfort.h"

int test2(void) {
    printf("I am a nested worker!\n");
    return 0;
}

int test(void) {
    printf("I am a worker!\n");

    assert(!bxf_run(test2));
    return 0;
}

int main(void)
{
    assert(!bxf_run(test));
    return 0;
}
