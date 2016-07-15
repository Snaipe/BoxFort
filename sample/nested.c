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

    bxf_instance *box;
    assert(!bxf_run(&box, test2));
    assert(!bxf_wait(box, 0));
    assert(!bxf_term(box));
    return 0;
}

int main(void)
{
    bxf_instance *box;
    assert(!bxf_run(&box, test));
    assert(!bxf_wait(box, 0));
    assert(!bxf_term(box));
    return 0;
}
