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
#include <windows.h>
#include <errno.h>

#include "config.h"
#include "sandbox.h"

#define BXFI_TIMEOUT_STATUS 0xEFFFFFFF

void CALLBACK timeout_killer_fn(void *lpParameter, BOOLEAN TimerOrWaitFired)
{
    (void) TimerOrWaitFired;

    struct bxfi_sandbox *sb = lpParameter;

    if (WaitForSingleObject(sb->proc, 0) == WAIT_OBJECT_0)
        return;

    TerminateProcess(sb->proc, BXFI_TIMEOUT_STATUS);
    sb->props.status.timed_out = 1;
}

int bxfi_push_timeout(struct bxfi_sandbox_s *instance, double timeout)
{
    HANDLE timer;
    BOOL ok = CreateTimerQueueTimer(&timer, NULL, timeout_killer_fn, instance,
            timeout * 1000, 0, WT_EXECUTEDEFAULT);

    if (!ok)
        return -1;
    return 0;
}

void bxfi_cancel_timeout(struct bxfi_sandbox_s *instance)
{
    (void) instance;
}

void bxfi_reset_timeout_killer(void)
{
}
