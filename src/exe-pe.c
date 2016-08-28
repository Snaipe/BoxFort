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
#include "exe.h"
#include "common.h"

#include <tlhelp32.h>

#ifdef _MSC_VER
#include <malloc.h>
#endif

static void *get_main_addr(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
            GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE)
        return NULL;

    MODULEENTRY32 mod = { .dwSize = sizeof(MODULEENTRY32) };
    for (BOOL more = Module32First(snap, &mod); more;
            more = Module32Next(snap, &mod))
    {
        FARPROC fn = GetProcAddress(mod.hModule, "main");
        if (fn != NULL)
            return nonstd (void *) fn;
    }
    return NULL;
}

extern void *bxfi_trampoline;
extern void *bxfi_trampoline_addr;
extern void *bxfi_trampoline_end;

#define PAGE_SIZE 4096

int bxfi_exe_patch_main(bxfi_exe_fn *new_main)
{
    void *addr = get_main_addr();
    if (!addr)
        return -1;

    /* Reserve enough space for the trampoline and copy the default opcodes */
    uintptr_t size = (uintptr_t)&bxfi_trampoline_end - (uintptr_t)&bxfi_trampoline;
#ifndef _MSC_VER
    char opcodes[size]; // VLA
#else
    char *opcodes = alloca(size);
#endif

    memcpy(opcodes, &bxfi_trampoline, sizeof (opcodes));

    uintptr_t jmp_offset = (uintptr_t)&bxfi_trampoline_addr
                         - (uintptr_t)&bxfi_trampoline;

    /* The trampoline code is a jump followed by an aligned pointer value --
       after copying the jmp opcode, we write this pointer value. */
    *(uintptr_t *)(&opcodes[jmp_offset]) = (uintptr_t)new_main;

    void *base = (void *) align2_down((uintptr_t) addr, PAGE_SIZE);
    uintptr_t offset = (uintptr_t) addr - (uintptr_t) base;
    size_t len = align2_up(offset + sizeof (opcodes), PAGE_SIZE);

    DWORD old;
    VirtualProtect(base, len, PAGE_EXECUTE_READWRITE, &old);
    memcpy(nonstd (void *) addr, opcodes, sizeof (opcodes));
    VirtualProtect(base, len, old, NULL);
    return 0;
}

bxfi_exe_lib bxfi_lib_from_addr(const void *addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)))
        return (HMODULE)mbi.AllocationBase;
    return BXFI_INVALID_LIB;
}

bxfi_exe_lib bxfi_lib_from_name(const char *name)
{
    if (!strcmp(name, "self"))
        name = NULL;
    return GetModuleHandle(name);
}

const char *bxfi_lib_name(bxfi_exe_lib lib)
{
    char *out = LocalAlloc(LMEM_FIXED, MAX_PATH);
    if (GetModuleFileNameA(lib, out, MAX_PATH))
        return out;
    LocalFree(out);
    return NULL;
}

size_t bxfi_exe_get_vmslide(bxfi_exe_lib lib)
{
    return (size_t)lib;
}
