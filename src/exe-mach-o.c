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
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include "config.h"

#if defined (HAVE_MACH_VM_PROTECT)
# include <mach/mach.h>
# include <mach/mach_vm.h>
# include <mach/vm_prot.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "exe.h"
#include "addr.h"
#include "common.h"

#if BXF_BITS == 32
typedef struct mach_header mach_hdr;
typedef struct nlist sym;
typedef struct section section;
typedef struct segment_command segment_cmd;
# define BXF_LC_SEGMENT LC_SEGMENT
#elif BXF_BITS == 64
typedef struct mach_header_64 mach_hdr;
typedef struct nlist_64 sym;
typedef struct section_64 section;
typedef struct segment_command_64 segment_cmd;
# define BXF_LC_SEGMENT LC_SEGMENT_64
#else
# error Unsupported architecture
#endif

static inline void *ptr_add(const void *ptr, size_t off)
{
    return (char *) ptr + off;
}

void *get_main_addr(void)
{
    return dlsym(RTLD_DEFAULT, "main");
}

extern void *bxfi_trampoline;
extern void *bxfi_trampoline_addr;
extern void *bxfi_trampoline_end;

static int mem_protect(void *addr, size_t len, int prot)
{
    int result = mprotect(addr, len, prot);

#if defined (HAVE_MACH_VM_PROTECT)
    if (result == 0)
        return 0;

    vm_prot_t mach_prot = 0;
    if (prot & PROT_READ)
        mach_prot |= VM_PROT_READ;
    if (prot & PROT_WRITE)
        mach_prot |= VM_PROT_WRITE;
    if (prot & PROT_EXEC)
        mach_prot |= VM_PROT_EXECUTE;

    result = mach_vm_protect(mach_task_self(), (mach_vm_address_t) addr, len, FALSE, mach_prot);
#endif

    return result;
}

static int bxfi_exe_remapped_patch_main(void *addr, size_t len,
    const void *opcodes, size_t opcodes_len)
{
    mach_vm_address_t remapped;
    vm_prot_t cur_prot;
    vm_prot_t max_prot;

    kern_return_t result = mach_vm_remap(mach_task_self(), &remapped, len, 0,
        VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
        mach_task_self(), (mach_vm_address_t) addr, FALSE, &cur_prot, &max_prot, VM_INHERIT_NONE);

    if (result != KERN_SUCCESS)
        return -1;

    result = mach_vm_protect(mach_task_self(), (mach_vm_address_t) remapped, len, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

    if (result != KERN_SUCCESS)
        return -1;

    result = mach_vm_write(mach_task_self(), remapped, (vm_offset_t) opcodes, opcodes_len);
    if (result != KERN_SUCCESS)
        return -1;

    result = mach_vm_protect(mach_task_self(), remapped, len, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (result != KERN_SUCCESS)
        return -1;

    result = mach_vm_remap(mach_task_self(), (mach_vm_address_t *) &addr, len, 0,
        VM_FLAGS_OVERWRITE | VM_FLAGS_RETURN_DATA_ADDR,
        mach_task_self(), remapped, FALSE, &cur_prot, &max_prot, VM_INHERIT_NONE);

    if (result != KERN_SUCCESS)
        return -1;

    bxfi_exe_clear_cache(addr, len);

    return 0;
}

int bxfi_exe_patch_main(bxfi_exe_fn *new_main)
{
    void *addr = get_main_addr();

    if (!addr)
        return -1;

    /* Reserve enough space for the trampoline and copy the default opcodes */
    char opcodes[BXFI_TRAMPOLINE_SIZE(&bxfi_trampoline, &bxfi_trampoline_end)];
    memcpy(opcodes, &bxfi_trampoline, sizeof (opcodes));

    uintptr_t jmp_offset = (uintptr_t) &bxfi_trampoline_addr
            - (uintptr_t) &bxfi_trampoline;

    /* The trampoline code is a jump followed by an aligned pointer value --
       after copying the jmp opcode, we write this pointer value. */
    *(uintptr_t *) (&opcodes[jmp_offset]) = (uintptr_t) new_main;

    void *base = (void *) align2_down((uintptr_t) addr, BXFI_PAGE_SIZE);
    uintptr_t offset = (uintptr_t) addr - (uintptr_t) base;
    size_t len = align2_up(offset + sizeof (opcodes), BXFI_PAGE_SIZE);

    if (mem_protect(base, len, PROT_READ | PROT_WRITE) == 0) {
        memcpy(nonstd (void *) addr, opcodes, sizeof (opcodes));
        mem_protect(base, len, PROT_READ | PROT_EXEC);
        bxfi_exe_clear_cache(addr, sizeof(opcodes));
        return 0;
    }

    bxfi_exe_remapped_patch_main(addr, sizeof(opcodes), opcodes, sizeof(opcodes));

    return 0;
}

uintptr_t bxfi_slide_from_addr(const void *addr, const char **name, size_t *seg)
{
    /* TODO: this is not thread safe, as another thread can load or unload
     * images on the fly -- find a way to fix this. */
    bxfi_exe_lib nb_images = _dyld_image_count();

    for (bxfi_exe_lib i = 0; i < nb_images; ++i) {
        const mach_hdr *hdr = (const mach_hdr *) _dyld_get_image_header(i);
        intptr_t slide = bxfi_exe_get_vmslide(i);
        size_t segidx = 0;

        const struct load_command *lc = ptr_add(hdr, sizeof (mach_hdr));
        for (size_t c = 0; c < hdr->ncmds; ++c, lc = ptr_add(lc, lc->cmdsize)) {
            if (lc->cmd == BXF_LC_SEGMENT) {
                const segment_cmd *sc = (void *) lc;
                uintptr_t start = sc->vmaddr + slide;
                uintptr_t end   = start + sc->vmsize - 1;

                if ((uintptr_t) addr >= start && (uintptr_t) addr <= end) {
                    *name = bxfi_lib_name(i);
                    *seg  = segidx;
                    return start;
                }

                ++segidx;
            }
        }
    }
    errno = EINVAL;
    return (uintptr_t) -1;
}

uintptr_t bxfi_slide_from_name(const char *name, size_t seg)
{
    bxfi_exe_lib lib = 0;

    if (strcmp("self", name)) {
        /* TODO: this is not thread safe, as another thread can load or unload
         * images on the fly -- find a way to fix this. */
        bxfi_exe_lib nb_images = _dyld_image_count();
        for (bxfi_exe_lib i = 1; i < nb_images; ++i) {
            const char *img_name = _dyld_get_image_name(i);
            if (img_name && !strcmp(img_name, name)) {
                lib = i;
                break;
            }
        }
        if (!lib) {
            errno = EINVAL;
            return (uintptr_t) -1;
        }
    }

    const mach_hdr *hdr = (const mach_hdr *) _dyld_get_image_header(lib);
    uintptr_t slide = bxfi_exe_get_vmslide(lib);
    size_t segidx = 0;

    const struct load_command *lc = ptr_add(hdr, sizeof (mach_hdr));
    for (size_t c = 0; c < hdr->ncmds; ++c, lc = ptr_add(lc, lc->cmdsize)) {
        if (lc->cmd != BXF_LC_SEGMENT)
            continue;

        const segment_cmd *sc = (void *) lc;

        if (segidx == seg)
            return sc->vmaddr + slide;
        ++segidx;
    }
    errno = EINVAL;
    return (uintptr_t) -1;
}

const char *bxfi_lib_name(bxfi_exe_lib lib)
{
    if (!lib)
        return "self";
    return _dyld_get_image_name(lib);
}

void bxfi_lib_name_term(const char *str)
{
    (void) str;
}

size_t bxfi_exe_get_vmslide(bxfi_exe_lib lib)
{
    return _dyld_get_image_vmaddr_slide(lib);
}
