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
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "config.h"
#include "exe.h"
#include "addr.h"
#include "common.h"

#if BXF_BITS == 32
typedef Elf32_Word ElfWord;
typedef Elf32_Sword ElfSWord;
# ifndef ELF_R_SYM
#  define ELF_R_SYM(i) ELF32_R_SYM(i)
# endif
#elif BXF_BITS == 64
typedef Elf64_Xword ElfWord;
typedef Elf64_Sxword ElfSWord;
# ifndef ELF_R_SYM
#  define ELF_R_SYM(i) ELF64_R_SYM(i)
# endif
#else
# error Unsupported architecture
#endif

typedef ElfW (Addr) ElfAddr;
typedef ElfW (Dyn) ElfDyn;
typedef ElfW (Sym) ElfSym;
typedef ElfW (Word) ElfWWord;
typedef ElfW (Off) ElfOff;

extern char **environ;

static void *lib_dt_lookup(bxfi_exe_lib lib, ElfSWord tag)
{
    ElfAddr base = (ElfAddr) lib->l_addr;

    for (const ElfDyn *dyn = lib->l_ld; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == tag) {
            if (dyn->d_un.d_ptr >= base
                    && (dyn->d_un.d_ptr >> (BXF_BITS - 8)) ^ 0xff)
                return (void *) dyn->d_un.d_ptr;
            else
                return (char *) base + dyn->d_un.d_ptr;
        }
    }
    return NULL;
}

static ElfWord lib_dt_lookup_val(bxfi_exe_lib lib, ElfSWord tag)
{
    for (const ElfDyn *dyn = lib->l_ld; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == tag)
            return dyn->d_un.d_val;
    }
    return (ElfWord) - 1;
}

#if !defined HAVE__R_DEBUG
static int find_dynamic(struct dl_phdr_info *info, size_t size, void *data)
{
    ElfAddr *ctx = data;
    (void)size;

    for (ElfOff i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            *ctx = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
            return 1;
        }
    }
    return -1;
}

static struct r_debug *r_debug_from_dynamic(void *dynamic)
{
    for (const ElfDyn *dyn = dynamic; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == DT_DEBUG)
            return (struct r_debug *) dyn->d_un.d_ptr;
    }
    return NULL;
}
#endif

static struct r_debug *get_r_debug(void)
{
    /* Find our own r_debug */
    struct r_debug *dbg = NULL;

    /* First use some known shortcuts */
#if defined HAVE__R_DEBUG
    dbg = &_r_debug;
#elif defined HAVE__DYNAMIC
    dbg = r_debug_from_dynamic(_DYNAMIC);
#endif

#if !defined HAVE__R_DEBUG
    /* If there are no available shortcuts, we manually query our own phdrs */

    /* *INDENT-OFF* (formatters cannot handle this part of the code) */
# if defined HAVE__DYNAMIC
    if (!dbg) {
# endif
        ElfAddr dynamic;
        if (dl_iterate_phdr(find_dynamic, &dynamic) > 0)
            dbg = r_debug_from_dynamic((void *) dynamic);
# if defined HAVE__DYNAMIC
    }
# endif
    /* *INDENT-ON* */
#endif

    return dbg;
}

static bxfi_exe_ctx init_exe_ctx(void)
{
    static struct r_debug *dbg = (void *) -1;

    if (dbg == (void *) -1)
        dbg = get_r_debug();
    return dbg;
}

static unsigned long elf_hash(const char *s)
{
    unsigned long h = 0, high;

    while (*s) {
        h = (h << 4) + (unsigned char) *s++;
        if ((high = h & 0xf0000000))
            h ^= high >> 24;
        h &= ~high;
    }
    return h;
}

static ElfSym *elf_hash_find(ElfWWord *hash, ElfSym *symtab,
        const char *strtab, const char *name)
{
    struct {
        ElfWWord nb_buckets;
        ElfWWord nb_chains;
    } *h_info = (void *) hash;

    ElfWWord *buckets = (ElfWWord *) (h_info + 1);
    ElfWWord *chains  = (ElfWWord *) (h_info + 1) + h_info->nb_buckets;

    unsigned long idx = elf_hash(name) % h_info->nb_buckets;

    for (ElfWWord si = buckets[idx]; si != STN_UNDEF; si = chains[si]) {
        if (!strcmp(&strtab[symtab[si].st_name], name))
            return &symtab[si];
    }
    return NULL;
}

static ElfSym *dynsym_lookup(bxfi_exe_lib lib, const char *name)
{
    ElfWWord *hash = lib_dt_lookup(lib, DT_HASH);
    ElfSym *symtab = lib_dt_lookup(lib, DT_SYMTAB);
    const char *strtab = lib_dt_lookup(lib, DT_STRTAB);

    if (!hash || !symtab || !strtab)
        return NULL;

    return elf_hash_find(hash, symtab, strtab, name);
}

extern int main(void);

extern void *bxfi_trampoline;
extern void *bxfi_trampoline_addr;
extern void *bxfi_trampoline_end;

#define BXFI_TRAMPOLINE_SIZE          \
    ((uintptr_t) &bxfi_trampoline_end \
    - (uintptr_t) &bxfi_trampoline)

int bxfi_exe_patch_main(bxfi_exe_fn *new_main)
{
    void *addr = nonstd (void *) &main;

    if (!addr)
        return -1;

    /* Reserve enough space for the trampoline and copy the default opcodes */
    char opcodes[BXFI_TRAMPOLINE_SIZE];
    memcpy(opcodes, &bxfi_trampoline, sizeof (opcodes));

    uintptr_t jmp_offset = (uintptr_t) &bxfi_trampoline_addr
            - (uintptr_t) &bxfi_trampoline;

    /* The trampoline code is a jump followed by an aligned pointer value --
       after copying the jmp opcode, we write this pointer value. */
    *(uintptr_t *) (&opcodes[jmp_offset]) = (uintptr_t) new_main;

    void *base = (void *) align2_down((uintptr_t) addr, PAGE_SIZE);
    uintptr_t offset = (uintptr_t) addr - (uintptr_t) base;
    size_t len = align2_up(offset + sizeof (opcodes), PAGE_SIZE);

    mprotect(base, len, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(nonstd (void *) addr, opcodes, sizeof (opcodes));
    mprotect(base, len, PROT_READ | PROT_EXEC);
    return 0;
}

struct find_lib_from_addr_ctx {
    const void *addr;
    const char *name;
    size_t segidx;
    void *base;
    int first;
};

static int find_lib_from_addr(struct dl_phdr_info *info,
        size_t size, void *data)
{
    (void) size;

    struct find_lib_from_addr_ctx *ctx = data;
    size_t segidx = 0;

    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];

        if (phdr->p_type != PT_LOAD)
            continue;

        void *base = (void *) (info->dlpi_addr + phdr->p_vaddr);
        void *end = (char *) base + phdr->p_memsz;

        if (ctx->addr >= base && ctx->addr < end) {
            if (!ctx->first) {
                ctx->name = info->dlpi_name;
            } else {
                ctx->name = "";
            }
            ctx->segidx = segidx;
            ctx->base = base;
            return 1;
        }
        ++segidx;
    }
    ctx->first = 0;
    return 0;
}

uintptr_t bxfi_slide_from_addr(const void *addr, const char **name, size_t *seg)
{
    struct find_lib_from_addr_ctx ctx = {
        .addr = addr,
        .first = 1,
    };
    if (!dl_iterate_phdr(find_lib_from_addr, &ctx)) {
        errno = EINVAL;
        return (uintptr_t) -1;
    }

    *name = ctx.name;
    *seg = ctx.segidx;
    return (uintptr_t) ctx.base;
}

struct find_lib_from_name_ctx {
    const char *name;
    size_t segidx;
    void *base;
    int first;
};

static int find_lib_from_name(struct dl_phdr_info *info,
        size_t size, void *data)
{
    (void) size;

    struct find_lib_from_name_ctx *ctx = data;
    size_t segidx = 0;

    if (!(ctx->first && !ctx->name[0]) && strcmp(info->dlpi_name, ctx->name))
        return 0;

    ctx->first = 0;

    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];

        if (phdr->p_type != PT_LOAD)
            continue;

        if (segidx == ctx->segidx) {
            ctx->base = (void *) (info->dlpi_addr + phdr->p_vaddr);
            return 1;
        }
        ++segidx;
    }
    return 0;
}

uintptr_t bxfi_slide_from_name(const char *name, size_t seg)
{
    struct find_lib_from_name_ctx ctx = {
        .name = name,
        .segidx = seg,
        .first = 1,
    };
    if (!dl_iterate_phdr(find_lib_from_name, &ctx)) {
        errno = EINVAL;
        return (uintptr_t) -1;
    }

    return (uintptr_t) ctx.base;
}

const char *bxfi_lib_name(bxfi_exe_lib lib)
{
    bxfi_exe_ctx ctx = init_exe_ctx();

    /* The name of the main shared object is the empty string,
       we return something to be consistent with the eglibc weirdity */
    if (lib == ctx->r_map)
        return "self";

    /* Somewhy, eglibc always set l_name to the empty string. */
    if (lib->l_name[0])
        return lib->l_name;

    const char *strtab = lib_dt_lookup(lib, DT_STRTAB);
    ElfWord soname_off = lib_dt_lookup_val(lib, DT_SONAME);
    if (!strtab || soname_off == (ElfWord) - 1)
        return NULL;

    return &strtab[soname_off];
}

void bxfi_lib_name_term(const char *str)
{
    (void) str;
}

size_t bxfi_exe_get_vmslide(bxfi_exe_lib lib)
{
    return (size_t)lib->l_addr;
}
