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

#if defined HAVE_ELF_AUXV_T
typedef ElfW(auxv_t) ElfAux;
#elif defined HAVE_ELF_AUXINFO
typedef ElfW(Auxinfo) ElfAux;
#else
# error Unsupported platform
#endif

extern char **environ;

static void *lib_dt_lookup(bxfi_exe_lib lib, ElfSWord tag)
{
    ElfW(Addr) base =(ElfW(Addr)) lib->l_addr;
    for (const ElfW(Dyn) *dyn = lib->l_ld; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == tag) {
            if (dyn->d_un.d_ptr >= base
                    && (dyn->d_un.d_ptr >> (BXF_BITS - 8)) ^ 0xff)
                return (void*) dyn->d_un.d_ptr;
            else
                return (char*) base + dyn->d_un.d_ptr;
        }
    }
    return NULL;
}

static ElfWord lib_dt_lookup_val(bxfi_exe_lib lib, ElfSWord tag)
{
    for (const ElfW(Dyn) *dyn = lib->l_ld; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == tag)
            return dyn->d_un.d_val;
    }
    return (ElfWord) -1;
}

#if !defined HAVE__R_DEBUG
static ElfW(Addr) get_auxval(ElfAux *auxv, ElfW(Off) tag)
{
    for (; auxv->a_type != AT_NULL; auxv++) {
        if (auxv->a_type == tag)
            return auxv->a_un.a_val;
    }
    return (ElfW(Addr)) -1;
}

static ElfW(Addr) find_dynamic(ElfW(Phdr) *phdr, ElfW(Off) phent)
{
    for (ElfW(Off) i = 0; i < phent; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC)
            return phdr[i].p_vaddr;
    }
    return 0;
}

static struct r_debug *r_debug_from_dynamic(void *dynamic)
{
    for (const ElfW(Dyn) *dyn = dynamic; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == DT_DEBUG)
            return (struct r_debug *) dyn->d_un.d_ptr;
    }
    return NULL;
}
#endif

static struct r_debug *get_r_debug(void)
{
    // Find our own r_debug
    struct r_debug *dbg = NULL;

    // First use some known shortcuts
#if defined HAVE__R_DEBUG
    dbg = &_r_debug;
#elif defined HAVE__DYNAMIC
    dbg = r_debug_from_dynamic(_DYNAMIC);
#endif

#if !defined HAVE__R_DEBUG
    // If there are no available shortcuts, we manually query our own phdrs
# if defined HAVE__DYNAMIC
    if (!dbg) {
# endif
        char **envp = environ;
        while (*envp++ != NULL);
        ElfAux *auxv = (ElfAux*) envp;
        ElfW(Addr) phdr = get_auxval(auxv, AT_PHDR);
        ElfW(Addr) phent = get_auxval(auxv, AT_PHENT);
        if (phdr != (ElfW(Addr)) -1 && phent != (ElfW(Addr)) -1) {
            ElfW(Addr) dynamic = find_dynamic((void*) phdr, phent);
            dbg = r_debug_from_dynamic((void*) dynamic);
        }
# if defined HAVE__DYNAMIC
    }
# endif
#endif

    return dbg;
}

static bxfi_exe_ctx init_exe_ctx(void)
{
    static struct r_debug *dbg = (void*) -1;
    if (dbg == (void*) -1)
        dbg = get_r_debug();
    return dbg;
}

static unsigned long elf_hash (const char *s)
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

static ElfW(Sym) *elf_hash_find(ElfW(Word) *hash, ElfW(Sym) *symtab,
    const char *strtab, const char *name)
{
    struct {
        ElfW(Word) nb_buckets;
        ElfW(Word) nb_chains;
    } *h_info = (void*) hash;

    ElfW(Word) *buckets = (ElfW(Word)*) (h_info + 1);
    ElfW(Word) *chains = (ElfW(Word)*) (h_info + 1) + h_info->nb_buckets;

    unsigned long idx = elf_hash(name) % h_info->nb_buckets;

    for (ElfW(Word) si = buckets[idx]; si != STN_UNDEF; si = chains[si]) {
        if (!strcmp(&strtab[symtab[si].st_name], name))
            return &symtab[si];
    }
    return NULL;
}

static ElfW(Sym) *dynsym_lookup(bxfi_exe_lib lib, const char *name)
{
    ElfW(Word) *hash    = lib_dt_lookup(lib, DT_HASH);
    ElfW(Sym) *symtab   = lib_dt_lookup(lib, DT_SYMTAB);
    const char *strtab  = lib_dt_lookup(lib, DT_STRTAB);

    if (!hash || !symtab || !strtab)
        return NULL;

    return elf_hash_find (hash, symtab, strtab, name);
}

extern int main(void);

static void *get_main_addr(bxfi_exe_ctx ctx)
{
    /* It just so happens that `main` can exist in the symbol hash table of
       our executable if it is a dynamic symbol, and gives the address of
       its PLT stub.
       Effectively, we don't need to traverse the link map list, but
       this is the exception rather than the norm. */
    struct link_map *lm = ctx->r_map;

    /* First, do a fast lookup in the dynamic symbol hash table to get
       the PLT address if we have a dynamic symbol */
    ElfW(Sym) *sym = dynsym_lookup(lm, "main");
    if (sym)
        return (void *) (sym->st_value + lm->l_addr);

    /* Otherwise, we fallback to whatever the linker says */
    return nonstd (void *) &main;
}

extern void *bxfi_trampoline;
extern void *bxfi_trampoline_addr;
extern void *bxfi_trampoline_end;

#define PAGE_SIZE 4096

int bxfi_exe_patch_main(bxfi_exe_fn *new_main)
{
    void *addr = get_main_addr(init_exe_ctx());
    if (!addr)
        return -1;

    /* Reserve enough space for the trampoline and copy the default opcodes */
    char opcodes[(uintptr_t)&bxfi_trampoline_end - (uintptr_t)&bxfi_trampoline];
    memcpy(opcodes, &bxfi_trampoline, sizeof (opcodes));

    uintptr_t jmp_offset = (uintptr_t)&bxfi_trampoline_addr
                         - (uintptr_t)&bxfi_trampoline;

    /* The trampoline code is a jump followed by an aligned pointer value --
       after copying the jmp opcode, we write this pointer value. */
    *(uintptr_t *)(&opcodes[jmp_offset]) = (uintptr_t)new_main;

    void *base = (void *) align2_down((uintptr_t) addr, PAGE_SIZE);
    uintptr_t offset = (uintptr_t) addr - (uintptr_t) base;
    size_t len = align2_up(offset + sizeof (opcodes), PAGE_SIZE);

    mprotect(base, len, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(nonstd (void *) addr, opcodes, sizeof (opcodes));
    mprotect(base, len, PROT_READ | PROT_EXEC);
    return 0;
}

bxfi_exe_lib bxfi_lib_from_addr(const void *addr)
{
    bxfi_exe_ctx ctx = init_exe_ctx();

    struct link_map *lo = ctx->r_map;
    for (struct link_map *lm = lo; lm; lm = lm->l_next) {
        if (addr >= (void *) lm->l_addr && lo->l_addr < lm->l_addr)
            lo = lm;
    }
    return lo;
}

bxfi_exe_lib bxfi_lib_from_name(const char *name)
{
    bxfi_exe_ctx ctx = init_exe_ctx();
    for (struct link_map *lm = ctx->r_map; lm; lm = lm->l_next) {
        const char *lname = bxfi_lib_name(lm);
        if (!strcmp(lname, name))
            return lm;
    }
    return BXFI_INVALID_LIB;
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

    const char *strtab  = lib_dt_lookup(lib, DT_STRTAB);
    ElfWord soname_off = lib_dt_lookup_val(lib, DT_SONAME);
    if (!strtab || soname_off == (ElfWord) -1)
        return NULL;

    return &strtab[soname_off];
}

size_t bxfi_exe_get_vmslide(bxfi_exe_lib lib)
{
    return lib->l_addr;
}
