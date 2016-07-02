#ifndef ADDR_H_
# define ADDR_H_

# include "boxfort.h"
# include "common.h"

void *bxfi_normalize_addr(void *addr);
void *bxfi_denormalize_addr(void *addr);

static inline bxf_fn *bxfi_normalize_fnaddr(bxf_fn *addr)
{
    return nonstd (bxf_fn *) bxfi_normalize_addr(nonstd (void *) addr);
}

static inline bxf_fn *bxfi_denormalize_fnaddr(bxf_fn *addr)
{
    return nonstd (bxf_fn *) bxfi_denormalize_addr(nonstd (void *) addr);
}

#endif /* !ADDR_H_ */
