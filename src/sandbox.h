#ifndef SANDBOX_H_
# define SANDBOX_H_

# include "config.h"

# define BXFI_OS_SANDBOX_STR_(x) #x
# define BXFI_OS_SANDBOX_STR(x) BXFI_OS_SANDBOX_STR_(x)

# define BXFI_OS_SANDBOX_H_ sandbox-BXF_OS_FAMILY.h
# define BXFI_OS_SANDBOX_H BXFI_OS_SANDBOX_STR(BXFI_OS_SANDBOX_H_)

# include BXFI_OS_SANDBOX_H

int bxfi_check_local_ctx(const char *name);
int bxfi_map_local_ctx(struct bxfi_map *map, const char *name);
int bxfi_unmap_local_ctx(struct bxfi_map *map, const char *name, int destroy);

#endif /* !SANDBOX_H_ */
