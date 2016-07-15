#ifndef SANDBOX_H_
# define SANDBOX_H_

# include "config.h"

# define BXFI_OS_SANDBOX_STR_(x) #x
# define BXFI_OS_SANDBOX_STR(x) BXFI_OS_SANDBOX_STR_(x)

# define BXFI_OS_SANDBOX_H_ sandbox-BXF_OS_FAMILY.h
# define BXFI_OS_SANDBOX_H BXFI_OS_SANDBOX_STR(BXFI_OS_SANDBOX_H_)

# include BXFI_OS_SANDBOX_H

int bxfi_exec(bxf_instance **out, bxf_sandbox *sandbox, bxf_fn *fn, bxf_preexec *preexec);
int bxfi_check_sandbox_ctx(void);
int bxfi_init_sandbox_ctx(struct bxfi_map *map);
int bxfi_term_sandbox_ctx(struct bxfi_map *map);

#endif /* !SANDBOX_H_ */
