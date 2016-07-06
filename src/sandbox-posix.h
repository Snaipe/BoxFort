#ifndef SANDBOX_POSIX_H_
# define SANDBOX_POSIX_H_

struct bxfi_context {
    size_t total_sz;
    void *fn;
    size_t fn_soname_sz;
    int ok;
};

struct bxfi_map {
    struct bxfi_context *ctx;
    int fd;
    char map_name[sizeof ("bxfi_") + 21];
};

# ifndef __GNUC__
#  error Compiler not supported -- use a GNU C compiler.
# endif

# define BXFI_INITIALIZER(...) __attribute__((constructor))

#endif /* !SANDBOX_POSIX_H_ */
