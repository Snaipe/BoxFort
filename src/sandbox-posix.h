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
};

#endif /* !SANDBOX_POSIX_H_ */
