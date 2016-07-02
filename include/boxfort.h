#ifndef BOXFORT_H_
# define BOXFORT_H_

# include <stddef.h>

typedef unsigned long long bxf_pid;
typedef int (bxf_fn)(void);
typedef void (bxf_callback)(void);

struct bxf_sandbox {
    bxf_pid pid;
};

typedef const struct bxf_sandbox *bxf_sandbox;

struct bxf_run_params {
    bxf_fn *fn;
    bxf_callback *callback;
};

typedef const struct bxf_run_params *bxf_run_params;

# define bxf_run(Ctx, ...) (bxf_run_impl((Ctx), &(struct bxf_run_params) { __VA_ARGS__ }))

int bxf_run_impl(bxf_sandbox *ctx, bxf_run_params params);
int bxf_wait(bxf_sandbox ctx, size_t timeout);

#endif /* !BOXFORT_H_ */
