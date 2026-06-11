/* SecureBank — memory-safety demo (HARDENED BUILD)
 *
 * Each function mirrors the unsafe counterpart in `vuln.c` and applies the
 * mitigation the project brief asks for.  The same `attack.sh` payload is
 * fed to this binary during the Red/Blue drill — it must either succeed
 * safely or abort cleanly via __stack_chk_fail / __fortify_fail.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

/* Fail fast on any internal misuse — never silently truncate. */
static void die(const char *why) {
    fprintf(stderr, "abort: %s\n", why);
    abort();
}

static void safe_bof(const char *user) {
    char name[16];
    /* snprintf always NUL-terminates within the destination. */
    int n = snprintf(name, sizeof name, "%s", user);
    if (n < 0 || (size_t)n >= sizeof name) die("input too long");
    printf("hello %s\n", name);
}

static void safe_fmt(const char *user) {
    /* Always pass a constant format string with %s. */
    printf("%s\n", user);
}

static void safe_int_alloc(int count) {
    if (count < 0) die("negative count");
    size_t bytes = 0;
    /* GCC/clang built-in overflow check — refuses to allocate on wrap. */
    if (__builtin_mul_overflow((size_t)count, sizeof(int), &bytes))
        die("integer overflow");
    int *p = (int *)calloc(count, sizeof(int));
    if (!p) die("OOM");
    for (int i = 0; i < count; i++) p[i] = i;
    free(p);
}

/* free + clear pointer to make UAF impossible. */
#define FREE_AND_NULL(p) do { free(p); (p) = NULL; } while (0)

static void safe_uaf(void) {
    char *p = (char *)malloc(32);
    if (!p) die("OOM");
    snprintf(p, 32, "use-after-free");
    FREE_AND_NULL(p);
    if (p) printf("%s\n", p);   /* unreachable — p is NULL */
    else  printf("(safely cleared)\n");
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: hardened {bof|fmt|int|uaf} <arg>\n");
        return 2;
    }
    if (!strcmp(argv[1], "bof")) safe_bof(argv[2]);
    else if (!strcmp(argv[1], "fmt")) safe_fmt(argv[2]);
    else if (!strcmp(argv[1], "int")) safe_int_alloc(atoi(argv[2]));
    else if (!strcmp(argv[1], "uaf")) safe_uaf();
    else { fprintf(stderr, "unknown mode\n"); return 2; }
    return 0;
}
