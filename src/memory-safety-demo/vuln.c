/* SecureBank — memory-safety demo (VULNERABLE BUILD)
 *
 * INTENTIONALLY UNSAFE.  Compiled without hardening flags so the Red Team
 * drill can exhibit:
 *   1) classic stack buffer overflow  (CWE-121)
 *   2) format-string vulnerability     (CWE-134)
 *   3) integer overflow → small alloc  (CWE-190)
 *   4) use-after-free                  (CWE-416)
 *
 * Never compile this with hardening flags; never ship it in a production
 * image.  See `hardened.c` for the safe counterpart.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void demo_bof(const char *user) {
    char name[16];
    strcpy(name, user);              /* CWE-121: no bounds check */
    printf("hello %s\n", name);
}

static void demo_fmt(const char *user) {
    printf(user);                    /* CWE-134: format-string */
    putchar('\n');
}

static void demo_int_overflow(int count) {
    /* On 32-bit, count*sizeof(int) wraps and we malloc a tiny buffer
       then write past it. */
    size_t bytes = (size_t)(count * (int)sizeof(int));  /* CWE-190 */
    int *p = (int *)malloc(bytes);
    if (!p) return;
    for (int i = 0; i < count; i++) p[i] = i;
    free(p);
}

static void demo_uaf(void) {
    char *p = (char *)malloc(32);
    if (!p) return;
    strcpy(p, "use-after-free");
    free(p);
    printf("%s\n", p);               /* CWE-416 */
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: vuln {bof|fmt|int|uaf} <arg>\n");
        return 2;
    }
    if (!strcmp(argv[1], "bof")) demo_bof(argv[2]);
    else if (!strcmp(argv[1], "fmt")) demo_fmt(argv[2]);
    else if (!strcmp(argv[1], "int")) demo_int_overflow(atoi(argv[2]));
    else if (!strcmp(argv[1], "uaf")) demo_uaf();
    else { fprintf(stderr, "unknown mode\n"); return 2; }
    return 0;
}
