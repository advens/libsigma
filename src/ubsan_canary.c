/* ubsan_canary.c
 * make wasm-san builds this with the same UBSan flags and expects it to trap.
 * If it exits 0, the sanitizer is not instrumenting and the gate proves
 * nothing.
 */
#include <limits.h>
#include <stdio.h>

int main(int argc, char** argv) {
    (void)argv;
    int x = INT_MAX;
    x += argc; /* signed overflow: argc >= 1 */
    printf("%d\n", x);
    return 0;
}
