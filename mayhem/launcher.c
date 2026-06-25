/*
 * launcher.c — tiny ELF shim so the Mayhem target `cmd` is a native executable (Mayhem rejects
 * script/wrapper targets; fuzz-smoke checks the ELF magic). It exec's the CPython interpreter on
 * the Atheris harness, forwarding every argument unchanged.
 *
 * Atheris is a libFuzzer engine: when invoked with libFuzzer flags (`-runs=...`,
 * `-max_total_time=...`) the harness iterates like any libFuzzer target; when invoked with a file
 * argument it replays that single input once — so the SAME binary is both the fuzz target and the
 * standalone reproducer.
 *
 * The harness path and interpreter are fixed by the image layout (the repo is COPYed to /mayhem).
 */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifndef HARNESS_PATH
#define HARNESS_PATH "/mayhem/mayhem/fuzz_extract.py"
#endif
#ifndef PYTHON_BIN
#define PYTHON_BIN "/usr/bin/python3"
#endif

int main(int argc, char **argv) {
    /* new argv: python3 HARNESS_PATH <forwarded args...> NULL */
    char **nargv = calloc((size_t)argc + 2, sizeof(char *));
    if (!nargv) return 1;
    nargv[0] = (char *)PYTHON_BIN;
    nargv[1] = (char *)HARNESS_PATH;
    for (int i = 1; i < argc; i++) nargv[i + 1] = argv[i];
    nargv[argc + 1] = NULL;
    execv(PYTHON_BIN, nargv);
    /* execv only returns on error */
    return 127;
}
