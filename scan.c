/*
 * scan.c - Full binary scan (runs all analysis modules)
 */

#include "common.h"

/* External command functions */
extern int cmd_info(int argc, char **argv);
extern int cmd_hexdump(int argc, char **argv);
extern int cmd_strings(int argc, char **argv);
extern int cmd_elf(int argc, char **argv);
extern int cmd_pe(int argc, char **argv);
extern int cmd_entropy(int argc, char **argv);

int cmd_scan(int argc, char **argv) {
    const char *path = NULL;
    for (int i = 2; i < argc; i++) {
        if (argv[i][0] != '-') {
            path = argv[i];
            break;
        }
    }
    if (!path) {
        fprintf(stderr, "Usage: %s scan <file>\n", TOOL_NAME);
        return 1;
    }

    file_t *f = file_open(path);
    if (!f) return 1;

    printf("\n%s%s", c(C_BOLD), c(C_RESET));
    printf("======================================================================\n");
    printf("  FULL BINARY SCAN: %s%s%s\n", c(C_BRIGHT_CYAN), path, c(C_RESET));
    printf("======================================================================\n");
    printf("%s\n", c(C_RESET));

    file_close(f);

    /* Run info */
    {
        char *args[] = { (char*)TOOL_NAME, (char*)"info", (char*)"-f", (char*)path, NULL };
        cmd_info(4, args);
    }

    /* Run entropy */
    {
        char *args[] = { (char*)TOOL_NAME, (char*)"entropy", (char*)path, NULL };
        cmd_entropy(3, args);
    }

    /* Run strings */
    {
        char *args[] = { (char*)TOOL_NAME, (char*)"strings", (char*)"-n", (char*)"6", (char*)path, NULL };
        cmd_strings(5, args);
    }

    /* Run hex preview */
    printf("\n%s%sFirst 256 bytes:%s\n", c(C_BOLD), c(C_RESET), c(C_RESET));
    printf("%s\n", "============================================================");
    {
        char *args[] = { (char*)TOOL_NAME, (char*)"hex", (char*)"-n", (char*)"256", (char*)path, NULL };
        cmd_hexdump(5, args);
    }

    return 0;
}
