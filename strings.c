/*
 * strings.c - Extract printable strings from binary files
 */

#include "common.h"

int cmd_strings(int argc, char **argv) {
    const char *path = NULL;
    int min_len = 4;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            min_len = atoi(argv[++i]);
        } else if (!path) {
            path = argv[i];
        }
    }
    if (!path) {
        fprintf(stderr, "Usage: %s strings <file> [-n min_length]\n", TOOL_NAME);
        return 1;
    }

    file_t *f = file_open(path);
    if (!f) return 1;

    printf("\n%s%sStrings:%s %s%s%s (min_length=%d)\n",
           c(C_BOLD), c(C_RESET), c(C_RESET), c(C_CYAN), path, c(C_RESET), min_len);
    printf("%s\n", "============================================================");
    printf("%10s %s%-8s%s String\n", "Offset", c(C_BOLD), "Type", c(C_RESET));
    printf("%s\n", "------------------------------------------------------------");

    size_t i = 0;
    while (i < f->size) {
        /* ASCII strings */
        if (f->data[i] >= 32 && f->data[i] <= 126) {
            size_t start = i;
            while (i < f->size && f->data[i] >= 32 && f->data[i] <= 126) {
                i++;
            }
            if (i - start >= (size_t)min_len) {
                printf("%s%08zx%s   %s%-8s%s ",
                       c(C_BRIGHT_BLUE), start, c(C_RESET),
                       c(C_GREEN), "ASCII", c(C_RESET));
                for (size_t j = start; j < i && j < start + 200; j++) {
                    putchar(f->data[j]);
                }
                printf("\n");
            }
            continue;
        }
        /* UTF-16LE strings */
        if (i + 1 < f->size && f->data[i] != 0 && f->data[i] >= 32 && f->data[i] <= 126 && f->data[i+1] == 0) {
            size_t start = i;
            while (i + 1 < f->size && f->data[i+1] == 0 && f->data[i] >= 32 && f->data[i] <= 126) {
                i += 2;
            }
            if ((i - start) / 2 >= (size_t)min_len) {
                printf("%s%08zx%s   %s%-8s%s ",
                       c(C_BRIGHT_BLUE), start, c(C_RESET),
                       c(C_MAGENTA), "UTF-16", c(C_RESET));
                for (size_t j = start; j < i && j < start + 200; j += 2) {
                    putchar(f->data[j]);
                }
                printf("\n");
            }
            continue;
        }
        i++;
    }

    file_close(f);
    return 0;
}
