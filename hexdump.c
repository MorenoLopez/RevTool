/*
 * hexdump.c - Hex dump with colorized output
 */

#include "common.h"

int cmd_hexdump(int argc, char **argv) {
    const char *path = NULL;
    size_t offset = 0;
    size_t count = 256;
    int width = 16;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            offset = strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            count = strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            width = atoi(argv[++i]);
        } else if (!path) {
            path = argv[i];
        }
    }
    if (!path) {
        fprintf(stderr, "Usage: %s hex <file> [-o offset] [-n count] [-w width]\n", TOOL_NAME);
        return 1;
    }

    file_t *f = file_open(path);
    if (!f) return 1;
    if (offset >= f->size) {
        fprintf(stderr, "%sError: Offset beyond file size%s\n", c(C_RED), c(C_RESET));
        file_close(f);
        return 1;
    }
    size_t end = offset + count;
    if (end > f->size) end = f->size;

    printf("\n%s%sHex Dump:%s %s%s%s (offset=%zu, %zu bytes)\n",
           c(C_BOLD), c(C_RESET), c(C_RESET), c(C_CYAN), path, c(C_RESET), offset, end - offset);
    printf("%s\n", "============================================================");

    for (size_t row = offset; row < end; row += width) {
        printf("%s%08zx%s  ", c(C_BRIGHT_BLUE), row, c(C_RESET));
        size_t j;
        for (j = 0; j < (size_t)width && row + j < end; j++) {
            uint8_t b = f->data[row + j];
            const char *col = c(C_WHITE);
            if (b == 0) col = c(C_DIM);
            else if (b < 32 || b > 126) col = c(C_CYAN);
            printf("%s%02x%s ", col, b, c(C_RESET));
        }
        for (; j < (size_t)width; j++) {
            printf("   ");
        }
        printf(" |");
        for (j = 0; j < (size_t)width && row + j < end; j++) {
            uint8_t b = f->data[row + j];
            printf("%c", (b >= 32 && b <= 126) ? b : '.');
        }
        printf("|\n");
    }

    file_close(f);
    return 0;
}
