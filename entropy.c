/*
 * entropy.c - Entropy analysis for detecting packed/encrypted regions
 */

#include "common.h"

int cmd_entropy(int argc, char **argv) {
    const char *path = NULL;
    size_t window = 256;
    double threshold = 7.0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            window = strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            threshold = strtod(argv[++i], NULL);
        } else if (!path) {
            path = argv[i];
        }
    }
    if (!path) {
        fprintf(stderr, "Usage: %s entropy <file> [-w window] [-t threshold]\n", TOOL_NAME);
        return 1;
    }

    file_t *f = file_open(path);
    if (!f) return 1;

    double total_ent = calc_entropy(f->data, f->size);

    printf("\n%s%sEntropy Analysis:%s %s%s%s\n",
           c(C_BOLD), c(C_RESET), c(C_RESET), c(C_CYAN), path, c(C_RESET));
    printf("%s\n", "============================================================");
    printf("  Total Entropy: %s%.4f%s/8.00\n", entropy_color(total_ent), total_ent, c(C_RESET));
    printf("  Window Size:   %zu bytes\n", window);
    printf("  Threshold:     %.1f\n", threshold);
    printf("\n");

    int found = 0;
    size_t step = window / 4;
    if (step == 0) step = 1;

    for (size_t i = 0; i + window <= f->size; i += step) {
        double ent = calc_entropy(f->data + i, window);
        if (ent >= threshold) {
            if (!found) {
                printf("%s%sHigh-Entropy Regions (possible packing/encryption):%s\n",
                       c(C_BOLD), c(C_RESET), c(C_RESET));
                printf("%10s  %8s\n", "Offset", "Entropy");
                printf("%s\n", "-------------------------");
                found = 1;
            }
            printf("%s%08zx%s   %.4f%s\n",
                   entropy_color(ent), i, c(C_RESET), ent, c(C_RESET));
        }
    }

    if (!found) {
        printf("%s%sNo high-entropy regions detected.%s\n", c(C_GREEN), c(C_BOLD), c(C_RESET));
    }

    file_close(f);
    return 0;
}
