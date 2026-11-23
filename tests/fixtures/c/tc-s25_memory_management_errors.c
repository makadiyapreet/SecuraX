#include <stdlib.h>

char read_and_free(char *ptr) {
    if (!ptr) return 0;
    char c = *ptr;
    free(ptr);
    ptr = NULL;
    return c;
}
