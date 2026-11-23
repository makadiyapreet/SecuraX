#include <stdlib.h>

void use_after_free(char *ptr) {
    free(ptr);
    // Vulnerable: reading from freed pointer
    char c = *ptr;
}
