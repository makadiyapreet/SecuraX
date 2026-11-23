#include <stdlib.h>

void *allocate_matrix(size_t width, size_t height) {
    size_t total = width * height;
    return malloc(total);
}
