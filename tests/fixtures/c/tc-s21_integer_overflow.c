#include <stdlib.h>
#include <stdint.h>

void *allocate_matrix(size_t width, size_t height) {
    if (height != 0 && width > SIZE_MAX / height) {
        return NULL;
    }
    return malloc(width * height);
}
