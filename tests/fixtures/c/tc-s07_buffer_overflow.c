#include <stdio.h>

void read_line(void) {
    char buf[64];
    if (fgets(buf, sizeof(buf), stdin) != NULL) {
        printf("Read: %s", buf);
    }
}
