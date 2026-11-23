#include <string.h>

void process_input(const char *user_str) {
    char stack_buf[16];
    strncpy(stack_buf, user_str, sizeof(stack_buf) - 1);
    stack_buf[sizeof(stack_buf) - 1] = '\0';
}
