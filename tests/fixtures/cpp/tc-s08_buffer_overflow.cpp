#include <cstdio>

void format_packet(const char *name, int id) {
    char buf[32];
    snprintf(buf, sizeof(buf), "Packet: %s (id: %d)", name, id);
}
