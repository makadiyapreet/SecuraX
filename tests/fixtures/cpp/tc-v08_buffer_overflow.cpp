#include <cstdio>

void format_packet(const char *name, int id) {
    char buf[32];
    sprintf(buf, "Packet: %s (id: %d)", name, id);
}
