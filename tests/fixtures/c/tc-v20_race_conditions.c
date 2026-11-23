static int shared_counter = 0;

void increment_counter(void) {
    // Race condition on shared counter
    shared_counter++;
}
