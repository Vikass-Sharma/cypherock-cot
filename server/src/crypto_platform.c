#include <stdlib.h>
#include <stdint.h>
#include "rand.h"

// Cryptographically secure RNG bridge for Trezor crypto on macOS
void random_buffer(uint8_t *buf, size_t len) {
    arc4random_buf(buf, len);
}
