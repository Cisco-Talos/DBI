#include <stdio.h>
#include <string.h>

void xor_decode(char* buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] ^= key;
    }
}

int main(void) {
    unsigned char key = 0x42;
    unsigned char obf[] = {
        'H' ^ 0x42, 'a' ^ 0x42, 'l' ^ 0x42, 'l' ^ 0x42, 'o' ^ 0x42, ' ' ^ 0x42,
        'W' ^ 0x42, 'e' ^ 0x42, 'l' ^ 0x42, 't' ^ 0x42, '!' ^ 0x42, 0
    };

    xor_decode((char*)obf, strlen((char*)obf), key);
    printf("%s\n", obf);
    return 0;
}
