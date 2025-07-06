

#include <string.h>
#include "aes_ecb.h"

void AES128_CBC_encrypt_buffer(const uint8_t* input, const uint8_t* key, const uint8_t* iv, uint8_t* output, size_t length) {
    uint8_t buffer[16];
    uint8_t previous[16];
    memcpy(previous, iv, 16);

    for (size_t i = 0; i < length; i += 16) {
        for (int j = 0; j < 16; ++j)
            buffer[j] = input[i + j] ^ previous[j];

        AES128_ECB_encrypt(buffer, key, output + i);
        memcpy(previous, output + i, 16);
    }
}

void AES128_CBC_decrypt_buffer(const uint8_t* input, const uint8_t* key, const uint8_t* iv, uint8_t* output, size_t length) {
    uint8_t buffer[16];
    uint8_t previous[16];
    memcpy(previous, iv, 16);

    for (size_t i = 0; i < length; i += 16) {
        AES128_ECB_decrypt(input + i, key, buffer);

        for (int j = 0; j < 16; ++j)
            output[i + j] = buffer[j] ^ previous[j];

        memcpy(previous, input + i, 16);
    }
}





