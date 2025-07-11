
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "aes_ecb.h"


int main()
{
    // Test Vector
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t input[16] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    uint8_t output[16];

    AES128_ECB_encrypt(input, key, output);

    printf("Ciphertext: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", output[i]);
    }
    printf("\n");


    uint8_t decrypted[16];
    AES128_ECB_decrypt(output, key, decrypted);

    printf("Decrypted: ");
    for (int i = 0; i < 16; i++) {
    printf("%02x ", decrypted[i]);
    }
    printf("\n");
    
    return 0;
}

