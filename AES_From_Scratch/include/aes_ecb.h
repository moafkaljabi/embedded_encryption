#ifndef AES_ECB_H
#define AES_ECB_H

#include <stdint.h>
#include <string.h>

#include "aes_tables.h"

#define AES_BLOCK_SIZE      16  // 16-bytes block
#define AES_KEY_SIZE        16
#define AES_COLUMNS          4   // Number of columns 
#define AES_KEY_LENGTH       4   // Key length for 32 bit words, 4 words = 16 bytes
#define AES_NUM_ROUNDS      10  // Number of rounds.
#define EXPANDED_KEY_SIZE   176 



void AES128_ECB_encrypt(const uint8_t* input, const uint8_t * key, uint8_t* output);

#endif