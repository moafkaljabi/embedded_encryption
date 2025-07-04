

/*

Define AES Parameters: 

- Block Size: 16 Bytes
- Key Size: 16 Bytes
- State Representation: 4x4 matrix of bytes.
- Round Key Storage: 11 round keys (AES-128)

AES transforms 16-byte block using a sequence
of operations on 4x4 matrix 

*/ 


#include "aes_ecb.h"


// Internal helper functions
static void KeyExpansion(const uint8_t* key, uint8_t* roundKeys); // Derives round keys from the input key
static void AddRoundKey(uint8_t* state, const uint8_t* roundKey); // XORs state with the round key 
static void SubBytes(uint8_t* state); // Applies the S-box substitution
static void ShiftRows(uint8_t* state); 
static void MixColumns(uint8_t* state);  



void AES128_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t* output)
{
    uint8_t state[16];
    uint8_t roundKeys[176];

    memcpy(state, input, AES_BLOCK_SIZE);

    KeyExpansion(key, roundKeys);

    AddRoundKey(state, roundKeys);

    // Rounds with column mixing
    for(int round=1; round < AES_NUM_ROUNDS; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);

        AddRoundKey(state, roundKeys + round * AES_BLOCK_SIZE);
    }

    // Final round no column mixing

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + AES_NUM_ROUNDS * AES_BLOCK_SIZE);

    memcpy(output, state, AES_BLOCK_SIZE);
}
