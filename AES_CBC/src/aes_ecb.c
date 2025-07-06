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


static uint8_t multiply(uint8_t x, uint8_t y);


// Multiply in GF(2^8)
static uint8_t xtime(uint8_t x){
    return (x << 1) ^ ((x >> 7) * 0x1b);
}


// Key expansion
static void KeyExpansion(const uint8_t* key, uint8_t* roundKeys)
{
    memcpy(roundKeys, key, AES_KEY_SIZE);
    uint8_t temp[4];
    int i = AES_KEY_SIZE;

    int rcon = 1;
    while(i < EXPANDED_KEY_SIZE)
    {
        memcpy(temp, roundKeys + i -4, 4);

        if(i % AES_KEY_SIZE == 0)
        {
            uint8_t t = temp[0];
                        temp[0] = s_box[temp[1]] ^ rcon;
            temp[1] = s_box[temp[2]];
            temp[2] = s_box[temp[3]];
            temp[3] = s_box[t];
            rcon = xtime(rcon);
        }
        for (int j = 0; j < 4; ++j) {
            roundKeys[i] = roundKeys[i - AES_KEY_SIZE] ^ temp[j];
            ++i;
        }
    }
}




static void AddRoundKey(uint8_t* state, const uint8_t* roundKey) {
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] ^= roundKey[i];
    }
}

static void SubBytes(uint8_t* state) {
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] = s_box[state[i]];
    }
}

static void ShiftRows(uint8_t* state) {
    uint8_t tmp;

    // Row 1
    tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    // Row 2
    tmp = state[2];
    uint8_t tmp2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = tmp;
    state[14] = tmp2;

    // Row 3
    tmp = state[3];
    tmp2 = state[7];
    uint8_t tmp3 = state[11];
    state[3] = state[15];
    state[7] = tmp;
    state[11] = tmp2;
    state[15] = tmp3;
}

static void MixColumns(uint8_t* state) {
    for (int i = 0; i < 4; ++i) {
        int idx = i * 4;
        uint8_t a = state[idx];
        uint8_t b = state[idx + 1];
        uint8_t c = state[idx + 2];
        uint8_t d = state[idx + 3];

        uint8_t e = a ^ b ^ c ^ d;

        uint8_t xa = a;
        uint8_t xb = b;
        uint8_t xc = c;
        uint8_t xd = d;

        state[idx]     ^= e ^ xtime(a ^ b);
        state[idx + 1] ^= e ^ xtime(b ^ c);
        state[idx + 2] ^= e ^ xtime(c ^ d);
        state[idx + 3] ^= e ^ xtime(d ^ a);
    }
}




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





/*

====================================== Decryption ======================================


*/



// Inverse SubBytes — substitutes each byte using inv_s_box
static void InvSubBytes(uint8_t* state) {
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] = inv_s_box[state[i]];
    }
}

// Inverse ShiftRows — shift rows right instead of left
static void InvShiftRows(uint8_t* state) {
    uint8_t temp;

    // Row 1: shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9]  = state[5];
    state[5]  = state[1];
    state[1]  = temp;

    // Row 2: shift right by 2
    temp = state[2];
    state[2]  = state[10];
    state[10] = temp;
    temp = state[6];
    state[6]  = state[14];
    state[14] = temp;

    // Row 3: shift right by 3 (or left by 1)
    temp = state[3];
    state[3]  = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// Inverse MixColumns — use inverse polynomial multiplication
static void InvMixColumns(uint8_t* state) {
    for (int i = 0; i < 4; ++i) {
        uint8_t* col = &state[i * 4];
        uint8_t a = col[0];
        uint8_t b = col[1];
        uint8_t c = col[2];
        uint8_t d = col[3];

        col[0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        col[1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        col[2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        col[3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}

// Multiply two numbers in GF(2^8)
static uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t result = 0;
    uint8_t temp = x;

    for (int i = 0; i < 8; i++) {
        if ((y & 1) != 0) {
            result ^= temp;
        }
        uint8_t hi_bit_set = (temp & 0x80);
        temp <<= 1;
        if (hi_bit_set) {
            temp ^= 0x1b;
        }
        y >>= 1;
    }
    return result;
}

void AES128_ECB_decrypt(const uint8_t* input, const uint8_t* key, uint8_t* output) {
    uint8_t state[16];
    uint8_t roundKeys[176];

    memcpy(state, input, AES_BLOCK_SIZE);

    KeyExpansion(key, roundKeys);

    AddRoundKey(state, roundKeys + AES_NUM_ROUNDS * AES_BLOCK_SIZE);

    for (int round = AES_NUM_ROUNDS - 1; round > 0; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * AES_BLOCK_SIZE);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);

    memcpy(output, state, AES_BLOCK_SIZE);
}
