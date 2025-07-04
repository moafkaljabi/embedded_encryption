

/*

Define AES Parameters: 

- Block Size: 16 Bytes
- Key Size: 16 Bytes
- State Representation: 4x4 matrix of bytes.
- Round Key Storage: 11 round keys (AES-128)

AES transforms 16-byte block using a sequence
of operations on 4x4 matrix 

*/ 

#include <stdint.h>
 
uint8_t block_size;
uint8_t key_size;

