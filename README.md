# AES Implementation from Scratch

This repository contains a progressive implementation of AES-128 encryption in C, divided into three phases to facilitate learning and development:

## Project Structure

- **Phase 1 - AES-128 ECB Mode**  
  Core AES block cipher implementation with basic Electronic Codebook (ECB) mode encryption and decryption.  
  Implements the fundamental AES transformations and key expansion.  
  Suitable for understanding the basics of AES internals.

- **Phase 2 - AES-128 CBC Mode**  
  Builds on Phase 1 by adding Cipher Block Chaining (CBC) mode support.  
  Includes initialization vector (IV) handling, block chaining logic, and padding schemes.  
  Allows encryption and decryption of arbitrary-length data.

- **Phase 3 - Integration with External AES Libraries**  
  Replaces the custom AES core with established libraries like TinyAES or mbedTLS.  
  Provides a more robust, tested, and optimized implementation suitable for embedded or production use.  
  Includes benchmarking and refactoring to separate core logic from integration code.

## Building and Running

Use a C compiler supporting C11 standard to build the project.

Example:

```sh
make
./aes_test
