/* A cipher algorithm library:
Caesar's, Spartan's, Vigenere's, One-time pad (OTP) */

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdio.h>
#include <stdint.h>


/* One-time pad (OTP) cipher

Encrypts the specified plaintext using the specified key. Key should be the same length
as the plaintext. Allowed characters for the plaintext are (0-9A-Za-z).

Returns null if:
1) plaintext is NULL
2) key is NULL
3) length of key != length of plaintext */
uint8_t *otp_encrypt(uint8_t *plaintext, uint8_t *key);


/* One-time pad (OTP) cipher

Decrypts the specified ciphertext using the specified key. Key should be the same length
as the ciphertext.

Returns null if:
1) ciphertext is NULL
2) key is NULL
3) length of key != length of ciphertext */
uint8_t *otp_decrypt(uint8_t *ciphertext, uint8_t *key);


/* Caesar's cipher

Encrypts the specified plaintext using the specified number N.
Allowed characters for the plaintext are (0-9A-Za-z).

Returns NULL if plaintext is NULL */
uint8_t *caesar_encrypt(uint8_t *plaintext, unsigned short N);


/* Caesar's cipher

Decrypts the specified ciphertext using the specified number N.

Returns NULL if plaintext is NULL  */
uint8_t *caesar_decrypt(uint8_t *ciphertext, unsigned short N);


/* Spartan's cipher

Encrypts the specified plaintext using the specified circ (circumference of the scytale) and len (length of the scytale).
Allowed characters for the plaintext are (0-9A-Za-z).

Returns NULL if:
1) plaintext is NULL
2) circ * len < length of plaintext */
uint8_t *spartan_encrypt(uint8_t *plaintext, unsigned short circ, unsigned short len);


/* Spartan's cipher

Decrypts the specified ciphertext using the specified circ (circumference of the scytale) and len (length of the scytale).

Returns NULL if:
1) ciphertext is NULL
2) circ * len < length of ciphertext */
uint8_t *spartan_decrypt(uint8_t *ciphertext, unsigned short circ, unsigned short len);


/* Vigenere's cipher

Encrypts the specified plaintext using the specified key. Allowed characters for the plaintext are (A-Z).

Returns NULL if:
1) plaintext is NULL
2) key is NULL
3) length of plaintext < length of key */
uint8_t *vigenere_encrypt(uint8_t *plaintext, uint8_t *key);


/* Vigenere's cipher

Decrypts the specified ciphertext using the specified key.

Returns NULL if:
1) plaintext is NULL
2) key is NULL
3) length of plaintext < length of key */
uint8_t *vigenere_decrypt(uint8_t *ciphertext, uint8_t *key);

#endif
