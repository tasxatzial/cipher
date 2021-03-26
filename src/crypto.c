/* A cipher algorithm library:
Caesar's, Spartan's, Vigenere's, One-time pad (OTP) */

#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"
#include "util.h"

/* allowed characters for the caesar cipher */
const uint8_t CAESAR_ALPHABET[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const unsigned int CAESAR_ALPHABET_LENGTH = 62;


/* One-time pad (OTP) cipher

Encrypts the specified plaintext using the specified key. Key should be the same length
as the plaintext. Allowed characters for the plaintext are (0-9A-Za-z).

Returns null if:
1) plaintext is NULL
2) key is NULL
3) length of key != length of plaintext */
uint8_t *otp_encrypt(uint8_t *plaintext, uint8_t *key) {
    unsigned int i, length, key_length;
    uint8_t *encrypted;

    if (plaintext == NULL || key == NULL) {
        return NULL;
    }
    length = getlength(plaintext);
    key_length = getlength(key);
    if (key_length != length) {
        return NULL;
    }
    encrypted = malloc(length * sizeof(uint8_t));
    for (i = 0; i < length; i++) {
        encrypted[i] = plaintext[i]^key[i];
    }
    return encrypted;
}


/* One-time pad (OTP) cipher

Decrypts the specified ciphertext using the specified key. Key should be the same length
as the ciphertext.

Returns null if:
1) ciphertext is NULL
2) key is NULL
3) length of key != length of ciphertext */
uint8_t *otp_decrypt(uint8_t *ciphertext, uint8_t *key) {
    unsigned int i, ciphertext_length, key_length;
    uint8_t *decrypted;

    if (ciphertext == NULL || key == NULL) {
        return NULL;
    }
    key_length = getlength(key);
    ciphertext_length = getlength(ciphertext);
    if (key_length != ciphertext_length) {
        return NULL;
    }
    decrypted = malloc((1 + key_length)  * sizeof(uint8_t));
    for (i = 0; i < key_length; i++) {
        decrypted[i] = (ciphertext[i] == 0) ? key[i] : (ciphertext[i]^key[i]);
    }
    decrypted[i] = '\0';
    return decrypted;
}


/* Caesar's cipher

Encrypts the specified plaintext using the specified number N.
Allowed characters for the plaintext are (0-9A-Za-z).

Returns NULL if plaintext is NULL */
uint8_t *caesar_encrypt(uint8_t *plaintext, unsigned short N) {
    unsigned int i, length;
    uint8_t *encrypted;

    if (plaintext == NULL) {
        return NULL;
    }
    length = getlength(plaintext);
    encrypted = malloc((1 + length) * sizeof(uint8_t));
    for (i = 0; i < length; i++) {
        encrypted[i] = CAESAR_ALPHABET[(getposition(CAESAR_ALPHABET, plaintext[i]) + N) % CAESAR_ALPHABET_LENGTH];
    }
    encrypted[i] = '\0';
    return encrypted;
}


/* Caesar's cipher

Decrypts the specified ciphertext using the specified number N.

Returns NULL if plaintext is NULL */
uint8_t *caesar_decrypt(uint8_t *ciphertext, unsigned short N) {
    unsigned int i, length;
    uint8_t *decrypted;

    if (ciphertext == NULL) {
        return NULL;
    }
    length = getlength(ciphertext);
    decrypted = malloc((1 + length) * sizeof(uint8_t));
    for (i = 0; i < length; i++) {
        decrypted[i] = CAESAR_ALPHABET[(getposition(CAESAR_ALPHABET, ciphertext[i]) - N) % CAESAR_ALPHABET_LENGTH];
    }
    decrypted[i] = '\0';
    return decrypted;
}


/* Spartan's cipher

Encrypts the specified plaintext using the specified circ (circumference of the scytale) and len (length of the scytale).
Allowed characters for the plaintext are (0-9A-Za-z).

Returns NULL if:
1) plaintext is NULL
2) circ * len < length of plaintext */
uint8_t *spartan_encrypt(uint8_t *plaintext, unsigned short circ, unsigned short len) {
    unsigned int i, i_len, i_circ, plaintext_length, scytale_length, plaintext_padded_length;
    uint8_t *encrypted;
    uint8_t *plaintext_padded;

    if (plaintext == NULL) {
        return NULL;
    }
    plaintext_length = getlength(plaintext);
    scytale_length = circ * len;
    plaintext_padded = padmsg(plaintext, plaintext_length, scytale_length);
    if (plaintext_padded == NULL) {
        return NULL;
    }
    plaintext_padded_length = getlength(plaintext_padded);
    encrypted = malloc((1 + plaintext_padded_length) * sizeof(uint8_t));

    i = 0;
    for (i_len = 0; i_len < len; i_len++) {
        for (i_circ = 0; i_circ < circ; i_circ++) {
            encrypted[i++] = plaintext_padded[i_circ * len + i_len];
        }
    }
    encrypted[i] = '\0';
    free(plaintext_padded);
    return encrypted;
}


/* Spartan's cipher

Decrypts the specified ciphertext using the specified circ (circumference of the scytale) and len (length of the scytale).

Returns NULL if:
1) ciphertext is NULL
2) circ * len < length of ciphertext */
uint8_t *spartan_decrypt(uint8_t *ciphertext, unsigned short circ, unsigned short len) {
    unsigned int i, i_len, i_circ, ciphertext_length;
    uint8_t *decrypted_padded, *decrypted;

    if (ciphertext == NULL) {
        return NULL;
    }
    ciphertext_length = getlength(ciphertext);
    if (ciphertext_length > circ * len) {
        return NULL;
    }
    decrypted_padded = malloc((1 + ciphertext_length) * sizeof(uint8_t));
    
    i = 0;
    for (i_circ = 0; i_circ < circ; i_circ++) {
        for (i_len = 0; i_len < len; i_len++) {
            decrypted_padded[i++] = ciphertext[i_len * circ + i_circ];
        }
    }
    decrypted_padded[i] = '\0';
    decrypted = removepadding(decrypted_padded);
    free(decrypted_padded);
    return decrypted;
}


/* Vigenere's cipher

Encrypts the specified plaintext using the specified key. Allowed characters for the plaintext are (A-Z).

Returns NULL if:
1) plaintext is NULL
2) key is NULL
3) length of plaintext < length of key */
uint8_t *vigenere_encrypt(uint8_t *plaintext, uint8_t *key) {
    unsigned int i, plaintext_length, key_length;
    uint8_t *encrypted, *key_expanded;
    
    if (plaintext == NULL || key == NULL) {
        return NULL;
    }
    plaintext_length = getlength(plaintext);
    key_length = getlength(key);
    key_expanded = expand_key(key, key_length, plaintext_length);
    if (key_expanded == NULL) {
        return NULL;
    }
    encrypted = malloc((1 + plaintext_length) * sizeof(uint8_t));
    for (i = 0; i < plaintext_length; i++) {
        encrypted[i] = (key_expanded[i] + plaintext[i]) % 26 + 65;
    }
    encrypted[i] = '\0';
    free(key_expanded);
    return encrypted;
}


/* Vigenere's cipher

Decrypts the specified ciphertext using the specified key.

Returns NULL if:
1) plaintext is NULL
2) key is NULL
3) length of plaintext < length of key */
uint8_t *vigenere_decrypt(uint8_t *ciphertext, uint8_t *key) {
    unsigned int i, ciphertext_length, key_length;
    uint8_t *decrypted, *key_expanded;
    
    if (ciphertext == NULL || key == NULL) {
        return NULL;
    }
    ciphertext_length = getlength(ciphertext);
    key_length = getlength(key);
    key_expanded = expand_key(key, key_length, ciphertext_length);
    if (key_expanded == NULL) {
        return NULL;
    }
    decrypted = malloc((1 + ciphertext_length) * sizeof(uint8_t));
    for (i = 0; i < ciphertext_length; i++) {
        decrypted[i] = (ciphertext[i] - key_expanded[i] + 26) % 26 + 65;
    }
    decrypted[i] = '\0';
    free(key_expanded);
    return decrypted;
}
