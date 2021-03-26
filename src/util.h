/* A cipher algorithm library:
Caesar's, Spartan's, Vigenere's, One-time pad (OTP) */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <stdint.h>


/* Returns the length of msg */
unsigned int getlength(uint8_t *msg);

/* Prints the msg in hex format. The specified length is the
number of characters that should be printed */
void printmsg_hex(uint8_t *msg, unsigned int length);

/* Returns an integer that specifies the position of character c in the msg or -1
if c is not found */
unsigned int getposition(const uint8_t *msg, unsigned int c);

/* Pads the specified msg with # so that the total length of the new msg is scytale_length.
Returns NULL if scytale_length < msg_length */
uint8_t *padmsg(uint8_t *msg, unsigned int msg_length, unsigned int scytale_length);

/* Removes all padding from a msg that has been padded with # */
uint8_t *removepadding(uint8_t *msg);

/* Expands the key by padding it with itself until the new key has new_length characters.
Returns NULL if new_length < length */
uint8_t *expand_key(uint8_t *key, unsigned int length, unsigned int new_length);

/* Generates a random key of the specified length */
uint8_t *genkey(unsigned int length);

#endif
