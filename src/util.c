/* A cipher algorithm library:
Caesar's, Spartan's, Vigenere's, One-time pad (OTP) */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>


/* Returns the length of msg */
int getlength(uint8_t *msg) {
    uint8_t *ptr = msg;
    
    while (*ptr) {
        ptr++;
    }
    return ptr - msg;
}

/* Prints the msg in hex format. The specified length is the
number of characters that should be printed */
void printmsg_hex(uint8_t *msg, unsigned int length) {
    unsigned int i;
    
    for (i = 0; i < length; i++) {
        printf("%x ", msg[i]);
    }
    printf("\n");
}

/* Returns an integer that specifies the position of character c in the msg or -1
if c is not found */
int getposition(uint8_t *msg, unsigned int c) {
    uint8_t *ptr = msg;
    
    while(*ptr) {
        if (c == *ptr) {
            return ptr - msg;
        }
        ptr++;
    }
    if (*ptr == '\0') {
        return -1;
    }

    return ptr - msg;
}

/* Pads the specified msg with # so that the total length of the new msg is scytale_length.
Returns NULL if scytale_length < msg_length */
uint8_t *padmsg(uint8_t *msg, unsigned int msg_length, unsigned int scytale_length) {
    uint8_t *padded;
    int i;

    if (msg_length > scytale_length) {
        return NULL;
    }
    padded = malloc((1 + scytale_length) * sizeof(uint8_t));
    for (i = 0; i < msg_length; i++) {
        padded[i] = msg[i];
    }
    for(i = msg_length; i < scytale_length; i++) {
        padded[i] = '#';
    }
    padded[i] = '\0';
    return padded;
}

/* Removes all padding from a msg that has been padded with # */
uint8_t *removepadding(uint8_t *msg) {
    uint8_t *nopadded;
    int msg_length, i;
    
    for (i = 0; msg[i] != '\0' && msg[i] != '#'; i++);
    msg_length = i;

    nopadded = malloc((1 + msg_length) * sizeof(uint8_t));
    for (i = 0; i < msg_length; i++) {
        nopadded[i] = msg[i];
    }
    nopadded[i] = '\0';
    return nopadded;
}

/* Expands the key by padding it with itself until the new key has new_length characters.
Returns NULL if new_length < length */
uint8_t *expand_key(uint8_t *key, unsigned int length, unsigned int new_length) {
    uint8_t *expanded_key;
    int i;

    if (new_length < length) {
        return NULL;
    }
    expanded_key = malloc((1 + new_length) * sizeof(uint8_t));
    for (i = 0; i < new_length; i++) {
        expanded_key[i] = key[i % length];
    }
    expanded_key[i] = '\0';
    return expanded_key;
}

/* Generates a random key of the specified length */
uint8_t *genkey(unsigned int length) {
    uint8_t *key;
    int fd;
    unsigned int key_length; 
    key = malloc((1 + length) * sizeof(uint8_t));
    fd = open("/dev/urandom", O_RDONLY);
    while(1) {
        key_length = read(fd, key, length);
        if (key_length == length) {
            break;
        }
    }
    close(fd);
    key[length] = '\0';
    return key;
}
