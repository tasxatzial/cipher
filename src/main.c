/* Test file for all 4 ciphers:
Caesar's, Spartan's, Vigenere's, One-time pad (OTP) */

#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"
#include "util.h"

/* Demo of the OTP cipher functions */
static void test_otp() {
    uint8_t plaintext[] = "HelloWorld";
    uint8_t *key, *encrypted, *decrypted;
    unsigned int plaintext_length;

    printf("OTP text: %s\n", plaintext);
    plaintext_length = getlength(plaintext);
    key = genkey(plaintext_length);

    encrypted = otp_encrypt(plaintext, key);
    printf("OTP encrypted: ");
    printmsg_hex(encrypted, plaintext_length);

    decrypted = otp_decrypt(encrypted, key);
    printf("OTP decrypted: %s\n", decrypted);

    free(key);
    free(encrypted);
    free(decrypted);
}

/* Demo of the Caesar cipher functions */
static void test_caesar() {
    uint8_t plaintext[] = "hello";
    uint8_t *encrypted, *decrypted;

    printf("Caesar text: %s\n", plaintext);
    encrypted = caesar_encrypt(plaintext, 4);
    printf("Caesar encrypted: %s\n", encrypted);

    decrypted = caesar_decrypt(encrypted, 4);
    printf("Caesar decrypted: %s\n", decrypted);

    free(encrypted);
    free(decrypted);
}

/* Demo of the Spartan cipher functions */
static void test_spartan() {
    uint8_t plaintext[] = "iamhurtverybadlyhelp";
    uint8_t *encrypted, *decrypted;
    unsigned short circ = 5;
    unsigned short len = 5;

    printf("Spartan text: %s\n", plaintext);

    encrypted = spartan_encrypt(plaintext, circ, len);
    if (encrypted == NULL) {
        printf("Unable to encrypt\n");
        return;
    }
    else {
        printf("Spartan encrypted: %s\n", encrypted);
    }

    decrypted = spartan_decrypt(encrypted, circ, len);
    if (decrypted == NULL) {
        printf("Unable to decrypt\n");
        free(encrypted);
        return;
    }
    else {
        printf("Spartan decrypted: %s\n", decrypted);
    }

    free(encrypted);
    free(decrypted);
}

/* Demo of the Vigenere cipher functions */
static void test_vigenere() {
    uint8_t plaintext[] = "ATTACKATDAWN";
    uint8_t key[] = "LEMON";
    uint8_t *encrypted, *decrypted;

    printf("Vigenere text: %s\n", plaintext);

    encrypted = vigenere_encrypt(plaintext, key);
    if (encrypted == NULL) {
        printf("Unable to encrypt\n");
        return;
    }
    else {
        printf("Vigenere encrypted: %s\n", encrypted);
    }

    decrypted = vigenere_decrypt(encrypted, key);
    if (decrypted == NULL) {
        printf("Unable to decrypt\n");
        free(encrypted);
        return;
    }
    else {
        printf("Vigenere decrypted: %s\n", decrypted);
    }
    
    free(encrypted);
    free(decrypted);
}

int main(int argc, char **argv) {
    test_otp();
    test_caesar();
    test_spartan();
    test_vigenere();
    return 0;
}
