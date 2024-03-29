# Cipher algorithms

A library of 4 simple cipher algorithms:

* Caesar's cipher
* Spartan's cipher
* Vigenere's cipher
* One-time pad (OTP) cipher

## Compile

Build the library:

```bash
make crypto.o
```

## Demo

Using the library is demonstrated in [main.c](src/main.c)

Build:

```bash
make crypto_demo
```

Run:

```bash
./crypto_demo
```

## Profiling

'crypto_demo' has been tested for memory leaks with [valgrind](https://valgrind.org/) and [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer).
