# Cipher algorithms

A library of 4 simple cipher algorithms:

* Caesar's cipher
* Spartan's cipher
* Vigenere's cipher
* One-time pad (OTP) cipher

## Profiling

The program has been tested for memory leaks with [valgrind](https://valgrind.org/) and [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer).

## Compile

Build the library:

```bash
make crypto.o
```

## Tests

Using the library is demonstrated in [main.c](src/main.c)

Build:

```bash
make crypto
```

Run:

```bash
./crypto
```
