# Implementation of the SHA 256 Secure Hash Algorithm

## What is a Secure Hash Algorithm

--------------------------------------------------------------------------------

A secure hash algorithm or SHA is a set of cryptographic hash functions. The intention of using such an algorithm is to be able to encrypt data so that the resulting output would be complete indistinguishable from the original content and would be very difficult to determine the input even if you know the output.

The algorithm we will be using is the SHA256 algorithm, created by NSA. This is known as a keyless encryption method as it does not use any form of key to encrypt the data, which technically means it is not an encryption at all but a hashing function. This as mentioned above uses a one way compression format, meaning that it cannot be undone, or at the very least would be difficult to undo the algorithm output or convert back to the original input. Also it is possible to get the same output with different inputs.

With the SHA256 a message is processed by blocks of 512 = 16 × 32 bits, each block requiring 64 rounds.

### How my version of the program works

--------------------------------------------------------------------------------

When you run the program, you will run the following command

```
./sha256 <INSERT NAME OF FILE HERE>
```

This is the command to run the program itself but also to specify the file that you wish to hash. In my example I will use the Sha256.c file itself as a test like so:

```
./sha256 sha256.c
```

once you run this command you will be presented with two options

```
1\. Hash FILE
2\. Exit the program
```

The first option, if you select option 1 will show the resulting hash values for the file that you had specified. The second option will exit the program. Hashing the SHA256.c file above at the moment will show the following hash function.

```
E7F1F8B2 1B3E6D7E 6FA417FF 2ED75000 562B184C 47C6E358 F8C5C33A 3A792872
```

### Test cases

--------------------------------------------------------------------------------

### Resources

--------------------------------------------------------------------------------
