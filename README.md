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
./sha256 test.txt
```

once you run this command you will be presented with a screen similar to this:

```
File Content
--------------------------
abc
--------------------------
Hash Value
--------------------------
7D55ECC0 23DEF8DC 90DB199 CCF368A0 F2F66788 F13217EB BA407DF1 29af21cb
```

This is not the correct result and shows an incorrect hash value at the moment, this is partially due to not checking if the bit values have been converted to Big Endian yet. This is to show an example of an incorrect hash value. If we run this same file content through an online version of SHA256 we get:

```
552bab68 64c7a7b6 9a502ed1 854b9245 c0e1a30f 008aaa0b 281da625 85fdb025
```

After making sure the information is converted to big endian

```
Code Here
```

### How the Code works

--------------------------------------------------------------------------------

### Resources

--------------------------------------------------------------------------------
