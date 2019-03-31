# Implementation of the SHA 256 Secure Hash Algorithm

## What is a Secure Hash Algorithm

--------------------------------------------------------------------------------

A secure hash algorithm or SHA is a set of cryptographic hash functions. The intention of using such an algorithm is to be able to encrypt data so that the resulting output would be complete indistinguishable from the original content and would be very difficult to determine the input even if you know the output.

The algorithm we will be using is the SHA256 algorithm, created by NSA. This is known as a keyless encryption method as it does not use any form of key to encrypt the data, which technically means it is not an encryption at all but a hashing function. This as mentioned above uses a one way compression format, meaning that it cannot be undone, or at the very least would be difficult to undo the algorithm output or convert back to the original input. Also it is possible to get the same output with different inputs.

With the SHA256 a message is processed by blocks of 512 = 16 × 32 bits, each block requiring 64 rounds.

### How my version of the program works

--------------------------------------------------------------------------------

When you run the program, you will run the following command

```bash
./sha256 <INSERT NAME OF FILE HERE>
```

This is the command to run the program itself but also to specify the file that you wish to hash. In my example I will use the Sha256.c file itself as a test like so:

```bash
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

Firstly we need to read in a file from the terminal as the user executes the program, in C this is passed as a parameter to the main method call as follows

```c
int main (int argc, char *argv[]){

  //HERE we call our methods and run the program while passing argv[]

  return 0;
}
```

argv[] in this content passes a pointer to a string which represents the title of our file. Now that we have the name of the file we must read it in.

```c
//Declare the file
FILE * fi;
//Open the file to be read
fi = fopen(argv[1], "r");

//HERE WE RUN THE CODE NEEDED TO HASH THE FILE

//to close the file when it has all been completed.
fclose(fi);
```

when using the Sha256 algorithm we have certain values that start are defined before the code is running, these have been labeled as H and K, these store an array of hash values H are the initial Hash values used and at the start of the program should be reset. K is a constant value and should not change. these represent the first 32-bits of the fractional parts of the cube roots of the first 64 primes. These are required by the Secure hash standard.

```c
//Hash Value from section 6.2
//values come from section 5.3.3
static uint32_t H[8]= {
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19
};

// The K constants Defined in section 4.2.2
static uint32_t K[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
```

I originally was passing these variables to the functions but then changed to make these fields static as to allow them access from a class level, Malloc could have been another option here or have the Sha256 function return the array, but this method seemed more straight forward. I have tested the same test files in order to make sure that the output hasn't been changed by doing this. I also tested it against two other students code to ensure the same result.

When we call the Hashing function we will need a message block so that we can pad the file when needed.

```c

//the message block union
union msgblock{
  uint8_t e [64];
  uint32_t t [16];
  uint64_t s [8]
};

//The declaration of the message block
union msgblock M;
```

Now we need some variables, we need an unsigned to store the number of bits. We will also need an enum to store the state of the padding. We need a message Schedule. We store the message schedule as an array of 64 indices. We need some working variables labeled as a-h, and two temp variables.

```c
uint64_t nobits = 0;
//status of the message blocks, in terms of padding
enum status S = READ;
//message schedule from section 6.2
uint32_t W[64];
//working variables from section 6.2
uint32_t a, b, c, d, e, f, g, h;
//Two temp variables from section 6.2
uint32_t T1, T2;
```

### Resources

--------------------------------------------------------------------------------

<https://crypto.stackexchange.com/questions/41496/how-to-generate-the-sha-2-constants>
