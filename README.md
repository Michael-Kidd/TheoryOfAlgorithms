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
781347F5 FA1A26A5 A095F493 665683CB 48699A34 E329F6DD FD1AE4D0 82410157
```

This is the same result that two other student had at this point in the code and have not yet accounted for endianness, by the time I had tried multiple ways to account for this, I had failed to get the correct hash returned, I used some online calculators to test the expected result and they all had the same result, I can only assume that they are correct and that my code is flawed. I could submit the code that I had changed that was still incorrect but as other students have the same result that I have at this point, This tells me that I may not have the right code now, but I am more correct than I was after altering the code. So this would be a good baseline to go back to later.

The reason that the code is not working is an issue with little endian vs big endian values, after trying to account for this, it felt like I was getting further and further from a correct result so reverted.

This is not the correct result and shows an incorrect hash value at the moment, this is partially due to not checking if the bit values have been converted to Big Endian yet. This is to show an example of an incorrect hash value. If we run this same file content through an online version of SHA256 we get:

```
552bab68 64c7a7b6 9a502ed1 854b9245 c0e1a30f 008aaa0b 281da625 85fdb025
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

Next we need a loop that will loop through the msgblocks, the purpose of doing this is to pad the message so that it is 512 bits long. That is 448 before padding. This always done, even if the message is already 448 bits.

> "The input message is "padded" (extended) so that its length (in bits) equals to 448 mod 512\. Padding is always performed, even if the length of the message is already 448 mod 512\. Padding is performed as follows: a single "1" bit is appended to the message, and then "0" bits are appended so that the length in bits of the padded message becomes congruent to 448 mod 512\. At least one bit and at most 512 bits are appended. A 64-bit representation of the length of the message is appended to the result of step1\. If the length of the message is greater than 2^64, only the low-order 64 bits will be used. The resulting message (after padding with bits and with b) has a length that is an exact multiple of 512 bits. The input message will have a length that is an exact multiple of 16 (32-bit) words."

To pad 1 bit is added on as a flag, then the remaining bits are added as 0.

```c
while (nextmsgblock(fi, &M, &S, &nobits)){

  //from page 22, W[t] = M[t] for 0 <= t <= 15

  //Go through the first 16 bytes
  for(t = 0; t < 16; t++){
    W[t] = M.t[t];        
  }

  //Go through the remianing 48 bytes
  for (t = 16; t < 64; t++){
    W[t] = sig1(W[t-2]) + W[t-7] +sig0(W[t-15]) + W[t-16];
  }

  //Initialise a-h, per step 2 on page 22.
  a = H[0];
  b = H[1];
  c = H[2];
  d = H[3];
  e = H[4];
  f = H[5];
  g = H[6];
  h = H[7];

  //step 3.
  for(t = 0; t < 64; t++){
    T1 = h +SIG_1(e) + Ch(e, f, g) + K[t] + W[t];
    T2 = SIG_0(a) + Maj(a,b,c);

    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }    

  //step 4
  H[0] = a + H[0];
  H[1] = b + H[1];
  H[2] = c + H[2];
  H[3] = d + H[3];
  H[4] = e + H[4];
  H[5] = f + H[5];
  H[6] = g + H[6];
  H[7] = h + H[7];
}
```

With the padding of the message block, we check if the Status we set in the enum earlier is read as finished, this would indicate that the entire file is finished and has been padded, so the loop can end.

When ever padding occurs, the first step is to add 1 bit then pad the remaining bits as 0\. it will then test if another full block of padding is needed, if it is needed it will set the first 56 bytes to 0 bits. it will then set the remaining 64 bits to the number of bits in the file, then will end the loop.

the code is as follows.

```c
//Number of bytes we get from file
    uint64_t nobytes;

    int i;

    //if all messages blocks done
    if (*S == FINISH)
        return 0;

    //Check if we need another block of full padding
    if(*S == PAD0 || *S == PAD1){
        //set the first 56 bytes to zero bits
        for(i = 0; i < 56; i++){
            M->e[i] = 0x00;
        }
        //set the last 64 bits to the number of the bits in the file, - Big endian
        M->s[7] = *nobits;
        //tell the status we are finished
        *S = FINISH;

        //Set the first bit of M to 1
        if (*S == PAD1){
            M->e[0] = 0x80;
        }
        //Keep the loop going for another iteration
        return 1;
    }

    //if we get down here, then we still havent finished reading the file
    nobytes = fread(M->e, 1, 64, fi);

    //Keep track of the number of bytes we have read
    *nobits = *nobits + (nobytes * 8);
    //If we read less than 56 bytes, we can put all padding in this block
    if(nobytes < 56){
        M->e[nobytes] = 0x80;
        //get the last 8 bytes
        while(nobytes < 56){
            nobytes = nobytes + 1;
            //set all bytes to 0
            M->e[nobytes] = 0x00;
        }
        //Append the file size in bits as a (big endian) unsigned 64 bit int
        M->s[7] = *nobits;
        *S = FINISH;
    }
    //otherwise, check if we can put some padding in this block
    else if (nobytes < 64){
        //tell S we need one more message block with padding but wont have the 1 bit.
        *S = PAD0;
        //put the one bit in this block
        M->e[nobytes]  = 0x80;
        //pad the rest of the block with zero bits    
        while(nobytes < 64){
            nobytes = nobytes +1;
            M->e[nobytes] = 0x00;
        }
    //otherwise check if we are at the end of the file    
    } else if(feof(fi)){
        //tell S that we need a message block with all the padding.
        *S = PAD1;
    }

    //if we get this far, then we will return 1, so that the function will be called again
return 1;
```

one of the main issues that I found with troubleshooting this program is simply because the hash method works so well and that it is difficult to revert, that I cannot tell if my code is closer or further away from being correct. This is because any single change in the message has a dramatic change with the resulting hash that is returned.

Below is a video of the program running and a few simple examples of online tests<br>

[![Video of running program](https://theaudacitytopodcast.b-cdn.net/wp-content/uploads/2014/08/YouTube-logo-full_color-300x300.jpg)](https://youtu.be/RHfaocmBH_g)

### Resources

--------------------------------------------------------------------------------

<https://crypto.stackexchange.com/questions/41496/how-to-generate-the-sha-2-constants><br>
<https://ws680.nist.gov/publication/get_pdf.cfm?pub_id=919060><br>
<https://crypto.stackexchange.com/questions/9369/how-is-input-message-for-sha-2-padded> <https://www.webopedia.com/TERM/B/big_endian.html><br>
<https://betterexplained.com/articles/understanding-big-and-little-endian-byte-order/><br>
<https://stackoverflow.com/questions/19275955/convert-little-endian-to-big-endian/19276193><br>

#### Sha256 testers

<https://emn178.github.io/online-tools/sha256_checksum.html><br>
<https://passwordsgenerator.net/sha256-hash-generator/>
