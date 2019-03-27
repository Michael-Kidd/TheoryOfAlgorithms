// Michael Kidd, 2019 Theory of Algorithms Project
// Secure Hash Algorithm for 256bits
// https://ws680.nist.gov/publication/get_pdf.cfm?pub_id=919060

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

union msgblock{
	uint8_t e[64];
	uint32_t t[16];
	uint64_t s[8];
};

void mainMenu(char *argv[]);
void sha256(FILE *f);

//section 4.2.1
uint32_t sig0(uint32_t x);
uint32_t sig1(uint32_t x);

uint32_t rotr(uint32_t n, uint32_t x);
uint32_t shr(uint32_t n, uint32_t x);

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);
uint32_t Ch(uint32_t x, uint32_t y, uint32_t z);

uint32_t SIG_0(uint32_t x);
uint32_t SIG_1(uint32_t x);

//flag for position within the file being read
enum status {READ, PAD0, PAD1, FINISH};

int nextmsgblock(FILE *file, union msgblock *M, enum status *S, int *nobits);

int main(int argc, char *argv[]){
	
	mainMenu(argv);
	
	return 0;
}

void mainMenu(char *argv[]){
	
	FILE *f;
	int input = 0;

	printf("\n1.\tFile\n");
	printf("2.\tMessage\n");
	printf("3.\tExit\n");
	printf("Choose an Option: ");
	scanf("%d", &input);
	
	switch(input){
	case 1:
		//open file given from console
		f = fopen(argv[1], "r");
		//Should error check
		//run the secure hash algorithm
		sha256(f);
		//close the file
		fclose(f);
		//start program code here
		mainMenu(argv);
		break;
	case 2:
		//Read in a message from console and Hash it.
		mainMenu(argv);
		break;
	case 3:
		//Exit the Program
		exit(1);
		break;
	default:
		printf("Invalid Selection\n");
		mainMenu(argv);
	}
}

void sha256(FILE *file){
	
	//The current message block
	union msgblock M;
	//number of bits read from file
	uint64_t nobits = 0;
	//status of the message blocks, in terms of padding
	enum status S = READ;

	// The K constants Defined in section 4.2.2
	uint32_t K[] = {
		0x42802f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};
	
	//message schedule from section 6.2
	uint32_t W[64];
	//working variables from section 6.2
	uint32_t a, b, c, d, e, f, g, h;
	//Two temp variables from section 6.2
	uint32_t T1, T2;
	
	//Hash Value from section 6.2
	//values come from section 5.3.3
	uint32_t H[8]= {
		  0x6a09e667
		, 0xbb67ae85
		, 0x3c6ef372
		, 0xa54ff53a
		, 0x510e527f
		, 0x1f83d9ab
		, 0x5be0cd19
	};

	int t;

	while (nextmsgblock(file, *M, *S, *nobits)){
	
		//from page 22, W[t] = M[t] for 0 <= t <= 15
		for(t = 0; t < 16; t++){
			W[t] = M.t[t];		
		}

		//from page 22
		for (t = 16; t < 64; t++){
			sig1(W[t-2]) + W[t-7] +sig0(W[t-15]) + W[t-16];
		}

		//Initialise a-h, per step 2 on page 22.
		a = H[0]; b = H[1]; c = H[2]; d = H[3];
		e = H[4]; f = H[5]; g = H[6]; h = H[7];
	
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
		H[1] = b + H[2];
		H[2] = c + H[3];
		H[3] = d + H[4];
		H[4] = e + H[5];
		H[5] = f + H[6];
		H[6] = g + H[7];
		H[7] = h + H[8];
	}
}

int nextmsgblock(FILE *f, union msgblock *M, enum status *S, int *nobits){

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
	nobytes = fread(M->e, 1, 64, f);
	//Keep track of the number of bytes we have read
	nobits += (nobytes * 8);
	//If we read less than 56 bytes, we can put all padding in this block
	if(nobytes < 56){
		M->e[nobytes] = 0x80;
		//get the last 8 bytes
		while(nobytes < 56){
			nobytes += 1;
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
	} else if(feof(f)){
		//tell S that we need a message block with all the padding.
		*S = PAD1;
	}
	
	//if we get this far, then we will return 1, so that the function will be called again
	return 1;
}

uint32_t sig0(uint32_t x){
	//See section 3.2 and 4.2.1
	return (rotr(7, x) ^ rotr(18, x ^ shr(3, x)));
}

uint32_t sig1(uint32_t x){
	//see section 3.2 and 4.1.2
	return (rotr(17, x) ^ rotr(19, x) ^ shr(10, x));
}

//rotate to the right
uint32_t rotr(uint32_t n, uint32_t x){
	return (x >> n) | (x << (32 - n));
}

//Shift to the right
uint32_t shr(uint32_t n, uint32_t x){	
	return (x << n);
}

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z){
	return (x & y) ^ ((!x) & z);
}

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z){	 
	return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t SIG_0(uint32_t x){
	return(rotr(2, x) ^ rotr(13, x) ^ rotr(22, x));
}

uint32_t SIG_1(uint32_t x){
	return(rotr(6, x) ^ rotr(11, x) ^ rotr(25, x));
}
