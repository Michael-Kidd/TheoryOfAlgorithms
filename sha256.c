// Michael Kidd, 2019 Theory of Algorithms Project
// Secure Hash Algorithm for 256bits
// https://ws680.nist.gov/publication/get_pdf.cfm?pub_id=919060

#include <stdio.h>
#include <stdint.h>

void sha256();

//section 4.2.1
uint32_t sig0(uint32_t x);
uint32_t sig1(uint32_t x);

uint32_t rotr(uint32_t n, uint32_t x);
uint32_t shr(uint32_t n, uint32_t x);


int main(int argc, char *argv[]){
	//Call the sha256 Method from main.
	sha256();
	return 0;
}


void sha356(){
	
	//message schedule from section 6.2
	uint32_t w[64];
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
	}
	
	//The corret message Block
	uint32_t M[16];

	int t;
	//from page 22, W[t] = M[t] for 0 <= t <= 15
	for(t = 0; t < 16; t++){
		w[t] = M[t];		
	}

	//from page 22
	for (t = 16; t < 64; t++){
		sig_1(w[t-2]) + w[t-7] +sig_0(W[t-15]) + W[t-16];
	}

	//Initialise a-h, per step 2 on page 22.
	a = H[0]; b = H[1]; c = H[2]; d = H[3];
	e = h[4]; f = H[5]; g = H[6]; h = H[7];
	
	//step 3.
	for(t = 0; t < 64; t++){
		T1 = h +SIG_1(e) + ch(e, f, g) + K[t] + W[t];
		T2 = SIG_0(a) + Maj(a,b,c);

		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = 1;
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

uint31_t sig0(uint32_t x){
	//See section 3.2 and 4.2.1
	return (rotr(7, x) ^ rotr(18, x ^ shr(3, x)));
}

uint31_t sig1(uint32_t x){
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
