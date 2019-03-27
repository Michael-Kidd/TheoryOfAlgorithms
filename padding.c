// Michael Kidd, 2019 Theory of Algorithms Project
// Secure Hash Algorithm for 256bits
// https://ws680.nist.gov/publication/get_pdf.cfm?pub_id=919060

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void readFile(char *argv[]);

union msgblock{
	uint8_t 	e[64];
	uint32_t 	t[16];
	uint64_t 	s[8];
};

void readFile(char *argv[]){
	FILE* f;
	
	union msgblock M;

	uint64_t nobytes;
	uint64_t nobits = 0;

	// read in a file, taken from the input when the program is run.
	f = fopen(argv[1], "r");

	// while we have not reached the end of the file
	while ( !feof(f) ){

		nobytes = fread(M.e, 1, 64, f);
		nobits += (nobytes * 8);
	
		if(nobytes < 56){
			//make the right most bit a 1 and zero the rest
			//adding 1
			M.e[nobytes] = 0x80;

			//get the last 8 bytes
			while(nobytes < 56){
				nobytes += 1;
				//set all bytes to 0
				M.e[nobytes] = 0x00;
			}

			//set the last block of s as the value of nobits
			M.s[7] = nobits;


		}

		printf("%llu\n", nobytes);
	}
	
	//close the file reader
	fclose(f);
}