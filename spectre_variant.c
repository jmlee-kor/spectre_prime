#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#define DISTANCE 256 // 64bytes * 4SETs
#define INDICES 16 // 16 * 8WAY
/* Intel 32KB L1 cache consists of 8-way 64 sets, each has 64 bytes line */
#define WAY 8
#define SET 64
#define LINE 64 // bytes

/********************************************************************
Victim code.
********************************************************************/
//unsigned int array1_size = 16;
//uint8_t unused1[LINE];
//uint8_t array1[WAY * SET * LINE] = { /* L1 Cache Size */
//  1,
//  2,
//  3,
//  4,
//  5,
//  6,
//  7,
//  8,
//  9,
//  10,
//  11,
//  12,
//  13,
//  14,
//  15,
//  16 // array1[15]
//};
// array1[16] : time1
// array1[17] : time2
// array1[18] : i
// array1[19] : j
// array1[20] : junk
// array1[21] : addr
//uint8_t unused2[LINE];
uint8_t array2[WAY * SET * LINE] = {
//	//		0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
/*000*/   '\n', '\0',  'w',  'a',  'y',  ' ', '\0',  'i',  'n',  'd',  ' ', '\0',  ',',  ' ',  'a',  'd',
/*001*/	   'd',  'r',  ' ', '\0',  ',',  ' ',  't',  'i',  'm',  'e',  ' ', '\0',  ' ',  'h',  'i',  't',
/*002*/   '\0',  ' ',  'm',  'i',  's',  's', '\0'
/*003*/
/*004*/
/*005*/
/*006*/
/*007*/

/*010*/
/*011*/
/*012*/
/*013*/
/*014*/
/*015*/
/*016*/
/*017*/

/*020*/
/*021*/
/*022*/
/*023*/
/*024*/
/*025*/
/*026*/
/*027*/

/*030*/
/*031*/
/*032*/
/*033*/
/*034*/
/*035*/
/*036*/
/*037*/

/*040*/
/*041*/
/*042*/
/*043*/
/*044*/
/*045*/
/*046*/
/*047*/

/*050*/
/*051*/
/*052*/
/*053*/
/*054*/
/*055*/
/*056*/
/*057*/

/*060*/
/*061*/
/*062*/
/*063*/
/*064*/
/*065*/
/*066*/
/*067*/

/*070*/
/*071*/
/*072*/
/*073*/
/*074*/
/*075*/
/*076*/
/*077*/






};

char * secret = "The Magic Words are Squeamish Ossifrage.";

//uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */


/********************************************************************
Analysis code
********************************************************************/

#define CACHE_HIT_THRESHOLD 80 /* assume cache hit if time <= threshold */
#define L1_CACHE_HIT_THRESHOLD 40 /* assume cache hit if time <= threshold */

int main (int argc, const char ** argv) {
	volatile uint8_t *addr;
	uint8_t i,j = 0;
	int junk, time1,time2 = 0;
	
	//printf("flushing...\n");
	
	//flushing
	for(i = 0 ; i < WAY ; i++){
		for(j = 0 ; j < INDICES ; j++){
			_mm_clflush( & array2[(i * INDICES + j) * DISTANCE]);
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}

	//printf("prime\n");
	printf("%d",i);
	for(i = 0 ; i < 6 ; i++){
		printf("way %02d\n", i);
		for(j = 0 ; j < INDICES ; j++){
			addr = &array2[(i * INDICES + j) *  DISTANCE]; 
			time1 = __rdtscp(&junk);
			junk &= * addr;
			time2 = __rdtscp(&junk) - time1;
			printf("ind %02d, address %p, time is %d\n",
					j, 
					addr, 
					time2);
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}

	//printf("probe\n");

	for(i = 0 ; i < WAY ; i++){
		printf("way %02d\n", i);
		for(j = 0 ; j < INDICES ; j++){
			addr = &array2[(i * INDICES + j) *  DISTANCE]; 
			time1 = __rdtscp(&junk);
			junk = * addr;
			time2 = __rdtscp(&junk) - time1;
			printf("ind %02d, address %p, time is %d",
					j, 
					addr, 
					time2);
			if(time2 > L1_CACHE_HIT_THRESHOLD) {
				printf(" miss\n");
			} else {
				printf(" hit\n");
			}
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}
}
