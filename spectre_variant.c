#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#define DISTANCE 64 // 64bytes * 4SETs
#define INDICES 64 // 16 * 8WAY
/* Intel 32KB L1 cache consists of 8-way 64 sets, each has 64 bytes line */
#define WAY 8
#define SET 64
#define LINE 64 // bytes

/********************************************************************
Victim code.
********************************************************************/
//unsigned int array1_size = 16;
uint8_t array1[0xfd0] = { 
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16 // array1[15]
};
// array1[16] : time1
// array1[17] : time2
// array1[18] : i
// array1[19] : j
// array1[20] : junk
// array1[21] : addr
//uint8_t unused2[DISTANCE] = {0,};
uint8_t array2[WAY * SET * LINE] = {
//	//		0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
/*000*/   '\n', '\0',  'w',  'a',  'y',  ' ', '\0',  'i',  'n',  'd',  ' ', '\0',  ',',  ' ',  'a',  'd',
/*001*/	   'd',  'r',  ' ', '\0',  ',',  ' ',  't',  'i',  'm',  'e',  ' ', '\0',  ' ',  'h',  'i',  't',
/*002*/   '\n', '\0',  ' ',  'm',  'i',  's',  's', '\n', '\0',  'f',  'l',  'u',  's',  'h', '\n', '\0', 
/*003*/	   'p',  'r',  'i',  'm',  'e', '\n', '\0',  'p',  'r',  'o',  'b',  'e', '\n', '\0', '\0', '\0',
/*004*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
/*005*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
/*006*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
/*007*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',

/*010*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
/*011*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
/*012*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
/*013*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
/*014*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
/*015*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
/*016*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
/*017*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',

//*010*/	addr-	-	-	-	-	-	-	i	-	-	-	j	-	-	-
//*011*/	junk-	-	-	time1	-	-	time2	-	-	temp-	-	-	
//*012*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
//*013*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
//*014*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
//*015*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
//*016*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
//*017*/	  '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',

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


uint8_t unused3[DISTANCE] = {0,};

char * secret = "The Magic Words are Squeamish Ossifrage.";

//uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */


/********************************************************************
Analysis code
********************************************************************/

#define CACHE_HIT_THRESHOLD 80 /* assume cache hit if time <= threshold */
#define L1_CACHE_HIT_THRESHOLD 40 /* assume cache hit if time <= threshold */

int main (int argc, const char ** argv) {
	//volatile uint8_t *addr;
	//uint8_t j = 0;
	int i,j,k=0;
	uint8_t n = 0;
	int junk, time1,time2 = 0;
	
	printf("%s",&array2[0x29]);// flush\n
	for(array2[0x88] = 0 ; array2[0x88] < WAY ; array2[0x88]++){
		for(array2[0x8C] = 0 ; array2[0x8C] < INDICES ; array2[0x8C]++){
			_mm_clflush( & array2[(array2[0x88] * INDICES + array2[0x8C]) * DISTANCE]);
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}

	printf("%s",&array2[0x30]);// prime\n
	for(array2[0x88] = 0 ; array2[0x88] < 8 ; array2[0x88]++){
		printf("%s%02d", &array2[0x02], array2[0x88]);// way i
		printf("%s",&array2[0x00]); // \n
		for(array2[0x8C] = 0 ; array2[0x8C] < INDICES ; array2[0x8C]++){
			//addr = &array2[(i * INDICES + j) *  DISTANCE]; 
			((uint8_t**)array2)[0x10] = &array2[(array2[0x88] * INDICES + array2[0x8C]) *  DISTANCE];
			//printf("%p,%p\n",addr,((uint8_t**)array2)[0x10]);
			//printf("%p,%p\n",&array2[0x80],&((uint8_t**)array2)[0x10]);
			time1 = __rdtscp(&junk);
			junk &= * ((uint8_t**)array2)[0x10];
			time2 = __rdtscp(&junk) - time1;
			printf("%s%02d", &array2[0x07], array2[0x8C]); // ind j
			printf("%s%p", &array2[0x0C], ((uint8_t**)array2)[0x10]); // , address addr
			printf("%s%02d", &array2[0x14], time2); // , time time2
			printf("%s",&array2[0x00]); // \n
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}

	junk &= *(uint8_t*)(((unsigned long)array1 & ~0xFFF) + 0x940);
	//printf("%p\n",&junk);

	printf("%s",&array2[0x37]);// probe\n
	for(array2[0x88] = 0 ; array2[0x88] < WAY ; array2[0x88]++){
		printf("%s%02d", &array2[0x02], array2[0x88]);// way i
		printf("%s",&array2[0x00]); // \n
		for(array2[0x8C] = 0 ; array2[0x8C] < INDICES ; array2[0x8C]++){
			//addr = &array2[(i * INDICES + j) *  DISTANCE]; 
			((uint8_t**)array2)[0x10] = &array2[(array2[0x88] * INDICES + array2[0x8C]) *  DISTANCE];
			time1 = __rdtscp(&junk);
			junk = * ((uint8_t**)array2)[0x10];
			time2 = __rdtscp(&junk) - time1;
			printf("%s%02d", &array2[0x07], array2[0x8C]); // ind j
			printf("%s%p", &array2[0x0C], ((uint8_t**)array2)[0x10]); // , address addr
			printf("%s%02d", &array2[0x14], time2); // , time time2
			
			if(time2 > L1_CACHE_HIT_THRESHOLD) {
				printf("%s",&array2[0x22]);//  miss\n
			} else {
				printf("%s",&array2[0x1C]);//  hit\n
			}
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}

	printf("%p,%p,%p\n",&i,&j,&k);
	printf("%p,%p,%p\n",&junk,&time1,&time2);
}
