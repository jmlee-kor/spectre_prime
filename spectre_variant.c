#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#define DISTANCE 256
/* Intel 32KB L1 cache consists of 8-way 64 sets, each has 64 bytes line */
#define WAY 8
#define SET 64
#define LINE 64 // bytes

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[63];
uint8_t array1[WAY * SET * LINE] = { /* L1 Cache Size */
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
uint8_t unused2[32];
uint8_t array2[WAY * SET * LINE];

char * secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */


/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD 80 /* assume cache hit if time <= threshold */


int flush_prototype(){
	volatile uint8_t *addr;
	int i,j,junk, time1,time2 = 0;
	for(i = 0 ; i < WAY ; i++){
		for(j = 0 ; j < SET ; j++){
			_mm_clflush( & array1[(i * SET + j) * LINE]);
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}
	return junk;

}

int prime_prototype() {
	volatile uint8_t *addr;
	int i,j,junk, time1,time2 = 0;
	for(i = 0 ; i < WAY ; i++){
		printf("way %02d\n", i);
		for(j = 0 ; j < SET ; j++){
			addr = &array1[(i * SET + j) *  LINE]; 
			//time1 = __rdtscp(&junk);
			junk += * addr;
			//time2 = __rdtscp(&junk) - time1;
			//printf("set %02d, address %p, time is %d\n",
			//		j, 
			//		addr, 
			//		time2);
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}
	return junk;
}

int probe_prototype() {
	volatile uint8_t *addr;
	int i,j,junk, time1,time2 = 0;
	for(i = 0 ; i < WAY ; i++){
		printf("way %02d\n", i);
		for(j = 0 ; j < SET ; j++){
			addr = &array1[(i * SET + j) *  LINE]; 
			time1 = __rdtscp(&junk);
			junk = * addr;
			time2 = __rdtscp(&junk) - time1;
			printf("set %02d, address %p, time is %d\n",
					j, 
					addr, 
					time2);
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}
	return junk;
}

int main (int argc, const char ** argv) {
	volatile uint8_t *addr;
	int i,j,junk, time1,time2 = 0;
	
	printf("flushing...\n");
	
	//flushing
	for(i = 0 ; i < WAY ; i++){
		for(j = 0 ; j < SET ; j++){
			_mm_clflush( & array2[(i * SET + j) * LINE]);
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}

	printf("prime\n");

	for(i = 0 ; i < 3 ; i++){
		printf("way %02d\n", i);
		for(j = 0 ; j < 2 ; j++){
			addr = &array2[(i * SET + j) *  LINE]; 
			time1 = __rdtscp(&junk);
			junk &= * addr;
			time2 = __rdtscp(&junk) - time1;
			printf("set %02d, address %p, time is %d\n",
					j, 
					addr, 
					time2);
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}

	printf("probe\n");

	for(i = 0 ; i < SET-32 ; i++){
		printf("set %02d\n", i);
		for(j = 0 ; j < WAY-4 ; j++){
			addr = &array2[(j * SET + i) *  LINE-32]; 
			time1 = __rdtscp(&junk);
			junk = * addr;
			time2 = __rdtscp(&junk) - time1;
			printf("way %02d, address %p, time is %d\n",
					j, 
					addr, 
					time2);
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}
}
