#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#define DIST_BIT 8
#define DIST 256 // 64 * 4 for preventing prefetching
#define INDICES 16 // 16 * ways
#define WAY 8
#define LINE 64
#define SET 64 

#define TRYTIMES 1

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
//uint8_t unused1[64];
uint8_t array0[0xfa0] = {
  0x0,
  0x1,
  0x2,
  0x3,
  0x4,
  0x5,
  0x6,
  0x7,
  0x8,
  0x9,
  0xa,
  0xb,
  0xc,
  0xd,
  0xe,
  0xf
};

uint8_t array1[0xfe0] = {
  0x00,
  0x10,
  0x20,
  0x30,
  0x40,
  0x50,
  0x60,
  0x70,
  0x80,
  0x90,
  0xa0,
  0xb0,
  0xc0,
  0xd0,
  0xe0,
  0xf0
};
//uint8_t unused2[64];
uint8_t array2[WAY * SET * LINE]; // for prime
uint8_t array3[WAY * SET * LINE]; // for eviction
uint8_t array4[WAY * SET * LINE]; // for 2nd eviction
//uint8_t unused3[64];

char * secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */


/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD 80 /* assume cache hit if time <= threshold */
#define L1_CACHE_HIT_THRESHOLD 40 // for L1 Cache hit //

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte() {
  int tries, i = 0;
  int j = 0;

  for (tries = TRYTIMES; tries > 0; tries--) {
    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < WAY; i++){
	    for (j = 0; j < INDICES ; j++) {
        _mm_clflush( & array2[(i * INDICES + j) * DIST]); /* intrinsic for clflush instruction */
        _mm_clflush( & array3[(i * INDICES + j) * DIST]); /* intrinsic for clflush instruction */
        _mm_clflush( & array4[(i * INDICES + j) * DIST]); /* intrinsic for clflush instruction */
	    }
	  }

    j = 5;
	
	  for( i = 0; i < WAY; i++) {
		  // for( j = 0; j < INDICES; j++) {
        printf("array2 addr : %p\n",&array2[(i * INDICES + j) * DIST]);
        temp&= array2[(i * INDICES + j) * DIST];
		  // }
	  }

    for (i = 0; i < WAY; i++) {
      // for ( j = 0; j < INDICES ; j++) {
        array3[(i * INDICES + j) * DIST] = i * INDICES + j;
        printf("array3 addr : %p\n",&array3[(i * INDICES + j) * DIST]);
      // }
    }

    for (i = 0; i < WAY; i++) {
      // for ( j = 0; j < INDICES ; j++) {
		  	temp&= array4[(i * INDICES + j) * DIST];
        printf("array4 addr : %p\n",&array4[(i * INDICES + j) * DIST]);
      // }
    }
  }
}

int main(int argc,
  const char * * argv) {
  
  printf("addr : %p, %p, %p\n",array2, array3, array4);
  int cnt = 0;
  while (cnt < 1) {
    readMemoryByte();
    cnt++;
  }
  return (0);
}
