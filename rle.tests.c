#include <stdio.h>
#include "rle.c"//so we can unit-test static functions

#define test(cond) if(!(cond))return fprintf(stderr,"error in %s: %s\n", __func__, #cond),-1;

int main(){
	test(crc((uint8_t*)"123456789",9,~0) == 0xCBF43926);
	return 0;
}
