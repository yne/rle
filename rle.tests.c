#include <stdio.h>
#define TESTING
#include "rle.c"//so we can unit-test static functions

#define test(cond) if(!(cond))return fprintf(stderr,"error in %s: %s\n", __func__, #cond),-1;

int main(){
	rle_init();
	test(crc((uint8_t*)"123456789",9,~0) == 0xCBF43926);
	test(proto_list[0x00] == 0x0000);
	test(proto_list[0x42] == 0x0082);
	test(proto_list[0xFF] == 0xFFFF);
	return 0;
}
