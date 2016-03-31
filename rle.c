#include <string.h>
#include "rle.h"

/**
PPDUs prefix each "fragments" of the ALPDU
There is 4 kinds of PPDU:
-  Full PPDU: Only For when the PPDU is big enought to contain the whole ALPDU
- Start PPDU: First PPDU before a series of [0,4096] "Cont" PPDUs and a Final "End" PPDU
-  Cont PPDU:
-   End PPDU:
```
**/
uint16_t proto_list[0x100];
uint8_t proto_list_rev[0x10000];

/* Common function/macro */

uint32_t swap(uint32_t data, size_t nBits){
	uint32_t res = 0;
	for (size_t bit = 0; bit < nBits; ++bit){
		if (data & 1)
			res |= (1 << ((nBits - 1) - bit));
		data >>= 1;
	}
	return res;
}

uint32_t crc_tab[256];
uint32_t crc(uint8_t*buffer, int size, uint32_t accu){
	for (int byte = 0; byte < size; ++byte)
		accu = crc_tab[swap(buffer[byte], 8) ^ (accu >> 24)] ^ (accu << 8);
	return swap(accu, 32) ^ 0xFFFFFFFF;
}

#define APPEND(buf,elem,elem_len) memcpy((void*)((uint8_t*)buf)+(buf##_length), (void*)(elem), elem_len)
#define MIN(A, B) ((A)<(B)?(A):(B))
int rle_init(){
	for (int i = 0; i < 256; ++i){
		crc_tab[i] = i << 24;
		for (int bit = 8; bit > 0; --bit)
			crc_tab[i] = (crc_tab[i] << 1) ^ ((crc_tab[i] & (1 << 31)) ? 0x04C11DB7 : 0);
	}

	memset(proto_list,~0,sizeof(proto_list));
	proto_list[0x00]=0x0000;
	proto_list[0x01]=0x0001;
	proto_list[0x02]=0x0002;
	proto_list[0x03]=0x0003;
	proto_list[0x04]=0x00C8;
	proto_list[0x05]=0x0100;
	proto_list[0x0D]=0x0800;
	proto_list[0x11]=0x86DD;
	proto_list[0x42]=0x0082;

	memset(proto_list_rev,~0,sizeof(proto_list));
	proto_list_rev[0x0000]=0x00;
	proto_list_rev[0x0001]=0x01;
	proto_list_rev[0x0002]=0x02;
	proto_list_rev[0x0003]=0x03;
	proto_list_rev[0x00C8]=0x04;
	proto_list_rev[0x0082]=0x42;
	proto_list_rev[0x0100]=0x05;
	proto_list_rev[0x0800]=0x0D;
	proto_list_rev[0x86DD]=0x11;

}
int rle_encap(rle_profile*profile, size_t sdu_len, uint8_t*sdu, uint16_t protocol_type, rle_fpdu*fpdu){
	// See table 5.1
	uint8_t label[16];
	if(profile->ptype_suppress && (protocol_type != profile->ptype_default)){
		APPEND(fpdu->alpdu_header, label, profile->alpdu_label_size);
	}else if(profile->ptype_compress){
		APPEND(fpdu->alpdu_header, &proto_list_rev[protocol_type], 1);
		APPEND(fpdu->alpdu_header, label, profile->alpdu_label_size);
		if(proto_list_rev[protocol_type]==0xFF)
			APPEND(fpdu->alpdu_header, &protocol_type, 2);
	}else{
		APPEND(fpdu->alpdu_header, &protocol_type, 2);
		APPEND(fpdu->alpdu_header, label, profile->alpdu_label_size);
	}

	//content
	size_t remaining = sdu_len + fpdu->alpdu_footer_length;
	//for(size_t remaining = sdu_len + fpdu->alpdu_footer_length;remaining;remaining-=fpdu->ppdu[fpdu->ppdu_len-1].length)
	{
		fpdu->ppdu[fpdu->ppdu_count++] = (rle_ppdu){
			start:fpdu->ppdu_count==0,
			end:1+remaining+fpdu->alpdu_footer_length<profile->alpdu_label_size,
			length:MIN(remaining+fpdu->alpdu_footer_length,profile->alpdu_label_size),
		};
	}
	//footer
	bool fragmented_alpdu = sdu_len + fpdu->alpdu_footer_length > RLE_MAX_ALPDU;

	if (fragmented_alpdu) {
		if (profile->alpdu_crc) {
			//compute CRC (label+ext_header+sdu)
			uint8_t label[15] = {};
			uint8_t ext_header[15] = {};
			uint32_t accu = 0xFFFFFFFF;
			accu = crc(label, profile->alpdu_label_size, accu);
			accu = crc(ext_header, 15, accu);
			accu = crc(sdu, sdu_len, accu);
			*(uint32_t*)(fpdu->alpdu_footer) = accu;
			APPEND(fpdu->alpdu_footer, &accu, 4);
		}else{
			uint8_t seq = 0;
			APPEND(fpdu->alpdu_footer, &seq, 1);
		}
	}
	/////////5.2 : PPDU
	//start_indicator:1
	//end_indicator:1
	//ppdu_length:11
	//if (start_indicator && end_indicator) {
	//	alpdu_label_type 2
	//	protocol_type_suppressed 1
	//}else{
	//	fragment_id 3
	//}
	//ppdu_label : X
	//if (start_indicator = 1 and end_indicator = 0) {
	//	if (large_alpdus)
	//	total_length 13
	//}else{
	//	use_alpdu_crc 1
	//	total_length 12
	//}
	//alpdu_label_type 2
	//protocol_type_suppressed 1
	//alpdu : X

	////////////5.3 : FPDU
	/*
	if (use_explicit_payload_header_map = 1) {
		payload_label_length 4
		ppdu_label_length 4
	}
	payload_label : N
	ppdus : X*Y
	padding_byte X

	if (use_frame_protection) 
		protection

	padding_bit N
	*/
	return 0;
}
