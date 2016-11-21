#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rle.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define CEIL(a,b) ((a+b-1)/b)
#define DUMP(DATA,LEN) {printf("< ");int i;for(i=0;i<LEN;i++)printf("%02X ",DATA[i]);printf(">\n");}
#define mempush(dst,src,size) memcpy(dst,src,size);dst+=size;

uint32_t crc_tab[256];

void crc_init(){
	for(int i = 0; i < 256; i++){
		crc_tab[i] = i << 24;
		for (int bit = 8; bit > 0; bit--)
			crc_tab[i] = (crc_tab[i] << 1) ^ ((crc_tab[i] & (1 << 31)) ? RLE_CRC_POLY : 0);
	}
}

uint32_t crc_compute(uint8_t*buffer, size_t size, uint32_t accu){
	for(size_t byte = 0; byte < size; byte++)
		accu = accu << 8 ^ crc_tab[(accu) >> 24 ^ (buffer[byte])];
	return accu;
}

uint32_t crc(uint8_t*buffer, size_t size){
	return crc_compute(buffer, size, RLE_CRC_INIT);
}

uint16_t ptype_comp[0x100];
uint8_t ptype_uncomp[0x10000];

typedef struct __attribute__((packed)){
	uint16_t start_indicator:1;
	uint16_t end_indicator:1;
	uint16_t ppdu_length:11;
	uint16_t extra:3;/*alpdu_label_type:2 + protocol_type_suppressed:1 if COMP else fragment_id:3*/
} Ppdu_header;
typedef struct __attribute__((packed)){
	uint16_t total_length:13;/* msb is use_alpdu_crc if not profile->large_alpdu */
	uint16_t alpdu_label_type:2;
	uint16_t protocol_type_suppressed:1;
} Ppdu_start_extra;

void rle_init(){
	/* default uncomp<->comp ptype association */
	struct {
		uint16_t full;
		uint8_t comp;
	} comptypes[] = {
		{0x0000,0x00},
		{0x0001,0x01},
		{0x0002,0x02},
		{0x0003,0x03},
		{0x00C8,0x04},
		{0x0100,0x05},
		{0x0800,0x0D},
		{0x86DD,0x11},
		{0x0082,0x42},
	};
	memset(ptype_comp,~0,sizeof(ptype_comp));
	memset(ptype_uncomp,~0,sizeof(ptype_uncomp));
	for(int i=0;i<sizeof(comptypes)/sizeof(*comptypes);i++){
		ptype_comp[comptypes[i].comp]=comptypes[i].full;
		ptype_uncomp[comptypes[i].full]=comptypes[i].comp;
	}
	
	crc_init();
}

size_t rle_frag_count(size_t length, size_t avail){/*avail:how much data can be put in a non-START PPDU*/
	return 1 + (length/(avail+1)?CEIL(length-avail+RLE_FPDU_HEADER_START_OVERHEAD,avail):0);
}

int rle_encap(rle_profile*profile,
              uint8_t*sdu, size_t sdu_len, uint16_t protocol_type,
              uint8_t alpdu_label_type, bool use_alpdu_crc,
              size_t*fpdu_len, uint8_t*fpdu){
	size_t ppdu_label_size = 0;
	uint8_t ppdu_label_byte[15];
	size_t fragment_id=0;
	/* check for invalid arguments first */
	if(profile==NULL || sdu==NULL || fpdu_len==NULL || fpdu==NULL ||
		sdu_len>RLE_SDU_SIZE_MAX || sdu_len==0 ||
		alpdu_label_type>=RLE_ALPDU_TYPE_COUNT
		//TODO check profile->ppdu_max_size against ppdu_label_length
		//profile->ppdu_max_size<RLE_PPDU_MIN_SIZE
		){
		return -1;
	}
	/**
	* ALPDU encapsulation
	**/
	
	/* ALPDU header */
	uint8_t header[RLE_PROTO_SIZE_MAX+RLE_ALPDU_LABEL_MAX];
	uint8_t*h = header;
	uint8_t*comp_ptype=NULL;
	if (profile->implied_protocol_type[alpdu_label_type] != protocol_type) {
		if (profile->protocol_type_compressed[alpdu_label_type]) {
			comp_ptype = &ptype_uncomp[protocol_type];
			mempush(h, comp_ptype, sizeof(*comp_ptype));
		} else {
			mempush(h, &protocol_type, sizeof(protocol_type));
		}
	}
	mempush(h,profile->alpdu_label_byte[alpdu_label_type],profile->alpdu_label_size[alpdu_label_type]);
	if ((comp_ptype != NULL) && (*comp_ptype == 0xff)) {
		mempush(h, &protocol_type, sizeof(protocol_type));
	}
	size_t header_len = h - header;
	memcpy(sdu - header_len, header, header_len);
	
	/* ALPDU footer */
	size_t alpdu_len = header_len + sdu_len;
	//ASSERT profile->ppdu_max_size > RLE_PPDU_HEADER_LEN + ppdu_label_size
	size_t ppdu_size = profile->ppdu_max_size - RLE_PPDU_HEADER_LEN - ppdu_label_size;
	/* first, try to fit into a COMP ppdu by ommiting the protection length */
	size_t nb_frag = rle_frag_count(alpdu_len, ppdu_size);
	//TODO ASSERT nb_frag
	if (nb_frag > 1) {
		if (use_alpdu_crc) {
			uint32_t alpdu_crc = crc(sdu,sdu_len);
			memcpy(sdu + sdu_len, &alpdu_crc, sizeof(alpdu_crc));
		} else {
			uint8_t alpdu_seq = 0;
			memcpy(sdu + sdu_len, &alpdu_seq, sizeof(alpdu_seq));
		}
		alpdu_len += use_alpdu_crc ? sizeof(uint32_t) : sizeof(uint8_t);
		/* update nb_frag with the new alpdu_len */
		nb_frag = rle_frag_count(alpdu_len, ppdu_size);
	}

	/**
	* PPDU fragmentation
	**/
	bool protocol_type_suppressed = false;
	size_t frag;
	uint8_t*p = fpdu;
	for(frag = 0 ; frag < nb_frag ; frag++){
		profile->ppdu_max_size;
		Ppdu_header hdr;
		hdr.start_indicator = (frag==0);
		hdr.end_indicator = (frag==nb_frag-1);
		hdr.ppdu_length = ppdu_size;
		if(hdr.start_indicator && hdr.end_indicator){
			hdr.extra = (protocol_type_suppressed << 2) | alpdu_label_type;
		} else {
			hdr.extra = fragment_id;
		}
		size_t header_len = sizeof(Ppdu_header);
		if (hdr.start_indicator && !hdr.end_indicator) {
			Ppdu_start_extra start_extra;
			start_extra.total_length = alpdu_len;
			if(!profile->large_alpdus){
				start_extra.total_length | use_alpdu_crc << 12;
			}
			mempush(h,ppdu_label_byte,ppdu_label_size);
			//header_len += sizeof(start_extra) + ppdu_label_len;
		}
		//ppdu_data_len = profile->ppdu_max_size - header_len;
		//mempush(p, alpdu, 1);
	}

	return 0;
}
int rle_decap(const rle_profile*profile,
	uint8_t*fpdu, size_t fpdu_len,
	uint16_t*protocol_type, uint8_t*alpdu_label_type, size_t*sdu_len, uint8_t*sdu){
	if(profile==NULL || fpdu==NULL || fpdu_len>RLE_FPDU_SIZE_MAX || protocol_type==NULL || sdu_len==NULL || sdu==NULL){
		return -1;
	}
	/*
	Header*header = (Header*)fpdu;
	uint8_t*data = fpdu + sizeof(Header);
	Trailer*trail = (Trailer*)(fpdu + sizeof(Header) + header->length);
	*sdu_len = header->length;
	*protocol_type = header->ptype;
	memcpy(sdu, data, *sdu_len);
	return trail->crc != crc(data,*sdu_len);
	*/
	return 0;
}

#ifndef NOMAIN
#include <stdio.h>
int main(){
	#define CHECK(msg, cond) if(!(cond)){printf(msg "\n");failed=true;}
	bool failed = false;
	/* init */
	rle_init();

	/* ptype resolving */
	CHECK("Comp->Uncomp association", ptype_comp[0x0D] == 0x0800);
	CHECK("Uncomp->Comp association", ptype_uncomp[0x0800] == 0x0D);
	CHECK("Unknown Uncomp value", ptype_uncomp[1234] == 0xFF);
	CHECK("Unknown Comp value", ptype_comp[123] == 0xFFFF);

	CHECK("CRC self test", crc((uint8_t*)"123456789",9) == RLE_CRC_CHECK);

	/* frag */
	size_t nb_frags[2][12]={
		{1,1,1,2,3,3,3,4,4,4,5,5},//label_len=0
		{1,1,3,3,4,4,5,5,6,6,7,7},//label_len=1 (worst case)
	};
	size_t frag_len=5,label_len,alpdu_len;
	for(label_len=0;label_len<(sizeof(nb_frags)/sizeof(*nb_frags));label_len++)
		for(alpdu_len=0;alpdu_len<(sizeof(*nb_frags)/sizeof(**nb_frags));alpdu_len++)
			CHECK("frag",rle_frag_count(alpdu_len+1,frag_len-RLE_PPDU_HEADER_LEN-label_len) == nb_frags[label_len][alpdu_len])

	rle_profile profile;
	profile.ppdu_max_size=499;
	uint8_t buffer[RLE_RECV_SIZE];
	uint8_t*sdu=buffer+RLE_RECV_OFFSET;

	char msg[]="simple message";
	size_t sdu_len=sizeof(msg);
	memcpy(sdu, msg, sdu_len);
	
	uint16_t ptype=0x0800;
	uint8_t  ltype=0;
	bool     use_crc=true;
	uint8_t  fpdu[RLE_FPDU_SIZE_MAX];
	size_t   fpdu_len=0;

	uint8_t  sdu_out[RLE_SDU_SIZE_MAX];
	size_t   sdu_len_out=sizeof(sdu_out);
	uint16_t ptype_out=~ptype; /**< ptype_out MUST be != than ptype */
	uint8_t  ltype_out=~ltype; /**< ltype_out MUST be != than ltype */
	
	/* bad args tests */
	CHECK("encap without profile",  rle_encap(NULL    , sdu , sdu_len           , ptype, ltype, use_crc, &fpdu_len, fpdu) < 0);
	CHECK("encap without sdu",      rle_encap(&profile, NULL, sdu_len           , ptype, ltype, use_crc, &fpdu_len, fpdu) < 0);
	CHECK("encap with too big sdu", rle_encap(&profile, sdu , RLE_SDU_SIZE_MAX+1, ptype, ltype, use_crc, &fpdu_len, fpdu) < 0);
	CHECK("encap without fpdu_len", rle_encap(&profile, sdu , sdu_len           , ptype, ltype, use_crc, NULL     , fpdu) < 0);
	CHECK("encap without fpdu",     rle_encap(&profile, sdu , sdu_len           , ptype, ltype, use_crc, &fpdu_len, NULL) < 0);
	
	CHECK("decap without profile",  rle_decap(NULL    , fpdu, fpdu_len           , &ptype_out, &ltype_out, &sdu_len, sdu ) < 0);
	CHECK("decap without fpdu",     rle_decap(&profile, NULL, fpdu_len           , &ptype_out, &ltype_out, &sdu_len, sdu ) < 0);
	CHECK("decap with too big sdu", rle_decap(&profile, fpdu, RLE_FPDU_SIZE_MAX+1, &ptype_out, &ltype_out, &sdu_len, sdu ) < 0);
	CHECK("decap without ptype",    rle_decap(&profile, fpdu, fpdu_len           , NULL      , &ltype_out, &sdu_len, sdu ) < 0);
	CHECK("decap without sdu_len",  rle_decap(&profile, fpdu, fpdu_len           , &ptype_out, &ltype_out, NULL    , sdu ) < 0);
	CHECK("decap without sdu",      rle_decap(&profile, fpdu, fpdu_len           , &ptype_out, &ltype_out, &sdu_len, NULL) < 0);
	
	CHECK("mirror encap", rle_encap(&profile, sdu, sdu_len, ptype, ltype, use_crc, &fpdu_len, fpdu) == 0);
	DUMP(sdu,sdu_len);
	DUMP(fpdu,fpdu_len);
	//CHECK("mirror decap", rle_decap(&profile, fpdu, fpdu_len, &ptype_out, &sdu_len_out, sdu_out) == 0);
	CHECK("mirror size", sdu_len_out == sdu_len);
	CHECK("mirror ptype", ptype_out == ptype);
	CHECK("mirror content", memcmp(sdu, sdu_out, sdu_len_out) == 0);
	
	return failed;
}
#endif