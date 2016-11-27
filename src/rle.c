#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rle.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define CEIL(a,b) ((a+b-1)/b)
#define DUMP(DATA,LEN) {printf("< ");int i;for(i=0;i<LEN;i++)printf("%02X ",DATA[i]);printf(">\n");}
#define mempush(DST,SRC,LEN,OFF) memcpy(DST+OFF,SRC,LEN);OFF+=LEN;

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
	uint16_t extra:3;/*sdu->label_type:2 + protocol_type_suppressed:1 if COMP else fragment_id:3*/
} ppdu_header_t;
typedef struct __attribute__((packed)){
	uint16_t total_length:13;/* msb is use_alpdu_crc if not profile->large_alpdu */
	uint16_t label_type:2;
	uint16_t protocol_type_suppressed:1;
} ppdu_start_t;

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
	for(size_t i=0;i<sizeof(comptypes)/sizeof(*comptypes);i++){
		ptype_comp[comptypes[i].comp]=comptypes[i].full;
		ptype_uncomp[comptypes[i].full]=comptypes[i].comp;
	}
	
	crc_init();
}

int rle_encap(rle_profile* profile, rle_sdu_t** sdus, rle_fpdu_t** fpdus){
	/* TODO: find a way to specify all PPDU label*/
	size_t ppdu_label_size=0;
	uint8_t*ppdu_label_byte=NULL;
	/* set the ppdu_max_size to the max if none given */
	if(profile->ppdu_max_size == 0){
		profile->ppdu_max_size=RLE_FPDU_SIZE_MAX;
	}
	/* check for invalid sdu/profile attributs */
	if((profile->ppdu_max_size < (RLE_PPDU_HEADER_START_LEN + ppdu_label_size + RLE_FPDU_LABEL_SIZE))
	|| (profile->ppdu_max_size > RLE_FPDU_SIZE_MAX)
	){
		/* TODO we can fit a start PPDU (bigest overhead) + ppdu_label + fpdu_label + frame prot in a  */
		return -1;
	}
	
	/**
	* encapsulate all SDU into ALPDU
	**/
	for(size_t sdu_num=0; sdus[sdu_num] != NULL; sdu_num++){
		rle_sdu_t*sdu = sdus[sdu_num];
		if(sdu->size > RLE_SDU_SIZE_MAX){
			return -1;
		}
		/* use profile defined alpdu_label if none given */
		if(sdu->label_byte == NULL){
			sdu->label_byte = profile->alpdu_label_byte[sdu->label_type];
			sdu->label_size = profile->alpdu_label_size[sdu->label_type];
		}
		/* ALPDU header */
		uint8_t header[RLE_ALPDU_HEADER_MAX];
		uint8_t*comp_ptype=NULL;
		sdu->_protocol_type_suppressed = (profile->implied_protocol_type[sdu->label_type] == sdu->protocol_type);
		if (!sdu->_protocol_type_suppressed) {
			if (profile->protocol_type_compressed[sdu->label_type]) {
				comp_ptype = &ptype_uncomp[sdu->protocol_type];
				mempush(header, comp_ptype, sizeof(*comp_ptype), sdu->_header_size);
			} else {
				mempush(header, &sdu->protocol_type, sizeof(sdu->protocol_type), sdu->_header_size);
			}
		}
		mempush(header, profile->alpdu_label_byte[sdu->label_type],profile->alpdu_label_size[sdu->label_type], sdu->_header_size);
		if ((comp_ptype != NULL) && (*comp_ptype == 0xff)) {
			mempush(header, &sdu->protocol_type, sizeof(sdu->protocol_type), sdu->_header_size);
		}
		/* write this header right before the sdu->data */
		memcpy(sdu->data - sdu->_header_size, header, sdu->_header_size);
		/* don't create ALPDU footer yet because we don't know if the ALPDU will be splited */
	}
	/*
	* Fit all the ALPDU into FPDU using PPDU
	*/
	size_t sdu_num=0;
	size_t fpdu_num=0;
	while((sdus[sdu_num] != NULL) && (fpdus[fpdu_num] != NULL)){
		rle_fpdu_t*fpdu = fpdus[fpdu_num];
		rle_sdu_t*sdu = sdus[sdu_num];
		size_t fpdu_remaining_size = profile->ppdu_max_size - fpdu->size - (profile->use_frame_protection?RLE_FPDU_PROT_SIZE:0) - RLE_FPDU_LABEL_SIZE;
		size_t alpdu_len = sdu->_header_size + sdu->size + sdu->_footer_size;
		if(sdu->_is_frag){ /* current SDU was partialy sent, continue/finish sending using CONT/END PPDU */
			/* try to fit the whole PPDU using a END PPDU */
			if(RLE_PPDU_HEADER_END_LEN + ppdu_label_size + (alpdu_len-sdu->_sent_size) <= fpdu_remaining_size){
				size_t ppdu_length = RLE_PPDU_HEADER_END_LEN + ppdu_label_size + (alpdu_len-sdu->_sent_size);
				ppdu_header_t ppdu_hdr = {RLE_PPDU_TYPE_END, ppdu_length, sdu->fragment_id};
				mempush(fpdu->data, &ppdu_hdr, sizeof(ppdu_hdr),fpdu->size);
				mempush(fpdu->data, ppdu_label_byte, ppdu_label_size,fpdu->size);
				mempush(fpdu->data, sdu->data-sdu->_header_size, alpdu_len-sdu->_sent_size,fpdu->size);
				sdu_num++;/* we are done with this SDU */
				sdu->done=true;
				continue;
			}
			/* try again, using a CONT PPDU*/
			if(RLE_PPDU_HEADER_CONT_LEN + ppdu_label_size <= fpdu_remaining_size){
				size_t ppdu_length = MIN(fpdu_remaining_size, RLE_PPDU_HEADER_CONT_LEN + ppdu_label_size + (alpdu_len-sdu->_sent_size));
				ppdu_header_t ppdu_hdr = {RLE_PPDU_TYPE_END, ppdu_length, sdu->fragment_id};
				mempush(fpdu->data, &ppdu_hdr, sizeof(ppdu_hdr),fpdu->size);
				mempush(fpdu->data, ppdu_label_byte, ppdu_label_size,fpdu->size);
				mempush(fpdu->data, sdu->data-sdu->_header_size, alpdu_len-sdu->_sent_size,fpdu->size);
				continue;
			}
		}else{ /* First time with this SDU (not yet frag) : find out if we can fit a COMP, or a START, (or nothing) */
			/* try to fit a COMP ppdu */
			if (RLE_PPDU_HEADER_COMP_LEN + ppdu_label_size + alpdu_len <= fpdu_remaining_size){
				ppdu_header_t ppdu_hdr = {RLE_PPDU_TYPE_COMP,alpdu_len + RLE_PPDU_HEADER_COMP_LEN, (sdu->_protocol_type_suppressed << 2) | sdu->label_type}; /*this kind of extra if for COMP only*/
				mempush(fpdu->data, &ppdu_hdr, sizeof(ppdu_hdr), fpdu->size);
				mempush(fpdu->data, ppdu_label_byte, ppdu_label_size, fpdu->size);
				mempush(fpdu->data, sdu->data-sdu->_header_size, alpdu_len, fpdu->size);
				sdu->_sent_size=sdu->size;/* mark the SDU as fully sent */
				sdu_num++;/* we are done with this SDU */
				sdu->done=true;
				continue;
			}
			/* try to fit a START ppdu (protection is needed) */
			if(RLE_PPDU_HEADER_START_LEN + ppdu_label_size <= fpdu_remaining_size) {
				sdu->_footer_size = sdu->use_crc ? sizeof(uint32_t) : sizeof(uint8_t);
				alpdu_len += sdu->_footer_size;
				/* compute the protection */
				if (sdu->use_crc) {
					uint32_t checksum = crc(sdu->data,sdu->size);
					memcpy(sdu + sdu->size, &checksum, sdu->_footer_size);
				} else {
					memcpy(sdu + sdu->size, &profile->alpdu_seq, sdu->_footer_size);
					profile->alpdu_seq[sdu->fragment_id]++;
				}
				size_t ppdu_length = MIN(fpdu_remaining_size, RLE_PPDU_HEADER_START_LEN + ppdu_label_size + alpdu_len);
				sdu->_sent_size = ppdu_length - RLE_PPDU_HEADER_START_LEN + ppdu_label_size;
				/* now we can create the START header with the appropriate ALPDU/PPDU length */
				ppdu_header_t ppdu_hdr = {RLE_PPDU_TYPE_START, ppdu_length, sdu->fragment_id};
				ppdu_start_t start_hdr = {alpdu_len | (profile->large_alpdus?0:sdu->use_crc << 12),sdu->label_type,sdu->_protocol_type_suppressed};
				mempush(fpdu->data, &ppdu_hdr      ,sizeof(ppdu_hdr), fpdu->size);
				mempush(fpdu->data, ppdu_label_byte, ppdu_label_size, fpdu->size);
				mempush(fpdu->data, &start_hdr,    sizeof(start_hdr), fpdu->size);
				mempush(fpdu->data, sdu->data-sdu->_header_size, sdu->_sent_size, fpdu->size);
				sdu->_is_frag = true; /* reminder for the next iteration */
				continue;
			}
		}
		/* nothing can fit */
		fpdu_num++;/* try with the next FPDU*/
	}
	return 0;
}

int rle_decap(rle_profile* profile, rle_sdu_t** sdus, rle_fpdu_t** fpdus){
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
	#if 0
	size_t rle_frag_count(size_t length, size_t avail){/*avail:how much data can be put in a non-START PPDU*/
		return 1 + (length/(avail+1)?CEIL(length-avail+sizeof(ppdu_start_t),avail):0);
	}
	size_t nb_frags[][12]={
		{1,1,1,2,3,3,3,4,4,4,5,5},//label_len=0
		{1,1,3,3,4,4,5,5,6,6,7,7},//label_len=1 (worst case)
	};
	size_t frag_len=5;
	for(size_t label_len=0;label_len<(sizeof(nb_frags)/sizeof(*nb_frags));label_len++)
		for(size_t alpdu_len=0;alpdu_len<(sizeof(*nb_frags)/sizeof(**nb_frags));alpdu_len++)
			CHECK("frag",rle_frag_count(alpdu_len+1,frag_len-RLE_PPDU_HEADER_CONT_LEN-label_len) == nb_frags[label_len][alpdu_len])
	#endif
	rle_profile profile={};
	rle_sdu_t*sdus[]={
		&(rle_sdu_t){size:5,protocol_type:0x0800,data:"super",fragment_id:4},
		&(rle_sdu_t){size:4,protocol_type:0x0800,data:"test",label_size:15},
		&(rle_sdu_t){size:4,protocol_type:0x0800,data:"okay"},
		NULL
	};
	rle_fpdu_t*fpdus[]={
		&(rle_fpdu_t){},
		&(rle_fpdu_t){},
		&(rle_fpdu_t){},
		NULL
	};
	
	int ret=rle_encap(&profile, sdus, fpdus);
	printf("encap:%i\n",ret);
#if 0
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
#endif
	return failed;
}
#endif