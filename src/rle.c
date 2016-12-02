#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rle.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define DUMP(DATA,LEN) {printf("%p <<< line %i\n",DATA,__LINE__);size_t i;for(i=0;i<(size_t)LEN;i++)printf("%02X ",((uint8_t*)DATA)[i]);printf(">\n");}
#define mempush(DST,SRC,LEN,OFF) {memcpy(DST+OFF,SRC,LEN);OFF+=LEN;}
#define mempush_(DST,SRC,LEN,OFF) {fprintf(stderr,"%i (%p<%zu<%p@%zu)",__LINE__,DST,LEN,SRC,OFF);memcpy(DST+OFF,SRC,LEN);OFF+=LEN;fprintf(stderr,"\n");}
#define DBG(...) 
#define DBG_(...) fprintf(stderr,__VA_ARGS__)
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

uint16_t rle_ptype_comp[0x100];
uint8_t rle_ptype_uncomp[0x10000];

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
	memset(rle_ptype_comp,~0,sizeof(rle_ptype_comp));
	memset(rle_ptype_uncomp,~0,sizeof(rle_ptype_uncomp));
	for(size_t i=0;i<sizeof(comptypes)/sizeof(*comptypes);i++){
		rle_ptype_comp[comptypes[i].comp]=comptypes[i].full;
		rle_ptype_uncomp[comptypes[i].full]=comptypes[i].comp;
	}
	
	crc_init();
}

int rle_encap(rle_profile* profile, rle_sdu_iter next_sdu, rle_fpdu_iter next_fpdu){
	/* TODO: find a way to specify each PPDU label*/
	size_t ppdu_label_size=0;
	uint8_t ppdu_label_byte[32];
	/* set the fpdu_max_size to the max if none given */
	if(profile->fpdu_max_size == 0){
		profile->fpdu_max_size=RLE_FPDU_SIZE_MAX;
	}
	/* check for invalid sdu/profile attributs */
	if((profile->fpdu_max_size < (sizeof(ppdu_start_header_t) + ppdu_label_size + RLE_FPDU_LABEL_SIZE))
	|| (profile->fpdu_max_size > RLE_FPDU_SIZE_MAX)
	){
		/* TODO we can fit a start PPDU (bigest overhead) + ppdu_label + fpdu_label + frame prot in a  */
		return -1;
	}
	rle_fpdu_t*fpdu = next_fpdu();
	rle_sdu_t*sdu = next_sdu();
	while (fpdu && sdu) {
		/**
		* encapsulate current SDU into ALPDU (if hasn't been done yet)
		**/
		if (sdu->_.is_alpdu == false) {
			if(sdu->size > RLE_SDU_SIZE_MAX){
				printf("sdu size too big\n");
				sdu = next_sdu();
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
			sdu->_.ptype_suppr = (profile->implied_protocol_type[sdu->label_type] == sdu->protocol_type);
			if (!sdu->_.ptype_suppr) {
				if (profile->protocol_type_compressed[sdu->label_type]) {
					comp_ptype = &rle_ptype_uncomp[sdu->protocol_type];
					mempush(header, comp_ptype, sizeof(*comp_ptype), sdu->_.header_size);
				} else {
					mempush(header, &sdu->protocol_type, sizeof(sdu->protocol_type), sdu->_.header_size);
				}
			}
			mempush(header, profile->alpdu_label_byte[sdu->label_type],profile->alpdu_label_size[sdu->label_type], sdu->_.header_size);
			if ((comp_ptype != NULL) && (*comp_ptype == 0xff)) {
				mempush(header, &sdu->protocol_type, sizeof(sdu->protocol_type), sdu->_.header_size);
			}
			/* write this header right before the sdu->data */
			memcpy(sdu->data - sdu->_.header_size, header, sdu->_.header_size);
			/* don't create ALPDU footer yet because we don't know if the ALPDU will be splited */
			sdu->_.is_alpdu=true;
		}
		
		/**
		* reserve some header space in the current FPDU
		**/
		if(fpdu->size == 0){
			fpdu->size += RLE_FPDU_LABEL_SIZE;
			fpdu->size += profile->use_eplh_map?1:0;
		}

		/*
		* Fit current ALPDU into FPDU using PPDU
		*/
		if(fpdu->size > profile->fpdu_max_size){
			fprintf(stderr,"given fpdu size(%zu) is larger that profile max (%zu)\n",fpdu->size, profile->fpdu_max_size);
			return -1;
		}
		size_t fpdu_remaining_size = profile->fpdu_max_size - (profile->use_frame_protection?RLE_FPDU_PROT_SIZE:0) - RLE_FPDU_LABEL_SIZE - fpdu->size - RLE_FPDU_PROT_SIZE;
		size_t alpdu_len = sdu->_.header_size + sdu->size + sdu->_.footer_size;
		if (sdu->_.is_frag == false) { /* SDU not (yet) fragged, because it's it first pass: find out if we can fit a COMP, or a START, (or nothing) */
			if (sizeof(ppdu_comp_header_t) + ppdu_label_size + alpdu_len <= fpdu_remaining_size){
				ppdu_comp_header_t ppdu_hdr = {1,1,alpdu_len - ppdu_label_size, (sdu->_.ptype_suppr<<2) | sdu->label_type};
				mempush(fpdu->data, &ppdu_hdr, sizeof(ppdu_hdr), fpdu->size);
				mempush(fpdu->data, ppdu_label_byte, ppdu_label_size, fpdu->size);
				mempush(fpdu->data, sdu->data-sdu->_.header_size, alpdu_len, fpdu->size);
				sdu = next_sdu();/* we are done with this SDU */
				continue;
			}
			if(sizeof(ppdu_start_header_t) + ppdu_label_size + sizeof(ppdu_start2_header_t) <= fpdu_remaining_size) {
				/* START require an ALPDU protection computation */
				if (sdu->use_crc)
					*(uint32_t*)(sdu->data + sdu->size)=crc(sdu->data,sdu->size);
				else
					*(uint8_t *)(sdu->data + sdu->size)=profile->alpdu_seq[sdu->fragment_id]++;
				alpdu_len += (sdu->_.footer_size = sdu->use_crc ? sizeof(uint32_t) : sizeof(uint8_t));
				sdu->_.alpdu_sent = MIN(alpdu_len, fpdu_remaining_size - sizeof(ppdu_start_header_t) - ppdu_label_size - sizeof(ppdu_start2_header_t));

				mempush(fpdu->data, &((ppdu_start_header_t){1,0, sdu->_.alpdu_sent + ppdu_label_size + sizeof(ppdu_start2_header_t), sdu->fragment_id})      ,sizeof(ppdu_start_header_t), fpdu->size);
				mempush(fpdu->data, ppdu_label_byte, ppdu_label_size, fpdu->size);
				mempush(fpdu->data, &((ppdu_start2_header_t){alpdu_len | (profile->large_alpdus?0:sdu->use_crc << 12),sdu->label_type,sdu->_.ptype_suppr}),    sizeof(ppdu_start2_header_t), fpdu->size);
				mempush(fpdu->data, sdu->data-sdu->_.header_size, sdu->_.alpdu_sent, fpdu->size);
				sdu->_.is_frag = true; /* reminder for the next iteration */
				continue;
			}
		} else { /* current SDU was partialy sent, continue/finish sending using CONT/END PPDU */
			/* try to fit the rest of the PPDU using a END PPDU */
			if(sizeof(ppdu_end_header_t) + ppdu_label_size + (alpdu_len-sdu->_.alpdu_sent) <= fpdu_remaining_size){
				mempush(fpdu->data, &((ppdu_end_header_t){0,1, (alpdu_len-sdu->_.alpdu_sent), sdu->fragment_id}), sizeof(ppdu_end_header_t),fpdu->size);
				mempush(fpdu->data, ppdu_label_byte, ppdu_label_size,fpdu->size);
				mempush(fpdu->data, sdu->data-sdu->_.header_size+sdu->_.alpdu_sent, alpdu_len-sdu->_.alpdu_sent,fpdu->size);
				sdu = next_sdu();/* we are done with this SDU */
				continue;
			}
			/* try again, using a CONT PPDU*/
			if(sizeof(ppdu_cont_header_t) + ppdu_label_size <= fpdu_remaining_size){
				size_t alpdu_avail = MIN(alpdu_len-sdu->_.alpdu_sent ,fpdu_remaining_size - sizeof(ppdu_cont_header_t) - ppdu_label_size);
				mempush(fpdu->data, &((ppdu_cont_header_t){0,0, alpdu_avail + ppdu_label_size, sdu->fragment_id}), sizeof(ppdu_cont_header_t),fpdu->size);
				mempush(fpdu->data, ppdu_label_byte, ppdu_label_size,fpdu->size);
				mempush(fpdu->data, sdu->data-sdu->_.header_size+sdu->_.alpdu_sent, alpdu_avail, fpdu->size);
				sdu->_.alpdu_sent += alpdu_avail; /* reminder for the next iteration */
				continue;
			}
		}
		/* nothing can fit => pad the remaining bytes */
		memset(fpdu->data+fpdu->size,RLE_FPDU_PADDING,profile->fpdu_max_size-fpdu->size-RLE_FPDU_PROT_SIZE);
		fpdu = next_fpdu();/* try with the next FPDU*/
	}
	return 0;
}

int rle_decap(rle_profile* profile, rle_fpdu_iter next_fpdu, rle_sdu_iter next_sdu){
	size_t ppdu_label_size=0;
	uint8_t ppdu_label_byte[32];
	rle_sdu_t*sdu = next_sdu();
	rle_fpdu_t*fpdu = next_fpdu();
	size_t fpdu_offset = RLE_FPDU_LABEL_SIZE + (profile->use_eplh_map?sizeof(fpdu_header_t):0);
	while (fpdu && sdu) {
		uint16_t hdr_int = *((uint16_t*)&(fpdu->data[fpdu_offset]));
		/* is this FPDU too small to hold some data ? or have an (impossible) 0-sized CONT is in fact... padding !*/
		if((profile->fpdu_max_size - fpdu_offset < sizeof(ppdu_header_t) + ppdu_label_size) || (hdr_int == 0)){
			DBG(",");//fprintf(stderr,"Exausted FPDU: %zu/%zu (hdr:%04x)\n", fpdu_offset, profile->fpdu_max_size,hdr_int);
			fpdu = next_fpdu();
			fpdu_offset = RLE_FPDU_LABEL_SIZE+(profile->use_eplh_map?sizeof(fpdu_header_t):0);
			continue;
		}
		size_t frag_id=0;
		ppdu_header_t*ppdu_hdr = (ppdu_header_t*)&(fpdu->data[fpdu_offset]);
		fpdu_offset += sizeof(*ppdu_hdr);
		if(ppdu_hdr->start_indicator && ppdu_hdr->end_indicator){
			sdu->label_type    = ppdu_hdr->frag_id & 4;
			sdu->_.ptype_suppr = ppdu_hdr->frag_id & 3;
			sdu->size          = ppdu_hdr->ppdu_length;
		}else{
			frag_id = ppdu_hdr->frag_id;
			(void)frag_id;
		}
		memcpy(ppdu_label_byte,&(fpdu->data[fpdu_offset]),ppdu_label_size);
		fpdu_offset += ppdu_label_size;
		if(ppdu_hdr->start_indicator && !ppdu_hdr->end_indicator){
			ppdu_start2_header_t* hdr = (ppdu_start2_header_t*)&(fpdu->data[fpdu_offset]);
			sdu->size          = hdr->total_length & (profile->large_alpdus?0x1FFF:0x0FFF);
			sdu->use_crc       = hdr->total_length & (profile->large_alpdus?0x0000:0x1000);
			sdu->label_type    = hdr->label_type;
			sdu->_.ptype_suppr = hdr->ptype_suppr;
			sdu->_.is_frag     = true;
			fpdu_offset += sizeof(*hdr);
			ppdu_hdr->ppdu_length -= sizeof(*hdr);
		}
		//fprintf(stderr,"S:%i E:%i L:%5zu ID:%zu\n", ppdu_hdr->start_indicator, ppdu_hdr->end_indicator, ppdu_hdr->ppdu_length, id);
		memcpy(sdu->data + sdu->_.alpdu_sent, &(fpdu->data[fpdu_offset]), ppdu_hdr->ppdu_length);
		sdu->_.alpdu_sent += ppdu_hdr->ppdu_length;
		DBG("%c%zu",(ppdu_hdr->start_indicator?"SF":"CE")[ppdu_hdr->end_indicator],ppdu_hdr->ppdu_length);
		fpdu_offset+=ppdu_hdr->ppdu_length;
		if(ppdu_hdr->end_indicator){
			if(sdu->_.alpdu_sent!= sdu->size)
				DBG("(sum:%zu != expect:%zu)\n", sdu->_.alpdu_sent, sdu->size);
			DBG(" %s\n",ppdu_hdr->start_indicator?"COMP":"END");
			if(sdu->_.is_frag){
				sdu->size -= (sdu->_.footer_size = sdu->use_crc ? sizeof(uint32_t) : sizeof(uint8_t));
			}
			sdu = next_sdu();
			continue;
		}
	}
	return 0;
}

#ifndef NOMAIN
#include <stdio.h>
#define BUILD_CHECK(condition) ((void)sizeof(char[1-2*!(condition)]))

#include "rle.lambda.c"

int main(){
	#define CHECK(msg, cond) if(!(cond)){printf(msg "\n");failed=true;}
	bool failed = false;
	/* init */
	rle_init();

	/* ptype resolving */
	CHECK("Comp->Uncomp association", rle_ptype_comp[0x0D] == 0x0800);
	CHECK("Uncomp->Comp association", rle_ptype_uncomp[0x0800] == 0x0D);
	CHECK("Unknown Uncomp value", rle_ptype_uncomp[1234] == 0xFF);
	CHECK("Unknown Comp value", rle_ptype_comp[123] == 0xFFFF);

	CHECK("CRC self test", crc((uint8_t*)"123456789",9) == RLE_CRC_CHECK);
	/* compilation check */
	BUILD_CHECK(sizeof(ppdu_header_t) == 2);
	BUILD_CHECK(sizeof(ppdu_start_header_t) == 2);
	BUILD_CHECK(sizeof(ppdu_cont_header_t) == 2);
	BUILD_CHECK(sizeof(ppdu_end_header_t) == 2);
	BUILD_CHECK(sizeof(ppdu_comp_header_t) == 2);
	BUILD_CHECK(sizeof(ppdu_start2_header_t) == 2);
	BUILD_CHECK(sizeof(fpdu_header_t) == 1);
	
	/* frag */
	rle_profile profile = {fpdu_max_size:FPDU_SIZE};
	CHECK("encap failed", rle_encap(&profile, make_sdu, save_fpdu) == 0);
	
	printf("SDU:%zu->FPDU:%zu\n",make_sdu_nb,saved_fpdu_nb);
	CHECK("decap", rle_decap(&profile, load_fpdu, diff_sdu) == 0);
	//CHECK("decap", rle_decap(&profile, bench_fpdu, bench_sdu) == 0);
	//fprintf(stderr,"sdu:%i fpdu:%zu (%i MiB)\n",total_sdu, filled_fpdu,(filled_fpdu*profile.fpdu_max_size)/1000000);
	return failed;
	#undef CHECK
}
#endif