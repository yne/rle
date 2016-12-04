#include <string.h>
#include <stdlib.h>

#include "rle.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define mempush(DST,SRC,LEN,OFF) {memcpy(DST+OFF,SRC,LEN);OFF+=LEN;}

uint32_t crc_tab[256];

uint16_t rle_ptype_short[0x100];
uint8_t rle_ptype_long[0x10000];

void crc_init(){
	int i=0;
	for(i = 0; i < 256; i++){
		crc_tab[i] = i << 24;
		int bit;
		for (bit = 8; bit > 0; bit--)
			crc_tab[i] = (crc_tab[i] << 1) ^ ((crc_tab[i] & (1 << 31)) ? RLE_CRC_POLY : 0);
	}
}

uint32_t crc_compute(uint8_t*buffer, size_t size, uint32_t accu){
	size_t byte;
	for(byte = 0; byte < size; byte++)
		accu = accu << 8 ^ crc_tab[(accu) >> 24 ^ (buffer[byte])];
	return accu;
}

uint32_t crc(uint8_t*buffer, size_t size){
	return crc_compute(buffer, size, RLE_CRC_INIT);
}

void rle_log_null(rle_log_level level, const char *format, ...){}

void rle_init(){
	/* default uncomp<->compr ptype association */
	struct {
		uint16_t full;
		uint8_t compr;
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
	memset(rle_ptype_short,~0,sizeof(rle_ptype_short));
	memset(rle_ptype_long,~0,sizeof(rle_ptype_long));
	size_t i;
	for(i=0; i<sizeof(comptypes)/sizeof(*comptypes); i++){
		rle_ptype_short[comptypes[i].compr]=comptypes[i].full;
		rle_ptype_long[comptypes[i].full]=comptypes[i].compr;
	}
	
	crc_init();
}

int rle_encap(rle_profile* profile, rle_iterator_sdu next_sdu, rle_iterator_fpdu next_fpdu){
	/* TODO: find a way to specify each PPDU label*/
	size_t ppdu_label_size=0;
	uint8_t ppdu_label_byte[32];
	if(profile->log == NULL)
		profile->log = rle_log_null;
	/* set the fpdu_max_size to the max if none given */
	if(profile->fpdu_max_size == 0){
		profile->fpdu_max_size=RLE_FPDU_SIZE_MAX;
	}
	/* check for invalid sdu/profile attributs */
	if(profile->fpdu_max_size < RLE_FPDU_LABEL_SIZE + sizeof(ppdu_start_header_t) + ppdu_label_size + sizeof(ppdu_start2_header_t) + RLE_FPDU_PROT_SIZE)
		return -1;
	if(profile->fpdu_max_size > RLE_FPDU_SIZE_MAX)
		return -1;
	rle_fpdu_t*fpdu = next_fpdu(RLE_ITERATOR_FIRST);
	rle_sdu_t*sdu = next_sdu(RLE_ITERATOR_FIRST);
	while (fpdu && sdu) {
		/**
		* encapsulate current SDU into ALPDU (if hasn't been done yet)
		**/
		if ((sdu->_.ptype_suppr == false) && (sdu->_.header_size == 0)) {
			if(sdu->size > RLE_SDU_SIZE_MAX){
				profile->log(RLE_LOG_DBG,"sdu size too big\n");
				sdu = next_sdu(RLE_ITERATOR_NEXT);
				return -1;
			}
			/* use profile defined alpdu_label if none given */
			if(sdu->label_byte == NULL){
				sdu->label_byte = profile->alpdu_label_byte[sdu->label_type];
				sdu->label_size = profile->alpdu_label_size[sdu->label_type];
			}
			/* ALPDU header */
			uint8_t header[RLE_ALPDU_HEADER_MAX];
			uint8_t*ptype_short=NULL;
			sdu->_.ptype_suppr = (profile->implied_ptype[sdu->label_type] == sdu->protocol_type);
			if (!sdu->_.ptype_suppr) {
				if (profile->use_ptype_short[sdu->label_type]) {
					mempush(header, ptype_short = &rle_ptype_long[sdu->protocol_type], sizeof(*ptype_short), sdu->_.header_size);
				} else {
					mempush(header, &sdu->protocol_type, sizeof(sdu->protocol_type), sdu->_.header_size);
				}
			}
			mempush(header, profile->alpdu_label_byte[sdu->label_type],profile->alpdu_label_size[sdu->label_type], sdu->_.header_size);
			if ((ptype_short != NULL) && (*ptype_short == 0xff)) {
				mempush(header, &sdu->protocol_type, sizeof(sdu->protocol_type), sdu->_.header_size);
			}
			/* write this header right before the sdu->data */
			memcpy(sdu->data - sdu->_.header_size, header, sdu->_.header_size);
			/* don't create ALPDU footer yet because we don't know if the ALPDU will be splited */
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
			profile->log(RLE_LOG_DBG,"given fpdu size(%zu) is larger that profile max (%zu)\n",fpdu->size, profile->fpdu_max_size);
			return -1;
		}
		size_t fpdu_remaining_size = profile->fpdu_max_size - (profile->use_frame_protection?RLE_FPDU_PROT_SIZE:0) - RLE_FPDU_LABEL_SIZE - fpdu->size - RLE_FPDU_PROT_SIZE;
		size_t alpdu_len = sdu->_.header_size + sdu->size + sdu->_.footer_size;
		if (sdu->_.is_frag == false) { /* SDU not (yet) fragged, because it's it first pass: find out if we can fit a FULL, or a START, (or nothing) */
			if (sizeof(ppdu_full_header_t) + ppdu_label_size + alpdu_len <= fpdu_remaining_size){
				ppdu_full_header_t ppdu_hdr = {1,1,alpdu_len - ppdu_label_size, (sdu->_.ptype_suppr<<2) | sdu->label_type};
				mempush(fpdu->data, &ppdu_hdr, sizeof(ppdu_hdr), fpdu->size);
				mempush(fpdu->data, ppdu_label_byte, ppdu_label_size, fpdu->size);
				mempush(fpdu->data, sdu->data-sdu->_.header_size, alpdu_len, fpdu->size);
				sdu = next_sdu(RLE_ITERATOR_NEXT);/* we are done with this SDU */
				continue;
			}
			if(sizeof(ppdu_start_header_t) + ppdu_label_size + sizeof(ppdu_start2_header_t) <= fpdu_remaining_size) {
				/* START require an ALPDU protection computation */
				if (sdu->use_crc)
					*(uint32_t*)(sdu->data + sdu->size)=crc(sdu->data,sdu->size);
				else
					*(uint8_t *)(sdu->data + sdu->size)=profile->alpdu_seq_send[sdu->fragment_id]++;
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
				sdu = next_sdu(RLE_ITERATOR_NEXT);/* we are done with this SDU */
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
		fpdu = next_fpdu(RLE_ITERATOR_NEXT);/* try with the next FPDU*/
	}
	return 0;
}

int rle_decap(rle_profile* profile, rle_iterator_fpdu next_fpdu, rle_iterator_sdu next_sdu){
	if(profile->log == NULL)
		profile->log = rle_log_null;
	size_t ppdu_label_size=0;
	uint8_t ppdu_label_byte[32];
	rle_sdu_t*sdu = next_sdu(RLE_ITERATOR_FIRST);
	rle_fpdu_t*fpdu = next_fpdu(RLE_ITERATOR_FIRST);
	size_t fpdu_offset = RLE_FPDU_LABEL_SIZE + (profile->use_eplh_map?sizeof(fpdu_header_t):0);
	while (fpdu && sdu) {
		uint16_t hdr_int = *(uint16_t*)(fpdu->data+fpdu_offset);
		/* is this FPDU too small to hold some data ? or have an (impossible) 0-sized CONT is in fact... padding !*/
		if((profile->fpdu_max_size - fpdu_offset < sizeof(ppdu_header_t) + ppdu_label_size) || (hdr_int == 0)){
			fpdu = next_fpdu(RLE_ITERATOR_NEXT);
			fpdu_offset = RLE_FPDU_LABEL_SIZE+(profile->use_eplh_map?sizeof(fpdu_header_t):0);
			continue;
		}
		ppdu_header_t*ppdu_hdr = (ppdu_header_t*)&(fpdu->data[fpdu_offset]);
		if(ppdu_hdr->start_indicator && ppdu_hdr->end_indicator){
			sdu->size          = ppdu_hdr->ppdu_length;
			sdu->label_type    = ppdu_hdr->frag_id & 3;
			sdu->_.ptype_suppr = ppdu_hdr->frag_id & 4;
		}else{
			sdu->fragment_id   = ppdu_hdr->frag_id;
		}
		fpdu_offset += sizeof(*ppdu_hdr);
		memcpy(ppdu_label_byte,&(fpdu->data[fpdu_offset]),ppdu_label_size);
		fpdu_offset += ppdu_label_size;
		if(ppdu_hdr->start_indicator && !ppdu_hdr->end_indicator){
			ppdu_start2_header_t* hdr = (ppdu_start2_header_t*)&(fpdu->data[fpdu_offset]);
			sdu->size          = hdr->total_length & (profile->large_alpdus?0x1FFF:0x0FFF);
			sdu->use_crc       = hdr->total_length & (profile->large_alpdus?0x0000:0x1000);
			sdu->label_type    = hdr->label_type;
			sdu->_.ptype_suppr = hdr->ptype_suppr;
			fpdu_offset += sizeof(*hdr);
			ppdu_hdr->ppdu_length -= sizeof(*hdr);
		}
		memcpy(sdu->_header + sdu->_.alpdu_sent, &(fpdu->data[fpdu_offset]), ppdu_hdr->ppdu_length);
		sdu->_.alpdu_sent += ppdu_hdr->ppdu_length;
		profile->log(RLE_LOG_DBG,"%c%02zu","CSEF"[ppdu_hdr->start_indicator|ppdu_hdr->end_indicator<<1],ppdu_hdr->ppdu_length);
		fpdu_offset+=ppdu_hdr->ppdu_length;
		if(ppdu_hdr->end_indicator){
			/* Received FPDUs doesn not match the size announced by the START FPDU*/
			if(sdu->_.alpdu_sent!= sdu->size){
				/*profile->log(RLE_LOG_DBG,"(sum:%zu != expect:%zu)\n", sdu->_.alpdu_sent, sdu->size);*/
				/*TODO: what should we do ...? reset current SDU and continue */
			}
			profile->log(RLE_LOG_DBG,"\n");
			/* update header attribut */
			uint8_t*ptype=NULL;
			if(sdu->_.ptype_suppr){
				sdu->protocol_type = profile->implied_ptype[sdu->label_type];
			}else if(profile->use_ptype_short[sdu->label_type]){
				sdu->_.header_size += sizeof(*(ptype = sdu->_header + sdu->_.header_size));
			}else{
				sdu->_.header_size += sizeof(sdu->protocol_type = *((uint16_t*)(sdu->_header+sdu->_.header_size)));
			}
			sdu->_.header_size += 0;/*TODO:alpdu_label_size*/
			if(ptype!=NULL && *ptype==0xFF){
				sdu->_.header_size += sizeof(sdu->protocol_type = *((uint16_t*)(sdu->_header+sdu->_.header_size)));
			}
			/* update data attribut */
			sdu->recv_data = sdu->_header + sdu->_.header_size;
			sdu->size -= sdu->_.header_size;
			/* update footer attribut (END frag only, COMP does not have protection)*/
			if(!ppdu_hdr->start_indicator){
				if(sdu->use_crc){
					sdu->size -= (sdu->_.footer_size = sizeof(uint32_t));
					uint32_t prot_crc = *(uint32_t*)(sdu->recv_data+sdu->size);
					if(prot_crc != crc(sdu->recv_data,sdu->size)){
						profile->log(RLE_LOG_DBG,"invalid CRC (expect:%08X got:%08X) \n",prot_crc,crc(sdu->recv_data,sdu->size));
					}
				}else{
					sdu->size -= (sdu->_.footer_size = sizeof(uint8_t));
					uint8_t prot_seq = *(uint8_t*)(sdu->recv_data+sdu->size);
					if(prot_seq != profile->alpdu_seq_recv[sdu->label_type]++){
						profile->log(RLE_LOG_DBG,"unordered sequence ! \n");
					}
				}
			}
			sdu = next_sdu(RLE_ITERATOR_NEXT);
			continue;
		}
	}
	return 0;
}
