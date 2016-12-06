#include <stdio.h>
#include <string.h>
#include <stdarg.h>
/* use .c to unit test RLE privates functions */
#include "rle.c"

#define DUMP(DATA,LEN) {printf("%p <<< ",DATA);size_t i;for(i=0;i<(size_t)LEN;i++)printf("%02X ",((uint8_t*)DATA)[i]);printf(">>>\n");}

#define CONTENT "l'essentiel est invisible pour les yeux"
#define MAX_GENERATED_SDU 5

rle_sdu_t*make_sdu(rle_iterator_step step){
	static size_t make_sdu_nb;
	static rle_sdu_t curr_sdu = {size:sizeof(CONTENT),data:CONTENT};

	if(step == RLE_ITERATOR_FIRST){
		make_sdu_nb = 0;
	}
	curr_sdu.use_crc = make_sdu_nb&1;
	curr_sdu.protocol_type = ((uint16_t[]){0,1,0x0800,0x42})[make_sdu_nb&2];
	memset(&curr_sdu._,0,sizeof(curr_sdu._));
	return (make_sdu_nb++<MAX_GENERATED_SDU-1)?&curr_sdu:NULL;
}
rle_sdu_t*make_sdu_big(rle_iterator_step step){
	static rle_sdu_t big_sdu = {size:RLE_SDU_SIZE_MAX+1,data:CONTENT};
	return &big_sdu;
}

/* shared FPDU list between save_fpdu/load_fpdu*/
rle_fpdu_t saved_fpdu[MAX_GENERATED_SDU*10]={};
size_t saved_fpdu_nb;
rle_fpdu_t*save_fpdu(rle_iterator_step step){
	if(step == RLE_ITERATOR_FIRST){
		saved_fpdu_nb = 0;
	}
	return (saved_fpdu_nb<MAX_GENERATED_SDU*10-1)?&saved_fpdu[saved_fpdu_nb++]:NULL;
}
rle_fpdu_t*load_fpdu(rle_iterator_step step){
	static size_t loaded_fpdu_nb;
	if(step == RLE_ITERATOR_FIRST){
		loaded_fpdu_nb = 0;
	}
	if(loaded_fpdu_nb<saved_fpdu_nb){
		rle_fpdu_t*ret = &saved_fpdu[loaded_fpdu_nb];
		loaded_fpdu_nb++;
		return ret;
	}
	return NULL;
}

bool diff_sdu_found;
rle_sdu_t*diff_sdu(rle_iterator_step step){
	static rle_sdu_t diffed_sdu;
	if(step == RLE_ITERATOR_NEXT){
		bool diff = memcmp(CONTENT,diffed_sdu.recv_data,diffed_sdu.size);
		diff_sdu_found |= diff;
		if(diff){
			DUMP(diffed_sdu.recv_data,diffed_sdu.size)
			DUMP(CONTENT,diffed_sdu.size)
		}
	}
	memset(&diffed_sdu._,0,sizeof(diffed_sdu._));
	return &diffed_sdu;
}
void log_stderr(rle_log_level level, const char *format, ...){
	va_list valist;
	va_start(valist,format);
	vfprintf(stderr,format,valist);
	va_end(valist);
}

int main(){
	#define CHECK(msg, cond) fprintf(stderr,"[    ] "msg" ...");\
		if(!(cond)){fprintf(stderr,msg "\r[FAIL\n");failed=true;}\
		else{fprintf(stderr,"\r[ OK \n");}
	#define BUILD_CHECK(condition) ((void)sizeof(char[1-2*!(condition)]))

	bool failed = false;
	/* init */
	rle_init();

	/* ptype resolving */
	CHECK("short->long ptype resolving", rle_ptype_short[0x0D] == 0x0800);
	CHECK("long->short ptype resolving", rle_ptype_long[0x0800] == 0x0D);
	CHECK("Unknown long ptype resolving", rle_ptype_long[1234] == 0xFF);
	CHECK("Unknown short ptype resolving", rle_ptype_short[123] == 0xFFFF);

	CHECK("CRC self test", crc((uint8_t*)"123456789",9) == RLE_CRC_CHECK);
	/* compilation check */
	BUILD_CHECK(sizeof(ppdu_header_t) == 2);
	BUILD_CHECK(sizeof(ppdu_start_header_t) == 2);
	BUILD_CHECK(sizeof(ppdu_cont_header_t) == 2);
	BUILD_CHECK(sizeof(ppdu_end_header_t) == 2);
	BUILD_CHECK(sizeof(ppdu_full_header_t) == 2);
	BUILD_CHECK(sizeof(ppdu_start2_header_t) == 2);
	BUILD_CHECK(sizeof(fpdu_header_t) == 1);
	
	rle_profile profile = {/*log:log_stderr*/};
	profile.fpdu_max_size=RLE_FPDU_SIZE_MAX+1;
	CHECK("Encap a too big fpdu", rle_encap(&profile, make_sdu, save_fpdu) < 0);
	profile.fpdu_max_size=sizeof(ppdu_start_header_t) /*- ppdu_label_size*/ - RLE_FPDU_LABEL_SIZE -1;
	CHECK("Encap a too small fpdu", rle_encap(&profile, make_sdu, save_fpdu) < 0);
	profile.fpdu_max_size=0;//will use default (max) value
	CHECK("Encap a too big sdu", rle_encap(&profile, make_sdu_big, save_fpdu) < 0);
	
	
	/* {en,de}cap at multiple FPDU size */
	int i;
	for(i=0;i<2;i++){
		memset(saved_fpdu,0,sizeof(saved_fpdu));
		profile.fpdu_max_size=(i+1)*40;
		fprintf(stderr,"<frag=%zu>\n",profile.fpdu_max_size);
		CHECK("encap SDU into FPDU", rle_encap(&profile, make_sdu, save_fpdu) == 0);
		CHECK("decap FPDU into SDU", rle_decap(&profile, load_fpdu, diff_sdu) == 0);
		CHECK("compare original<->decapsulated",  !diff_sdu_found);
	}
	return failed;
	#undef CHECK
}
