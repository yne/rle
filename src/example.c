#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "rle.h"

int usage(char* name){
	fprintf(stderr, "Usage: %s [OPTION]... MODE\n"
	"  OPTIONS:\n"
	"    -S           Use Sequence protection\n"
	"    -C           Use CRC protection\n"
	"    -L           Use Large ALPDU mode\n"
	"    -F           Use Frame protection\n"
	"    -M           Use FPDU header Map\n"
	"    -P=y,n,y,y   Use short Protocols types\n"
	"    -i=N,N,N,N   Implied protocols types\n"
	"    -l=S,S,S,S   ALPDU labels\n"
	"    -f=N         FPDU max size []\n"
	"  MODE:\n"
	"    encap        encapsulate given SDUs into FPDUs\n"
	"    decap        decapsulate given FPDUs into SDUs\n"
	, name);
	return -1;
}

rle_sdu_t*read_sdu(rle_iterator_step step){
	static rle_sdu_t sdu;
	memset(&sdu._,0,sizeof(sdu._));
	if(step != RLE_ITERATOR_FIRST){
		sdu.size=read(STDIN_FILENO,sdu.data,sizeof(sdu.data));
		//fprintf(stderr,"SDU->%zu\n",sdu.size);
	}
	return &sdu;
}
rle_fpdu_t*write_fpdu(rle_iterator_step step){
	static rle_fpdu_t fpdu;
	if(step != RLE_ITERATOR_FIRST){
		write(STDOUT_FILENO,fpdu.data,fpdu.size);
		//fprintf(stderr,"FPDU->%zu\n",fpdu.size);
	}
	fpdu.size=0;
	return &fpdu;
}
rle_fpdu_t*read_fpdu(rle_iterator_step step){
	static rle_fpdu_t fpdu;
	fpdu.size=read(STDIN_FILENO,fpdu.data,sizeof(fpdu.data));
	return &fpdu;
}
rle_sdu_t*write_sdu(rle_iterator_step step){
	static rle_sdu_t sdu;
	write(STDOUT_FILENO,sdu.recv_data,sdu.size);
	memset(&sdu._,0,sizeof(sdu._));
	sdu.size=0;
	return &sdu;
}

int main(int argc, char**argv){
	rle_profile profile = {/*log:log_stderr*/};
	int opt;
	while ((opt = getopt(argc, argv, "SCLFMP:i:l:f:")) != -1) {
		switch (opt) {
			case 'S':profile.use_alpdu_seq = true;break;
			case 'C':profile.use_alpdu_crc = true;break;
			case 'L':profile.large_alpdus  = true;break;
			case 'F':profile.use_frame_protection = true;break;
			case 'M':profile.use_eplh_map  = true;break;
			case 'P':sscanf(optarg,"%i,%i,%i,%i",
			                (int*)&profile.use_ptype_short[0],
			                (int*)&profile.use_ptype_short[1],
			                (int*)&profile.use_ptype_short[2],
			                (int*)&profile.use_ptype_short[3]);break;
			case 'i':sscanf(optarg,"%hu,%hu,%hu,%hu",
			                &profile.implied_ptype[0],
			                &profile.implied_ptype[1],
			                &profile.implied_ptype[2],
			                &profile.implied_ptype[3]);break;
			/*case 'l':sscanf(optarg,"%15c,%15c,%15c,%15c",
			                &profile.alpdu_label_byte[0],
			                &profile.alpdu_label_byte[1],
			                &profile.alpdu_label_byte[2],
			                &profile.alpdu_label_byte[3]);
			                profile.alpdu_label_size[0]=
			                profile.alpdu_label_size[1]=
			                profile.alpdu_label_size[2]=
			                profile.alpdu_label_size[3]=RLE_ALPDU_LABEL_MAX;break;*/
			case 'f':profile.fpdu_max_size = atoi(optarg);break;
			default:return usage(argv[0]);
		}
	}
	if (optind >= argc) {
		fprintf(stderr, "Missing MODE (encap/decap)\n");
		return usage(argv[0]);
	}
	if(argv[optind][0]=='e'){
		rle_encap(&profile, read_sdu, write_fpdu);
	}else{
		rle_decap(&profile, read_fpdu, write_sdu);
	}
	return 0;
}