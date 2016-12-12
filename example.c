#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <string.h>
#include "rle.c"
#define DBG 
int usage(char* name){
	fprintf(stderr, "Usage: %s [OPTIONS]... MODE"
	"\n OPTIONS:"
	"\n   -v           Verbose mode"
	"\n   -S           Use Sequence protection"
	"\n   -C           Use CRC protection"
	"\n   -A           Use large ALPDU mode"
	"\n   -F           Use Frame protection"
	"\n   -M           Use FPDU header Map"
	"\n   -P=y,n,y,y   Use short Protocols types"
	"\n   -i=N,N,N,N   Implied protocols types"
	"\n   -l=S,S,S,S   ALPDU labels"
	"\n   -L=S         FPDU labels"
	"\n   -f=N         FPDU size"
	"\n   -s=N         SDU size"
	"\n   -t=N         Temporize (us)"
	"\n MODE:"
	"\n   encap        encapsulate given SDUs into FPDUs"
	"\n   decap        decapsulate given FPDUs into SDUs"
	"\n", name);
	return -1;
}
//sanitize
rle_sdu_t sdu;
rle_fpdu_t fpdu;
size_t sdu_size=sizeof(sdu.data);
size_t duration=0;
char* color="",*reset="\x1b[0m";

rle_sdu_t*read_sdu(rle_iterator_step step){
	sdu.size=read(STDIN_FILENO,sdu.data,sdu_size);
	usleep(duration);
	DBG(stderr,"%s(%zu>%s",color,sdu.size,reset);
	return &sdu;
}
rle_fpdu_t*write_fpdu(rle_iterator_step step){
	write(STDOUT_FILENO,fpdu.data,fpdu.size);
	usleep(duration);
	DBG(stderr,"%s[%zu]%s",color,fpdu.size,reset);
	return &fpdu;
}
rle_fpdu_t*read_fpdu(rle_iterator_step step){
	fpdu.size=read(STDIN_FILENO,fpdu.data,sizeof(fpdu.data));
	usleep(duration);
	DBG(stderr,"%s[%zu]%s",color,fpdu.size,reset);
	return &fpdu;
}
rle_sdu_t*write_sdu(rle_iterator_step step){
	write(STDOUT_FILENO,sdu.recv_data,sdu.size);
	usleep(duration);
	DBG(stderr,"%s(%zu>%s",color,sdu.size,reset);
	return &sdu;
}
void log_stderr(rle_log_level level, const char *format, ...){
	fprintf(stderr,"%s",color);
	va_list valist;
	va_start(valist,format);
	vfprintf(stderr,format,valist);
	va_end(valist);
	fprintf(stderr,"%s",reset);
}

int main(int argc, char**argv){
	rle_profile profile = {};
	int opt;
	while ((opt = getopt(argc, argv, "vSCAFMP:i:l:f:s:t:")) != -1) {
		switch (opt) {
			case 'v':profile.log = log_stderr;break;
			case 'S':profile.use_alpdu_seq = true;break;
			case 'C':profile.use_alpdu_crc = true;break;
			case 'A':profile.large_alpdus  = true;break;
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
			case 'L':profile.fpdu_label_size = atoi(optarg);break;
			case 'F':profile.fpdu_pro_size = atoi(optarg);break;
			case 'f':profile.fpdu_max_size = atoi(optarg);break;
			case 's':sdu_size = atoi(optarg);break;
			case 't':duration = atoi(optarg);break;
			default:return usage(argv[0]);
		}
	}
	if (optind >= argc) {
		fprintf(stderr, "Missing MODE (encap/decap)\n");
		return usage(argv[0]);
	}
	rle_init();
	if(argv[optind][0]=='e'){
		color="\x1b[31m";
		rle_encap(&profile, read_sdu, write_fpdu);
	}else{
		color="\x1b[32m";
		rle_decap(&profile, read_fpdu, write_sdu);
	}
	return 0;
}