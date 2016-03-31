#include <stdint.h>
#include <stdbool.h>

#define RLE_MAX_PROTO 3 //0,1,2,3
#define RLE_MAX_LABEL 15 // 0-15
#define RLE_MAX_ALPDU 8191
#define RLE_MAX_SDU (RLE_MAX_ALPDU - RLE_MAX_PROTO - RLE_MAX_LABEL)
#define RLE_MAX_PPDU 42 //TODO

typedef enum{NONE, SEQUENCE, CRC32} rle_protection;
typedef struct{
//ALPDU
	bool           ptype_compress;
	bool           ptype_suppress;
	uint16_t       ptype_default;
	bool           alpdu_seq;//disable crc if enabled
	bool           alpdu_crc;//unused if alpdu_seq!=0
	bool           large_alpdus;
//PPDU
	size_t         ppdu_max_size;
	size_t         alpdu_label_size;
}rle_profile;


#define ALPDU_LABEL_MAX 16
#define ALPDU_HEADER_MAX (1+ALPDU_LABEL_MAX+2)
#define ALPDU_FOOTER_MAX (4)

typedef struct {
	int start:1;
	int end:1;
	int length:11;
	union{
		//comp
		int LabelType:2;
		int OmitProto:1;
		//start,cont,end
		int FragId:3;
	};
	int PPDU_Label  :ALPDU_LABEL_MAX;
	//start only
	int _OmitProto:1;
	int nb_ppdu:12;
	int _LabelType:2;
	int __OmitProto:1;
}rle_ppdu;

typedef struct{
	uint8_t alpdu_header[ALPDU_HEADER_MAX];
	size_t alpdu_header_length;

	rle_ppdu ppdu[RLE_MAX_PPDU];
	size_t ppdu_count;

	uint8_t alpdu_footer[ALPDU_FOOTER_MAX];
	size_t alpdu_footer_length;
}rle_fpdu;

/*
  +--  SDU <-+     payload
encap      decap
  |  ALPDU   |     @@@payload~ (max 4095B)
fragm      reasm
  |   PPDU   |     ####@@@p ##aylo ##ad~
fpack      upack
  +-> FPDU --+     ####@@@p##aylo##ad~__
*/
