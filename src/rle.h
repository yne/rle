#include <stdint.h>
#include <stdbool.h>

#define RLE_CRC_POLY 0x04C11DB7
#define RLE_CRC_INIT 0xFFFFFFFF
#define RLE_CRC_CHECK 0x0376E6E7
#define RLE_ALPDU_PROTO_MAX 3
#define RLE_ALPDU_PROTO_MIN 0
#define RLE_ALPDU_LABEL_MAX 15
#define RLE_ALPDU_LABEL_MIN 0
#define RLE_ALPDU_SIZE_MAX ((1<<13)-1)
#define RLE_ALPDU_TYPE_MIN 0
#define RLE_ALPDU_TYPE_MAX 3
#define RLE_ALPDU_TYPE_COUNT 4
#define RLE_ALPDU_FRAGID_COUNT 8
#define RLE_ALPDU_HEADER_MAX (RLE_ALPDU_PROTO_MAX+RLE_ALPDU_LABEL_MAX)
#define RLE_ALPDU_HEADER_MIN (RLE_ALPDU_PROTO_MIN+RLE_ALPDU_LABEL_MIN)
#define RLE_ALPDU_FOOTER_MAX 4
#define RLE_ALPDU_FOOTER_MIN 0
#define RLE_PPDU_HEADER_LEN  (sizeof(ppdu_header_t))
#define RLE_PPDU_HEADER_START_LEN (sizeof(ppdu_header_t)+sizeof(ppdu_start_t))

#define RLE_PPDU_TYPE_CONT  start_indicator:0,end_indicator:0
#define RLE_PPDU_TYPE_END   start_indicator:0,end_indicator:1
#define RLE_PPDU_TYPE_START start_indicator:1,end_indicator:0
#define RLE_PPDU_TYPE_COMP  start_indicator:1,end_indicator:1

#define RLE_PPDU_SIZE_MIN 0
#define RLE_PPDU_SIZE_MAX 0
#define RLE_FPDU_SIZE_MAX 599 /* User defined */
#define RLE_FPDU_LABEL_SIZE 12 /* User defined */
#define RLE_FPDU_PROT_SIZE 4 /* User defined */
#define RLE_SDU_SIZE_MAX (RLE_ALPDU_SIZE_MAX-RLE_ALPDU_HEADER_MIN-RLE_ALPDU_FOOTER_MIN)

typedef struct{
//ALPDU
	uint16_t  implied_protocol_type[RLE_ALPDU_TYPE_COUNT];
	bool      protocol_type_compressed[RLE_ALPDU_TYPE_COUNT];
	bool      use_alpdu_seq;
	bool      use_alpdu_crc;//only used when !alpdu_seq
	bool      large_alpdus;
	size_t    alpdu_label_size[RLE_ALPDU_TYPE_COUNT];
	uint8_t   alpdu_label_byte[RLE_ALPDU_TYPE_COUNT][RLE_ALPDU_LABEL_MAX];
//PPDU      
	uint8_t   alpdu_seq[RLE_ALPDU_FRAGID_COUNT];
	size_t    fpdu_max_size;
	bool      use_frame_protection;
	bool      use_explicit_payload_header_map;
}rle_profile;

typedef struct __attribute__((packed)){
	/* the followings should be 0-memset by default */
	size_t    size;
	uint16_t  protocol_type;
	uint8_t*  label_byte;
	uint8_t   label_size:4,:4;
	uint8_t   label_type:2,:6;
	uint8_t   fragment_id:3,:5;
	bool      use_crc;
	bool      done;/* ==true once fully sent into FPDU */
	/* the followings need to be ((packed)) next to each other */
	uint8_t   _pre[RLE_ALPDU_HEADER_MAX];
	uint8_t   data[RLE_SDU_SIZE_MAX];
	uint8_t   _suf[RLE_ALPDU_FOOTER_MAX];
	/* internals attributs (underscore-prefixed) */
	bool      _protocol_type_suppressed;
	size_t    _header_size;
	size_t    _footer_size;
	size_t    _sent_size;
	bool      _is_frag;
	bool      _is_alpdu;
}rle_sdu_t;

typedef struct __attribute__((packed)){
	size_t    size;
	uint8_t   data[RLE_FPDU_SIZE_MAX];
	size_t    _offset;
}rle_fpdu_t;

typedef rle_fpdu_t*(*rle_fpdu_iter)();
typedef rle_sdu_t *(*rle_sdu_iter )();

//int rle_encap(rle_profile* profile, rle_sdu_t** sdus, rle_fpdu_t** fpdus)
//              __attribute__((warn_unused_result, nonnull (1,2,3)));