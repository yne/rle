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
#define RLE_SDU_SIZE_MAX (RLE_ALPDU_SIZE_MAX-RLE_ALPDU_HEADER_MIN-RLE_ALPDU_FOOTER_MIN)

#define RLE_FPDU_SIZE_MAX 599 /* User defined */
#define RLE_FPDU_LABEL_SIZE 5 /* User defined */
#define RLE_FPDU_PROT_SIZE 4 /* User defined */
#define RLE_FPDU_DATA_SIZE (RLE_FPDU_SIZE_MAX-RLE_FPDU_LABEL_SIZE-RLE_FPDU_PROT_SIZE)
//RLE_FPDU_LABEL_SIZE+RLE_FPDU_PROT_SIZE > RLE_FPDU_SIZE_MAX
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

typedef struct{
	size_t    size;
	uint16_t  protocol_type;
	uint8_t*  label_byte;
	uint8_t   label_size:4,:4;
	uint8_t   label_type:2,:6;
	uint8_t   fragment_id:3,:5;
	bool      use_crc;

	uint8_t   _pre[RLE_ALPDU_HEADER_MAX];
	uint8_t   data[RLE_SDU_SIZE_MAX];
	uint8_t   _suf[RLE_ALPDU_FOOTER_MAX];
	struct    {/* internal attributs */
	  bool    ptype_suppr;
	  size_t  header_size;
	  size_t  footer_size;
	  size_t  alpdu_sent;
	  bool    is_frag;
	  bool    is_alpdu;
	}_;
}rle_sdu_t;

typedef struct{
	size_t    size;
	uint8_t   label[RLE_FPDU_LABEL_SIZE];
	uint8_t   data[RLE_FPDU_DATA_SIZE];
	uint8_t   prot[RLE_FPDU_PROT_SIZE];
}rle_fpdu_t;

typedef rle_fpdu_t*(*rle_fpdu_iter)();
typedef rle_sdu_t *(*rle_sdu_iter )();