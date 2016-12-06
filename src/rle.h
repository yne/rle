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
#define RLE_FPDU_PADDING 0x00
#define RLE_FPDU_SIZE_MAX 599 /* User defined */
#define RLE_FPDU_LABEL_SIZE 8 /* User defined */
#define RLE_FPDU_PROT_SIZE 4 /* User defined */
#define RLE_FPDU_DATA_SIZE (RLE_FPDU_SIZE_MAX-RLE_FPDU_LABEL_SIZE-RLE_FPDU_PROT_SIZE)

typedef enum{
	RLE_LOG_CRI,
	RLE_LOG_ERR,
	RLE_LOG_WRN,
	RLE_LOG_NFO,
	RLE_LOG_DBG,
}rle_log_level;

typedef void (*rle_log)(rle_log_level level, const char *format, ...);

typedef struct{
/* ALPDU */
	uint16_t  implied_ptype[RLE_ALPDU_TYPE_COUNT];
	bool      use_ptype_short[RLE_ALPDU_TYPE_COUNT];
	bool      use_alpdu_seq;
	bool      use_alpdu_crc;/*only used when !alpdu_seq*/
	bool      large_alpdus;
	size_t    alpdu_label_size[RLE_ALPDU_TYPE_COUNT];
	uint8_t   alpdu_label_byte[RLE_ALPDU_TYPE_COUNT][RLE_ALPDU_LABEL_MAX];
/* PPDU */
	uint8_t   alpdu_seq_send[RLE_ALPDU_FRAGID_COUNT];/*TODO:use specific structure*/
	uint8_t   alpdu_seq_recv[RLE_ALPDU_FRAGID_COUNT];/*TODO:use specific structure*/
	size_t    fpdu_max_size;
	bool      use_frame_protection;
	bool      use_eplh_map;
/* General */
	rle_log   log;

}rle_profile;

typedef struct{
	size_t    size;
	uint16_t  protocol_type;
	uint8_t*  label_byte;
	uint8_t   label_size:4,:4;
	uint8_t   label_type:2,:6;
	uint8_t   fragment_id:3,:5;
	bool      use_crc;
	uint8_t*  recv_data;/*pointer to data (receiving case only)*/

	uint8_t   _header[RLE_ALPDU_HEADER_MAX];
	uint8_t   data[RLE_SDU_SIZE_MAX];
	uint8_t   _footer[RLE_ALPDU_FOOTER_MAX];
	struct    {/* internal attributs */
	  size_t  header_size;
	  size_t  footer_size;
	  bool    ptype_suppr;
	  size_t  alpdu_sent;
	  bool    is_frag;
	}_;
}rle_sdu_t;

typedef struct{
	size_t    size;
	uint8_t   data[RLE_FPDU_LABEL_SIZE+RLE_FPDU_DATA_SIZE+RLE_FPDU_PROT_SIZE];
}rle_fpdu_t;

typedef enum{
	RLE_ITERATOR_FIRST,
	RLE_ITERATOR_NEXT,
	RLE_ITERATOR_LAST,
}rle_iterator_step;

typedef rle_fpdu_t*(*rle_iterator_fpdu)(rle_iterator_step);
typedef rle_sdu_t *(*rle_iterator_sdu )(rle_iterator_step);

extern int rle_encap(rle_profile* profile, rle_iterator_sdu next_sdu, rle_iterator_fpdu next_fpdu);
extern int rle_decap(rle_profile* profile, rle_iterator_fpdu next_fpdu, rle_iterator_sdu next_sdu);

/* Internal structs */

typedef struct __attribute__((packed)){
	uint16_t start_indicator:1;
	uint16_t end_indicator:1;
	uint16_t ppdu_length:11;/* length of the PPDU exclusive of the two byte PPDU header and exclusive of the PPDU label*/
	uint16_t frag_id:3;/* label_type:2 ptsuppr:1 (for full only)*/
} ppdu_header_t;

typedef struct __attribute__((packed)){
	uint16_t total_length:13;/* msb is use_alpdu_crc if not profile->large_alpdu */
	uint16_t label_type:2;
	uint16_t ptype_suppr:1;
} ppdu_start2_header_t;

typedef ppdu_header_t ppdu_start_header_t;
typedef ppdu_header_t ppdu_cont_header_t;
typedef ppdu_header_t ppdu_end_header_t;
typedef ppdu_header_t ppdu_full_header_t;

typedef struct __attribute__((packed)){
	uint8_t payload_len:4;
	uint8_t ppdu_label_len:4;
} fpdu_header_t;
