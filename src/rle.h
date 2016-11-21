#include <stdint.h>
#include <stdbool.h>

#define RLE_CRC_POLY 0x04C11DB7
#define RLE_CRC_INIT 0xFFFFFFFF
#define RLE_CRC_CHECK 0x0376E6E7
#define RLE_PROTO_SIZE_MAX 3
#define RLE_PROTO_SIZE_MIN 0
#define RLE_ALPDU_LABEL_MAX 15
#define RLE_ALPDU_LABEL_MIN 0
#define RLE_ALPDU_SIZE_MAX ((1<<13)-1)
#define RLE_ALPDU_TYPE_COUNT 4
#define RLE_ALPDU_TRAILER_MAX 4
#define RLE_ALPDU_TRAILER_MIN 0
#define RLE_PPDU_HEADER_LEN sizeof(Ppdu_header)
#define RLE_FPDU_HEADER_START_OVERHEAD sizeof(Ppdu_start_extra)
#define RLE_PPDU_MIN_SIZE 0
#define RLE_PPDU_COUNT_MAX RLE_ALPDU_SIZE_MAX/RLE_MIN_ALPDU_SIZE //TODO
#define RLE_FPDU_SIZE_MAX 9000 //TODO
#define RLE_SDU_SIZE_MAX (RLE_ALPDU_SIZE_MAX -RLE_PROTO_SIZE_MIN-RLE_ALPDU_LABEL_MIN)
#define RLE_RECV_SIZE    (RLE_ALPDU_LABEL_MAX+RLE_PROTO_SIZE_MAX+RLE_SDU_SIZE_MAX+RLE_ALPDU_TRAILER_MAX)
#define RLE_RECV_OFFSET  (RLE_ALPDU_LABEL_MAX+RLE_PROTO_SIZE_MAX)

typedef struct{
//ALPDU
	uint16_t       implied_protocol_type[RLE_ALPDU_TYPE_COUNT];
	bool           protocol_type_compressed[RLE_ALPDU_TYPE_COUNT];
	bool           use_alpdu_seq;//disable crc if enabled
	bool           use_alpdu_crc;//unused if alpdu_seq!=0
	bool           large_alpdus;
	size_t         alpdu_label_size[RLE_ALPDU_TYPE_COUNT];
	uint8_t        alpdu_label_byte[RLE_ALPDU_TYPE_COUNT][RLE_ALPDU_LABEL_MAX];
//PPDU
	size_t         ppdu_max_size;
}rle_profile;
