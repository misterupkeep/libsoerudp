#include <libsoerudp/packet_types.h>

/* ntohl(), ntohs() */
#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <libsoerudp/defines.h>

static unsigned int crc_table[256] = {0};

__attribute__((constructor))
__SOE_LOCAL
void
generate_crc32_table()
{
	/* Table might already be generated */
	if(crc_table[1] != 0) return;

	unsigned int c;
	int n, k;
	for (n = 0; n < 256; n++) {
		c = n;
		for (k = 0; k < 8; k++) {
			if (c & 1)
				c = 0xedb88320L ^ (c >> 1);
			else
				c >>= 1;
		}
		crc_table[n] = c;
	}
}

uint32_t
soe_crc32(uint32_t crc_seed, const uint8_t data[], size_t len)
{
	uint_fast32_t r = 0xFFFFFFFF;

	/* #crcSeed is prepended little-endian (host order) to the data */
	for(int i = 0; i < 4; i++) r = ((r >> 8) & 0x00FFFFFF) ^ crc_table[(*(((char *)&crc_seed)+i) ^ r) & 0xFF];

	/* Regular (reflected) CRC calculation */
	while(len--) r = ((r >> 8) & 0x00FFFFFF) ^ crc_table[(*data++ ^ r) & 0xFF];

	return ~r;
}

#define n32(buf, offset) ntohl(*(uint32_t *)(buf + offset));
#define n16(buf, offset) ntohs(*(uint16_t *)(buf + offset));
#define h32(buf, offset) *(uint32_t *)(buf + offset)

__SOE_LOCAL
soe_session_request *
parse_session_request(const uint8_t buf[], size_t len)
{
	/* Invalid by virtue of being too short */
	if(len <= 13) return NULL;

	soe_session_request *req = malloc(sizeof(soe_session_request));
	if(req == NULL) return NULL;

	req->crc_length = n32(buf, 0);

	/* The connection ID is useless;
	   no need to swap endianness. */
	req->conn_id = h32(buf, 4);

	req->buf_size = n32(buf, 8);

	size_t version_str_sz = len - 12;
	req->version = malloc(version_str_sz);
	if(req->version == NULL) {
		free(req);
		return NULL;
	}
	strcpy(req->version, (char *)buf + 12);

	return req;
}

__SOE_LOCAL
soe_session_reply *
parse_session_reply(const uint8_t buf[], size_t len)
{
	/* Invalid by virtue of being too short */
	if(len <= 18) return NULL;

	soe_session_reply *res = malloc(sizeof(soe_session_reply));
	if(res == NULL) return NULL;

	/* The connection ID is useless;
	   no need to swap endianness. */
	res->conn_id = h32(buf, 0);

	res->crc_seed = n32(buf, 4);
	res->crc_length = *(buf + 8);
	res->zflag = *(buf + 9);
	res->enc_flag = *(buf + 10);
	res->buf_size = n32(buf, 11);
	res->footer = n32(buf, 15);

	return res;
}

#include <zlib.h>

__SOE_LOCAL
soe_data_packet *
parse_data_packet_multi(const uint8_t buf[], size_t len)
{
	soe_data_packet *data = malloc(sizeof(soe_session_request));
	if(data == NULL) return NULL;

	data->_has_zflag_crc = 0;

	/* Everything is data except starting seq_num short */
	data->_data_sz = len - 2;

	data->data = malloc(len);
	if(data->data == NULL) goto packet_free;
	memcpy(data->data, buf + 2, data->_data_sz);

	/* Would have been already compressed if inside SOE_MULTI_SOE */
	data->zflag = 0;

	data->seq_num = n16(buf, 0);

	return data;

packet_free:
	free(data);
	return NULL;
}


 // TODO: #data_sz parametrised by buffer size
/** Reads and sets zflag, checks CRC, uncompresses data, reads and
 * sets _data_sz
 */
#define DATA_PACKET_UNCOMPRESS_BOILERPLATE(p)				\
	p->zflag = *buf;						\
	p->crc = n16(buf, len - 2);					\
									\
        uint16_t calculated_crc = soe_crc32(crc_seed, buf, len - 2) & 0xFFFF; \
	if(p->crc != calculated_crc) goto packet_free;			\
									\
	size_t data_sz;							\
	if(p->zflag) data_sz = 512;					\
	else p->_data_sz = data_sz = len - 3;				\
									\
	p->data = malloc(data_sz);					\
	if(p->data == NULL) goto packet_free;				\
									\
	if (p->zflag) {							\
		int err = uncompress(p->data, &data_sz, buf + 1, len - 3); \
		if (err != Z_OK) goto data_free;			\
		p->_data_sz = data_sz;					\
	} else {							\
		memcpy(p->data, buf + 1, len - 3);			\
	}


__SOE_LOCAL
soe_data_packet *
parse_data_packet(const uint8_t buf[], size_t len, uint32_t crc_seed)
{
	soe_data_packet *data = malloc(sizeof(soe_session_request));
	if(data == NULL) return NULL;

	data->_has_zflag_crc = 1;

	DATA_PACKET_UNCOMPRESS_BOILERPLATE(data);

	data->seq_num = n16(data->data, 0);

	return data;

data_free:
	free(data->data);
packet_free:
	free(data);
	return NULL;
}

__SOE_LOCAL
soe_fragment_packet *
parse_fragmented_packet_multi(const uint8_t buf[], size_t len, int initial_packet)
{
	soe_fragment_packet *fragment = malloc(sizeof(soe_fragment_packet));
	if(fragment == NULL) return NULL;

	fragment->_has_zflag_crc = 1;

	fragment->seq_num = n16(buf, 0);

	fragment->_data_sz = len - 2;
	fragment->data = malloc(fragment->_data_sz);
	if(fragment->data) goto packet_free;

	memcpy(fragment->data, buf + 2, fragment->_data_sz);

	if(initial_packet) {
		fragment->total_sz = n32(fragment->data, 2);
	} else {
		fragment->total_sz = 0;
	}

	return fragment;

data_free:
	free(fragment->data);
packet_free:
	free(fragment);
	return NULL;
}

__SOE_LOCAL
soe_fragment_packet *
parse_fragmented_packet(const uint8_t buf[], size_t len, uint32_t crc_seed, int initial_packet)
{
	soe_fragment_packet *fragment = malloc(sizeof(soe_fragment_packet));
	if(fragment == NULL) return NULL;

	fragment->_has_zflag_crc = 0;

	DATA_PACKET_UNCOMPRESS_BOILERPLATE(fragment);
	fragment->seq_num = n16(fragment->data, 0);

	if(initial_packet) {
		fragment->total_sz = n32(fragment->data, 2);
	} else {
		fragment->total_sz = 0;
	}

	return fragment;

data_free:
	free(fragment->data);
packet_free:
	free(fragment);
	return NULL;
}

__SOE_LOCAL
soe_multi_packet *
parse_multi(const uint8_t buf[], size_t len, uint32_t crc_seed)
{
	soe_multi_packet *multi = malloc(sizeof(soe_multi_packet));
	if(multi == NULL) return NULL;

	DATA_PACKET_UNCOMPRESS_BOILERPLATE(multi);

	multi->_start_index = 0;

	return multi;

data_free:
	free(multi->data);
packet_free:
	free(multi);
	return NULL;
}

__SOE_LOCAL
soe_ack *
parse_ack_out_order_multi(const uint8_t buf[], size_t len)
{
	soe_ack *ack_out_order = malloc(sizeof(soe_ack));
	if(ack_out_order == NULL) return NULL;

	ack_out_order->_has_zflag_crc = 0;

	ack_out_order->seq_num = n16(buf, 0);

	return ack_out_order;
}

__SOE_LOCAL
soe_ack *
parse_ack_out_order(const uint8_t buf[], size_t len, uint32_t crc_seed)
{
	soe_ack *ack_out_order = malloc(sizeof(soe_ack));
	if(ack_out_order == NULL) return NULL;

	ack_out_order->_has_zflag_crc = 1;
	ack_out_order->zflag = *buf;
	ack_out_order->seq_num = n16(buf, 1);
	ack_out_order->crc = n16(buf, 3);

	uint16_t calculated_crc = soe_crc32(crc_seed, buf, len - 2) & 0xFFFF;
	if(ack_out_order->crc != calculated_crc) {
		free(ack_out_order);
		return NULL;
	}

	return ack_out_order;
}

#define PACKET_HANDLER_CALL(f, ...) {					\
		void *_ptr = f(buf + 2, len - 2, ##__VA_ARGS__);	\
		if(_ptr == NULL) goto packet_free;			\
		packet->data = _ptr;					\
	}

#define HANDLE_PACKET(t, f, ...) case t:				\
	PACKET_HANDLER_CALL(f, ##__VA_ARGS__)				\
	break;

__SOE_LOCAL
soe_rudp_packet *
parse_packet_in_multi(const uint8_t buf[], size_t len, uint8_t initial_packet)
{
	/* Invalid by virtue of being too short */
	if(len < 4) return NULL;

	uint16_t opcode = ntohs(*(uint16_t *)buf);

	/* Invalid opcode */
	if(opcode >= SOE_OPCODE_COUNT || opcode == 0) return NULL;

	soe_rudp_packet *packet = malloc(sizeof(soe_rudp_packet));
	if(packet == NULL) return NULL;

	packet->type = opcode;

	switch(opcode) {
		HANDLE_PACKET(SOE_SESSION_REQUEST, parse_session_request);
		HANDLE_PACKET(SOE_SESSION_REPLY, parse_session_reply);
	case SOE_CHL_DATA_A:
	case SOE_CHL_DATA_B:
	case SOE_CHL_DATA_C:
	case SOE_CHL_DATA_D:
		PACKET_HANDLER_CALL(parse_data_packet_multi);
		break;
	case SOE_DATA_FRAG_A:
	case SOE_DATA_FRAG_B:
	case SOE_DATA_FRAG_C:
	case SOE_DATA_FRAG_D:
		PACKET_HANDLER_CALL(parse_fragmented_packet_multi, initial_packet);
		break;
	case SOE_ACK_A:
	case SOE_ACK_B:
	case SOE_ACK_C:
	case SOE_ACK_D:
	case SOE_OUT_ORDER_PKT_A:
	case SOE_OUT_ORDER_PKT_B:
	case SOE_OUT_ORDER_PKT_C:
	case SOE_OUT_ORDER_PKT_D:
		PACKET_HANDLER_CALL(parse_ack_out_order_multi);
		break;
	default:
		goto packet_free;
	}

	return packet;

	/* Used implicitly in PACKET_HANDLER_CALL macro */
packet_free:
	free(packet);
	return NULL;

}

soe_rudp_packet *
parse_multi_packet(soe_multi_packet *packet, uint8_t initial_packet)
{
	if(packet->_start_index >= packet->_data_sz) return NULL;

	uint8_t len = *(packet->data + packet->_start_index++);
	soe_rudp_packet *parsed = parse_packet_in_multi(packet->data + packet->_start_index, len, initial_packet);
	packet->_start_index += len;

	return parsed;
}

soe_rudp_packet *
parse_packet(const uint8_t buf[], size_t len, uint32_t crc_seed, uint8_t initial_packet)
{
	/* Invalid by virtue of being too short */
	if(len < 4) return NULL;

	uint16_t opcode = ntohs(*(uint16_t *)buf);

	/* Invalid opcode */
	if(opcode >= SOE_OPCODE_COUNT || opcode == 0) return NULL;

	soe_rudp_packet *packet = malloc(sizeof(soe_rudp_packet));
	if(packet == NULL) return NULL;

	packet->type = opcode;

	switch(opcode) {
		HANDLE_PACKET(SOE_SESSION_REQUEST, parse_session_request);
		HANDLE_PACKET(SOE_SESSION_REPLY, parse_session_reply);
		HANDLE_PACKET(SOE_MULTI_SOE, parse_multi, crc_seed);
	case SOE_CHL_DATA_A:
	case SOE_CHL_DATA_B:
	case SOE_CHL_DATA_C:
	case SOE_CHL_DATA_D:
		PACKET_HANDLER_CALL(parse_data_packet, crc_seed);
		break;
	case SOE_DATA_FRAG_A:
	case SOE_DATA_FRAG_B:
	case SOE_DATA_FRAG_C:
	case SOE_DATA_FRAG_D:
		PACKET_HANDLER_CALL(parse_fragmented_packet, crc_seed, initial_packet);
		break;
	case SOE_ACK_A:
	case SOE_ACK_B:
	case SOE_ACK_C:
	case SOE_ACK_D:
	case SOE_OUT_ORDER_PKT_A:
	case SOE_OUT_ORDER_PKT_B:
	case SOE_OUT_ORDER_PKT_C:
	case SOE_OUT_ORDER_PKT_D:
		PACKET_HANDLER_CALL(parse_ack_out_order, crc_seed);
		break;
	default:
		goto packet_free;
	}

	return packet;

	/* Used implicitly in PACKET_HANDLER_CALL macro */
packet_free:
	free(packet);
	return NULL;
}
