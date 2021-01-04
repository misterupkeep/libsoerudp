#ifndef LIBSOERUDP_PACKET_TYPES
#define LIBSOERUDP_PACKET_TYPES
/** The layout of packets and their opcodes are defined here.
 *
 * Struct member identifiers starting with an underscore `_` aren't
 * actually present in the packet: they are used internally.
 */

#include <stddef.h>
#include <stdint.h>

/** Packet types and their opcodes.
 * Opcodes are 2 bytes wide.
 */
enum SOE_PACKET_TYPE {
	SOE_SESSION_REQUEST = 0x0001,
	SOE_SESSION_REPLY = 0x0002,

	SOE_MULTI_SOE  = 0x0003, /**< Grouped packets */
	SOE_NOT_USED = 0x0004, /**< Reserved */

	SOE_DISCONNECT = 0x0005,
	SOE_PING = 0x0006,

	SOE_NET_STATUS_REQ = 0x0007,
	SOE_NET_STATUS_RES = 0x0008,

	SOE_CHL_DATA_A = 0x0009,
	SOE_CHL_DATA_B = 0x000A,
	SOE_CHL_DATA_C = 0x000B,
	SOE_CHL_DATA_D = 0x000C,

	SOE_DATA_FRAG_A = 0x000D,
	SOE_DATA_FRAG_B = 0x000E,
	SOE_DATA_FRAG_C = 0x000F,
	SOE_DATA_FRAG_D = 0x0010,

	SOE_OUT_ORDER_PKT_A = 0x0011,
	SOE_OUT_ORDER_PKT_B = 0x0012,
	SOE_OUT_ORDER_PKT_C = 0x0013,
	SOE_OUT_ORDER_PKT_D = 0x0014,

	SOE_ACK_A = 0x0015,
	SOE_ACK_B = 0x0016,
	SOE_ACK_C = 0x0017,
	SOE_ACK_D = 0x0018,

	SOE_MULTI_A = 0x0019,
	SOE_MULTI_B = 0x001A,
	SOE_MULTI_C = 0x001B,
	SOE_MULTI_D = 0x001C,

	SOE_FATAL_ERR = 0x001D,
	SOE_FATAL_ERR_REPLY = 0x001E,

	SOE_OPCODE_COUNT
};

typedef struct {
	uint16_t type;
	void *data; /**< Pointer to one of #soe_session_request,
		     * #soe_session_reply, #soe_data_packet, #soe_ack,
		     * #soe_out_order_pkt */
} soe_rudp_packet;

/** Supported version string */
#define SOE_RUDP_VERSION CGAPI_527

/** Sent by prospective clients to initiate a session
 */
typedef struct {
	uint32_t crc_length;
	/**< CRC checksum length. Usually 2 */

	uint32_t conn_id;
	/**< Connection ID. Perplexingly set by the client */

	uint32_t buf_size;
	/**< Client's buffer size. The server honors this by sending
	 * data in chunks up to this size. */

	char *version;
	/**< Version string. This library supports only version
	 * #SOE_RUDP_VERSION */
} soe_session_request;

/** Send by the server as a reply to client requesting a session
 */
typedef struct {
	uint32_t conn_id;
	/**< Connection ID. Same value as #soe_session_request#conn_id */

	uint32_t crc_seed;
	/**< Initial CRC value */

	uint8_t crc_length;
	/**< CRC checksum length. Usually 2 */

	uint8_t zflag;
	/**< Indicates support for compression (gzip) */

	uint8_t enc_flag;
	/**< Indicates whether subsequent data is encrypted. Usually 0 */

	uint32_t buf_size;
	/**< Server's buffer size. The client honors this by sending
	 * data in chunks up to this size. */

	uint32_t footer;
	/**< Unknown meaning. Usually set to 3 */
} soe_session_reply;

/** Reliably-sent data.
 */
typedef struct {
	uint8_t _has_zflag_crc;
	/**< Not part of packet. Used internally */

	uint8_t zflag;
	/**< Is the rest of the packet compressed? */

	size_t _data_sz;
	/**< Not part of packet. Size of #data buffer. */

	uint8_t *data;
	/**< Sent data */

	uint16_t seq_num;
	/**< This packet's sequence number. First half-word inside
	 * #data */

	uint16_t crc;
	/**< CRC checksum */
} soe_data_packet;

/** (A chunk of) Reliably-sent data.
 */
typedef struct {
	uint8_t _has_zflag_crc;
	/**< Not part of packet. Used internally */

	uint8_t zflag;
	/**< Is the rest of the packet compressed? */

	size_t _data_sz;
	/**< Not part of packet. Size of #data buffer. */

	uint8_t *data;
	/**< Sent data */

	uint16_t seq_num;
	/**< This packet's sequence number. First half-word inside
	 * #data */

	uint32_t total_sz;
	/**< Total size of the reassembled data. Only present in the
	 * first fragmented packet in a series. First word after
	 * #seq_num */

	uint16_t crc;
	/**< CRC checksum */
} soe_fragment_packet;

typedef struct {
	uint8_t zflag;
	/**< Is the rest of the packet compressed? */

	size_t _data_sz;
	/**< Not part of packet. Size of #data buffer. */

	uint8_t *data;
	/**< Sent data */

	uint16_t crc;
	/**< CRC checksum */
} soe_multi_packet;

/** ACKs a received packet
 */
typedef struct {
	uint8_t _has_zflag_crc;
	/**< Not part of packet. Used internally */

	uint8_t zflag;
	/**< Is the rest of the packet compressed? Usually no for
	 * SOE_ACK packets */

	uint16_t seq_num;
	/**< The received packet's sequence number */

	uint16_t crc;
	/**< CRC checksum */
} soe_ack;

/** Sent when received packet's sequence number is out of order. Same
 * layout as #soe_ack
 */
typedef soe_ack soe_out_order_pkt;

/** Calculates the checksum for #packet using the SOE RUDP modified CRC32 algorithm.
 * @param crc_seed The CRC seed exchanged during session handshake.
 * @param data The data buffer
 * @param len Size of #data
 * @return The calculated checksum.
 */
uint32_t
soe_crc32(uint32_t crc_seed, const uint8_t data[], size_t len);

/** Parse out a packet from bytes.
 * @param buf The buffer from which to read
 * @param len Size of #buf
 * @param crc_seed CRC seed used for data checksum validation
 * @return Pointer to parsed packet. NULL if no packet could be parsed.
 */
soe_rudp_packet*
parse_packet(const uint8_t buf[], size_t len, uint32_t crc_seed);

#endif
