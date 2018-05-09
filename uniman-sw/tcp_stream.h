#ifndef __TCP_STREAM_H_
#define __TCP_STREAM_H_

#define MAC_OS 1

typedef uint32_t event_t;
typedef uint32_t event_bitmap_t;

#if MAC_OS

struct ethhdr{
	uint8_t h_dest[6];
	uint8_t h_source[6];
	uint16_t h_proto;
};
struct iphdr{
	uint8_t protocol;
	uint32_t saddr;
	uint32_t daddr;
};
struct tcphdr{
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
	uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
	uint16_t window;
};

#else 

#include "linux/if_ether.h"

#endif /** MAC_OS */


struct pkt_info{
	uint8_t direction;
	// uint32_t	cur_ts;	/* packet receiving time (read-only) */
	// uint8_t		in_ifidx; /* input interface */

	// /* ETH */
	// uint16_t	eth_len;
	// /* IP */
	// uint16_t	ip_len;
	// /* TCP */
	// uint16_t	payloadlen;
	// uint32_t	seq;
	// uint32_t	ack_seq;
	//uint16_t	window;

	/* packet struct */
	struct ethhdr 	*ethh;
	struct iphdr 	* iph;
	struct tcphdr 	*tcph;
	uint8_t 		*payload;
	/** ethhdr
	*      unsigned char h_dest[ETH_ALEN];
	*      unsigned char h_source[ETH_ALEN];
	*      _be16 h_proto;
	**  iphdr
	*      uint8_t protocol;
	*      uint32_t saddr;
	*      uint32_t daddr;
	*   tcphdr
	*      uint16_t source;
	*      uint16_t dest;
	*      uint32_t seq;
	*      uint32_t ack_seq;
	*      fin, syn, rst, psh, ack, urg, res2;
	*      uint16_t window;
	*/
};

struct tcp_endPoint_vars{
	uint8_t		state;
	uint32_t	last_ack_seq;	/* hightest ack seq */
	// "send seq" is on the road;
};

struct flow_info{
	uint32_t	saddr;	/* in network order */
	uint32_t	daddr;	/* in network order */
	uint16_t	sport;	/* in network order */
	uint16_t	dport;	/* in network order */
	uint8_t		protocol;
};

struct tcp_stream{
	uint16_t	flowID;

	struct flow_info flowK;

	uint16_t	hashTb_idx_1;
	uint16_t	hashTb_idx_2;

	uint8_t		direction;	/* the saddr is the client or server */
	struct tcp_endPoint_vars *sndvar;
	struct tcp_endPoint_vars *rcvvar;

	struct pkt_info * cur_pkt;

	uint32_t	pkt_count;
	uint32_t	byte_count;

	uint16_t	next_idx;
	struct tcp_stream *next;
};
typedef struct tcp_stream connection_t;

struct metadata{
	uint16_t	hashTb_idx_1;
	uint16_t	hashTb_idx_2;
	struct flow_info flowK;
	event_t		evb;
	uint16_t	flowID;
	uint8_t		reserved: 3;
	uint8_t		direction: 1;
	uint8_t		state_cli: 2;
	uint8_t		state_ser: 2;
};


#endif /* __TCP_STREAM_H_ */