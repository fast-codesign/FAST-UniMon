#ifndef __BUILD_IN_EVENT_H_
#define __BUILD_IN_EVENT_H_


/** build-in event provided by UniMan */
enum uniman_event_type { 
	/** a packet is comming in */
	UINMAN_ON_PKT_IN = (0x1<<0),
	/** SYN packet as seen by UniMan */
	UINMAN_ON_CONN_START = (0x1<<1),
	/** SYN-ACK packet as seen by UniMan */
	UINMAN_ON_HALF_CONN = (0x1<<2),
	/** 3-way handshake is finished.
	* server side: ACK is coming in as a response of SYN-ACK.
	* client side: SYN-ACK is coming in as a response of SYN.
	 */
	UINMAN_ON_CONN_SETUP = (0x1<<3),
	/** no packet is seen for a long time */
	UINMAN_ON_TIMEOUT = (0x1<<4),
	/** a flow is about to be destroyed.
	* 4-way handshake, RST packet, or timeout could be the reason.
	* NOTE: in current implementation, UniMan raises this event while destroying
	*  "struct tcp_stream". 
	*/
	UINMAN_ON_CONN_END = (0x1<<5),
	/** Retransmission is detected */
	UINMAN_ON_RETRANS = (0x1<<6),
	/** the sequence of received packet is out of the scope of recv's window (more 
	* 	or less than 65535 than the latest ack sequence). */
	UINMAN_ON_INVALID_SEQ = (0x1<<7)
};

#endif /* __BUILD_IN_EVENT_H_ */