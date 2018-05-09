#ifndef __UNIMAN_ESM_H_
#define __UNIMAN_ESM_H_

#include "common.h"
//s#include "tcp_stream.h"
//#include "fast.h??"

struct fpga_stream{
	struct flow_info flowInfo;
	uint8_t reserved: 3;
	uint8_t direction: 1;
	uint8_t state_cli: 2;
	uint8_t state_ser: 2;
	uint32_t cli_ack_seq;
	uint32_t ser_ack_seq;
	uint8_t action_cli: 4;
	uint8_t action_ser: 4;
	uint16_t next_idx;
	uint32_t pkt_count;
	uint32_t byte_count;
};




/*************************************************************************************************/
/** add a connection in esm */
int esm_add_connection(connection_t *conn);

/** del a connection in esm */
int esm_del_connection(connection_t *conn);

/** read a connection in esm */
int esm_read_connection(connection_t *conn);

/** update a connection in esm */
int esm_update_connection(connection_t *conn);

/*************************************************************************************************/
/** change conneciton format to reg of fast-fpga format */
uint32_t *conn2reg(connection_t *conn);

/** change reg of fast-fpga format to conneciton format */
void reg2conn(connection_t *conn, uint32_t *regvalue);


uint32_t fast_reg[NUM_REG_OF_CONN];

#ifndef FAST_FUNC

void fast_reg_wr(uint32_t regaddr, uint32_t regvalue);

uint32_t fast_reg_rd(uint32_t regaddr);

#endif


#endif /* __UNIMAN_ESM_H_ */