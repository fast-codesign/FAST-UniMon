#include "uniman_esm_task.h"

/*************************************************************************************************/
/** add a connection in esm */
int esm_add_connection(connection_t *conn){
	uint32_t regaddr = 0x3000000000+conn->flowID*16;
	uint32_t *regvalue = conn2reg(conn);
	int i =0;
	for (int i = 0; i < NUM_REG_OF_CONN; ++i)
	{
		/** 300_0000_0 - 300_ffff_6 */
		fast_reg_wr(regaddr, regvalue[i]);
		regaddr++;
	}
	free((struct fpga_conn *) regvalue);
	return 1;
}

/** del a connection in esm */
int esm_del_connection(connection_t *conn){
	uint32_t regaddr = 0x3000000000+conn->flowID*16;
	uint32_t regvalue[NUM_REG_OF_CONN] = {0};
	for (int i = 0; i < NUM_REG_OF_CONN; ++i)
	{
		/** 300_0000_0 - 300_ffff_6 */
		fast_reg_wr(regaddr, regvalue[i]);
		regaddr++;
	}
	return 1;
}

/** read a connection in esm */
int esm_read_connection(connection_t *conn){
	uint32_t regaddr = 0x3000000000+conn->flowID*16;
	uint32_t regvalue[NUM_REG_OF_CONN] = {0};
	for (int i = 0; i < NUM_REG_OF_CONN; ++i)
	{
		/** 300_0000_0 - 300_ffff_6 */
		regvalue[i] = fast_reg_rd(regaddr);
		regaddr++;
	}
	reg2conn(conn, regvalue);
	return 1;
}

/** update a connection in esm */
int esm_update_connection(connection_t *conn){
	uint32_t regaddr = 0x3000000000+conn->flowID*16;
	uint32_t *regvalue = conn2reg(conn);
	int i =0;
	for (int i = 0; i < NUM_REG_OF_CONN; ++i)
	{
		/** 300_0000_0 - 300_ffff_6 */
		fast_reg_wr(regaddr, regvalue[i]);
		regaddr++;
	}
	free((struct fpga_conn *) regvalue);
	return 1;
}


/*************************************************************************************************/
/** change conneciton format to reg of fast-fpga format */
uint32_t *conn2reg(connection_t *conn){
	struct fpga_stream *fpga_conn;
	fpga_conn = (struct fpga_stream *)malloc(sizeof(struct fpga_stream));

	fpga_conn->flowInfo.saddr = conn->flowK.saddr;
	fpga_conn->flowInfo.daddr = conn->flowK.daddr;
	fpga_conn->flowInfo.sport = conn->flowK.sport;
	fpga_conn->flowInfo.dport = conn->flowK.dport;
	fpga_conn->flowInfo.protocol = conn->flowK.protocol;
	fpga_conn->reserved = 0;
	fpga_conn->direction = conn->direction;
	fpga_conn->state_cli = conn->sndvar->state;
	fpga_conn->state_ser = conn->rcvvar->state;
	fpga_conn->cli_ack_seq = conn->sndvar->last_ack_seq;
	fpga_conn->ser_ack_seq = conn->rcvvar->last_ack_seq;
	fpga_conn->action_cli = 0;	// wait to be modified;
	fpga_conn->action_ser = 0;	// wait to be modified;
	fpga_conn->next_idx = conn->next_idx;
	fpga_conn->pkt_count = conn->pkt_count;
	fpga_conn->byte_count = conn->byte_count;

	return (uint32_t *) fpga_conn;
}

/** change reg of fast-fpga format to conneciton format */
void reg2conn(connection_t *conn, uint32_t *regvalue){
	struct fpga_stream *fpga_conn;
	fpga_conn = (struct fpga_stream *) regvalue;

	conn->flowK.saddr = fpga_conn->flowInfo.saddr;
	conn->flowK.daddr = fpga_conn->flowInfo.daddr;
	conn->flowK.sport = fpga_conn->flowInfo.sport;
	conn->flowK.dport = fpga_conn->flowInfo.dport;
	conn->flowK.protocol = fpga_conn->flowInfo.protocol;
	conn->direction = fpga_conn->direction;
	conn->sndvar->state = fpga_conn->state_cli;
	conn->rcvvar->state = fpga_conn->state_ser;
	conn->sndvar->last_ack_seq = fpga_conn->cli_ack_seq;
	conn->rcvvar->last_ack_seq = fpga_conn->ser_ack_seq;
	conn->pkt_count = fpga_conn->pkt_count;
	conn->byte_count = fpga_conn->byte_count;
	
	free(fpga_conn);
}




#ifndef FAST_FUNC

void fast_reg_wr(uint32_t regaddr, uint32_t regvalue){
	if(regaddr & 0x00f00000){
		printf("regaddr:%x\tregvalue:%u\n", regaddr, regvalue);
	}
	else 
		fast_reg[regaddr] = regvalue;
}
uint32_t fast_reg_rd(uint32_t regaddr){
	return fast_reg[regaddr];
}

#endif