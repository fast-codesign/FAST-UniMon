//=====================================================================//
//	Module name: lookup connTb in connection searcher of UniMan;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/11 (Happy Singles' Day,  Je t'attendrai toujours.)
//	Function outline: UniMan_v1.0
//=====================================================================//

`timescale 1ns/1ps

/*	function description:
*	1) search the conneciton table according to the result of flowKey table;
*	2)  check the validation of current packet, and update the conneciton entry; 
*		if missing, add a new connection by hardware itself;
*/
module lookup_connTb(
clk,
reset,
metadata_in_valid,
metadata_in,
conn_idx_valid,
conn_idx_info,
idx_connTb_search,
idx_connTb_conf,
rdValid_connTb_search,
wrValid_connTb_conf,
data_connTb_conf,
ctx_connTb_search,
action_valid,
action,
eventInfo_valid,
eventInfo,
conn_closed_valid,
conn_closed_info
);



/*	width or depth or words info of signals
*/
parameter 	w_meta = 104,		// width of metadata, includes length of content, 
								//	tcp falg, send seq, ack seq and window; 
			w_eventInfo = 16,	// width of evnetInfo, includes, event type,
								//	(flowID/entryID), and connection state;
			w_evb = 8,			// width of event bitmap;
			w_connTb = 200,	// the width of connTb(table) entry, (4b clientState, 
								//	32b*2 sendSeq+ackSeq, 16b window, 16b max win,
								//	4b serverState, 32b*2 sendSeq+ackSeq, 
								//	16b window, 16b max window);
			d_connTb = 3,		// depth of connTb;
			w_state = 4,			// width of state field in connTb;
			w_seq = 32,			// width of sequence;
			w_window = 16,	// width of window;
			w_length = 16,		// width of content length;
			w_tcpFlag = 8,		// width of tcpFlag in packet, top 2-bit is pad;
			w_flowID = 16,		// width of flowID;
			w_ip = 32,			// width of ip addr;
			w_connIdx_info = 19,	// width of conn_idx_info, include hitness, addness,
									// 	direction, and connection_index ('1' is server2client, '0' is 
									//	client2server);
			d_metaBuffer = 5,		// depth of (flowKTb_conflict) idx buffer;
			words_metaBuffer = 32,// words of idx buffer;
			
			/** format of metadata */
			b_length_meta = 88,		// last bit of content length in metadata;
			b_tcpFlag_meta = 80,		// last bit of tcp Flag in metadata;
			b_sendSeq_meta = 48,		// last bit of send seq in metadata;
			b_ackSeq_meta = 16,		// last bit of ack seq in metadata;
			b_window_meta = 0,		// last bit of window in metadata;
			/** format of connIdx_info */
			b_hit_connIdxInfo = 18,	// last bit of hitness in connIdx_info;
			b_add_connIdxInfo = 17,	// last bit of addness in connIdx_info;
			b_dir_connIdxInfo = 16,	// last bit of direction in connIdx_info;
			b_idx_connIdxInfo = 0,		// last bit of index in connIdx_info;
			/** format of connTb */
			b_cliState_connTb = 196,		// last bit of client's state in connTb;
			b_cliSendSeq_connTb = 164,	// last bit of client's send seq in connTb;
			b_cliAckSeq_connTb = 132,		// last bit of client's ack seq in connTb;
			b_cliWin_connTb = 116,		// last bit of client's window in connTb;
			b_cliMaxWin_connTb = 100,	// last bit of client's max window in connTb;
			b_serState_connTb = 96,		// last bit of server's state in connTb;
			b_serSendSeq_connTb = 64,	// last bit of server's send seq in connTb;
			b_serAckSeq_connTb = 32,		// last bit of server's ack seq in connTb;
			b_serWin_connTb = 16,			// last bit of server's window in connTb;
			b_serMaxWin_connTb = 0,		// last bit of server's max window in connTb;

			/* event bitmap */
			NONE_STATE = 8'd0,		// no change;
			NEW_FLOW = 8'd1,			// new flow (conneciton start);
			HALF_CONN = 8'd2,			// connection start (server);
			CONN_SETUP = 8'd4,		// conneciton setup;
			TIME_OUT = 8'd8,			// conneciton time out;
			CONN_END_CLI = 8'd16,	// connection end by client;
			CONN_END_SER = 8'd32,	// connection end by server;
			STATE_CHANGE = 8'd128,	// connection state changes;
			
			/** states */
			CLOSED_STATE = 4'd0,			// state of closed;
			REQUESTED_STATE = 4'd1,		// state of requested;
			ESTABLISHED_STATE = 4'd2,	// state of established;
			WAITING_CLOSE_STATE = 4'd3,	// state of waiting close; 
			
			DEFAULT_SEQ = 32'b0,

			b_fin_flag = 0,			// fin location in tcp flags;
			b_syn_flag = 1,			// syn location in tcp flags;
			b_rst_flag = 2,			// rst location in tcp flags;
			b_ack_flag = 4,			// ack location in tcp flags;
			ONLY_FIN = 8'h01,		// tcp flag: fin;
			ONLY_SYN = 8'h02,		// tcp flag: syn;
			ONLY_RST = 8'h04,		// tcp flag: rst;
			ONLY_ACK = 8'h10;		// tcp flag: ack;

input								clk;
input								reset;
input								metadata_in_valid;
input		[w_meta-1:0]			metadata_in;
input								conn_idx_valid;
input		[w_connIdx_info-1:0]	conn_idx_info;
output	reg	[d_connTb-1:0]			idx_connTb_search;
output	reg	[d_connTb-1:0]			idx_connTb_conf;
output	reg							rdValid_connTb_search;
output	reg							wrValid_connTb_conf;
output	reg	[w_connTb-1:0]			data_connTb_conf;
input		[w_connTb-1:0]			ctx_connTb_search;
output	reg 							action_valid;
output	reg 							action;
output	reg 							eventInfo_valid;
output	reg 	[w_eventInfo-1:0]		eventInfo;
output 	reg 							conn_closed_valid;
output 	reg 	[w_flowID-1:0]			conn_closed_info;

/*************************************************************************************/
/*	varialbe declaration */
/*	temps used to buffer internal variables;
*/
reg 									valid_temp[3:0];
reg			[w_connIdx_info-1:0]	connIdx_info_temp[3:0];
reg 			[w_meta-1:0]			meta_temp[3:0];

/**	flowKIdx_info buffer */
wire								empty_meta;
wire		[w_meta-1:0]			ctx_meta;

/*	state machine of update connTb
*	wine signal is equal to the state maintained by connTb;
*	reg signals are used to update the state;
*/
wire		[w_state-1:0]			stateCli_connTb,stateSer_connTb;
wire		[w_seq-1:0]				sendSeqCli_connTb, sendSeqSer_connTb;
wire		[w_seq-1:0]				ackSeqCli_connTb, ackSeqSer_connTb;
wire		[w_window-1:0]		winCli_connTb, winSer_connTb;
wire		[w_window-1:0]		MwinCli_connTb, MwinSer_connTb;
reg			[w_state-1:0]			stateCli_temp, stateSer_temp;
reg			[w_seq-1:0]				sendSeqCli_temp, sendSeqSer_temp;
reg			[w_seq-1:0]				ackSeqCli_temp, ackSeqSer_temp;
reg			[w_window-1:0]		winCli_temp, winSer_temp;
reg			[w_window-1:0]		MwinCli_temp, MwinSer_temp;
reg 			[w_seq-1:0]				seq_temp, ack_temp;
reg 			[w_length-1:0]			length_temp;
reg 			[w_window-1:0]		wind_temp;
reg 			[w_tcpFlag-1:0]			tcpFlag_temp;

/*	assign pktIn_info
*/
reg			[w_evb-1:0]				event_bitmap_t;

//reg	test1,test2;

/*************************************************************************************/
/***	state register declaration */

/*************************************************************************************/
/***	submodule declaration */
/**	meta_buffer used to cache metadata_in;
*/
fifo meta_buffer(
.aclr(!reset),
.clock(clk),
.data(metadata_in),
.rdreq(conn_idx_valid),
.wrreq(metadata_in_valid),
.empty(empty_meta),
.full(),
.q(ctx_meta),
.usedw()
);
defparam
	meta_buffer.width = w_meta,
	meta_buffer.depth = d_metaBuffer,
	meta_buffer.words = words_metaBuffer;

/*************************************************************************************/
/**	this state machine used to 1) lookup connTb with idx from flowKTb;
*		2) read meta fifo;
*/
integer	i, j;
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		idx_connTb_search <= {d_connTb{1'b0}};
		rdValid_connTb_search <= 1'b0;
		
		for(i = 0; i < 4; i = i+1) begin
			valid_temp[i] <= 1'b0;
			connIdx_info_temp[i] <= {w_connIdx_info{1'b0}};
			meta_temp[i] <= {w_meta{1'b0}};
		end
	end
	else begin
		if(conn_idx_valid == 1'b1) begin
			valid_temp[0] <= 1'b1;
			meta_temp[0] <= ctx_meta;
			connIdx_info_temp[0] <= conn_idx_info;
			rdValid_connTb_search <= 1'b1;
			idx_connTb_search <= conn_idx_info[b_idx_connIdxInfo+d_connTb-1:
				b_idx_connIdxInfo];
		end
		else begin
			valid_temp[0] <= 1'b0;
			meta_temp[0] <= {w_meta{1'b0}};
			connIdx_info_temp[0] <= {w_connIdx_info{1'b0}};
			rdValid_connTb_search <= 1'b0;
		end
		/** maintain temps */
		for(j = 0; j < 3; j = j+1) begin
			valid_temp[j+1] <= valid_temp[j];
			connIdx_info_temp[j+1] <= connIdx_info_temp[j];
			meta_temp[j+1] <= meta_temp[j];
		end
	end
end

/*************************************************************************************/
/** get seq, ack and length */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		{length_temp,tcpFlag_temp,seq_temp,ack_temp,wind_temp}  <= {w_meta{1'b0}};
	end
	else begin
		{length_temp,tcpFlag_temp,seq_temp,ack_temp,wind_temp}  <= meta_temp[1];
	end
end

/**	this state machine is used lookup and update connTb;
*	When I wrote this, only God and I understood what I was doing. Now, God only knows.
*/
assign {stateCli_connTb, sendSeqCli_connTb, ackSeqCli_connTb, winCli_connTb,
		MwinCli_connTb, stateSer_connTb, sendSeqSer_connTb, ackSeqSer_connTb, 
		winSer_connTb, MwinSer_connTb} = ctx_connTb_search;

always @(posedge clk or negedge reset) begin
	if (!reset) begin
		{stateCli_temp,sendSeqCli_temp,ackSeqCli_temp,winCli_temp,
			MwinCli_temp,stateSer_temp,sendSeqSer_temp,
			ackSeqSer_temp,winSer_temp,MwinSer_temp} <= {w_connTb{1'b0}};
		event_bitmap_t <= {w_evb{1'b0}};
		action_valid <=1 'b0;
		action <= 1'b0;
	end
	else begin
		action_valid <= valid_temp[2];
		if(valid_temp[2] == 1'b1) begin /** update or add a connTb (or drop)*/
			if(connIdx_info_temp[2][b_add_connIdxInfo] == 1'b1) begin
				/** add a new flow */
				stateCli_temp <= REQUESTED_STATE;
				sendSeqCli_temp <= seq_temp;
				ackSeqCli_temp <= 32'b0;
				winCli_temp <= wind_temp;
				MwinCli_temp <= {w_window{1'b0}};
				/**state of server*/
				stateSer_temp <= REQUESTED_STATE;
				sendSeqSer_temp <= {w_seq{1'b0}}; 
				ackSeqSer_temp <= {w_seq{1'b0}};
				winSer_temp <= {w_window{1'b0}};
				MwinSer_temp <= {w_window{1'b0}};
				/** output */
				event_bitmap_t <= NEW_FLOW | STATE_CHANGE;
				//action_valid <= 1'b1;
				action <= 1'b1;
			end
			/** warnings: the following 400 lines of code may make you feel uncomfortable */
			else if (connIdx_info_temp[2][b_hit_connIdxInfo] == 1'b1) begin 
				/** check and update the connection */
				if(connIdx_info_temp[2][b_dir_connIdxInfo] == 1'b0) begin
					/**  packt is from client, and update client state */
					case(stateCli_connTb)
/**	CLOSED_STATE transfered from WAITING_CLOSED_STATE, and can only received ack 
*	packet from client. When receiving ack packet, we should check whether need to close 
*	current connection (ack packet of FIN to Server);
*/
CLOSED_STATE: begin
	/** client state;*/
	stateCli_temp <= CLOSED_STATE;
	sendSeqCli_temp <= seq_temp + {16'b0,length_temp};
	ackSeqCli_temp <= ack_temp;
	winCli_temp <= wind_temp;
	MwinCli_temp <= MwinCli_connTb;
	/** server state*/
	sendSeqSer_temp <= sendSeqSer_connTb;
	ackSeqSer_temp <= ackSeqSer_connTb;
	winSer_temp <= winSer_connTb;
	MwinSer_temp <= MwinSer_connTb;
	/** before output, we check send_seq's and ack's condition	*/
	action <= check_seq_valid(seq_temp, length_temp, ackSeqSer_connTb, winSer_connTb, sendSeqCli_connTb) & 
		check_ack_valid(ack_temp, sendSeqSer_connTb, ackSeqCli_connTb, MwinCli_connTb);

	/** check whether need to transfer server's state. 
	*	Acutally, we just update when action is '1'.
	*/
	if((ack_temp == (sendSeqSer_connTb+32'd1)) && (stateSer_connTb == WAITING_CLOSE_STATE)) begin
		stateSer_temp <= CLOSED_STATE;
		event_bitmap_t <= CONN_END_SER;
	end
	else begin
		stateSer_temp <= stateSer_connTb;
		event_bitmap_t <= NONE_STATE;
	end
end
/**	REQUESTED transfered from CLOSED_STATE aftering SYN packet.
*		->We are waiting for ack packet (3th shake hand), and the ack_seq = send_seq +1.
*		->We may receive retransmited SYN packet, but currently, we do not support.
*		->We may receive RST packet, just close the current connection.
*/
REQUESTED_STATE: begin
	if((tcpFlag_temp[b_ack_flag] == 1'b1) && (ack_temp == (32'd1 + sendSeqSer_connTb))) 
	begin /** valid packet */
		/** client state */
		stateCli_temp <= ESTABLISHED_STATE;
		sendSeqCli_temp <= seq_temp + {16'b0,length_temp};
		ackSeqCli_temp <= ack_temp;
		winCli_temp <= wind_temp;
		MwinCli_temp <= MwinCli_connTb;
		/** server state */
		stateSer_temp <= ESTABLISHED_STATE;
		sendSeqSer_temp <= sendSeqSer_connTb;
		ackSeqSer_temp <= ackSeqSer_connTb;
		winSer_temp <= winSer_connTb;
		MwinSer_temp <= MwinSer_connTb;
		/** update event_bitmap */
		event_bitmap_t <= STATE_CHANGE | CONN_SETUP;
		/** check sequence */
		action <= check_seq_valid(seq_temp, length_temp, ackSeqSer_connTb, winSer_connTb, sendSeqCli_connTb) & 
			check_ack_valid(ack_temp, sendSeqSer_connTb, ack_temp, MwinCli_connTb);
		//test1 <= check_seq_valid(seq_temp, length_temp, ackSeqSer_connTb, winSer_connTb, sendSeqCli_connTb);	
		//test2 <= check_ack_valid(ack_temp, sendSeqSer_connTb, ack_temp, MwinCli_connTb);
	end
	else if(tcpFlag_temp[b_rst_flag] == 1'b1) begin
	/** close connection */
		{stateCli_temp,sendSeqCli_temp,ackSeqCli_temp,winCli_temp,
			MwinCli_temp,stateSer_temp,sendSeqSer_temp,
			ackSeqSer_temp,winSer_temp,MwinSer_temp} <= {w_connTb{1'b0}};
		/** update event_bitmap */
		event_bitmap_t <= STATE_CHANGE | CONN_END_CLI | CONN_END_SER;
		action <= 1'b1;
	end
	else begin /** invalid packet, and drop packet*/
		action <= 1'b0;
	end
end
/**	ESTABLISHED_STATE transfered from REQUESTED aftering ACK packet.
*		->We may receive Retransmitted ACK packet (3th shake hand), and the ack_seq = send_seq +1.
*		->We may receive FIN packet.
*		->We may receive RST packet, just close the current connection.
*/
/* recv fin/rst, and wait ack */
ESTABLISHED_STATE: begin
	/* record the sequence of fin packet */
	if(tcpFlag_temp[b_fin_flag] == 1'b1)begin
		/** client state */
		stateCli_temp <= WAITING_CLOSE_STATE;
		sendSeqCli_temp <= seq_temp + {16'b0,length_temp};
		/** all packets expcet SYN packet have ACK flag, is that TURE? */
		/** just record the biggest ack sequence */
		if((ack_temp > ackSeqCli_connTb) && (tcpFlag_temp[b_ack_flag] == 1'b1))
			ackSeqCli_temp <= ack_temp;
		else 
			ackSeqCli_temp <= ackSeqCli_connTb;
		winCli_temp <= wind_temp;
		MwinCli_temp <= MwinCli_connTb;
		/** server state */
		sendSeqSer_temp <= sendSeqSer_connTb; 
		ackSeqSer_temp <= ackSeqSer_connTb;
		winSer_temp <= winSer_connTb;
		MwinSer_temp <= MwinSer_connTb;
		/** check_seq_valid*/
		action <= check_seq_valid(seq_temp, length_temp, ackSeqSer_connTb, winSer_connTb, sendSeqCli_connTb);
		/** check whether need to transfer server's state */
		if((ack_temp == (sendSeqSer_connTb+32'd1)) && (stateSer_connTb == WAITING_CLOSE_STATE)) begin
			stateSer_temp <= CLOSED_STATE;
			event_bitmap_t <= STATE_CHANGE | CONN_END_SER;
		end
		else begin
			stateSer_temp <= stateSer_connTb;
			event_bitmap_t <= NONE_STATE;
		end
	end
	/** SYN does not exist with RST flag? */
	else if(tcpFlag_temp[b_rst_flag] == 1'b1) begin
		{stateCli_temp,sendSeqCli_temp,ackSeqCli_temp,winCli_temp,
			MwinCli_temp,stateSer_temp,sendSeqSer_temp,
			ackSeqSer_temp,winSer_temp,MwinSer_temp} <= {w_connTb{1'b0}};
		/** update event_bitmap */
		event_bitmap_t <= STATE_CHANGE | CONN_END_CLI | CONN_END_SER;
		action <= 1'b1;
	end
	else begin /** check packet's seq, and update conneciton state */
		/** output */
		action <= check_seq_valid(seq_temp, length_temp, ackSeqSer_connTb, winSer_connTb, sendSeqCli_connTb) & 
			check_ack_valid(ack_temp, sendSeqSer_connTb, ackSeqCli_connTb, MwinCli_connTb);
	/** client state */
		stateCli_temp <= stateCli_connTb;
		/** just record the biggest send_seq and ack_seq */
		if((({1'b0,seq_temp} + {17'b0,length_temp}) > {1'b0,sendSeqCli_connTb})||
		({seq_temp[31],sendSeqCli_connTb[31]} == 2'b01)) 
			sendSeqCli_temp <= seq_temp + {16'b0,length_temp};
		else
			sendSeqCli_temp <= sendSeqCli_connTb;
		if(((ack_temp > ackSeqCli_connTb)||({ack_temp[31],ackSeqCli_connTb[31]}==2'b01)) 
		&& (tcpFlag_temp[b_ack_flag] == 1'b1)) 
			ackSeqCli_temp <= ack_temp;
		else 
			ackSeqCli_temp <= ackSeqCli_connTb;
		
		winCli_temp <= wind_temp;
		MwinCli_temp <= MwinCli_connTb;
	/** server state*/
		sendSeqSer_temp <= sendSeqSer_connTb; 
		ackSeqSer_temp <= ackSeqSer_connTb;
		winSer_temp <= winSer_connTb;
		MwinSer_temp <= MwinSer_connTb;

		if((ack_temp == (sendSeqSer_connTb+32'd1)) && (stateSer_connTb == WAITING_CLOSE_STATE))
		begin
			stateSer_temp <= CLOSED_STATE;
			event_bitmap_t <= STATE_CHANGE | CONN_END_SER;
		end
		else begin
			stateSer_temp <= stateSer_connTb;
			event_bitmap_t <= NONE_STATE;
		end
	end
end
WAITING_CLOSE_STATE: begin
	if(tcpFlag_temp[b_rst_flag] == 1'b1) begin
		{stateCli_temp,sendSeqCli_temp,ackSeqCli_temp,winCli_temp,
			MwinCli_temp,stateSer_temp,sendSeqSer_temp,
			ackSeqSer_temp,winSer_temp,MwinSer_temp} <= {w_connTb{1'b0}};
		/** update event_bitmap */
		event_bitmap_t <= STATE_CHANGE | CONN_END_CLI | CONN_END_SER;
		//action_valid <= 1'b1;
		action <= 1'b1;
	end
/* record the sequence of fin packet, may be a retransmit, just passing, TO DO? */
	else begin 
	/** invalid packet, and drop packet, currently, we do not consider the packets
	*	received later than the FIN packet;
	*/
		/** output */
		action <= check_seq_valid(seq_temp, length_temp, ackSeqSer_connTb, winSer_connTb, sendSeqCli_connTb) & 
			check_ack_valid(ack_temp, sendSeqSer_connTb, ackSeqCli_connTb, MwinCli_connTb);
		/** maintain conneciton state*/
		// {stateCli_temp,sendSeqCli_temp,ackSeqCli_temp,winCli_temp,
		// 	MwinCli_temp,stateSer_temp,sendSeqSer_temp,
		// 	ackSeqSer_temp,winSer_temp,MwinSer_temp} <= ctx_connTb_search;
	/** client's state */
		stateCli_temp <= stateCli_connTb;
		/** just record the biggest send_seq and ack_seq */
		if((({1'b0,seq_temp} + {17'b0,length_temp}) > {1'b0,sendSeqCli_connTb})||
		({seq_temp[31],sendSeqCli_connTb[31]} == 2'b01)) 
			sendSeqCli_temp <= seq_temp + {16'b0,length_temp};
		else
			sendSeqCli_temp <= sendSeqCli_connTb;
		if(((ack_temp > ackSeqCli_connTb)||({ack_temp[31],ackSeqCli_connTb[31]}==2'b01)) 
		&& (tcpFlag_temp[b_ack_flag] == 1'b1)) 
			ackSeqCli_temp <= ack_temp;
		else 
			ackSeqCli_temp <= ackSeqCli_connTb;
		winCli_temp <= wind_temp;
		MwinCli_temp <= MwinCli_connTb;
	/** server state*/
		sendSeqSer_temp <= sendSeqSer_connTb; 
		ackSeqSer_temp <= ackSeqSer_connTb;
		winSer_temp <= winSer_connTb;
		MwinSer_temp <= MwinSer_connTb;

		if((ack_temp == (sendSeqSer_connTb+32'd1)) && (stateSer_connTb == WAITING_CLOSE_STATE)) begin
			stateSer_temp <= CLOSED_STATE;
			event_bitmap_t <= STATE_CHANGE | CONN_END_SER;
		end
		else begin
			stateSer_temp <= stateSer_connTb;
			event_bitmap_t <= NONE_STATE;
		end
	end
end
default: begin	/** discard */						
	/** output */
	event_bitmap_t <= NONE_STATE;
	action <= 1'b0;
	/** maintain conneciton state*/
	{stateCli_temp,sendSeqCli_temp,ackSeqCli_temp,winCli_temp,
		MwinCli_temp,stateSer_temp,sendSeqSer_temp,
		ackSeqSer_temp,winSer_temp,MwinSer_temp} <= {w_connTb{1'b0}};
end
					endcase
				end
				else begin
					/** packet is from server, and update server state */
					case(stateSer_connTb)
/**	CLOSED_STATE transfered from WAITING_CLOSED_STATE, and can only received ack 
*	packet from Server. When receiving ack packet, we should check whether need to close 
*	current connection (ack packet of FIN to Client);
*/
CLOSED_STATE: begin
	/** server state;*/
	stateSer_temp <= CLOSED_STATE;
	sendSeqSer_temp <= seq_temp + {16'b0,length_temp};
	ackSeqSer_temp <= ack_temp;
	winSer_temp <= wind_temp;
	MwinSer_temp <= MwinSer_connTb;
	/** client state*/
	sendSeqCli_temp <= sendSeqCli_connTb;
	ackSeqCli_temp <= ackSeqCli_connTb;
	winCli_temp <= winCli_connTb;
	MwinCli_temp <= MwinCli_connTb;
	/** before output, we check send_seq's and ack's condition	*/
	action <= check_seq_valid(seq_temp, length_temp, ackSeqCli_connTb, winCli_connTb, sendSeqSer_connTb) & 
		check_ack_valid(ack_temp, sendSeqCli_connTb, ackSeqSer_connTb, MwinSer_connTb);

	/** check whether need to transfer server's state. 
	*	Acutally, we just update when action is '1'.
	*/
	if((ack_temp == (sendSeqCli_connTb+32'd1)) && (stateCli_connTb == WAITING_CLOSE_STATE)) begin
		stateCli_temp <= CLOSED_STATE;
		event_bitmap_t <= CONN_END_SER;
	end
	else begin
		stateCli_temp <= stateCli_connTb;
		event_bitmap_t <= NONE_STATE;
	end
end
/**	REQUESTED_STATE transfered from CLOSED_STATE after receiving SYN packet, and wait for
*	SYN&ACK packet to ESTABLISHED_STATE;
*/
REQUESTED_STATE: begin
	if((tcpFlag_temp[b_ack_flag] == 1'b1) && (tcpFlag_temp[b_syn_flag] == 1'b1) &&
		(ack_temp == (32'd1 + sendSeqCli_connTb))) 
	begin /** valid packet */
		/** server state */
		stateSer_temp <= ESTABLISHED_STATE;
		sendSeqSer_temp <= seq_temp;
		ackSeqSer_temp <= ack_temp;
		winSer_temp <= wind_temp;
		MwinSer_temp <= MwinSer_connTb;
		/** client state */
		stateCli_temp <= stateCli_connTb;
		sendSeqCli_temp <= sendSeqCli_connTb;
		ackSeqCli_temp <= ackSeqCli_connTb;
		winCli_temp <= winCli_connTb;
		MwinCli_temp <= MwinCli_connTb;
		/** update event_bitmap */
		event_bitmap_t <= STATE_CHANGE;
		/** check sequence */
		action <= 1'b1;
		//action <= check_seq_valid(seq_temp, length_temp, ackSeqSer_connTb, winSer_connTb, sendSeqCli_connTb) & 
		//action <= check_ack_valid(ack_temp, sendSeqCli_connTb, ackSeqSer_connTb, MwinSer_connTb);
	end
	else if(tcpFlag_temp[b_rst_flag] == 1'b1) begin
	/** close connection */
		{stateCli_temp,sendSeqCli_temp,ackSeqCli_temp,winCli_temp,
			MwinCli_temp,stateSer_temp,sendSeqSer_temp,
			ackSeqSer_temp,winSer_temp,MwinSer_temp} <= {w_connTb{1'b0}};
		/** update event_bitmap */
		event_bitmap_t <= STATE_CHANGE | CONN_END_CLI | CONN_END_SER;
		action <= 1'b1;
	end
	else begin /** invalid packet, and drop packet*/
		action <= 1'b0;
	end
end

/**	ESTABLISHED_STATE transfered from REQUESTED aftering ACK packet.
*		->We may receive waiting for SYN&ACk packet (2th shake hand), and the ack_seq = send_seq +1.
*		->We may receive fin packet.
*		->We may receive RST packet, just close the current connection.
*/
/* recv fin/rst, and wait ack */
ESTABLISHED_STATE: begin
	/* record the sequence of fin packet */
	if(tcpFlag_temp[b_fin_flag] == 1'b1)begin
		/** server state */
		stateSer_temp <= WAITING_CLOSE_STATE;
		sendSeqSer_temp <= seq_temp + {16'b0,length_temp};
		/** just record the biggest ack sequence */
		if((ack_temp > ackSeqSer_connTb) && (tcpFlag_temp[b_ack_flag] == 1'b1))
			ackSeqSer_temp <= ack_temp;
		else 
			ackSeqSer_temp <= ackSeqSer_connTb;
		winSer_temp <= wind_temp;
		MwinSer_temp <= MwinSer_connTb;
		/** client state */
		sendSeqCli_temp <= sendSeqCli_connTb; 
		ackSeqCli_temp <= ackSeqCli_connTb;
		winCli_temp <= winCli_connTb;
		MwinCli_temp <= MwinCli_connTb;
		action <= 1'b1;
		//action <= check_seq_valid(seq_temp, length_temp, ackSeqCli_connTb, winCli_connTb, sendSeqSer_connTb);
		/** check whether need to transfer server's state */
		if((ack_temp == (sendSeqCli_connTb+32'd1)) && (stateCli_connTb == WAITING_CLOSE_STATE)) begin
			stateCli_temp <= CLOSED_STATE;
			event_bitmap_t <= STATE_CHANGE | CONN_END_SER;
		end
		else begin
			stateCli_temp <= stateCli_connTb;
			event_bitmap_t <= NONE_STATE;
		end
	end
	/** SYN does not exist with RST flag? */
	else if(tcpFlag_temp[b_rst_flag] == 1'b1) begin
		{stateCli_temp,sendSeqCli_temp,ackSeqCli_temp,winCli_temp,
			MwinCli_temp,stateSer_temp,sendSeqSer_temp,
			ackSeqSer_temp,winSer_temp,MwinSer_temp} <= {w_connTb{1'b0}};
		/** update event_bitmap */
		event_bitmap_t <= STATE_CHANGE | CONN_END_CLI | CONN_END_SER;
		action <= 1'b1;
	end
	else begin /** check packet's seq, and update conneciton state */
		/** output */
		action <= check_seq_valid(seq_temp, length_temp, ackSeqCli_connTb, winCli_connTb, sendSeqSer_connTb) & 
			check_ack_valid(ack_temp, sendSeqCli_connTb, ackSeqSer_connTb, MwinSer_connTb);
	/** server state */
		stateSer_temp <= stateSer_connTb;
		/** just record the biggest send_seq and ack_seq */
		if((({1'b0,seq_temp} + {17'b0,length_temp}) > {1'b0,sendSeqSer_connTb})||
		({seq_temp[31],sendSeqSer_connTb[31]} == 2'b01)) 
			sendSeqSer_temp <= seq_temp + {16'b0,length_temp};
		else
			sendSeqSer_temp <= sendSeqSer_connTb;
		if(((ack_temp > ackSeqSer_connTb)||({ack_temp[31],ackSeqSer_connTb[31]}==2'b01)) 
		&& (tcpFlag_temp[b_ack_flag] == 1'b1)) 
			ackSeqSer_temp <= ack_temp;
		else 
			ackSeqSer_temp <= ackSeqSer_connTb;
		
		winSer_temp <= wind_temp;
		MwinSer_temp <= MwinSer_connTb;
	/** client state*/
		sendSeqCli_temp <= sendSeqCli_connTb; 
		ackSeqCli_temp <= ackSeqCli_connTb;
		winCli_temp <= winCli_connTb;
		MwinCli_temp <= MwinCli_connTb;

		if((ack_temp == (sendSeqCli_connTb+32'd1)) && (stateCli_connTb == WAITING_CLOSE_STATE))
		begin
			stateCli_temp <= CLOSED_STATE;
			event_bitmap_t <= STATE_CHANGE | CONN_END_SER;
		end
		else begin
			stateCli_temp <= stateCli_connTb;
			event_bitmap_t <= NONE_STATE;
		end
	end
end
WAITING_CLOSE_STATE: begin
	if(tcpFlag_temp[b_rst_flag] == 1'b1) begin
		{stateCli_temp,sendSeqCli_temp,ackSeqCli_temp,winCli_temp,
			MwinCli_temp,stateSer_temp,sendSeqSer_temp,
			ackSeqSer_temp,winSer_temp,MwinSer_temp} <= {w_connTb{1'b0}};
		/** update event_bitmap */
		event_bitmap_t <= STATE_CHANGE | CONN_END_CLI | CONN_END_SER;
		action <= 1'b1;
	end
/* record the sequence of fin packet, may be a retransmit, just passing, TO DO? */
	else begin 
	/** invalid packet, and drop packet, currently, we do not consider the packets
	*	received later than the FIN packet;
	*/
		/** output */
		action <= check_seq_valid(seq_temp, length_temp, ackSeqCli_connTb, winCli_connTb, sendSeqSer_connTb) & 
			check_ack_valid(ack_temp, sendSeqCli_connTb, ackSeqSer_connTb, MwinSer_connTb);
	/** server's state */
		stateSer_temp <= stateSer_connTb;
		/** just record the biggest send_seq and ack_seq */
		if((({1'b0,seq_temp} + {17'b0,length_temp}) > {1'b0,sendSeqSer_connTb})||
		({seq_temp[31],sendSeqSer_connTb[31]} == 2'b01)) 
			sendSeqSer_temp <= seq_temp + {16'b0,length_temp};
		else
			sendSeqSer_temp <= sendSeqSer_connTb;
		if(((ack_temp > ackSeqSer_connTb)||({ack_temp[31],ackSeqSer_connTb[31]}==2'b01)) 
		&& (tcpFlag_temp[b_ack_flag] == 1'b1)) 
			ackSeqSer_temp <= ack_temp;
		else 
			ackSeqSer_temp <= ackSeqSer_connTb;
			
		winSer_temp <= wind_temp;
		MwinSer_temp <= MwinSer_connTb;
	/** client's state*/
		sendSeqCli_temp <= sendSeqCli_connTb; 
		ackSeqCli_temp <= ackSeqCli_connTb;
		winCli_temp <= winCli_connTb;
		MwinCli_temp <= MwinCli_connTb;

		if((ack_temp == (sendSeqCli_connTb+32'd1)) && (stateCli_connTb == WAITING_CLOSE_STATE)) begin
			stateCli_temp <= CLOSED_STATE;
			event_bitmap_t <= STATE_CHANGE | CONN_END_SER;
		end
		else begin
			stateCli_temp <= stateCli_connTb;
			event_bitmap_t <= NONE_STATE;
		end
	end
end
default: begin /** discard */
	/** output */
	event_bitmap_t <= NONE_STATE;
	action <= 1'b0;
	/** maintain conneciton state*/
	{stateCli_temp,sendSeqCli_temp,ackSeqCli_temp,winCli_temp,
		MwinCli_temp,stateSer_temp,sendSeqSer_temp,
		ackSeqSer_temp,winSer_temp,MwinSer_temp} <= {w_connTb{1'b0}};
end
					endcase
				end
			end
			else begin /** miss and do not need to add connetion, just drop this packet*/
				action <= 1'b0;
				event_bitmap_t <= {w_evb{1'b0}};
				{stateCli_temp,sendSeqCli_temp,ackSeqCli_temp,winCli_temp,
					MwinCli_temp,stateSer_temp,sendSeqSer_temp,
					ackSeqSer_temp,winSer_temp,MwinSer_temp} <= {w_connTb{1'b0}};
			end
		end
		else begin /** do not update connTb */
			action <= 1'b0;
		end
	end
end

/*************************************************************************************/
/*	this state machine used to rewrite connTb
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		idx_connTb_conf <= {d_connTb{1'b0}};
		wrValid_connTb_conf <= 1'b0;
		data_connTb_conf <= {w_connTb{1'b0}};
		eventInfo_valid <= 1'b0;
		eventInfo <= {w_eventInfo{1'b0}};
		conn_closed_valid <= 1'b0;
		conn_closed_info <= {w_flowID{1'b0}};
	end
	else begin
		if((action_valid == 1'b1) && (action == 1'b1)) begin
			/** rewrite connection */
			idx_connTb_conf <= connIdx_info_temp[3][b_idx_connIdxInfo+d_connTb-1:b_idx_connIdxInfo];
			wrValid_connTb_conf <= 1'b1;
			data_connTb_conf[w_connTb-1:b_cliWin_connTb] <= {stateCli_temp,sendSeqCli_temp,
				ackSeqCli_temp,winCli_temp};
			data_connTb_conf[b_cliMaxWin_connTb-1:b_serWin_connTb] <= {stateSer_temp,sendSeqSer_temp,
				ackSeqSer_temp,winSer_temp};
			if(winCli_temp > MwinCli_temp) 
				data_connTb_conf[b_cliWin_connTb-1:b_cliMaxWin_connTb] <= {winCli_temp};
			else
				data_connTb_conf[b_cliWin_connTb-1:b_cliMaxWin_connTb] <= {MwinCli_temp};
			if(winSer_temp > MwinSer_temp) 
				data_connTb_conf[b_serWin_connTb-1:b_serMaxWin_connTb] <= {winSer_temp};
			else
				data_connTb_conf[b_serWin_connTb-1:b_serMaxWin_connTb] <= {MwinSer_temp};

			if((event_bitmap_t == STATE_CHANGE) && (stateCli_temp == CLOSED_STATE) && 
				(stateSer_temp == CLOSED_STATE))
			begin
				conn_closed_valid <= 1'b1;
				conn_closed_info <= connIdx_info_temp[3][b_idx_connIdxInfo+d_connTb-1:b_idx_connIdxInfo];
			end
		end
		else begin
			wrValid_connTb_conf <= 1'b0;
			conn_closed_valid <= 1'b0;
		end
		eventInfo_valid <= action_valid;
		eventInfo <= {event_bitmap_t, stateCli_temp, stateSer_temp};
	end
end


function	check_seq_valid;
input	[31:0]	seq_temp;
input	[15:0]	length_temp;
input	[31:0]	ackSeqO_connTb;
input	[15:0]	winO_connTb;
input	[31:0]	seq_connTb;
begin
	//check_seq_valid = 1'b1;
	check_seq_valid = (({seq_temp[31],ackSeqO_connTb[31]} == 2'b01) || 
		({seq_temp[31],seq_connTb[31]} == 2'b01) || 
		((({1'd0,seq_temp} + {17'b0,length_temp}) <= ({1'b0,ackSeqO_connTb} + 
			{10'd0,winO_connTb,7'd0} + 33'd1)) && 
			({1'd1,seq_temp} >= ({1'd1,seq_connTb} -  {10'd0,winO_connTb,7'd0} - 33'd1))))? 1'b1:1'b0;
	
end
endfunction

function	check_ack_valid;
input	[31:0]	ack_temp;
input	[31:0]	seqO_connTb;
input	[31:0]	ackSeq_connTb;
input	[15:0]	Mwin_connTb;
begin
	//check_ack_valid = 1'b1;
	check_ack_valid = (({ack_temp[31],seqO_connTb[31]} == 2'b10) || 
		(({1'b0,ack_temp} <= ({1'b0,seqO_connTb} +33'd1)) &&
			({1'd1,ack_temp} >= ({1'd1,seqO_connTb} - {10'b0,Mwin_connTb,7'd0}) - 33'd1)))? 1'b1:1'b0;
end
endfunction



									

endmodule    
