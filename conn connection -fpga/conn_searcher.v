//=====================================================//
//	Module name: connection searcher of UniMon;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/04/21
//	Function outline: UniMon_v0.1
//=====================================================//

`timescale 1ns/1ps

/*	function description:
*	1) extract 4-tuple in the metadata, we assurme the location of 4-tuple
*		is metadata[127:32], and tcp flag is [31:24];
*	2) calculate two hash values used to search hash tables, the hash
*		functions are: a) flow_key[79:64]^[15:0] and b) flow_key
*		[47:32]^[31:16]; the simplified flow_key is flow_key[79:64]^
*		[47:32]^[31:16]^[15:0];
*	3) search the conneciton table according to the result of hash table;
*	4) if hiting, update the conneciton entry, and check whether needing
*		to generate build-in event or send packet to cpu; if missing,
*		send packe to cup and wait to add a new conneciton;
*/
module connection_searcher(
reset,
clk,
metadata_in_valid,
metadata_in,
/*
metadata_out_valid,
metadata_out,
*/
event_bitmap_valid,
event_bitmap,
pktIn_info,
hashV_1,
hashV_2,
hashV_valid,
ctx_hashTb_1,
ctx_hashTb_2,
idx_connTb,
data_connTb,
rdValid_connTb,
wrValid_connTb,
wrValid_agingTb,
ctx_connTb
);

/*	width or depth or words info of signals
*/
parameter 	w_meta = 134,		// width of metadata;
		w_pkt	= 134,		// width of packet;
		w_ctrl	= 32,		// width of ctrl's data;
		w_key = 96,		// width of flow key;
		w_evb = 10,		// width of event bitmap; 
		w_evb_s = 8,		// width of event bitmap (sw);
		w_connTb = 200,	// width of connTb's entry;
		d_connTb = 9,		// depth of connTb;
		w_hashTb = 33,	// width of hashTb's entry;
		d_hashTb = 9,		// depth of hashTb;
		w_simpleFlowKey = 16,	// width of simplified flow key;
		d_keyBuffer = 5,	// depth of flow key buffer;
		words_keyBuffer = 32,	// words of flow key buffer;
		w_state = 2,		// width of state field in connTb;
		w_tcpFlag = 6,		// width of tcpFlag in packet;
		w_pktIn = 8,		// width of pktIn field in connTb;
		w_nextIdx = 16,	// width of nextIdx field in connTb;
		w_act = 4,		// width of action field in connTb;
		w_hd_tag = 2,		// width of header tag in metadata;
		w_flowID = 16,		// width of flowID;
		w_state_total = 8, 	// width of total state info;
		w_pktIn_info = 32,	// width of pktIn info;
		w_ip = 32,		// width fo ip addr;
		
		/* bit(loaction) of each component in x(table/reg) */
		b_hdTag_meta = 134,	// top bit of header tag in metadata;
		b_agingTag_connTb = 201,	// top bit of aging tag returned from connTb;
		b_flowKey_meta = 128,	// top bit of flow key in metadata;
		/* used for calculating hash values */
		b_srcIP_h = 80,	// top bit of srcIP in flow key (hash calculation);
		b_dstIP_h = 48,	// top bit of dstIP in flow key (hash calculation);
		b_srcPort = 32,	// top bit of srcPort in flow key;
		b_dstPort = 16,	// top bit of dstPort in flwo key;
		/* used for comparing with connTb */
		b_srcIP = 96,		// top bit of srcIP in flow key;
		b_dstIP = 64,		// top bit of dstIP in flow key;

		b_idx_hashTb = 9,	// top bit(location) of the idx_info in hashTb;
		b_flowKey_connTb = 200,	// top bit of flow key in connTb;
		b_state_connTb = 104,	// top bit of state in connTb;
		b_dir_connTb = 101,		// top bit of direction in connTb;
		b_stateC_connTb = 100,	// top bit of state-client in connTb;
		b_stateS_connTb = 98,	// top bit of state-server in connTb;
		b_pktIn_connTb = 96,		// top bit of pktIn_cnd in connTb;
		b_actC_connTb = 88,		// top bit of action-client in connTb;
		b_actS_connTb = 84,		// top bit of action-server in connTb;
		b_nextIdx_connTb = 80,	// top bit of next idx in connTb;
		b_pktCnt_connTb = 64,	// top bit of packet count in connTb;
		b_btCnt_connTb = 32, 	// top bit of byte count in connTb;


		PKT_TAIL = 2'b10,		// packet tail;

		/* event bitmap */
		EVERY_PKT = 10'd1,		// evety packet (default);
		NEW_FLOW = 10'd2,		// new flow (conneciton start);
		CONN_SETUP = 10'd4,	// conneciton setup;
		TIME_OUT = 10'd8,		// conneciton time out;
		STATE_CHANGE = 10'd16,	// state changed;
		CONN_END = 10'd32,	// connection end;
		CONN_START = 10'd64,	// connection start (server);
		PKT_IN = 10'd256,		// pktIn_tag used by hardware;
		FORWARD = 10'd512,	// forward_tag used by hd;
		
		CLOSED_STATE = 2'd0,		// state of closed;
		REQUESTED_STATE = 2'd1,		// state of requested;
		ESTABLISHED_STATE = 2'd2,	// state of established;
		
		ONLY_ACK = 6'h10,		// tcp flag: ack;
		ONLY_SYN = 6'h02,		// tcp flag: syn;
		ONLY_FIN = 6'h01,		// tcp flag: fin;
		ONLY_RST = 6'h04,		// tcp flag: rst;
		
		FORWARD_ACT = 4'd1;	// aciton: forward;

input				clk;
input				reset;
input				metadata_in_valid;
input		[w_pkt-1:0]	metadata_in;
/*
output	reg			metadata_out_valid;
output	reg	[w_pkt-1:0]	metadata_out;
*/
output	reg			event_bitmap_valid;
output	reg	[w_evb-1:0]	event_bitmap;
output	wire[w_pktIn_info-1:0]	pktIn_info;
output	reg	[d_hashTb-1:0]	hashV_1;
output	reg	[d_hashTb-1:0]	hashV_2;
output	reg				hashV_valid;
input		[w_hashTb-1:0]	ctx_hashTb_1;
input		[w_hashTb-1:0]	ctx_hashTb_2;
output	reg	[d_connTb-1:0]	idx_connTb;
output	reg	[w_connTb-1:0]	data_connTb;
output	reg				rdValid_connTb;
output	reg				wrValid_connTb;
output	reg				wrValid_agingTb;
input	wire	[w_connTb:0]		ctx_connTb;	/* top bit is aging_tag */

/*************************************************************************************/
/*	varialbe declaration
*	flow_key is the 4-tuple info extracted from packet/flow header, i.e.,
*		src_ip, dst_ip, src_port, dst_port;
*/
/*	state machine of generating 4-tuple info;
*/
reg	[w_simpleFlowKey-1:0]	flowKey_sim[2:0];
wire	[w_key-1:0]			flowKey;
reg						valid_temp[1:0];
wire	[w_tcpFlag-1:0]		tcpFlag;

/*	flow key buffer(fifo)
*/
reg		[w_key+w_tcpFlag-1:0]	data_flowK;
reg					rdreq_flowK;
wire	[w_key+w_tcpFlag-1:0]	ctx_flowK;

/*	idx_connTb buffer(fifo)
*/
reg	[d_connTb-1:0]	data_idx;
reg				rdreq_idx,wrreq_idx;
wire				empty_idx;
wire	[d_connTb-1:0]	ctx_idx;

/*	state machine of search connTb
*/
reg	[w_key-1:0]		flowKey_temp;
reg				dir_temp;
reg	[w_tcpFlag-1:0]	tcpFlag_temp;
reg	[w_pktIn-1:0]		pktIn_cnd;
reg	[w_evb-1:0]		forward_temp;
reg	[w_state-1:0]	stateCli_temp,stateSer_temp;

/*	assign pktIn_info
*/
reg	[w_state_total-1:0]	state_pktIn;
reg	[w_flowID-1:0]		flowID_pktIn;
reg	[w_evb-1:0]			event_bitmap_t;

/*************************************************************************************/
/*	state register declaration
*	
*/
reg	[3:0]	state_genFK, state_searchConnTb;
parameter	IDLE_S			= 4'd0,
		WAIT_PKT_TAIL		= 4'd1,
		READ_FIFO_S			= 4'd1,
		WAIT_CONNTB_1_S		= 4'd2,
		WAIT_CONNTB_2_S		= 4'd3,
		READ_CONNTB_S		= 4'd4,
		UPDATE_STATE_S		= 4'd5,
		CHECK_PKTIN_CND_S	=4'd6,
		WAIT_CONNTB_1Re_S	= 4'd7;

/*************************************************************************************/
/*	submodule declaration
*	pkt fifo

fifo pkt_buffer(
.aclr(!reset),
.clock(clk),
.data(metadata_in),
.rdreq(rdreq_pktBuffer),
.wrreq(metadata_in_valid),
.empty(empty_pktBuffer),
.full(),
.q(ctx_pktBuffer),
.usedw(usedw_pktBuffer)
);
defparam
	pkt_buffer.width = w_pkt,
	pkt_buffer.depth = d_pktBuffer,
	pkt_buffer.words = words_pktBuffer;
*/	

/*	flowKey_buffer consists of flowKey and flowKey_sim;
*/
fifo flowKey_buffer(
.aclr(!reset),
.clock(clk),
.data(data_flowK),
.rdreq(rdreq_flowK),
.wrreq(hashV_valid),
.empty(),
.full(),
.q(ctx_flowK),
.usedw()
);
defparam
	flowKey_buffer.width = w_key+w_tcpFlag,
	flowKey_buffer.depth = d_keyBuffer,
	flowKey_buffer.words = words_keyBuffer;

/*	idx_connTb_buffer used to cache the idx from hash table;
*/
fifo idx_connTb_buffer(
.aclr(!reset),
.clock(clk),
.data(data_idx),
.rdreq(rdreq_idx),
.wrreq(wrreq_idx),
.empty(empty_idx),
.full(),
.q(ctx_idx),
.usedw()
);
defparam
	idx_connTb_buffer.width = d_connTb,
	idx_connTb_buffer.depth = d_keyBuffer,
	idx_connTb_buffer.words = words_keyBuffer;

/*************************************************************************************/
/*	used to get flow key and tcp tag;
*/
assign {flowKey,tcpFlag} = metadata_in[b_flowKey_meta-1:
			b_flowKey_meta-w_key-w_tcpFlag];

/*************************************************************************************/
/*	state machine declaration
*	this state machine is used extract 4-tuple info which used to gen two 
*		hash values, and extract tcp flags;
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		//flowKey <= {w_key{1'b0}};
		//tcpFlag <= {w_tcpFlag{1'b0}};
		hashV_valid <= 1'b0;
		hashV_1 <= {d_hashTb{1'b0}};
		hashV_2 <= {d_hashTb{1'b0}};
		data_flowK <= {(w_key+w_tcpFlag){1'b0}};
		flowKey_sim[0] <= {w_simpleFlowKey{1'b0}};
		state_genFK <= IDLE_S;
	end
	else begin
		case(state_genFK)
			IDLE_S: begin
				if(metadata_in_valid == 1'b1) begin
					//{flowKey,tcpFlag} <= metadata_in[b_flowKey_meta-1:
					//	b_flowKey_meta-w_key-w_tcpFlag];
					/* get simplified flow key & flowKey & tcpFlag */
					flowKey_sim[0] <= flowKey[b_srcIP_h-1:b_srcIP_h-w_simpleFlowKey]^
						flowKey[b_dstIP_h-1:b_dstIP_h-w_simpleFlowKey]^
						flowKey[b_srcPort-1:b_srcPort-w_simpleFlowKey]^
						flowKey[b_dstPort-1:b_dstPort-w_simpleFlowKey];
					hashV_1 <= flowKey[b_srcIP_h-1:b_srcIP_h-w_simpleFlowKey]^
						flowKey[b_srcPort-1:b_srcPort-w_simpleFlowKey];
					hashV_2 <= flowKey[b_dstIP_h-1:b_dstIP_h-w_simpleFlowKey]^
						flowKey[b_dstPort-1:b_dstPort-w_simpleFlowKey];
					hashV_valid <= 1'b1;
					data_flowK <= {flowKey,tcpFlag};
					state_genFK <= WAIT_PKT_TAIL;
				end
				else begin
					hashV_valid <= 1'b0;
					state_genFK <= IDLE_S;
				end
			end
			WAIT_PKT_TAIL: begin
				hashV_valid <= 1'b0;				
				if(metadata_in[b_hdTag_meta-1:b_hdTag_meta-w_hd_tag] ==
					PKT_TAIL) begin
						state_genFK <= IDLE_S;
					end
				else begin
					state_genFK <= WAIT_PKT_TAIL;
				end
			end
			default: state_genFK <= IDLE_S;
		endcase
	end
end
/*************************************************************************************/
/*	this state machine is used to buffer simplified flow key until getting
*		ctx_hashTb; 
*	another function is used to count clocks, i.e., wait the result from
*		two hash tables;
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		flowKey_sim[1] <= {w_simpleFlowKey{1'b0}};
		flowKey_sim[2] <= {w_simpleFlowKey{1'b0}};
		valid_temp[0] <= 1'b0;
		valid_temp[1] <= 1'b0;
	end
	else begin
		flowKey_sim[1] <= flowKey_sim[0];
		flowKey_sim[2] <= flowKey_sim[1];
		valid_temp[0] <= hashV_valid;
		valid_temp[1] <= valid_temp[0];
	end
end

/*************************************************************************************/
/*	this state machine is used to generate index which buffered in fifo; 
*/
always @ (posedge clk or negedge reset) begin
	if(!reset) begin
		wrreq_idx <= 1'b0;
		data_idx <= {d_connTb{1'b0}};
	end
	else begin
		/* read ctx_hashTb and compare with simpified hash key*/
		if(valid_temp[1] == 1'b1) begin	/* hit: read connTb */
			if((ctx_hashTb_1[w_hashTb-2:w_hashTb-1-w_simpleFlowKey] ==
				flowKey_sim[2]) && (ctx_hashTb_1[w_hashTb-1] == 1'b1)) 
			begin
				data_idx <= ctx_hashTb_1[b_idx_hashTb-1:b_idx_hashTb-d_hashTb];
				wrreq_idx <= 1'b1;
			end
			else if((ctx_hashTb_2[w_hashTb-2:w_hashTb-1-w_simpleFlowKey] ==
				flowKey_sim[2]) && (ctx_hashTb_2[w_hashTb-1] == 1'b1)) 
			begin
				data_idx <= ctx_hashTb_2[b_idx_hashTb-1:b_idx_hashTb-d_hashTb];
				wrreq_idx <= 1'b1;
			end
			else begin	/* miss: a new flow(packet), assign "0" */
				wrreq_idx <= 1'b1;
				data_idx <= {d_connTb{1'b0}};
			end
		end
		else begin
			wrreq_idx <= 1'b0;
		end
	end
end

/*************************************************************************************/
/*	read idx_connTb_buffer and search connTb to get the exact flowID;
*/
always @ (posedge clk or negedge reset) begin
	if(!reset) begin
		rdValid_connTb <= 1'b0;
		wrValid_connTb <= 1'b0;
		wrValid_agingTb <= 1'b0;
		idx_connTb <= {d_connTb{1'b0}};
		rdreq_idx <= 1'b0;
		rdreq_flowK <= 1'b0;
		event_bitmap_valid <= 1'b0;
		event_bitmap <= {w_evb{1'b0}};
		event_bitmap_t <= {w_evb{1'b0}};

		flowKey_temp <= {w_key{1'b0}};
		dir_temp <= 1'b0;
		tcpFlag_temp <= {w_tcpFlag{1'b0}};
		data_connTb <= {w_connTb{1'b0}};
		pktIn_cnd <= {w_pktIn{1'b0}};
		forward_temp <= {w_evb{1'b0}};
		stateCli_temp <= {{w_state{1'b0}}};
		stateSer_temp <= {{w_state{1'b0}}};
		state_pktIn <= {w_state_total{1'b0}};
		flowID_pktIn <= {w_flowID{1'b0}};
		
		state_searchConnTb <= IDLE_S;
	end
	else begin
		case(state_searchConnTb)
			IDLE_S: begin
				/* initial */
				event_bitmap_valid <= 1'b0;
				event_bitmap <= {w_evb{1'b0}};
				state_pktIn <= {w_state_total{1'b0}};
				flowID_pktIn <= {w_flowID{1'b0}};
				
				/* read idx_connTb_buffer */
				if(empty_idx == 1'b0) begin
					rdreq_idx <= 1'b1;
					state_searchConnTb <= READ_FIFO_S;
				end
				else begin
					rdreq_idx <= 1'b0;
					state_searchConnTb <= IDLE_S;
				end
			end
			READ_FIFO_S: begin
				rdreq_idx <= 1'b0;
				idx_connTb <= ctx_idx;
				flowID_pktIn[d_connTb-1:0] <= ctx_idx;
				
				/* miss: send packet to cpu */
				if(ctx_idx == {d_connTb{1'b0}}) begin
					event_bitmap_valid <= 1'b1;
					event_bitmap <= PKT_IN | NEW_FLOW;
					event_bitmap_t <= PKT_IN | NEW_FLOW;
					state_searchConnTb <= IDLE_S;
				end
				/* hit: read connTb */
				else begin
					rdValid_connTb <= 1'b1;
					rdreq_flowK <= 1'b1;
					/* initial event_bitmap to distinguish with out-time conn*/
					event_bitmap <= EVERY_PKT;
					state_searchConnTb <= WAIT_CONNTB_1_S;
				end
			end
			WAIT_CONNTB_1_S: begin
				rdValid_connTb <= 1'b0;
				{flowKey_temp,tcpFlag_temp} <= ctx_flowK;
				rdreq_flowK <= 1'b0;
				state_searchConnTb <= WAIT_CONNTB_2_S;
			end
			/* do not assign {flowKey_temp, tcpFlag_temp} again */
			WAIT_CONNTB_1Re_S: begin
				rdValid_connTb <= 1'b0;
				state_searchConnTb <= WAIT_CONNTB_2_S;
			end
			WAIT_CONNTB_2_S: begin
				state_searchConnTb <= READ_CONNTB_S;
			end
			READ_CONNTB_S: begin
				/* hit: read the aging tag and update state;
				* the direction of packet is same as the entry;
				*/
				if(flowKey_temp == ctx_connTb[b_flowKey_connTb-1:
					b_flowKey_connTb-w_key]) 
				begin
					dir_temp <= ctx_connTb[b_dir_connTb-1];
					data_connTb <= ctx_connTb[w_connTb-1:0];
					pktIn_cnd <= ctx_connTb[b_pktIn_connTb-1:
						b_pktIn_connTb-w_pktIn];
					if(ctx_connTb[b_agingTag_connTb-1] == 1'b1) begin
						event_bitmap_valid <= 1'b1;
						event_bitmap <= PKT_IN |NEW_FLOW;
						event_bitmap_t <= PKT_IN | NEW_FLOW;
						state_searchConnTb <= IDLE_S;
					end
					else begin
						/* update timestamp of last packet; */
						wrValid_agingTb <= 1'b1;
						stateCli_temp <= ctx_connTb[b_stateC_connTb-1:
							b_stateC_connTb-w_state];
						stateSer_temp <= ctx_connTb[b_stateS_connTb-1:
							b_stateS_connTb-w_state];
						//state_pktIn <= ctx_connTb[b_state_connTb-1:
						//	b_state_connTb-w_state_total];	
							
						state_searchConnTb <= UPDATE_STATE_S;
					end
				end
				/* hit: read the aging tag and update state;
				* the direction of packet is opposite as the entry;
				*/
				else if({flowKey_temp[b_dstIP-1:b_dstIP-w_ip], flowKey_temp[b_srcIP-1:b_srcIP-w_ip], 
					flowKey_temp[b_dstPort-1: b_dstPort-16], flowKey_temp[b_srcPort-1: b_srcPort-16]} == 
					ctx_connTb[b_flowKey_connTb-1:b_flowKey_connTb-w_key]) 
				begin
					dir_temp <= ~ctx_connTb[b_dir_connTb-1];
					data_connTb <= ctx_connTb[w_connTb-1:0];
					pktIn_cnd <= ctx_connTb[b_pktIn_connTb-1:
						b_pktIn_connTb-w_pktIn];
					if(ctx_connTb[b_agingTag_connTb-1] == 1'b1) begin
						event_bitmap_valid <= 1'b1;
						event_bitmap <= PKT_IN | NEW_FLOW;
						event_bitmap_t <= PKT_IN | NEW_FLOW;
						state_searchConnTb <= IDLE_S;
					end
					else begin
						wrValid_agingTb <= 1'b1;
						stateCli_temp <= ctx_connTb[b_stateC_connTb-1:
							b_stateC_connTb-w_state];
						stateSer_temp <= ctx_connTb[b_stateS_connTb-1:
							b_stateS_connTb-w_state];
						//state_pktIn <= ctx_connTb[b_state_connTb-1:
						//	b_state_connTb-w_state_total];
						state_searchConnTb <= UPDATE_STATE_S;
					end
				end
				/* miss: read the next index in connTb, if this index is 0(null), then 
				* 	send packet to cpu with NEW_FLOW(event_bitmap), else
				*	read the next entry;
				*/
				else begin
					/* search the hash conflict chain */
					if(ctx_connTb[b_nextIdx_connTb-1:b_nextIdx_connTb-w_nextIdx]!= 
						{w_connTb{1'b0}}) 
					begin
						rdValid_connTb <= 1'b1;
						idx_connTb <= ctx_connTb[b_nextIdx_connTb-1:b_nextIdx_connTb-w_nextIdx];
						flowID_pktIn[d_connTb-1:0] <= ctx_connTb[b_nextIdx_connTb-1:
							b_nextIdx_connTb-w_nextIdx];
						state_searchConnTb <= WAIT_CONNTB_1Re_S;
					end
					/* tail of hash chain: packet in */
					else begin
						event_bitmap_valid <= 1'b1;
						event_bitmap <= NEW_FLOW | PKT_IN;
						event_bitmap_t <= PKT_IN | NEW_FLOW;
						flowID_pktIn <= {w_flowID{1'b0}};
						state_searchConnTb <= IDLE_S;
					end
				end
			end
			UPDATE_STATE_S: begin
				wrValid_agingTb <= 1'b0;
				/* packet is from client */
				if(dir_temp == 1'b0) begin 
					/* check aciton in connTb */
					if((data_connTb[b_actC_connTb-1:b_actC_connTb-w_act] & 
						FORWARD_ACT) == FORWARD_ACT) 
							forward_temp <= FORWARD;
					else 		forward_temp <= {w_evb{1'b0}};

					/* update client state */
					case(stateCli_temp)
						/* recv syn packet, do not need consider */
						CLOSED_STATE: begin
							// assigned by CSM
							state_searchConnTb <= CHECK_PKTIN_CND_S;
						end
						/* recv ack packet, and check the seq */
						REQUESTED_STATE: begin
							/* 	check the sequence is on the road;
							*	recv ack packet: REQUESTED->ESTABLISHED;
							*/
							if(tcpFlag_temp == ONLY_ACK) begin
								data_connTb[b_stateC_connTb-1:
									b_stateC_connTb-w_state] <=
									ESTABLISHED_STATE;
								data_connTb[b_stateS_connTb-1:
									b_stateS_connTb-w_state] <=
									ESTABLISHED_STATE;	
								wrValid_connTb <= 1'b1;
								state_searchConnTb <= CHECK_PKTIN_CND_S;

								event_bitmap <= event_bitmap | STATE_CHANGE | 
									CONN_SETUP;
							end
							else if((tcpFlag_temp & ONLY_RST) == ONLY_RST) begin
								data_connTb[b_stateC_connTb-1:
									b_stateC_connTb-w_state] <=
									CLOSED_STATE;
								data_connTb[b_stateS_connTb-1:
									b_stateS_connTb-w_state] <=
									CLOSED_STATE;
								wrValid_connTb <= 1'b1;
								state_searchConnTb <= CHECK_PKTIN_CND_S;

								event_bitmap <= event_bitmap | STATE_CHANGE | 
									CONN_END;
							end
							else begin
								state_searchConnTb <= CHECK_PKTIN_CND_S;
							end
						end
						/* recv fin/rst, and wait ack */
						ESTABLISHED_STATE: begin
							/* record the sequence is on the road */
							if(((tcpFlag_temp & ONLY_FIN) == ONLY_FIN)||
								(((tcpFlag_temp & ONLY_RST) == ONLY_RST))) 
							begin
								data_connTb[b_stateC_connTb-1:
									b_stateC_connTb-w_state] <=
									CLOSED_STATE;
								if((tcpFlag_temp & ONLY_RST) == ONLY_RST) begin
									data_connTb[b_stateS_connTb-1:
										b_stateS_connTb-w_state] <=
										CLOSED_STATE;
								end
								wrValid_connTb <= 1'b1;
								state_searchConnTb <= CHECK_PKTIN_CND_S;

								event_bitmap <= event_bitmap | STATE_CHANGE | 
									CONN_END;
							end
							else begin
								state_searchConnTb <= CHECK_PKTIN_CND_S;
							end
						end
						default: begin
							state_searchConnTb <= CHECK_PKTIN_CND_S;
						end
					endcase
				end
				/* packet is from server */
				else begin
					/* check aciton in connTb */
					if((data_connTb[b_actS_connTb-1:b_actS_connTb-w_act] & 
						FORWARD_ACT) == FORWARD_ACT) 
							forward_temp <= FORWARD;
					else 		forward_temp <=  {w_evb{1'b0}};

					/* update server state */
					case(stateSer_temp)
						/* recv syn-ack packet, do not need consider;
						*  check sequence is on the road;
						*/
						CLOSED_STATE: begin
							if(tcpFlag_temp == (ONLY_SYN|ONLY_ACK)) begin
								data_connTb[b_stateS_connTb-1:
									b_stateS_connTb-w_state] <=
									REQUESTED_STATE;
								wrValid_connTb <= 1'b1;
								state_searchConnTb <= CHECK_PKTIN_CND_S;

								event_bitmap <= event_bitmap | STATE_CHANGE | 
									CONN_START;
							end
							else begin
								state_searchConnTb <= CHECK_PKTIN_CND_S;
							end
						end
						/* ack from client, and check the seq */
						REQUESTED_STATE: begin
							// on the road;
							// current state change is processed by recy ack packet;
							state_searchConnTb <= CHECK_PKTIN_CND_S;
						end
						/* recv fin, fill the sequence */
						ESTABLISHED_STATE: begin
							/* check the sequence is on the road */
							if((tcpFlag_temp & ONLY_FIN) == ONLY_FIN) begin
								data_connTb[b_stateS_connTb-1:
									b_stateS_connTb-w_state] <=
									CLOSED_STATE;
								wrValid_connTb <= 1'b1;
								state_searchConnTb <= CHECK_PKTIN_CND_S;

								event_bitmap <= event_bitmap | STATE_CHANGE | 
									CONN_END;
							end
							else begin
								state_searchConnTb <= CHECK_PKTIN_CND_S;
							end
						end
						default: begin
							state_searchConnTb <= CHECK_PKTIN_CND_S;
						end
					endcase
				end
			end
			CHECK_PKTIN_CND_S: begin
				wrValid_connTb <= 1'b0;
				event_bitmap_valid <= 1'b1;
				state_pktIn <= data_connTb[b_state_connTb-1:
							b_state_connTb-w_state_total];
				if(event_bitmap[w_pktIn-1:0] & pktIn_cnd) begin
					event_bitmap <= {event_bitmap[w_evb-1:w_pktIn], 
						(event_bitmap[w_pktIn-1:0] & pktIn_cnd)} | 
						PKT_IN | forward_temp;
					// the function of gen event_bitmap for UA 
					//		itself is on the road;
				end
				/* just do event_bitmap = forward_temp; */
				else begin
					event_bitmap <= forward_temp;
				end
				/* the original event bitmap */
				event_bitmap_t <= event_bitmap;
				state_searchConnTb <= IDLE_S;
			end

			default: begin
				state_searchConnTb <= IDLE_S;
			end
		endcase
	end
end

/*************************************************************************************/
/*	this state machine assign pktIn_info; 
*/
assign pktIn_info = {flowID_pktIn,state_pktIn,event_bitmap_t[w_evb_s-1:0]};

endmodule    
