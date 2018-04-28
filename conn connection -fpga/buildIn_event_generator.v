//=====================================================//
//	Module name: build-in event generator of UniMon;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/04/24
//	Function outline: UniMon_v0.1
//=====================================================//

`timescale 1ns/1ps

/*	function description:
*	1) working as a multiplexer to aggregate the event bitmpat from
*		conn_searcher and out-time inspector;
*	2) fill the event in the metadata;
*/

module buildIn_event_generator(
reset,
clk,
metadata_in_valid,
metadata_in,
metadata_out_valid,
metadata_out,
event_bitmap_valid,
event_bitmap,
pktIn_info,
agingInfo_valid,
agingInfo,
cur_timestamp
);

/*	width or depth or words info of signals
*/
parameter 	w_meta = 134,		// width of meta;
		w_evb = 10,		// width of event bitmap (hd); 
		w_evb_s = 8,		// width of event bitmap (sw);
		w_agingInfo = 40,	// width of aging info;
		d_metaBuffer = 8,	// depth of metadata buffer;
		words_metaBuffer = 256,	// words of metaBuffer;
		d_evbBuffer = 5,	// depth of event bitmap buffer;
		words_evbBuffer = 32,	// words of evb buffer;
		d_agingInfoBuffer = 5,	// depth of aging info buffer;
		words_agingInfoBuffer = 32,	// words of agingInfo buffer;
		w_timestamp = 8,	// width of timestamp;
		w_pktIn_info = 32,	/* width of packet info (connTb seracher
					*	to buildIn_event generator); */
		w_hdTag_meta = 2,	// width of header tag in metadata;
		w_flowID = 16,		// width of flowID;

		/* bit(loaction) of each component in x(table/reg) */
		b_pktIn_meta = 120,	// top bit of packet info in metadata;
		b_tmp_meta = 80,	// top bit of timestamp in metadata;
		b_reversed_meta = 72,	// top bit of reversed in meta;
		b_hdTag_meta = 134,	// top bit of header tag in metadata;
		b_flowID_agingInfo = 40,	// top bit of flowID in aging info;
		b_evb_agingInfo = 16,		// top bit of evb in aging info;
		b_lastTMP_agingInfo = 8,	/* top bit of last timestamp in 
						*	aging info; */
		
		
		/* constant/static parameter */
		PKT_TAIL = 2'b10,		// packet tail
		STATE_DEFAULT = 8'b0,	// initial event bitmap
		TIME_OUT = 8'd8;		// event bitmap of time out;

input					clk;
input					reset;
input					metadata_in_valid;
input		[w_meta-1:0]		metadata_in;
output	reg				metadata_out_valid;
output	reg	[w_meta-1:0]		metadata_out;
input					event_bitmap_valid;
input		[w_evb-1:0]		event_bitmap;
input		[w_pktIn_info-1:0]	pktIn_info;
input					agingInfo_valid;
input		[w_agingInfo-1:0]	agingInfo;
input		[w_timestamp-1:0]	cur_timestamp;

/*************************************************************************************/
/*	varialbe declaration
/*	from conn_search to two hash tables;
*/

/* metadata buffer*/
reg				rdreq_metaBuffer;
wire				empty_metaBuffer;
wire	[w_meta-1:0]		ctx_metaBuffer;
wire	[d_metaBuffer-1:0]	usedw_metaBuffer;

/* event bitmap buffer */
reg				rdreq_evbBuffer;
wire				empty_evbBuffer;
wire	[w_evb+w_pktIn_info-1:0]	ctx_evbBuffer;

/* aging infomation buffer */
reg				rdreq_agingInfoBuffer;
wire				empty_agingInfoBuffer;
wire	[w_agingInfo-1:0]	ctx_agingInfoBuffer;

/* fill event bitmap in metadata state machine */
reg	[w_evb-1:0]		evb_temp;
reg	[w_pktIn_info-1:0]	pktIn_info_temp;
reg	[w_agingInfo-1:0]	agingInfo_temp;

/*************************************************************************************/
/*	state register declaration
*	
*/
reg	[3:0]	state_genEVB;
parameter	IDLE_S		= 4'd0,
		READ_FIFO_EVB_S	= 4'd1,
		FILL_EVENT_BITMAP_S = 4'd2,
		WAIT_PKT_TAIL_S	= 4'd3,
		READ_FIFO_AGINGINFO_S = 4'd4,
		OUTPUT_METADATA_2_S = 4'd5;


/*************************************************************************************/
/*	submodule declaration
*	meta buffer(fifo)
*/
fifo meta_buffer(
.aclr(!reset),
.clock(clk),
.data(metadata_in),
.rdreq(rdreq_metaBuffer),
.wrreq(metadata_in_valid),
.empty(empty_metaBuffer),
.full(),
.q(ctx_metaBuffer),
.usedw(usedw_metaBuffer)
);
defparam
	meta_buffer.width = w_meta,
	meta_buffer.depth = d_metaBuffer,
	meta_buffer.words = words_metaBuffer;

/*	event bitmap buffer(fifo)
*/
fifo evb_buffer(
.aclr(!reset),
.clock(clk),
.data({event_bitmap,pktIn_info}),
.rdreq(rdreq_evbBuffer),
.wrreq(event_bitmap_valid),
.empty(empty_evbBuffer),
.full(),
.q(ctx_evbBuffer),
.usedw()
);
defparam
	evb_buffer.width = w_evb+w_pktIn_info,
	evb_buffer.depth = d_evbBuffer,
	evb_buffer.words = words_evbBuffer;

/*	aging infomation buffer(fifo)
*/
fifo agingInfo_buffer(
.aclr(!reset),
.clock(clk),
.data(agingInfo),
.rdreq(rdreq_agingInfoBuffer),
.wrreq(agingInfo_valid),
.empty(empty_agingInfoBuffer),
.full(),
.q(ctx_agingInfoBuffer),
.usedw()
);
defparam
	agingInfo_buffer.width = w_agingInfo,
	agingInfo_buffer.depth = d_agingInfoBuffer,
	agingInfo_buffer.words = words_agingInfoBuffer;


/*************************************************************************************/
/*	state machine declaration
*	this state machine is gen event bitmap and fill it in metadata; 
*/
always @ (posedge clk or negedge reset) begin
	if(!reset) begin
		metadata_out_valid <= 1'b0;
		metadata_out <= {w_meta{1'b0}};
		rdreq_evbBuffer <= 1'b0;
		rdreq_metaBuffer <= 1'b0;
		rdreq_agingInfoBuffer <= 1'b0;

		evb_temp <= {w_evb{1'b0}};
		pktIn_info_temp <= {w_pktIn_info{1'b0}};
		agingInfo_temp <= {w_agingInfo{1'b0}};

		state_genEVB <= IDLE_S;
	end
	else begin
		case(state_genEVB)
			IDLE_S: begin
				metadata_out_valid <= 1'b0;
				if(empty_evbBuffer == 1'b0) begin
					rdreq_evbBuffer <= 1'b1;
					rdreq_metaBuffer <= 1'b1;
					state_genEVB <= READ_FIFO_EVB_S;
				end
				else if(empty_agingInfoBuffer == 1'b0) begin
					rdreq_agingInfoBuffer <= 1'b1;
					state_genEVB <= READ_FIFO_AGINGINFO_S;
				end
				else begin
					state_genEVB <= IDLE_S;
				end
			end
			READ_FIFO_EVB_S: begin
				rdreq_evbBuffer <= 1'b0;
				// forward or drop ? 
				// this should be modified
				metadata_out_valid <= 1'b1;
				metadata_out <= ctx_metaBuffer;	// metadata[0];
				{evb_temp,pktIn_info_temp} <= ctx_evbBuffer;
				state_genEVB <= FILL_EVENT_BITMAP_S;
			end
			FILL_EVENT_BITMAP_S: begin
				metadata_out_valid <= 1'b1;		// metadata[1];
				metadata_out <= {ctx_metaBuffer[w_meta-1:b_pktIn_meta],
					pktIn_info_temp,evb_temp[w_evb_s-1:0], cur_timestamp,
					ctx_metaBuffer[b_reversed_meta-1:0]};
				state_genEVB <= WAIT_PKT_TAIL_S;
			end
			WAIT_PKT_TAIL_S: begin
				metadata_out_valid <= 1'b1;
				metadata_out <= ctx_metaBuffer;
				if(ctx_metaBuffer[b_hdTag_meta-1: b_hdTag_meta-
					w_hdTag_meta] == PKT_TAIL)
				begin
					rdreq_metaBuffer <= 1'b0;
					state_genEVB <= IDLE_S;
				end
				else begin
					state_genEVB <= WAIT_PKT_TAIL_S;
				end
			end
			READ_FIFO_AGINGINFO_S: begin
				rdreq_agingInfoBuffer <= 1'b0;
				agingInfo_temp <= ctx_agingInfoBuffer;
				// metadata[0]
				metadata_out_valid <= 1'b1;
				metadata_out <= {2'b01, 132'b0};
				state_genEVB <= OUTPUT_METADATA_2_S;
			end
			OUTPUT_METADATA_2_S: begin
				metadata_out_valid <= 1'b1;
				// metadata[1]
				metadata_out <= {2'b10, 4'h0,8'b0,agingInfo_temp[w_agingInfo-1:
					b_evb_agingInfo],TIME_OUT,agingInfo_temp[b_evb_agingInfo-1:
					0],{b_reversed_meta{1'b0}}};
				state_genEVB <= IDLE_S;
			end
			default: begin
				state_genEVB <= IDLE_S;
			end
		endcase
	end
end



endmodule    
