//=====================================================//
//	Module name: connection time-out inspector of UniMon;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/04/25
//	Function outline: UniMon_v0.1
//=====================================================//

`timescale 1ns/1ps

/*	function description:
*	1) check the connection's last timestamp;
*	2) send agingInfo ot build-in event generator if the connection is
*		out time;
*/

module connection_outTime_inspector(
reset,
clk,
aging_enable,
idx_agingTb,
data_agingTb,
rdValid_agingTb,
wrValid_agingTb,
ctx_agingTb,
agingInfo_valid,
agingInfo,
cur_timestamp
);

/*	width or depth or words info of signals
*/
parameter 	w_agingInfo = 40,	// width of aging info to build-in event generator;
		w_agingTb = 9,	// width of aging table;
		d_agingTb = 9,	// depth of aging table;
		w_timestamp = 8,	// width of timestamp;
		d_idxWRbuffer = 5,	// depth of idx fifo waiting to write aging table;
		words_idxWRbuffer = 32,	// words of idx fifo;

		/* bit(loaction) of each component in x(table/reg) */
		b_agingTag_agingTb = 9,	// top bit of aging tag in aging table;

		/* constant/static parameter */
		INCREASE_IDX_AGINGTB = 9'd1,	// check connetion one by one;
		INTERVAL_AGING = 8'd2,	// the out-time interval (10ms)
		TIME_OUT = 8'd8;	// event bitmap of time out;

input					clk;
input					reset;
input					aging_enable;
output	reg	[d_agingTb-1:0]	idx_agingTb;
output	reg	[w_agingTb-1:0]	data_agingTb;
output	reg				rdValid_agingTb;
output	reg				wrValid_agingTb;
input		[w_agingTb-1:0]	ctx_agingTb;
output	reg				agingInfo_valid;
output	reg	[w_agingInfo-1:0]	agingInfo;
input		[w_timestamp-1:0]	cur_timestamp;

/*************************************************************************************/
/*	varialbe declaration
/*	from conn_search to two hash tables;
*/

/* idx of waiting to write aging table in idxWR buffer*/
reg	[w_agingTb-1:0]	data_idxWRbuffer;
reg				rdreq_idxWRbuffer;
wire				empty_idxWRbuffer;
wire	[w_agingTb-1:0]		ctx_idxWRbuffer;

/* gen agingInfo state machine */
reg				aging_tag;
reg				rdValid_temp[1:0];
reg	[d_agingTb-1:0]	idx_temp[1:0];
reg	[d_agingTb-1:0]	idx_agingTb_t;	// temp of idx_agintTb;

reg	[3:0]	state_aging, state_wrAging;
parameter	IDLE_S			= 4'd0,
		READ_AGINGTB_S		= 4'd1,
		READ_IDXWR_FIFO_S	= 4'd1,
		WAIT_WRITE_AGINGTB_S	= 4'd2;


/*************************************************************************************/
/*	submodule declaration
*	index waited to be written //buffer(fifo)
*/
fifo idxWR_buffer(
.aclr(!reset),
.clock(clk),
.data(data_idxWRbuffer),
.rdreq(rdreq_idxWRbuffer),
.wrreq(agingInfo_valid),
.empty(empty_idxWRbuffer),
.full(),
.q(ctx_idxWRbuffer),
.usedw()
);
defparam
	idxWR_buffer.width = d_agingTb,
	idxWR_buffer.depth = d_idxWRbuffer,
	idxWR_buffer.words = words_idxWRbuffer;

/*************************************************************************************/
/*	state machine declaration
*	this state machine is used to read agingTb; 
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		idx_agingTb <= {d_agingTb{1'b0}};
		idx_agingTb_t <= {d_agingTb{1'b0}};
		rdValid_agingTb <= 1'b0;
		wrValid_agingTb <= 1'b0;
		rdreq_idxWRbuffer <= 1'b1;
		data_agingTb <= {w_agingTb{1'b0}};
		
		state_wrAging <= IDLE_S;
	end
	else begin
		case(state_wrAging)
			IDLE_S: begin
				wrValid_agingTb <= 1'b0;
				if((aging_enable == 1'b1)&&(aging_tag)) begin
					/* read WRbuffer to write agingTb */
					if(empty_idxWRbuffer == 1'b0) begin
						rdreq_idxWRbuffer <= 1'b1;
						rdValid_agingTb <= 1'b0;
						state_wrAging <= READ_IDXWR_FIFO_S;
					end
					/* read agingTb */
					else begin
						idx_agingTb <= idx_agingTb_t;
						idx_agingTb_t <= idx_agingTb_t + 
							INCREASE_IDX_AGINGTB;
						rdValid_agingTb <= 1'b1;
						state_wrAging <= IDLE_S;
					end
				end
				else begin
					rdreq_idxWRbuffer <= 1'b0;
					rdValid_agingTb <= 1'b0;
					state_wrAging <= IDLE_S;
				end
			end
			READ_IDXWR_FIFO_S: begin
				rdreq_idxWRbuffer <= 1'b0;
				idx_agingTb <= ctx_idxWRbuffer;
				state_wrAging <= WAIT_WRITE_AGINGTB_S;
			end
			/* update agingTb which aging_enable is enable */
			WAIT_WRITE_AGINGTB_S: begin
				if((aging_enable == 1'b1)&&(aging_tag)) begin
					wrValid_agingTb <= 1'b1;
					data_agingTb[b_agingTag_agingTb-1] <= 1'b1;
					state_wrAging <= IDLE_S;
				end
				else begin
					state_wrAging <= WAIT_WRITE_AGINGTB_S;
				end
			end
			default: begin
				state_wrAging <= IDLE_S;
			end
		endcase
	end
end

/*************************************************************************************/
/*	this state machine is used to count clocks; 
*/

always @(posedge clk or negedge reset) begin
	if (!reset) begin
		rdValid_temp[0] <= 1'b0;
		rdValid_temp[1] <= 1'b0;
		idx_temp[0] <= {d_agingTb{1'b0}};
		idx_temp[1] <= {d_agingTb{1'b0}};
	end
	else begin
		/* rdValidTb is "1", means wait_1;
		* rdValid_temp[0] is '1', means wait_2;
		* rdValid_temp[1] is '1', means read_ram;
		*/
		rdValid_temp[0] <= rdValid_agingTb;
		rdValid_temp[1] <= rdValid_temp[0];
		idx_temp[0] <= idx_agingTb;
		idx_temp[1] <= idx_temp[0];
	end
end

/*************************************************************************************/
/*	this state machine is used to read agingTb, and generate agingInfo; 
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		agingInfo_valid <= 1'b0;
		agingInfo <= {w_agingInfo{1'b0}};
		aging_tag <= 1'b0;
		data_idxWRbuffer <= {d_agingTb{1'b0}};

		state_aging <= IDLE_S;
	end
	else begin
		case(state_aging)
			IDLE_S: begin
				agingInfo_valid <= 1'b0;
				aging_tag <= 1'b1;
				state_aging <= READ_AGINGTB_S;
			end
			READ_AGINGTB_S: begin
				/* read agingTb */ 
				if((rdValid_temp[1]==1'b1)&&(ctx_agingTb[b_agingTag_agingTb-1]==1'b0)) 
				begin
					if((ctx_agingTb[w_timestamp-1:0]+INTERVAL_AGING) <
						cur_timestamp)
					begin
						agingInfo_valid <= 1'b1;
						// read state?
						agingInfo <= {idx_temp[1],8'd0,TIME_OUT,
							ctx_agingTb[w_timestamp-1:0]};
						/* input the idx_wr to fifo */
						data_idxWRbuffer <= idx_temp[1];
					end
					else begin
						agingInfo_valid <= 1'b0;
					end
				end
				else begin
					agingInfo_valid <= 1'b0;
				end
				state_aging <= READ_AGINGTB_S;
			end
			default: begin
				state_aging <= IDLE_S;
			end
		endcase
	end
end




endmodule    
