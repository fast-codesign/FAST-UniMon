//=====================================================//
//	Module name: connection/hash table configuration of UniMon;
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

module connection_table_configuration(
reset,
clk,
aging_enable,
cur_timestamp,
idx_connTb,
data_connTb,
wrValid_connTb,
rdValid_connTb,
ctx_connTb,
idx_hashTb,
data_hashTb,
wrValid_hashTb_1,
wrValid_hashTb_2,
rdValid_hashTb_1,
rdValid_hashTb_2,
ctx_hashTb_1,
ctx_hashTb_2,
idx_agingTb,
data_agingTb,
rdValid_agingTb,
wrValid_agingTb,
ctx_agingTb,
ctrl_in_valid,
ctrl_opt,
ctrl_addr,
ctrl_data_in,
ctrl_out_valid,
ctrl_data_out
);

/*	width or depth or words info of signals
*/
parameter 	w_connTb = 200,
		d_connTb = 9,
		d_hashTb = 9,
		w_hashTb = 33,
		d_agingTb = 9,
		w_agingTb = 9,
		w_ctrl = 32,
		w_timestamp = 8,

		b_agingTag_agingTb = 8,
		b_count_connTb = 64,

		CONNTB = 2'd0,
		HASHTB_1 = 2'd1,
		HASHTB_2 = 2'd2,
		READ_RULE = 2'd0,
		ADD_RULE = 2'd1,
		DEL_RULE = 2'd2;

input					clk;
input					reset;
output	reg				aging_enable;
input		[w_timestamp-1:0]	cur_timestamp;
output	reg	[d_connTb-1:0]	idx_connTb;
output	reg	[w_connTb-1:0]	data_connTb;
output	reg				wrValid_connTb;
output	reg				rdValid_connTb;
input		[w_connTb-1:0]	ctx_connTb;
output	reg	[d_hashTb-1:0]	idx_hashTb;
output	reg	[w_hashTb-1:0]	data_hashTb;
output	reg				wrValid_hashTb_1;
output	reg				wrValid_hashTb_2;
output	reg				rdValid_hashTb_1;
output	reg				rdValid_hashTb_2;
input		[w_hashTb-1:0]	ctx_hashTb_1;
input		[w_hashTb-1:0]	ctx_hashTb_2;
output	reg	[d_agingTb-1:0]	idx_agingTb;
output	reg	[w_agingTb-1:0]	data_agingTb;
output	reg				wrValid_agingTb;
output	reg				rdValid_agingTb;
input		[w_agingTb-1:0]	ctx_agingTb;
input					ctrl_in_valid;
input		[1:0]			ctrl_opt;	// 0 is read; 1 is add; 2 is del;
input		[w_ctrl-1:0]		ctrl_addr;
input		[w_ctrl-1:0]		ctrl_data_in;
output	reg				ctrl_out_valid;
output	reg	[w_ctrl-1:0]		ctrl_data_out;



/*************************************************************************************/
/*	varialbe declaration
/*	from conn_search to two hash tables;
*/

/* 	ctrl temp
reg	[w_ctrl-1:0]	ctrl_data_in_temp;
*/
reg	[1:0]			ctrl_opt_temp;
reg	[w_ctrl-1:0]	ctrl_addr_temp;

/* configuration state machine */
integer field,i;
reg	[31:0]	connTb_entry[4:0];	// with out counter(64b);


/*************************************************************************************/
/*	state  declaration
*	
*/
reg	[3:0]	state_conf;
parameter	IDLE_S			= 4'd0,
		WRITE_CONNTB_S	= 4'd1,
		WRITE_HASH_S	= 4'd2,
		WAIT_RAM_1_S	= 4'd3,
		WAIT_RAM_2_S	= 4'd4,
		READ_RAM_S		= 4'd5;

/*************************************************************************************/
/*	state machine declaration
*	this state machine is used to read agingTb; 
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		wrValid_connTb <= 1'b0;
		rdValid_connTb <= 1'b0;
		wrValid_hashTb_1 <= 1'b0;
		wrValid_hashTb_2 <= 1'b0;
		rdValid_hashTb_1 <= 1'b0;
		rdValid_hashTb_2 <= 1'b0;
		wrValid_agingTb <= 1'b0;
		rdValid_agingTb <= 1'b0;
		idx_agingTb <= {d_agingTb{1'b0}};
		idx_connTb <= {d_connTb{1'b0}};
		idx_hashTb <= {d_hashTb{1'b0}};
		data_connTb <= {w_connTb{1'b0}};
		data_hashTb <= {w_hashTb{1'b0}};
		data_agingTb <= {w_agingTb{1'b0}};

		aging_enable <= 1'b0;
		ctrl_opt_temp <= 2'b0;
		ctrl_addr_temp <= {w_ctrl{1'b0}};
		ctrl_out_valid <= 1'b0;
		ctrl_data_out <= {w_ctrl{1'b0}};
		for(i=0;i<6;i=i+1)
			connTb_entry[i] <= 32'b0;

		state_conf <= IDLE_S;
	end
	else begin
		case(state_conf)
			IDLE_S: begin
				wrValid_agingTb <= 1'b0;
				wrValid_connTb <= 1'b0;
				wrValid_hashTb_1 <= 1'b0;
				wrValid_hashTb_2 <= 1'b0;
				rdValid_agingTb <= 1'b0;
				ctrl_out_valid <= 1'b0;
				//rdValid_connTb <= 1'b0;
				//rdValid_hashTb_1 <= 1'b0;
				//rdValid_hashTb_2 <= 1'b0;
				if(ctrl_in_valid == 1'b1) begin
					aging_enable <= 1'b0;
					ctrl_opt_temp <= ctrl_opt;
					ctrl_addr_temp <= ctrl_addr;
					
					/* get idx_connTb/hashTb */
					idx_connTb <= ctrl_addr[d_connTb+3:4];
					idx_hashTb <= ctrl_addr[d_connTb+3:4];
					
					case(ctrl_addr[21:20])
						/* connTb: recombine connTb entry */
						CONNTB: begin
							case(ctrl_opt)
								ADD_RULE: begin
									data_agingTb <= {1'b0,cur_timestamp};
									for(field = 0; field < 5; field = field + 1) begin
										if(field[3:0] == ctrl_addr[3:0]) begin
											connTb_entry[field] <= ctrl_data_in;
										end
									end
									state_conf <= WRITE_CONNTB_S;
								end
								READ_RULE: begin
									rdValid_connTb <= 1'b1;
									state_conf <= WAIT_RAM_1_S;
								end
								DEL_RULE: begin
									data_agingTb <= {1'b1,cur_timestamp};
									for(field = 0; field < 5; field = field + 1) begin
										connTb_entry[field] <= 32'b0;
									end
									state_conf <= WRITE_CONNTB_S;
								end
								default: begin
									state_conf <= IDLE_S;
								end
							endcase
						end
						HASHTB_1: begin
							case(ctrl_opt)
								ADD_RULE: begin
									data_hashTb <= {1'b1,ctrl_data_in};
									state_conf <= WRITE_HASH_S;
								end
								READ_RULE: begin
									rdValid_hashTb_1 <= 1'b1;
									state_conf <= WAIT_RAM_1_S;
								end
								DEL_RULE: begin
									data_hashTb <= {w_hashTb{1'b0}};
									state_conf <= WRITE_HASH_S;
								end
								default: state_conf <= IDLE_S;
							endcase
						end
						HASHTB_2: begin
							case(ctrl_opt)
								ADD_RULE: begin
									data_hashTb <= {1'b1,ctrl_data_in};
									state_conf <= WRITE_HASH_S;
								end
								READ_RULE: begin
									rdValid_hashTb_2 <= 1'b1;
									state_conf <= WAIT_RAM_1_S;
								end
								DEL_RULE: begin
									data_hashTb <= {w_hashTb{1'b0}};
									state_conf <= WRITE_HASH_S;
								end
							endcase
						end
						default: begin
							state_conf <= IDLE_S;
						end
					endcase
				end
				else begin
					aging_enable <= 1'b1;
					state_conf <= IDLE_S;
				end
			end
			WRITE_CONNTB_S: begin
				/* write connTb and agingTb */
				if((ctrl_addr_temp[3:0] == 4'd4)||ctrl_opt_temp == DEL_RULE) begin
					data_connTb[w_connTb-1:b_count_connTb] <= 
						{connTb_entry[4][w_connTb-b_count_connTb-129:0],
						connTb_entry[3],connTb_entry[2],
						connTb_entry[1],connTb_entry[0]};
					wrValid_connTb <= 1'b1;
					wrValid_agingTb <= 1'b1;
					state_conf <= IDLE_S;
				end
				else state_conf <= IDLE_S;
			end
			WRITE_HASH_S: begin
				/* write 1st hashTb */
				if(ctrl_addr_temp[21:20] == HASHTB_1) begin
					wrValid_hashTb_1 <= 1'b1;
				end
				/* write 2nd hashTb */
				else begin
					wrValid_hashTb_2 <= 1'b1;
				end
				state_conf <= IDLE_S;
			end
			WAIT_RAM_1_S: begin
				rdValid_connTb <= 1'b0;
				rdValid_hashTb_1 <= 1'b0;
				rdValid_hashTb_2 <= 1'b0;
				state_conf <= WAIT_RAM_2_S;
			end
			WAIT_RAM_2_S: begin
				state_conf <= READ_RAM_S;
			end
			READ_RAM_S: begin
				ctrl_out_valid <= 1'b1;
				case(ctrl_addr_temp[21:20])
					CONNTB: begin 
						case(ctrl_addr_temp[3:0])
							4'd0: ctrl_data_out <= ctx_connTb[95:64];
							4'd1: ctrl_data_out <= ctx_connTb[127:96];
							4'd2: ctrl_data_out <= ctx_connTb[159:128];
							4'd3: ctrl_data_out <= ctx_connTb[191:160];
							4'd4: ctrl_data_out <= {24'b0,ctx_connTb[199:192]};
							default: ctrl_data_out <= 32'hffff_ffff;
						endcase
					end
					HASHTB_1: ctrl_data_out <= ctx_hashTb_1[w_ctrl-1:0];
					HASHTB_2: ctrl_data_out <= ctx_hashTb_2[w_ctrl-1:0];
					default: ctrl_data_out <= 32'hffff_ffff;
				endcase
				state_conf <= IDLE_S;
			end
			default: begin
				state_conf <= IDLE_S;
			end
		endcase
	end
end




endmodule    
