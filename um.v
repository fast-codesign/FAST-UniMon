//=====================================================//
//	Module name: top module for testing function in Verilog;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/29
//	Function outline: test-function
//=====================================================//

`timescale 1ns/1ps

module um(
	clk,
	reset,
	localbus_cs_n,
	localbus_rd_wr,
	localbus_data,
	localbus_ale,
	localbus_ack_n,
	localbus_data_out,

	um2cdp_path,
	cdp2um_data_valid,
	cdp2um_data,
	um2cdp_tx_enable,
	um2cdp_data_valid,
	um2cdp_data,
	cdp2um_tx_enable,
	um2cdp_rule,
	um2cdp_rule_wrreq,
	cdp2um_rule_usedw
);

input			clk;
input			reset;
input			localbus_cs_n;
input			localbus_rd_wr;
input			[31:0]	localbus_data;
input			localbus_ale;
output	reg		localbus_ack_n;
output	reg		[31:0]	localbus_data_out;

output	reg		um2cdp_path;
input			cdp2um_data_valid;
input			[138:0]	cdp2um_data;
output	reg		um2cdp_tx_enable;
output	reg		um2cdp_data_valid;
output	reg		[138:0]	um2cdp_data;
input			cdp2um_tx_enable;
output	reg		um2cdp_rule_wrreq;
output	reg		[29:0]	um2cdp_rule;
input			[4:0]	cdp2um_rule_usedw;

/*************************************************************************************/
/*	from parser to two uniMon;
*/
wire			wrreq_pkt;
reg				rdreq_pkt;
wire	[138:0]	data_pkt;
wire			empty_pkt;
wire	[138:0]	q_pkt;
/** action fifo*/
wire			action_valid;
wire			action;
reg				rdreq_action;
wire			empty_action;
wire			q_action;
/** tag fifo*/
reg				rdreq_tag, wrreq_tag, data_tag;
wire			empty_tag;
wire			q_tag;
/** temp */
reg				metadata_in_valid;
reg		[208:0]	metadata_in;
reg		[138:0]	pkt_temp;

wire			metadata_valid;
wire	[247:0]	metadata;

reg	[3:0]	state_output;
parameter	IDLE_S				= 4'd0,
			READ_TAG_FIFO_S		= 4'd1,
			WAIT_ACTION_FIFO_S	= 4'd2,
			READ_ACTION_FIFO_S	= 4'd3,
			READ_FIFO_S			= 4'd4,
			WAIT_TRANS_PKT_S	= 4'd5,
			WAIT_PKT_TAIL_S		= 4'd6,
			DISCARD_S			= 4'd7;
			
			
/** input */
L4_Parser L4parser(
.clk(clk),
.reset(reset),
.pktin_data_wr(cdp2um_data_valid),
.pktin_data(cdp2um_data),
.pktin_data_valid(),
.pktin_data_valid_wr(),
.pktin_ready(),
.pktout_data_wr(wrreq_pkt),
.pktout_data(data_pkt),
.pktout_data_valid(),
.pktout_data_valid_wr(),
.pktout_ready(1'b1),
.pfv_wr(metadata_valid),
.pfv(metadata),
//control path
.cin_data(),
.cin_data_wr(),
.cin_ready(),
.cout_data(),
.cout_data_wr(),
.cout_ready()
);

uniman_top uniman(
.clk(clk),
.reset(reset),
.metadata_in_valid(metadata_in_valid),
.metadata_in(metadata_in),
.action_valid(action_valid),
.action(action),
.eventInfo_valid(),
.eventInfo(),
.ready(),

/**	cin/cou used as control signals */
.cin_data_wr(),
.cin_data(),
.cin_ready(),
.cout_data_wr(),
.cout_data(),
.cout_ready(1'b0)
);

/** check the protocol */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		metadata_in_valid <= 1'b0;
		metadata_in <= 209'b0;
		wrreq_tag <= 1'b0;
		data_tag <= 1'b0;
	end
	else begin
		if(metadata_valid == 1'b1) begin
			wrreq_tag <= 1'b1;
			if(metadata[247:240] == 8'd6) begin
				metadata_in_valid <= 1'b1;
				data_tag <= 1'b1;
				metadata_in <= {1'b1,metadata[247:40]};
			end
			else begin
				data_tag <= 1'b0;
				metadata_in_valid <= 1'b0;
			end
		end
		else begin
			metadata_in_valid <= 1'b0;
			wrreq_tag <= 1'b0;
		end
	end
end
	
			

/** output */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		um2cdp_rule_wrreq <= 1'b0;
		um2cdp_rule <= 30'b0;
		um2cdp_data_valid <= 1'b0;
		um2cdp_data <= 139'b0;
		state_output <= IDLE_S;
		
		pkt_temp <= 139'b0;
		rdreq_pkt <= 1'b0;
		rdreq_action <= 1'b0;
		rdreq_tag <= 1'b0;
	end
	else begin
		case(state_output)
			IDLE_S: begin
				um2cdp_data_valid <= 1'b0;
				if((empty_tag == 1'b0) && (cdp2um_rule_usedw < 5'd30)) begin
					state_output <= READ_TAG_FIFO_S;
					rdreq_tag <= 1'b1;
				end
				else begin
					state_output <= IDLE_S;
				end
			end
			READ_TAG_FIFO_S: begin
				rdreq_tag <= 1'b0;
				if(q_tag == 1'b0) begin	// not a tcp packet;
					state_output <= READ_FIFO_S;
					rdreq_pkt <= 1'b1;
				end
				else begin // tcp packet;
					state_output <= WAIT_ACTION_FIFO_S;
				end
			end
			WAIT_ACTION_FIFO_S: begin
				if((empty_action == 1'b0) && (cdp2um_rule_usedw < 5'd30)) begin
					state_output <= READ_ACTION_FIFO_S;
					//rdreq_pkt <= 1'b1;
					rdreq_action <= 1'b1;
				end
				else begin
					state_output <= WAIT_ACTION_FIFO_S;
				end
			end
			READ_ACTION_FIFO_S: begin
				rdreq_action <= 1'b0;
				if(q_action == 1'b1) begin
					rdreq_pkt <= 1'b1;
					state_output <= READ_FIFO_S;
				end
				else begin
					rdreq_pkt <= 1'b1;
					state_output <= DISCARD_S;
				end
			end
			READ_FIFO_S: begin
				pkt_temp <= q_pkt;
				rdreq_pkt <= 1'b0;
				
				um2cdp_rule_wrreq <= 1'b1;
				um2cdp_rule <= {26'b0,cal_egressPort(q_pkt[131:128])};
				
				state_output <= WAIT_TRANS_PKT_S;
			end
			WAIT_TRANS_PKT_S: begin
				um2cdp_rule_wrreq <= 1'b0;
				if(cdp2um_tx_enable == 1'b1) begin
					state_output <= WAIT_PKT_TAIL_S;
					um2cdp_data_valid <= 1'b1;
					um2cdp_data <= pkt_temp;
					rdreq_pkt <= 1'b1;
				end
				else begin
					state_output <= WAIT_TRANS_PKT_S;
				end
			end
			WAIT_PKT_TAIL_S: begin
				um2cdp_data <= q_pkt;
				if(q_pkt[138:136] == 3'b110) begin
					rdreq_pkt <= 1'b0;
					state_output <= IDLE_S;
				end
				else begin
					state_output <= WAIT_PKT_TAIL_S;
				end
			end
			DISCARD_S: begin
				if(q_pkt[138:136] == 3'b110) begin
					rdreq_pkt <= 1'b0;
					state_output <= IDLE_S;
				end
				else begin
					state_output <= DISCARD_S;
				end
			end
			default: state_output <= IDLE_S;
		endcase
	end
end

function [3:0] cal_egressPort;
input	[3:0]	ingressPort;
begin
	cal_egressPort = (ingressPort == 4'd0)? 4'd2:4'd1;
end
endfunction

fifo pkt_buffer(
.aclr(!reset),
.clock(clk),
.data(data_pkt),
.rdreq(rdreq_pkt),
.wrreq(wrreq_pkt),
.empty(empty_pkt),
.full(),
.q(q_pkt),
.usedw()
);
defparam
	pkt_buffer.width = 139,
	pkt_buffer.depth = 8,
	pkt_buffer.words = 256;

fifo action_buffer(
.aclr(!reset),
.clock(clk),
.data(action),
.rdreq(rdreq_action),
.wrreq(action_valid),
.empty(empty_action),
.full(),
.q(q_action),
.usedw()
);
defparam
	action_buffer.width = 1,
	action_buffer.depth = 5,
	action_buffer.words = 32;

fifo tag_buffer(
.aclr(!reset),
.clock(clk),
.data(data_tag),
.rdreq(rdreq_tag),
.wrreq(wrreq_tag),
.empty(empty_tag),
.full(),
.q(q_tag),
.usedw()
);
defparam
	tag_buffer.width = 1,
	tag_buffer.depth = 5,
	tag_buffer.words = 32;
	
/*************************************************************************************/
/*	state machine declaration
*	this state machine used to gen um2cdp_tx_enable;
*/
reg	state;

always @(posedge clk or negedge reset) begin
	if (!reset) begin
		um2cdp_path <= 1'b0;
		localbus_ack_n <= 1'b1;
		localbus_data_out <= 32'b0;
		state <= 1'b0;
		um2cdp_tx_enable <= 1'b0;
	end
	else begin
		case(state)
			1'b0: begin
				if(cdp2um_data_valid == 1'b0) begin
					state <= 1'b1;
					um2cdp_tx_enable <= 1'b1;
				end
				else begin
					state <= 1'b0;
					um2cdp_tx_enable <= 1'b0;
				end
			end
			2'b0: begin
				if(cdp2um_data_valid == 1'b1) begin
					state <= 1'b0;
					um2cdp_tx_enable <= 1'b0;
				end
				else begin
					state <= 1'b1;
					um2cdp_tx_enable <= 1'b1;
				end
			end
			default: state <= 1'b0;
		endcase
	end
end

endmodule    
