//===============================================================//
//	Module name: L4Parser module for Unified Security Gateway (USG);
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/11/14 (I need a parser to parse the mind of others)
//	Function outline: USG_v0.1
//===============================================================//

`timescale 1ns/1ps

/***funciton description:
*		data processing:
*			1) identify Ethernet, IPv4, TCP, UDP, ICMP, HTTP protocol;
*			2) extract 5-tuple, TCP info., HTTP header;
*		control signal processing:
*			1) without any processing;
*/

module L4_Parser(
	clk,
	reset,
/** pktin/pktout and pfvin/pfvout used as data signals, and the width of pktin/
*	pktout is 134b, while the width of pfvin/pfvout is 248b, includes 104b 5-tuple 
*	info., 16b length of tcp content, 8b tcp flags, 32b send seq, 32b ack seq, 16b 
*	tcp window, 8b window scale factor, and 32b HTTP type field;
*/
	pktin_data_wr,
	pktin_data,
	pktin_data_valid_wr,
	pktin_data_valid,
	pktin_ready,
	pktout_data_wr,
	pktout_data,
	pktout_data_valid_wr,
	pktout_data_valid,
	pktout_ready,
	pfv_wr,
	pfv,
/**	cin/cou used as control signals */
	cin_data_wr,
	cin_data,
	cin_ready,
	cout_data_wr,
	cout_data,
	cout_ready
);
/***	width or depth or words info. of signals*/
parameter 	w_pkt = 139,		// the width of packet if NetMagic;
			w_pfv = 248;		// the width of pfv, includes:
								//	8b Protocol, 16b dstPort, 16b srcPort, 32b dstIp, 
								//	32b srcIP, 16b content length, 8b tcpFlag, 32b sendSeq, 
								//	32b ackSeq, 16b window, 8b winScale,32b HTTPtype;

input								clk;
input								reset;
input								pktin_data_wr;
input			[w_pkt-1:0]			pktin_data;
input								pktin_data_valid_wr;
input								pktin_data_valid;
output	reg							pktin_ready;
output	reg							pktout_data_wr;	
output	reg		[w_pkt-1:0]			pktout_data;
output	reg							pktout_data_valid_wr;
output	reg							pktout_data_valid;
input								pktout_ready;
output	reg 							pfv_wr;
output	reg 		[w_pfv-1:0]			pfv;

input								cin_data_wr;
input			[w_pkt-1:0]			cin_data;
output	reg							cin_ready;
output	reg							cout_data_wr;
output	reg		[w_pkt-1:0]			cout_data;
input								cout_ready;

/*************************************************************************************/
/***	varialbe declaration */
/** FIFOs used to buffer packet */
reg						rdreq_pkt;
wire	[w_pkt-1:0]		q_pkt;
wire					empty_pkt;

/** fields */
reg		[31:0]			src_ip, dst_ip, sendSeq, ackSeq, httpType;
reg 		[15:0]			src_port, dst_port, content_length, pkt_length, window;
reg 		[7:0]			protocol, ingressPort, egressPort, winScale, tcpFlag;
reg 		[3:0]			tcpH_length;

/** temps */
reg 						pfv_wr_tag;

/*************************************************************************************/
/** state for parsing */
reg 		[3:0]	state_parser;
parameter		IDLE_S					= 4'd0,
				READ_META_0_S		= 4'd1,
				READ_META_1_S		= 4'd2,
				PARSE_ETH_S			= 4'd3,
				PARSE_IP_S			= 4'd4,
				PARSE_TCP_UDP_ICMP_S = 4'd5,
				PARSE_TCP_S			= 4'd6,
				WAIT_PKT_TAIL_S		= 4'd7,
				OUTPUT_PFV_S		= 4'd8;


/*************************************************************************************/
/** just outputing cin/cou without modification */
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		cin_ready <= 1'b1;
		cout_data_wr <= 1'b0;
		cout_data <= {w_pkt{1'b0}};
	end
	else begin
		cin_ready <= cout_ready;
		cout_data_wr <= cin_data_wr;
		cout_data <= cin_data;
	end
end

/*************************************************************************************/
/** parse packets, and output packets without modification, so pfv is output later than 
*	the  packet's header, but do not worry that pfv output at the same time with the 
*	next packet;
*/
always @(posedge clk or negedge reset) begin
	if (!reset) begin
		// output signals inilization;
		pfv_wr <= 1'b0;
		pfv <= 248'b0;
		pktout_data_wr <= 1'b0;
		pktout_data <= {w_pkt{1'b0}};
		pktout_data_valid_wr <= 1'b0;
		pktout_data_valid <= 1'b0;
		pktin_ready <= 1'b1;
		// intermediate register inilization;
		pfv_wr_tag <= 1'b0;
		{ingressPort, egressPort, protocol, dst_port, src_port, dst_ip, src_ip, content_length, 
			tcpFlag, sendSeq, ackSeq, window, winScale, httpType} <= 264'b0;
		pkt_length <= 16'b0;	// length field in IPv4;
		tcpH_length <= 4'b0;	// length field in tcp;
		// fifo initialization;
		rdreq_pkt <= 1'b0;
		// state inilizaition;
		state_parser <= IDLE_S;
	end
	else begin
		case(state_parser)
			IDLE_S: begin
				// initialization;
				pktout_data_wr <= 1'b0;
				pfv_wr <= 1'b0;
				pfv_wr_tag <= 1'b0;
				{ingressPort, egressPort, protocol, dst_port, src_port, dst_ip, src_ip, content_length, 
					tcpFlag, sendSeq, ackSeq, window, winScale, httpType} <= 264'b0;
				pkt_length <= 16'b0;
				tcpH_length <= 4'b0;
				// wait for packet's header;
				if(empty_pkt == 1'b0) begin
					rdreq_pkt <= 1'b1;
					state_parser <= PARSE_ETH_S;
				end
				else begin
					rdreq_pkt <= 1'b0;
					state_parser <= IDLE_S;
				end
			end
			READ_META_0_S: begin
				pktout_data_wr <= 1'b1;
				pktout_data <= q_pkt;
				/** extract ingressPort and egressPort, meaningless */
				ingressPort <= q_pkt[127:120];
				egressPort <= q_pkt[119:112];
				state_parser <= READ_META_1_S;
			end
			READ_META_1_S: begin
				pktout_data <= q_pkt;

				state_parser <= PARSE_ETH_S;
			end
			PARSE_ETH_S: begin
				pktout_data_wr <= 1'b1;
				pktout_data <= q_pkt;

				// the pakcet belongs to IPv4 or not?
				if(q_pkt[31:16] == 16'h0800) state_parser <= PARSE_IP_S;
				else 	state_parser <= WAIT_PKT_TAIL_S; // write pfv in WAIT_PKT_TAIL_S;
			end
			PARSE_IP_S: begin
				pktout_data <= q_pkt;

				// extract srcIP and dstIP's top 16b, and pkt_length;
				{src_ip,dst_ip[31:16]} <= q_pkt[47:0];
				pkt_length <= q_pkt[127:112]; // without length of Ethernet header;
				// the packet belongs to TCP/UDP/ICMP or not, meaningless;
				if((q_pkt[71:64] == 8'h11) || (q_pkt[71:64] == 8'h06) || (q_pkt[71:64] == 8'h1))
					protocol <= q_pkt[71:64];
				else
					protocol <= 8'b0;
				state_parser <= PARSE_TCP_UDP_ICMP_S;
			end
			PARSE_TCP_UDP_ICMP_S: begin
				pktout_data <= q_pkt;

				// extract dstIP's low 16b and srcPort, dstPort;
				if(protocol == 8'h06) begin // TCP;
					{dst_ip[15:0],src_port,dst_port,sendSeq,ackSeq} <= q_pkt[127:16];
					// q_pkt[15:12] is the length of TCP header,  should left-shift 2 bit;
					content_length <= pkt_length - {10'b0,q_pkt[15:12],2'b0} - 16'd20;
					tcpH_length <= q_pkt[15:12];
					tcpFlag <= {2'b0,q_pkt[5:0]};
					state_parser <= PARSE_TCP_S;
				end
				else if(protocol == 8'h11) begin // UDP;
					{dst_ip[15:0],src_port,dst_port} <= q_pkt[127:80];
					state_parser <= WAIT_PKT_TAIL_S;
				end
				else if(protocol == 8'h1) begin // ICMP;
					dst_ip[15:0] <= q_pkt[127:112];
					src_port <= {8'b0,q_pkt[111:104]};
					dst_port <= {8'b0,q_pkt[103:96]};
					state_parser <= WAIT_PKT_TAIL_S;
				end
				else begin // IP packets;
					dst_ip[15:0] <= q_pkt[127:112];
					state_parser <= WAIT_PKT_TAIL_S;
				end
			end
			PARSE_TCP_S: begin
				pktout_data <= q_pkt;

				// extract window, httpType if existing;
				window <= q_pkt[127:112];

				// extract httpType just for fixed-length packet;
				if((dst_port == 16'd80) && (tcpH_length == 4'd5) && (content_length > 16'd0))	
					httpType <= q_pkt[79:48];

				// extract winScale for SYN packet;
				if((tcpFlag == 8'h02) && (tcpH_length > 4'd5)) begin
					// just for fixed position;
					if(q_pkt[47:24] == 24'h010303)	winScale <= q_pkt[23:16];
					else begin // for any position;
						//TO DO...;
					end
				end
				
				// go back to IDLE_S or not;
				if(q_pkt[138:136] == 3'b110) begin
					state_parser <= OUTPUT_PFV_S;
					rdreq_pkt <= 1'b0;
				end
				else begin
					state_parser <= WAIT_PKT_TAIL_S;
				end
			end
			WAIT_PKT_TAIL_S: begin
				pktout_data <= q_pkt;

				if(q_pkt[138:136] == 3'b110) begin 
				/** packet's tail, do not read fifo anymore, and return back to IDLE_S */
					rdreq_pkt <= 1'b0;
					state_parser <= IDLE_S;
				end
				else begin
					state_parser <= WAIT_PKT_TAIL_S;
				end
				/** if we have not output pfv, then output pfv and set pfv_wr_tag with "1"; */
				if(pfv_wr_tag == 1'b0) begin
					pfv_wr_tag <= 1'b1;
					pfv_wr <= 1'b1;
					pfv <= {protocol, dst_port, src_port, dst_ip, src_ip, content_length, 
							tcpFlag, sendSeq, ackSeq, window, winScale, httpType};
				end
				else begin
					pfv_wr <= 1'b0;
				end
			end
			OUTPUT_PFV_S: begin
				pktout_data_wr <= 1'b0;

				pfv_wr <= 1'b1;
				pfv <= {protocol, dst_port, src_port, dst_ip, src_ip, content_length, tcpFlag, 
						sendSeq, ackSeq, window, winScale, httpType};
				state_parser <= IDLE_S;
			end
			default: begin
				state_parser <= IDLE_S;
			end
		endcase
	end
end

fifo pkt_buffer(
.aclr(!reset),
.clock(clk),
.data(pktin_data),
.rdreq(rdreq_pkt),
.wrreq(pktin_data_wr),
.empty(empty_pkt),
.full(),
.q(q_pkt),
.usedw()
);
defparam
	pkt_buffer.width = 139,
	pkt_buffer.depth = 8,
	pkt_buffer.words = 256;


endmodule    
