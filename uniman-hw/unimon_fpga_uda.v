//=====================================================//
//	Module name: top module for UniMon;
//	Communication with lijunnan(lijunnan@nudt.edu.cn)
//	Last edited time: 2018/04/21
//	Function outline: UniMon_v0.1
//=====================================================//

`timescale 1ns/1ps

module unimon_top(
	clk,
	reset,
	pkt_in_valid,
	pkt_in,
	
/*	pkt_out has metadata and packet; */
	pkt_out_valid,
	pkt_out,
	
/*	controller API
*	ctrl_in_valid is the enable signal of controller API;
*	ctrl_opt is the optional type, i.e., 0 is read; 1 is update; 2 is add; 3 is delete;
*	ctrl_addr is used to distinguish connection table, hash_left_table,
*		hash_right_table, and used to assigne ram's addr;
*	ctrl_data convey the data;
*/	
	ctrl_in_valid,
	ctrl_opt,
	ctrl_addr,
	ctrl_data_in,
	ctrl_out_valid,
	ctrl_data_out
);
/*	width or depth or words info of signals
*/
parameter 	w_meta = 134,		// the width of metadata
		w_pkt	= 134,		// the width of pkt
		w_ctrl	= 32,		// the width of ctrl' data
		w_key = 96,		// the width of flow key
		w_evb = 10,		// the width of event bitmpa
		w_connTb = 200,	// the width of connTb(table) entry
		words_connTb = 512,	// the words of connTb
		d_connTb = 9,		// the depth of connTb
		w_agingTb = 9,	// the width of agingTb entry
		w_hashTb = 33,	// the width of hashTb entry
		d_hashTb = 9,		// the depth of hashTb
		words_hashTb = 512,	// the words of hashTb
		w_timestamp = 8,	// the width of timestamp
		w_pktIn_info = 32,	// width of pktIn info;
		w_agingInfo = 40,	// the width of agingInfo which connects
					//	time-out inspector and bie-generator
		
		/* bit(loaction) of each component in x(table/reg) */
		b_agingTag_agingTb = 8,

		/* constant/static parameter */
		INTERVAL_EQUAL_10MS = 32'd1250000,	// interval's clocks 
		INCREASE_TIME_TMP = 8'd1;	// added cur_timestamp by per time

input				clk;
input				reset;
input				pkt_in_valid;
input		[w_pkt-1:0]	pkt_in;
output	wire			pkt_out_valid;
output	wire	[w_pkt-1:0]	pkt_out;
input				ctrl_in_valid;
input		[1:0]		ctrl_opt;
input		[w_ctrl-1:0]	ctrl_addr;
input		[w_ctrl-1:0]	ctrl_data_in;
output	wire			ctrl_out_valid;
output	wire	[w_ctrl-1:0]	ctrl_data_out;

/*************************************************************************************/
/*	varialbe declaration
/*	from conn_search to two hash tables;
*/
wire	[d_hashTb-1:0]	hashV_search_1,hashV_search_2;
wire	[d_hashTb-1:0]	hashV_conf;
wire	[w_hashTb-1:0]	data_hashTb_conf;
wire				rden_hashTb_search;
wire				rden_hashTb_conf_1, rden_hashTb_conf_2;
wire				wren_hashTb_conf_1, wren_hashTb_conf_2;
wire	[w_hashTb-1:0]	ctx_hashTb_search_1,ctx_hashTb_search_2;
wire	[w_hashTb-1:0]	ctx_hashTb_conf_1, ctx_hashTb_conf_2;

/*	from conn_search to connection table
*/
wire	[d_connTb-1:0]	idx_connTb_search, idx_connTb_conf;
wire	[w_connTb-1:0]	data_connTb_search, data_connTb_conf;
wire				rden_connTb_search, rden_connTb_conf;
wire				wren_connTb_search, wren_connTb_conf;
wire	[w_connTb-1:0]	ctx_connTb_search, ctx_connTb_conf;

/*	from conn_searcher to aging_table;
*/
wire	[d_connTb-1:0]	idx_agingTb_aging,idx_agingTb_aging_a,
						idx_agingTb_aging_c;
wire	[w_agingTb-1:0]	data_agingTb_aging, data_agingTb_aging_a,
						data_agingTb_aging_c;
wire				rden_agingTb_aging,rden_agingTb_aging_a,
					rden_agingTb_agint_c;
wire				wren_agingTb_search, wren_agingTb_aging,
					wren_agingTb_aging_a, wren_agintTb_agint_c;
wire	[w_agingTb-1:0]	ctx_agingTb_search, ctx_agingTb_aging;

/*	from conn_searcher and connection_outTime to builtIn_event_gen;
*/
wire				event_bitmap_valid;
wire	[w_evb-1:0]		event_bitmap;
wire	[w_pktIn_info-1:0]	pktIn_info;
wire				metadataOut_valid_search;
wire	[w_meta-1:0]		metadataOut_search;
wire				agingInfo_valid;
wire	[w_agingInfo-1:0]	agingInfo;

/*	from conn_table_configuration to conn_outTime_inspector;
*	the priority of aging is lower than configuration;
*/
wire				aging_enable;

/*	timer;
*/
reg	[31:0]				timer;
reg	[w_timestamp-1:0]	cur_timestamp;


/*************************************************************************************/
/*	submodular declaration
*	conncetion_searcher  firstly gets 4-tuple flow key, and calculates two 
*		hash values to searh two hash table; secondly, searches the 
*		connection table and gets current flow's state, then translates/
*		updates the conncetion state by flow'state and current packet;
*/
connection_searcher conn_searcher(
.reset(reset),
.clk(clk),
.metadata_in_valid(pkt_in_valid),
.metadata_in(pkt_in),
//.metadata_out_valid(metadataOut_valid_search),
//.metadata_out(metadataOut_search),
.event_bitmap_valid(event_bitmap_valid),
.event_bitmap(event_bitmap),
.pktIn_info(pktIn_info),
.hashV_1(hashV_search_1),
.hashV_2(hashV_search_2),
.hashV_valid(rden_hashTb_search),
.ctx_hashTb_1(ctx_hashTb_search_1),
.ctx_hashTb_2(ctx_hashTb_search_2),
.idx_connTb(idx_connTb_search),
.data_connTb(data_connTb_search),
.rdValid_connTb(rden_connTb_search),
.wrValid_connTb(wren_connTb_search),
.wrValid_agingTb(wren_agingTb_search),
.ctx_connTb({ctx_agingTb_search[b_agingTag_agingTb], ctx_connTb_search})
);
/*	
defparam
	conn_searcher.w_key = w_key,
	conn_searcher.w_meta = w_meta,
	conn_searcher.w_evb = w_evb,
	conn_searcher.w_ram = w_connTb,
	conn_searcher.d_ram = d_connTb,
	conn_searcher.words_ram = words_connTb;
*/
	
/*************************************************************************************/
/*	conn_tablle is a double-port ram, one of which is used for searchiing and
*		another is used for configuration;
*/
ram conn_table(
.address_a(idx_connTb_search),
.address_b(idx_connTb_conf),
.clock(clk),
.data_a(data_connTb_search),
.data_b(data_connTb_conf),
.rden_a(rden_connTb_search),
.rden_b(rden_connTb_conf),
.wren_a(wren_connTb_search),
.wren_b(wren_connTb_conf),
.q_a(ctx_connTb_search),
.q_b(ctx_connTb_conf)
);
defparam
	conn_table.width = w_connTb,
	conn_table.depth = d_connTb,
	conn_table.words = words_connTb;

/*	aging_table is a douple-port ram, one of which is used for searching
*		and another is used for aging (and should be reseted by con-
*		figuration);
*/
ram aging_table(
.address_a(idx_connTb_search),
.address_b(idx_agingTb_aging),
.clock(clk),
.data_a({1'b0,cur_timestamp}),
.data_b(data_agingTb_aging),
.rden_a(rden_connTb_search),
.rden_b(rden_agingTb_aging),
.wren_a(wren_agingTb_search),
.wren_b(wren_agingTb_aging),
.q_a(ctx_agingTb_search),
.q_b(ctx_agingTb_aging)
);
defparam
	aging_table.width = w_agingTb,
	aging_table.depth = d_connTb,
	aging_table.words = words_connTb;

/*	hash_table is a double-port ram, one of which is used for searching
*		and another is used for configuration;
*/
ram hash_table_1(
.address_a(hashV_search_1),
.address_b(hashV_conf),
.clock(clk),
.data_a({w_hashTb{1'b0}}),
.data_b(data_hashTb_conf),
.rden_a(rden_hashTb_search),
.rden_b(rden_hashTb_conf_1),
.wren_a(1'b0),
.wren_b(wren_hashTb_conf_1),
.q_a(ctx_hashTb_search_1),
.q_b(ctx_hashTb_conf_1)
);
defparam
	hash_table_1.width = w_hashTb,
	hash_table_1.depth = d_hashTb,
	hash_table_1.words = words_hashTb;

ram hash_table_2(
.address_a(hashV_search_2),
.address_b(hashV_conf),
.clock(clk),
.data_a({w_hashTb{1'b0}}),
.data_b(data_hashTb_conf),
.rden_a(rden_hashTb_search),
.rden_b(rden_hashTb_conf_2),
.wren_a(1'b0),
.wren_b(wren_hashTb_conf_2),
.q_a(ctx_hashTb_search_2),
.q_b(ctx_hashTb_conf_2)
);
defparam
	hash_table_2.width = w_hashTb,
	hash_table_2.depth = d_hashTb,
	hash_table_2.words = words_hashTb;

/*************************************************************************************/
/*	builtIn_event_generator gets event bitmap from conneciton searcher, 
*		and gets aging info from connection_outTime_inspector, then
*		generates the final event bitmap which should be fileld in the
*		metadata[1], lastly combined with packet which will be sent to
*		cpu by packet_in message;
*/
buildIn_event_generator buildIn_event_gen(
.reset(reset),
.clk(clk),
.metadata_in_valid(pkt_in_valid),
.metadata_in(pkt_in),
.metadata_out_valid(pkt_out_valid),
.metadata_out(pkt_out),
.event_bitmap_valid(event_bitmap_valid),
.event_bitmap(event_bitmap),
.pktIn_info(pktIn_info),
.agingInfo_valid(agingInfo_valid),
.agingInfo(agingInfo),
.cur_timestamp(cur_timestamp)
);

/*************************************************************************************/
/*	connection_outTime_inspector check the connection entry whether it 
*		is outtime, and send the out-time inifo to build-in generator;
*/
connection_outTime_inspector conn_outTime_inspector(
.reset(reset),
.clk(clk),
.aging_enable(aging_enable),
.idx_agingTb(idx_agingTb_aging_a),
.data_agingTb(data_agingTb_aging_a),
.rdValid_agingTb(rden_agingTb_aging_a),
.wrValid_agingTb(wren_agingTb_aging_a),
.ctx_agingTb(ctx_agingTb_aging),
.agingInfo_valid(agingInfo_valid),
.agingInfo(agingInfo),
.cur_timestamp(cur_timestamp)
);

/*************************************************************************************/
/*	connection_table_configuration configures the connnection table accord-
*		ing to the configuration info from localbus; 
*	Another function is used to configure two hash tables;
*/
connection_table_configuration conn_table_conf(
.reset(reset),
.clk(clk),
.aging_enable(aging_enable),
.cur_timestamp(cur_timestamp),
.idx_connTb(idx_connTb_conf),
.data_connTb(data_connTb_conf),
.wrValid_connTb(wren_connTb_conf),
.rdValid_connTb(rden_connTb_conf),
.ctx_connTb(ctx_connTb_conf),
.idx_hashTb(hashV_conf),
.data_hashTb(data_hashTb_conf),
.wrValid_hashTb_1(wren_hashTb_conf_1),
.wrValid_hashTb_2(wren_hashTb_conf_2),
.rdValid_hashTb_1(rden_hashTb_conf_1),
.rdValid_hashTb_2(rden_hashTb_conf_2),
.ctx_hashTb_1(ctx_hashTb_conf_1),
.ctx_hashTb_2(ctx_hashTb_conf_2),
.idx_agingTb(idx_agingTb_aging_c),
.data_agingTb(data_agingTb_aging_c),
.rdValid_agingTb(rden_agingTb_aging_c),
.wrValid_agingTb(wren_agingTb_aging_c),
.ctx_agingTb(ctx_agingTb_aging),
.ctrl_in_valid(ctrl_in_valid),
.ctrl_opt(ctrl_opt),
.ctrl_addr(ctrl_addr),
.ctrl_data_in(ctrl_data_in),
.ctrl_out_valid(ctrl_out_valid),
.ctrl_data_out(ctrl_data_out)
);

/*************************************************************************************/
/*	state machine declaration
*	this state machine is used to generate a timer; 
*/
always @ (posedge clk or negedge reset) begin
	if(!reset) begin
		cur_timestamp <= {w_timestamp{1'b0}};
		timer <= 32'b0;
	end
	else begin
		if(timer == INTERVAL_EQUAL_10MS) begin
			cur_timestamp <= cur_timestamp + INCREASE_TIME_TMP;
			timer <= 32'b0;
		end
		else begin
			timer <= timer + 32'd1;
		end
	end
end

/*************************************************************************************/
/*	this state machine is used as multiplexer to select signal between time-out 
*		inspector and connTb configuration;
*	the priority of connTb configuration is higher than time-out inspector; 
*/
assign idx_agingTb_aging = ((rden_agingTb_aging_a)|(wren_agingTb_aging_a))? 
	idx_agingTb_aging_a:idx_agingTb_aging_c;
assign data_agingTb_aging = ((rden_agingTb_aging_a)|(wren_agingTb_aging_a))? 
	data_agingTb_aging_a:data_agingTb_aging_c;
assign wren_agingTb_aging = (wren_agingTb_aging_a)|(wren_agingTb_aging_c);
assign rden_agingTb_aging = (rden_agingTb_aging_a)|(rden_agingTb_aging_c);



endmodule    
