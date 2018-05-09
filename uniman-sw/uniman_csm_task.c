#include "uniman_csm_task.h"

/*************************************************************************************************/
/** initial completed state manager in uniman
*    initial successfully will return '1', otherwise return '0';
*/
int uniman_initial_csm(){
	/** initial conneciton table, i.e., connectionTb;
	*   initial connection free list, i.e. conn_free_list;
	*/
	csm_initial_connTb();
	/** initial hash table, i.e., hashTb */
	csm_initial_hashTb();
	/** initial connection conflict list, i.e., conn_conflict_list;
	*   initial conneciont conflict free list, i.e., conn_conflict_free_list;
	*/
	csm_initial_conn_conflict_list();

	return 1;
}

/*************************************************************************************************/
/** the processing function of uniman */
void uniman_run(){
	/* csm and em initialization has been executed by main();
	if(uniman_initial_csm()){
		printf("%s\n", "initial uniman completed state manager error !");
		exit(1);
	}
	
	if(uniman_initial_em()){
		printf("%s\n", "initial uniman event manager error !");
		exit(1);
	}
	*/
	if(uniman_initial_csm() == 0){
		printf("%s\n", "initial uniman csm error !");
		exit(1);
	}

	/** recv packet = {meta,pktInfo} from fast_ua_recv()*/
	struct pkt_info *pktInfo;
	pktInfo = (struct pkt_info*)malloc(sizeof(struct pkt_info));
	pktInfo->ethh = (struct ethhdr*)malloc(sizeof(struct ethhdr));
	pktInfo->iph = (struct iphdr*)malloc(sizeof(struct iphdr));
	pktInfo->tcph = (struct tcphdr*)malloc(sizeof(struct tcphdr));
	pktInfo->payload = (uint8_t*)malloc(sizeof(uint8_t)*100);
	
	struct metadata *meta;
	meta = (struct metadata*)malloc(sizeof(struct metadata));


	cycle = 0;

	while(1){
		cycle++;
#ifndef FAST_RECV
		uniman_recv_packet(meta, pktInfo);
#else

#endif
		/** recv a new flow, the procedure is introduced as following:
		*   i)   allocate a connection entry (flowID);
		*   ii)  initial this connection entry;
		*   iii) update hashTb;
		*   iv) raise event;
		*/
		connection_t *cur_connection;
		/** recv a new flow (syn packet) */
		if(meta->flowID == 0){		// && (pktInfo->tcph->syn == 1)
			uint16_t flowID;
			/** lookup hashTb in order to check whether it is a new flow */
			struct flow_info *flowInfo;
			flowInfo = (struct flow_info *)malloc(sizeof(struct flow_info)); 
			struct hash_value *hashV;
			hashV = (struct hash_value*)malloc(sizeof(struct hash_value));

			get_flowKey_sorted(flowInfo, pktInfo);
			csm_calc_hashValue(flowInfo, hashV);
#if 0
			printf("sip:%u,dip:%u,sport:%u,dport:%u,proto:%u\n", 
				flowInfo->saddr, flowInfo->daddr, flowInfo->sport,
				flowInfo->dport, flowInfo->protocol);
			printf("value1:%u, value2:%u, simplifiedK:%u\n", 
				hashV->hashValue_1, hashV->hashValue_2,
				hashV->simplified_flowK);
			return;

#endif

			flowID = csm_lookup_hashTb (hashV);
			/** hit in hashTb */
			if(flowID){
				cur_connection = csm_lookup_connTb(flowID, flowInfo);
				if(cur_connection){	/** hit: not a new flow */
					csm_update_connection(cur_connection, meta);
					uniman_raise_event(meta->evb, cur_connection);
					// check the fpga_connection is on the road;
					continue;
				}
			}
			/** miss in hashTb */

			/** assign a new connection */
			cur_connection = csm_add_connection(meta, pktInfo);
			/** add connection in FPGA-connection table*/
			if((esm_add_connection(cur_connection)) == 0){
				printf("add esm conneciton error!\n");
				exit(1);
			}
			/** update hashTb in both CPU- and FPGA-part; */
			uint16_t temp_flowID = csm_update_hashTb(cur_connection->flowID, 
				hashV);
			/** update hash chain */
			if((temp_flowID != 0) && (temp_flowID != 0xffff))
				connectionTb[flowID].next_idx = temp_flowID;
			/** add to a conflict chain? */
#ifdef NUM_MAX_FLOW_CONFLICT
			else if(temp_flowID == 0xffff){
				/** add conn at the conflict_list's header */
				if(conn_conflict_list == NULL){
					/** get a free conn node */
					conn_conflict_list = conn_conflict_free_list;
					conn_conflict_free_list = conn_conflict_free_list->next;
					/** update this conn node */
					conn_conflict_list->next = NULL;
					conn_conflict_list->connection = &connectionTb[flowID];
					
				}
				else{
					/** get a free conn node */
					struct connection_node *temp_conn;
					temp_conn = conn_conflict_list;
					conn_conflict_list = conn_conflict_free_list;
					conn_conflict_free_list = conn_conflict_free_list->next;
					/** update this conn node */
					conn_conflict_list->next = temp_conn;
					conn_conflict_list->connection = &connectionTb[flowID];
				}
			}
#endif
			/** there is a empty hash entry used to insert */
			else{
			}
		}
		/** recv a established flow */
		else{
			/** time-out event, should del connection and update hashTb */
			if((meta->evb & UINMAN_ON_TIMEOUT) || (
				meta->evb & UINMAN_ON_CONN_END)){
				csm_delete_connection(&connectionTb[meta->flowID]);
			}
			else{
				cur_connection = &connectionTb[meta->flowID];
				csm_update_connection(cur_connection, meta);
			}
		}
		uniman_raise_event(meta->evb, cur_connection);
#if TEST_CSM
		printf("cycle:%d\n", cycle);
		if(cycle > 10)
			return;
#endif
	}
}

/*************************************************************************************************/
/** pcap packet (will be replaced by fast_ua_recv()) */
void uniman_recv_packet(struct metadata *meta, struct pkt_info *pkt_info){
	// pcap packet is on the road;
#ifdef TEST_CLOSED
	meta->flowID = 0;
	meta->evb = UINMAN_ON_CONN_START;
	pkt_info->iph->saddr = 0;
	pkt_info->iph->daddr = 1;
	pkt_info->tcph->source = 2;
	pkt_info->tcph->dest = 3;
	pkt_info->iph->protocol = 6;
#else
	switch(cycle){
		case 1:
			meta->flowID = 0;
			meta->evb = UINMAN_ON_CONN_START;
			pkt_info->iph->saddr = 0;
			pkt_info->iph->daddr = 1;
			pkt_info->tcph->source = 2;
			pkt_info->tcph->dest = 3;
			pkt_info->iph->protocol = 6;
			break;
		case 2:
			meta->flowID = 1;
			meta->evb = UINMAN_ON_CONN_SETUP;
			pkt_info->iph->saddr = 0;
			pkt_info->iph->daddr = 1;
			pkt_info->tcph->source = 2;
			pkt_info->tcph->dest = 3;
			pkt_info->iph->protocol = 6;
			break;
		case 4:
			meta->flowID = 1;
			meta->evb = UINMAN_ON_CONN_END;
			pkt_info->iph->saddr = 0;
			pkt_info->iph->daddr = 1;
			pkt_info->tcph->source = 2;
			pkt_info->tcph->dest = 3;
			pkt_info->iph->protocol = 6;
			break;	
		default:
			meta->flowID = 1;
			meta->evb = UINMAN_ON_PKT_IN;
			pkt_info->iph->saddr = 0;
			pkt_info->iph->daddr = 1;
			pkt_info->tcph->source = 2;
			pkt_info->tcph->dest = 3;
			pkt_info->iph->protocol = 6;
	}
#endif
}

/*************************************************************************************************/
/** return a assigned connection (initial new conneciton) */
connection_t *csm_add_connection(struct metadata *meta, struct pkt_info *pktInfo){
	connection_t * new_conn = assign_connection();
	get_flowKey_sorted(&(new_conn->flowK), pktInfo);

	/** calculate hash values, this can be deleted if hash values have been
	*	transmited from hardware;
	*/
	struct hash_value hashV;
	csm_calc_hashValue (&(new_conn->flowK), &hashV);

	new_conn->hashTb_idx_1 = hashV.hashValue_1;
	new_conn->hashTb_idx_2 = hashV.hashValue_2;
	if(pktInfo->iph->saddr <= pktInfo->iph->daddr)
		new_conn->direction = 0;
	else
		new_conn->direction = 1;
	new_conn->sndvar->state = 1;
	new_conn->sndvar->last_ack_seq = 0;
	new_conn->rcvvar->state = 0;
	new_conn->sndvar->last_ack_seq = 0;
	new_conn->cur_pkt = pktInfo;
	new_conn->pkt_count = 0;
	new_conn->byte_count = 0;
	
	return new_conn;
}

/*************************************************************************************************/
/** update conneciont according to pkt-in metadata */
void csm_delete_connection(connection_t *conn){
	/** release connection (flowID) */
	release_connection (conn);
	/** lookup and maybe update hashTb */
	struct hash_value hashV;
	csm_calc_hashValue( &(conn->flowK), &hashV);
	uint16_t pre_flowID, cur_flowID;
	cur_flowID = csm_lookup_hashTb (&hashV);
	pre_flowID = 0;
	while(cur_flowID != conn->flowID){
		pre_flowID = cur_flowID;
		cur_flowID = connectionTb[cur_flowID].next_idx;
	}
	/* flowID in hashTb */
	if(pre_flowID == 0){
		/** delete hashTb, if does not have hash chain */
		if(conn->next_idx == 0)
			csm_delete_hashTb(&hashV);
		/** update hashTb, if has hash chain */
		else{
			uint16_t temp_flowID;
			temp_flowID = csm_update_hashTb(conn->next_idx, &hashV);
		}
	}
	/** flowID in connTb */
	else{
		connectionTb[pre_flowID].next_idx = conn->next_idx;
	}
}

/*************************************************************************************************/
/** update conneciont according to pkt-in metadata */
void csm_update_connection(connection_t *conn, struct metadata *meta){
	// more infomation is on the road;
	// ...
	conn->sndvar->state = meta->state_cli;
	conn->rcvvar->state = meta->state_ser;
}


/*************************************************************************************************/
/** initial flowID list */

/*************************************************************************************************/
/** allocate a new flowID */
connection_t *assign_connection(){
	if(conn_free_list){
		connection_t *temp_conn = conn_free_list;
		conn_free_list = conn_free_list->next;
		return temp_conn;
	}
	else
		return 0;
}

/*************************************************************************************************/
/** release a closed flow's flowID */
void release_connection(connection_t * conn){
	conn->next = conn_free_list;
	conn_free_list = conn;
}

/*************************************************************************************************/
/** initial connection table */
void csm_initial_connTb(){
	int i = 0;
	for (int i = 1; i < NUM_MAX_FLOW; ++i)
	{
		connectionTb[i].flowID = i;
		connectionTb[i].sndvar = (struct tcp_endPoint_vars *)malloc(sizeof(
			struct tcp_endPoint_vars));
		connectionTb[i].rcvvar = (struct tcp_endPoint_vars *)malloc(sizeof(
			struct tcp_endPoint_vars));
		connectionTb[i-1].next = &connectionTb[i];
	}
	connectionTb[i].next = NULL;
	conn_free_list = &connectionTb[1];
}

void csm_initial_conn_conflict_list(){
	/** initial conn_conflict_list */
	conn_conflict_list = NULL;
	/** initial conn_conflict_free_list */
	int i = 0;
	for (i = 0; i < (NUM_MAX_FLOW_CONFLICT-1); ++i)
	{
		conn_node[i].next = &conn_node[i+1];
	}
	conn_node[i].next = NULL;
	conn_conflict_free_list = conn_node;
}

/*************************************************************************************************/
/** lookup connection table */
connection_t *csm_lookup_connTb(uint16_t flowID, struct flow_info *flowInfo){
	connection_t *cur_conn = &connectionTb[flowID];
	while(cur_conn){
		if(cmpFlowKey(&(cur_conn->flowK), flowInfo) == 0)
			return cur_conn;
		else if(cur_conn->next_idx){
			cur_conn = &connectionTb[cur_conn->next_idx];
		}
		else{
			break;
		}
	}
#ifdef NUM_MAX_FLOW_CONFLICT
	struct connection_node *cur_conn_c = conn_conflict_list;
	while(cur_conn_c){
		if(cmpFlowKey(&(cur_conn_c->connection->flowK), flowInfo) == 0)
			return cur_conn_c->connection;
		else
			cur_conn_c = cur_conn_c->next;
	}
#endif
	return NULL;
}


