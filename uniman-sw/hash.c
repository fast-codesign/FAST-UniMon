#include "hash.h"


/*************************************************************************************************/
/** initial two hash tables, i.e. assign valid = 0 */
void csm_initial_hashTb(){
	int i = 0;
	for (int i = 0; i < NUM_HASH_ENTRY; ++i)
	{
		hashTb_1[i].valid = 0;
		hashTb_2[i].valid = 0;
	}
}

/*************************************************************************************************/
/** calculate two hash values;
*    the first hash function is srcIP[15:0] ^ srcPort;
*    the second hash function is dstIP[15:0] ^ dstPort;
*    two hash values is stored in hashV (struct hash_value);
*/
void csm_calc_hashValue (struct flow_info *flowK, struct hash_value *hashV){
	hashV->hashValue_1 = (uint16_t) flowK->saddr ^ flowK->sport;
	hashV->hashValue_2 = (uint16_t) flowK->saddr ^ flowK->sport;
	hashV->simplified_flowK = hashV->hashValue_1 ^ hashV->hashValue_2;
}

/*************************************************************************************************/
/** lookup hash table according to two hash values (indexes);
*    this function will return the connection index, and '0' represent "miss";
*/
uint16_t csm_lookup_hashTb (struct hash_value *hashV){
	struct hash_entry *hash_e1 = &hashTb_1[hashV->hashValue_1];
	struct hash_entry *hash_e2 = &hashTb_2[hashV->hashValue_2];
	if((hash_e1->valid) && (hash_e1->simplified_flowK == hashV->simplified_flowK)){
		return hash_e1->connectionTb_idx;
	}
	else if((hash_e2->simplified_flowK == hashV->simplified_flowK) && 
		(hash_e2->valid))
	{
		return hash_e2->connectionTb_idx;
	}
	else{
		return 0;
	}
}

/*************************************************************************************************/
/** update hash table;
*    return the original flowID in hashTb1 or hashTb2, if the flowID = 0, means that 
*	update an empty hash table enty;
*/
uint16_t csm_update_hashTb(uint16_t flowID, struct hash_value *hashV){
	struct hash_entry *hashEntry;
	hashEntry = (struct hash_entry*)malloc(sizeof(struct hash_entry));
	hashEntry->valid = 1;
	hashEntry->simplified_flowK = hashV->simplified_flowK;
	hashEntry->connectionTb_idx = flowID;

	struct hash_entry *hash_e1, *hash_e2;
	hash_e1 = &hashTb_1[hashV->hashValue_1];
	hash_e2 = &hashTb_2[hashV->hashValue_2];

	// on the road;

	if((hash_e1->valid) && (hash_e2->valid)){
		/** check the hash table 1 */
		if(hash_e1->simplified_flowK == hashV->simplified_flowK){
			update_hashTb(0, hashV->hashValue_1, hashEntry);
			return hash_e1->connectionTb_idx;
		}
		/** check the hash table 2 */
		else if (hash_e2->simplified_flowK == hashV->simplified_flowK){
			update_hashTb(1, hashV->hashValue_2, hashEntry);
			return hash_e2->connectionTb_idx;
		}
		/** del hasn conflict chain */
		else{
			/*
			update_hashTb(0, hashV->hashValue_1, hashEntry);
			cur_flowID = hash_e1->connectionTb_idx;
			while(cur_flowID){
				csm_delete_connection(cur_flowID);
				cur_flowID = connectionTb[cur_flowID].next_idx;
			}
			return 0;
			*/
			return 0xffff;
		}
	}
	else {
		if(hash_e1->valid == 0)
			update_hashTb(0, hashV->hashValue_1, hashEntry);
		else
			update_hashTb(1, hashV->hashValue_2, hashEntry);
	}
	return 0;
}

/*************************************************************************************************/
/** delete hash table */
void csm_delete_hashTb(struct hash_value *hashV){
	struct hash_entry *hash_e1, *hash_e2;
	hash_e1 = &hashTb_1[hashV->hashValue_1];
	hash_e2 = &hashTb_2[hashV->hashValue_2];

	if((hash_e1->valid) && (hash_e1->simplified_flowK == hashV->simplified_flowK)){
		hash_e1->valid = 0;
		fast_reg_wr(0x30100000+(uint32_t) hashV->hashValue_1 *16, 0);
	}
	else if((hash_e2->valid) && (hash_e2->simplified_flowK == hashV->simplified_flowK)){
		hash_e2->valid = 0;
		fast_reg_wr(0x30100000+(uint32_t) hashV->hashValue_2 *16, 0);
	}
	else{
	}
}


/*************************************************************************************************/
/** update hash table's entry both in cpu- and fpga-part; */
void update_hashTb (int table_id, uint16_t hash_idx, struct hash_entry * hashEntry){
	if(table_id == 0){
		cpy_hash_entry(&hashTb_1[hash_idx], hashEntry);
		/** 0x301_0000_0 */
		fast_reg_wr(0x30100000+(uint32_t) hash_idx *16, 
			(((uint32_t) hashEntry->simplified_flowK) << 16) + 
			(uint32_t) hashEntry->connectionTb_idx);
	}
	else{
		cpy_hash_entry(&hashTb_2[hash_idx], hashEntry);
		/** 0x302_0000_0 */
		fast_reg_wr(0x30200000+(uint32_t) hash_idx *16, 
			(((uint32_t) hashEntry->simplified_flowK) << 16) + 
			(uint32_t) hashEntry->connectionTb_idx);
	}
}

/*************************************************************************************************/
/** delete hash table's entry; */
void delete_hashTb (int table_id, uint16_t hash_idx){
	if(table_id == 0){
		hashTb_1[hash_idx].valid = 0;
		fast_reg_wr(0x30100000+(uint32_t) hash_idx *16, 0);
	}
	else{ 
		hashTb_2[hash_idx].valid = 0;
		fast_reg_wr(0x30200000+(uint32_t) hash_idx *16, 0);
	}
}



/*************************************************************************************************/
/** copy hashEntry_b to hashEntry_a */
void cpy_hash_entry(struct hash_entry *hashEntry_a, struct hash_entry *hashEntry_b){
	hashEntry_a->valid = hashEntry_b->valid;
	hashEntry_a->simplified_flowK = hashEntry_b->simplified_flowK;
	hashEntry_a->connectionTb_idx = hashEntry_b->connectionTb_idx;
}

/*************************************************************************************************/
/** get 5-tuple information of flow from packet*/
void get_flowKey_sorted(struct flow_info *flowInfo, struct pkt_info *pktInfo){
	if(pktInfo->iph->saddr <= pktInfo->iph->daddr){
		flowInfo->saddr = pktInfo->iph->saddr;
		flowInfo->daddr = pktInfo->iph->daddr;
		flowInfo->sport = pktInfo->tcph->source;
		flowInfo->dport = pktInfo->tcph->dest;
		flowInfo->protocol = pktInfo->iph->protocol;
	}
	else{
		flowInfo->saddr = pktInfo->iph->daddr;
		flowInfo->daddr = pktInfo->iph->saddr;
		flowInfo->sport = pktInfo->tcph->dest;
		flowInfo->dport = pktInfo->tcph->source;
		flowInfo->protocol = pktInfo->iph->protocol;
	}
}

/*************************************************************************************************/
/** compare flow key, equal will return "0", otherwise return "1"*/
int cmpFlowKey(struct flow_info *flow_a, struct flow_info *flow_b){
	if((flow_a->saddr == flow_b->saddr) && (flow_a->daddr == flow_b->daddr) && 
		(flow_a->sport == flow_b->sport) && (flow_a->dport == flow_b->dport) && 
		(flow_a->protocol == flow_b->protocol) )
		return 0;
	else
		return 1;
}