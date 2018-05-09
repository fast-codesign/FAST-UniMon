#ifndef __HASH_H_
#define __HASH_H_

#include "common.h"
//#include "tcp_stream.h"
#include "uniman_esm_task.h"

struct hash_value{
	uint16_t hashValue_1;
	uint16_t hashValue_2;
	simFlowK_t simplified_flowK;
};

struct hash_entry{
	simFlowK_t simplified_flowK;
	uint16_t connectionTb_idx;
	uint8_t valid;
};

struct hash_entry hashTb_1[NUM_HASH_ENTRY], hashTb_2[NUM_HASH_ENTRY];



/*************************************************************************************************/
/** initial two hash tables, i.e. assign valid = 0 */
void csm_initial_hashTb();

/*************************************************************************************************/
/** calculate two hash values;
*    the first hash function is srcIP[15:0] ^ srcPort;
*    the second hash function is dstIP[15:0] ^ dstPort;
*    two hash values is stored in hashV (struct hash_value);
*/
void csm_calc_hashValue (struct flow_info *flowK, struct hash_value *hashV);
/* Parameter:
*    flowK is the 5-tuple info of flow/packet;
*    hashV is a struct of hash_value, includes two hash values and a simplified flow key;
*/

/*************************************************************************************************/
/** lookup hash table according to two hash values (indexes);
*    this function will return the connection index, and '0' represent "miss";
*/
uint16_t csm_lookup_hashTb (struct hash_value *hashV);
/* Parameter
*    hashV is a struct of hash_value, includes two hash values and a simplified flow key;
*/

/** update hash table */
uint16_t csm_update_hashTb(uint16_t flowID, struct hash_value *hashV);

/** delete hash table */
void csm_delete_hashTb(struct hash_value *hashV);


/*************************************************************************************************/
/** update hash table's entry;
*    update hash table in fpga too;
*/
void update_hashTb (int table_id, uint16_t hash_idx, struct hash_entry * hashEntry);
/* Parameter
*    table_id represents hash table 1 or hash table 2;
*    hash_idx is the index of hash table;
*    hashEntry is the context used to update hash table;
*/

/*************************************************************************************************/
/** delete hash table's entry; */
void delete_hashTb (int table_id, uint16_t hash_idx);


/*************************************************************************************************/
/** copy hashEntry_b to hashEntry_a */
void cpy_hash_entry(struct hash_entry *hashEntry_a, struct hash_entry *hashEntry_b);

/*************************************************************************************************/
/** get 5-tuple information of flow from packet*/
void get_flowKey_sorted(struct flow_info *flowInfo, struct pkt_info *pktInfo);

/*************************************************************************************************/
/** compare flow key, equal will return "0", otherwise return "1"*/
int cmpFlowKey(struct flow_info *flow_a, struct flow_info *flow_b);

#endif /** __HASH_H_ */