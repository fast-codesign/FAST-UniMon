#ifndef __UNIMAN_CSM_TASK_H_
#define __UNIMAN_CSM_TASK_H_

#include "common.h"
#include "hash.h"
#include "uniman_esm_task.h"
#include "uniman_em_task.h"

/** declaration fo connection table, consists of NUM_MAX_FLOW tcp streams*/
struct tcp_stream connectionTb[NUM_MAX_FLOW];
/** header of free connection list, constructed by connectionTb */
struct tcp_stream * conn_free_list;

/** declaration of connection conflict list, and a free list to record free conn entries */
struct connection_node{
	struct tcp_stream *connection;
	struct connection_node *next;
};
struct connection_node *conn_conflict_list;
struct connection_node *conn_conflict_free_list;
struct connection_node conn_node[NUM_MAX_FLOW_CONFLICT];


/*************************************************************************************************/
/** initial completed state manager;
*     use csm_initial_flowIDlist() to intial flowID list
*   initial successfully will return '1', otherwise return '0';
*/
int uniman_initial_csm();

/** the processing function of uniman */
void uniman_run();


/*************************************************************************************************/
/** pcap packet (will be replaced by fast_ua_recv()) */
#ifndef FAST_RECV
void uniman_recv_packet(struct metadata *meta, struct pkt_info *pkt_info);
#else
void fast_ua_recv();
#endif

/*************************************************************************************************/
/** initial connection table, and return the free connection list (free flowID)*/
void csm_initial_connTb();

/** return a assigned connection point */
connection_t *csm_add_connection(struct metadata *meta, struct pkt_info *pktInfo);

/** update conneciont according to pkt-in metadata */
void csm_update_connection(connection_t *conn, struct metadata *meta);

/** delete connection according to flowID */
void csm_delete_connection(connection_t *conn);

/** lookup connection table */
connection_t *csm_lookup_connTb(uint16_t flowID, struct flow_info *flowInfo);

/*************************************************************************************************/
/** allocate a new flowID */
connection_t *assign_connection();

/** release a closed flow's flowID */
void release_connection(connection_t * conn);


/*************************************************************************************************/
/** initial connection conflict list, and connection free list */
void csm_initial_conn_conflict_list();

#ifndef TEST_CLOSED
int cycle;
#endif


#endif /* __UNIMAN_CSM_TASK_H_ */