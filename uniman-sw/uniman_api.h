#ifndef __UNIMAN_API_H_
#define __UNIMAN_API_H_

#include "common.h"
//#include "tcp_stream.h"
//#include "build_in_event.h"


/*************************************************************************************************/
/** callback funciton shouded be coded by user;
*/
typedef void (*callback_t)(event_t event_id);
/* Parameter:
*    event_id represents the triggered event type;
*/

/*************************************************************************************************/
/** Register a callback function binding to a build-in event;
*    register successfully will return '1', otherwise return '0';
*/
int uniman_register_callback(event_t event_id, callback_t cb, int NF_id);
/* Parameter:
*    evnet_id represent the event type;
*    cb is the callback function coded by user;
*    NF_id (network function id) used to identify NF coded by different user, and samller
*    	one has higher priority;
*/

/*************************************************************************************************/
/** Unregister a callback function binding to a build-in event;
*    unregister successfully will return '1', otherwise return '0';
*/
int uniman_unregister_callback(event_t event_id, callback_t cb, int NF_id);
/* Parameter:
*    evnet_id represent the event type;
*    cb is the callback function coded by user;
*    NF_id (network function id) used to identify NF coded by different user, and samller
*    	one has higher priority;
*/

/*************************************************************************************************/
/** Register a callback function binding to a build-in event;
*    get current flow state successfully will return connection point, otherwise return NULL;
*/
connection_t *uniman_get_current_flowState();
/* Parameter:
*    evnet_id represent the event type;
*    cb is the callback function coded by user;
*    NF_id (network function id) used to identify NF coded by different user, and samller
*    	one has higher priority;
*/

/*************************************************************************************************/
/** each event node has a network fuinction (id) and a callback function */
struct event_node{
	int networkFunction_id;
	callback_t callback_func;
	struct event_node *next;
};
struct event_node *event_forest[NUM_BUILD_IN_EVENT];

/** the triggered conneciton (flow state) */
connection_t *cur_conn;


#endif /* __UNIMAN_API_H_ */