#include "uniman_em_task.h"

/*************************************************************************************************/

/** initial event manager;
*	1) essential event_forest;
*    initial successfully will return '1', otherwise return '0';
*/
int uniman_initial_em(){
	int i = 0;
	for (int i = 0; i < NUM_BUILD_IN_EVENT; ++i)
	{
		event_forest[i] = NULL;
	}
	cur_conn = NULL;

	return 1;
}

/*************************************************************************************************/
/** raise/trigger event;
*/
void uniman_raise_event(event_bitmap_t evb, connection_t *connection){
	/** assign current conneciton triggering this event bitmap (events) */
	cur_conn = connection;

	/** traverse the event_forest according to the event bitmap*/
	int i = 0;
	event_t mask_bit = 1;
	event_t event_id;
	for(i = 0; i < NUM_BUILD_IN_EVENT; i++){
		event_id = evb & mask_bit;
		if(event_id){
			uniman_em_raise_event(i);
		}
		mask_bit = mask_bit << 1;
	}
}

/*************************************************************************************************/
/** EM trigger a type of event;
*    then search the event forest and execute the user-defined callback function;
*/
void uniman_em_raise_event(event_t event_id){
	struct event_node *cur_event_list_node;
	cur_event_list_node = event_forest[event_id];
	while(cur_event_list_node){
		cur_event_list_node->callback_func(event_id);
		cur_event_list_node = cur_event_list_node->next;
	}
}
