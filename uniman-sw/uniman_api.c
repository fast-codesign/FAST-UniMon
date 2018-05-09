#include "uniman_api.h"

/*************************************************************************************************/

/** Register a callback function binding to a build-in event;
*    register successfully will return '1', otherwise return '0';
*/
int uniman_register_callback(event_t event_id, callback_t cb, int NF_id){
	/* allocate memory for a new event node*/
	struct event_node *new_event_node;
	new_event_node = (struct event_node*)malloc(sizeof(struct event_node));
	new_event_node->callback_func = cb;
	new_event_node->networkFunction_id = NF_id;
	new_event_node->next = NULL;

	struct event_node * cur_event_list_node, *pre_event_list_node;
	cur_event_list_node = event_forest[event_id];
	pre_event_list_node = NULL;
	/* search event_list, and insert callback in a appropriate position; */
	while(cur_event_list_node){
		if(cur_event_list_node->networkFunction_id == NF_id)
			return 0;
		else if(cur_event_list_node->networkFunction_id < NF_id){
			pre_event_list_node = cur_event_list_node;
			cur_event_list_node = cur_event_list_node->next;
		}
		else{
			/** add new_event node at head of event_forest */
			if(pre_event_list_node == NULL){
				event_forest[event_id] = new_event_node;
				new_event_node->next = cur_event_list_node;
			}
			/** add new_event node after pre_event_list_node */
			else{
				pre_event_list_node->next = new_event_node;
				new_event_node->next = cur_event_list_node;
			}
			return 1;
		}
	}
	if(pre_event_list_node == NULL){
		event_forest[event_id] = new_event_node;
	}
	else{
		pre_event_list_node->next = new_event_node;
	}

#ifdef TEST_REG_CALLBACK
	cur_event_list_node = event_forest[event_id];
	while(cur_event_list_node){
		printf("%d\n", cur_event_list_node->networkFunction_id);
		cur_event_list_node = cur_event_list_node->next;
	}
#endif
	return 1;
}

/*************************************************************************************************/

/** Unregister a callback function binding to a build-in event;
*    unregister successfully will return '1', otherwise return '0';
*/
int uniman_unregister_callback(event_t event_id, callback_t cb, int NF_id){
	struct event_node * cur_event_list_node, *pre_event_list_node;
	cur_event_list_node = event_forest[event_id];
	pre_event_list_node = NULL;

	while(cur_event_list_node){
		if(cur_event_list_node->networkFunction_id == NF_id){
			if(pre_event_list_node == NULL)
				event_forest[event_id] = cur_event_list_node->next;
			else
				pre_event_list_node->next = cur_event_list_node->next;
			free(cur_event_list_node);
			
			return 1;
		}
		else{
			pre_event_list_node = cur_event_list_node;
			cur_event_list_node = cur_event_list_node->next;
		}
	}
	return 0;
}

/*************************************************************************************************/

/** Register a callback function binding to a build-in event;
*    get current flow state successfully will return connection point, otherwise return NULL;
*/
connection_t *uniman_get_current_flowState(){
	return cur_conn;
}


