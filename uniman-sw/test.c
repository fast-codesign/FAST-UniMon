#include "uniman_em_task.h"
#include "uniman_csm_task.h"
#include "uniman_esm_task.h"



void print_a(event_t event_id){
	printf("****************event_id: %d******************\n", event_id);
	/** test uniman_get_current_flowState */
	connection_t *curConn = uniman_get_current_flowState();
	printf("saddr:%u,daddr:%u\n", curConn->flowK.saddr,
		curConn->flowK.daddr);
	printf("sport:%u,dport:%u\n,protocol:%u\n", cur_conn->flowK.sport,
		cur_conn->flowK.dport,cur_conn->flowK.protocol);
}

int main(){


#ifdef TEST_CSM
	if(uniman_initial_em() == 0)
		return 0;

	if( uniman_register_callback( 1, print_a, 2) == 0 ){
		printf("register error!\n");
		return 0;
	}
	if( uniman_register_callback( 3, print_a, 4) == 0 ){
		printf("register error!\n");
		return 0;
	}
	if( uniman_register_callback( 5, print_a, 3) == 0 ){
		printf("register error!\n");
		return 0;
	}
	/** test unregister_callback
	if( uniman_unregister_callback( 5, print_a, 3) == 0 ){
		printf("unregister error!\n");
		return 0;
	}
	
	int i = 0;
	struct event_node * cur_event_list_node;
	for (int i = 0; i < NUM_BUILD_IN_EVENT; ++i)
	{
		printf("%d------------------------\n",i);
		cur_event_list_node = event_forest[i];
		while(cur_event_list_node){
			printf("\t network funciton id:%d \n", cur_event_list_node->networkFunction_id);
			cur_event_list_node = cur_event_list_node->next;
		}
	}
	*/

	uniman_run();
	/** test connection_free_list 
	printf("header flowID of conn_free_list: %u\n", conn_free_list->flowID);
	*/

#endif
	return 0;
}

