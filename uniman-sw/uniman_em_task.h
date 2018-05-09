#ifndef __UNIMAN_EM_TASK_H_
#define __UNIMAN_EM_TASK_H_

//#include "common.h"
#include "uniman_api.h"



/*************************************************************************************************/

/** initial event manager;
*    initial successfully will return '1', otherwise return '0';
*/
int uniman_initial_em();

/*************************************************************************************************/

/** raise/trigger event;
*/
void uniman_raise_event(event_bitmap_t evb, connection_t *connection);
/* Parameter:
*    evb represents the triggered event type (bitmap);
*    connection is the state of triggered flow;
*/

/*************************************************************************************************/
/** EM trigger a type of event;
*    then search the event forest and execute the user-defined callback function;
*/
void uniman_em_raise_event(event_t event_id);
/* Parameter:
*    event_id represents the triggered event type;
*/

#endif /* __UNIMAN_EM_TASK_H_ */