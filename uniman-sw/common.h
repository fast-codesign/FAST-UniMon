#ifndef __COMMMON_H_
#define __COMMMON_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tcp_stream.h"
#include "build_in_event.h"
//#include "fast.h??"

/** the types of build-in event */
#define NUM_BUILD_IN_EVENT 8	
/** the maximal number of flow (connection) can be maintained in onnection table */
#define NUM_MAX_FLOW 1024
/** the maximal number of flow (connection) in conflict list (chain) */
#define NUM_MAX_FLOW_CONFLICT 10

/** the number of hash entry */
#define NUM_HASH_ENTRY 65535
/** the number of 32b in a connection, used to configure fast fpga */
#define NUM_REG_OF_CONN 7

/** used for test */
#define TEST_CSM 1

typedef uint16_t simFlowK_t;

#endif /* __COMMMON_H_ */