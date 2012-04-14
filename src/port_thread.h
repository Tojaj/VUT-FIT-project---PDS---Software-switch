#ifndef __SWITCH_PORT_THREAD_H__
#define __SWITCH_PORT_THREAD_H__

#include "port.h"
#include "camtable.h"
#include "igmp.h"


class PortThreadData {
    public:
        CamTable *camtable;
        IgmpTable *igmptable;
        Port *port;
};


void *port_thread(void *arg);


#endif /* __SWITCH_PORT_THREAD_H__ */

