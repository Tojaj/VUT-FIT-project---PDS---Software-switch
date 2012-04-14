#ifndef __SWITCH_IGMP_H__
#define __SWITCH_IGMP_H__

#include <map>
#include <vector>
#include <linux/ip.h>
#include "port.h"

using namespace std;

#define MULT_OK         0
#define MULT_BROADCAST  1
#define MULT_ERR        2

class IgmpRecord {
    public:
        __be32 group_id;
        Port *igmp_querier;
        vector<Port*> ports;
};


typedef map<__be32, IgmpRecord> IgmpRecordTable;


class IgmpTable {
    private:
        pthread_mutex_t mutex;
        IgmpRecordTable records;
        vector<Port*> ports;
        int process_igmp_packet(Port *source_port, const void *packet, 
                           size_t size, struct igmphdr *igmp_hdr);

    public:
        IgmpTable();
        ~IgmpTable();
        void add_group(__be32 group_id, Port *port);
        void add_group_member(__be32 group_id, Port *port);
        void remove_group_member(__be32 group_id, Port *port);
        int send_to_group(__be32 group_id,  const void *packet, size_t size);
        int send_to_querier(__be32 group_id,  const void *packet, size_t size);

        void set_ports(vector<Port*> ports);
        string print_ip(int ip);
        int process_multicast_packet(Port *source_port, const void *buf, size_t size);
        void multicast(Port *source_port, const void *buf, size_t size);  // Send multicast
        void print_table();
};

#endif /* __SWITCH_IGMP_H__ */

