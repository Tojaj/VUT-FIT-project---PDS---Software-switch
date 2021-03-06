#ifndef __SWITCH_IGMP_H__
#define __SWITCH_IGMP_H__

#include <ctime>
#include <map>
#include <vector>
#include <linux/ip.h>
#include "port.h"

using namespace std;

#define IGMP_PORT_TIMEOUT 30

#define MULT_OK         0
#define MULT_BROADCAST  1
#define MULT_ERR        2

class IgmpRecord {
    public:
        __be32 group_id;
        Port *igmp_querier;
        vector<Port*> ports;
        vector<time_t> last_used_vector; // time of last membership query for port on same index in ports
};


typedef map<__be32, IgmpRecord*> IgmpRecordTable;


class IgmpTable {
    private:
        pthread_mutex_t mutex;
        IgmpRecordTable records;
        vector<Port*> queriers;
        vector<Port*> ports;
        int process_igmp_packet(Port *source_port, const u_char *packet, 
                           size_t size, struct igmphdr *igmp_hdr);

    public:
        IgmpTable();
        ~IgmpTable();
        void add_group(__be32 group_id); // Add group if doesn't exists
        void add_or_update_group(__be32 group_id, Port *port); // Add group if doesn't exists or just update quierier in group
        void add_group_member(__be32 group_id, Port *port);
        void add_querier(Port *port);
        void remove_group_member(__be32 group_id, Port *port);
        int send_to_group(__be32 group_id,  const u_char *packet, size_t size);
        void send_to_all_queriers(const u_char *packet, size_t size);
        int send_to_querier(__be32 group_id,  const u_char *packet, size_t size);

        void set_ports(vector<Port*> ports);
        string print_ip(int ip);
        int process_multicast_packet(Port *source_port, const u_char *packet, size_t size);
        void multicast(Port *source_port, const u_char *packet, size_t size);  // Send multicast
        void print_table();
        void purge();
};

#endif /* __SWITCH_IGMP_H__ */

