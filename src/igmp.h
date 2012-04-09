#ifndef __SWITCH_IGMP_H__
#define __SWITCH_IGMP_H__

class IgmpRecord {
    public:
        struct in_addr group_id;
        Port *igmp_querier;
        Port **clients;
};


//typedef std::map<MacAddress, CamRecord> RecordTable;


class IgmpTable {
    public:
        IgmpRecord *;
        Port *ports;

        void process_igmp_packet();
};

#endif /* __SWITCH_IGMP_H__ */

