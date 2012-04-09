#ifndef __SWITCH_CAMTABLE_H__
#define __SWITCH_CAMTABLE_H__

#include <ctime>
#include <map>
#include <vector>
#include <linux/if_ether.h>
#include "port.h"

#define PURGE_TIMEOUT   60


using namespace std;


class MacAddress {
    public:
        u_int8_t  mac[ETH_ALEN];

        MacAddress();
        MacAddress(unsigned char mac[]);
        void print();
        std::string str();
        MacAddress(const MacAddress &); // copy constructor
        bool is_broadcast();
        bool is_multicast();
        bool operator==(const MacAddress &) const;
        bool operator!=(const MacAddress &) const;
        bool operator<(const MacAddress &) const;
};


class CamRecord {
    public:
        MacAddress mac;
        time_t last_used;
        Port *port;

        //CamRecord();
        CamRecord(MacAddress &mac, Port *port);
        void refresh(); // call refresh of last use time
        int send_via_port(const void *buf, size_t size); // send data
};


typedef std::map<MacAddress, CamRecord*> RecordTable;
typedef std::map<MacAddress, CamRecord*>::iterator RecordTableIterator;


class CamTable {
    private:
        pthread_mutex_t mutex;
        vector<Port*> ports;
        RecordTable records;

    public:
        CamTable();
        ~CamTable();
        void set_ports(vector<Port*> ports);
        int update(MacAddress &mac, Port *port); // if doesn't exist -> add new record if exists -> refresh last_used
        void purge(); // TODO remove thread
        CamRecord *get_record(MacAddress &mac);
        void broadcast(Port *source_port, const void *buf, size_t size); // send message out via all port except soruce_port
        void print_table();
};

#endif /* __SWITCH_CAMTABLE_H__ */

