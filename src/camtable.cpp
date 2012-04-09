#include <sstream>
#include <assert.h> 
#include "camtable.h"

using namespace std;


MacAddress::MacAddress()
{
    for (int i=0; i < ETH_ALEN; i++) {
        this->mac[i] = 0;
    }
}

MacAddress::MacAddress(unsigned char mac[])
{
    for (int i=0; i < ETH_ALEN; i++) {
        this->mac[i] = mac[i];
    }
}


void MacAddress::print()
{
    printf("%02x", this->mac[0]);
    for (int i=1; i < ETH_ALEN; i++) {
        printf(":%02x", this->mac[i]);
    }
    printf("\n");
}


string MacAddress::str()
{
    char buffer[15];
    snprintf(buffer, 15, "%02x%02x.%02x%02x.%02x%02x", this->mac[0], this->mac[1],
                                                       this->mac[2], this->mac[3],
                                                       this->mac[4], this->mac[5]);
    return string(buffer);
}


MacAddress::MacAddress(const MacAddress &second)
{
    for (int i=0; i < ETH_ALEN; i++) {
        this->mac[i] = second.mac[i];
    }
}


bool MacAddress::is_broadcast()
{
    for (int i=0; i < ETH_ALEN; i++) {
        if (this->mac[i] != 255) {
            return false;
        }
    }
    return true;
}


bool MacAddress::is_multicast()
{
    if (this->mac[0] == 1 && this->mac[1] == 0 && this->mac[2] == 94) {
        return true;
    }
    return false;
}


bool MacAddress::operator==(const MacAddress &second) const
{
    for (int i=0; i < ETH_ALEN; i++) {
        if (this->mac[i] != second.mac[i]) {
            return false;
        }
    }
    return true;
}


bool MacAddress::operator!=(const MacAddress &second) const
{
    return !(*this == second);
}


bool MacAddress::operator<(const MacAddress &second) const
{
    for (int i=0; i < ETH_ALEN; i++) {
        if (this->mac[i] < second.mac[i]) {
/*            printf("LISI SE: %02x%02x.%02x%02x.%02x%02x | ", this->mac[0], this->mac[1],
                                                 this->mac[2], this->mac[3],
                                                 this->mac[4], this->mac[5]);
            printf("%02x%02x.%02x%02x.%02x%02x\n", second.mac[0], second.mac[1],
                                                 second.mac[2], second.mac[3],
                                                 second.mac[4], second.mac[5]);
*/
            return true;
        }
    }

    return false;
}



/*
CamRecord::CamRecord()
{
    this->mac = NULL;
    this->port = NULL;
    this->last_used = time(NULL);
}
*/

CamRecord::CamRecord(MacAddress &mac, Port *port)
{
    this->mac = mac;
    this->port = port;
    this->last_used = time(NULL);
}


void CamRecord::refresh()
{
    this->last_used = time(NULL);
}


int CamRecord::send_via_port(const void *buf, size_t size)
{
    assert(this->port);
    return this->port->send(buf, size);
}



CamTable::CamTable()
{
    pthread_mutex_init(&(this->mutex), NULL);
}


CamTable::~CamTable()
{
    pthread_mutex_destroy(&(this->mutex));
}



void CamTable::set_ports(vector<Port*> ports)
{
    this->ports = ports;
}



int CamTable::update(MacAddress &mac, Port *port)
{
    int ret;
//    RecordTable::iterator it;
    pthread_mutex_lock(&(this->mutex));
//    it = this->records.find(mac.str());

//    if (it == this->records.end()) {
    if (! this->records.count(mac.str())) {
        // Unknown source mac address -> Create record
        printf("Pridavam novy zaznam: %s\n", mac.str().c_str());
        CamRecord *camrecord = new CamRecord(mac, port);
        this->records[mac.str()] = camrecord;
        ret = 1;
    } else {
        printf("uz existuje: %s\n", mac.str().c_str());
//        it->second->refresh();
        ret = 0;
    }

    pthread_mutex_unlock(&(this->mutex));
    return ret;
}


void CamTable::print_table()
{
    RecordTableIterator it, it2;
    time_t cur_time = time(NULL);

    printf("MAC address      Port  Age\n");

    pthread_mutex_lock(&(this->mutex));
    printf("SIZE: %d\n", this->records.size());
    for (it=this->records.begin(); it != this->records.end(); it++) {
        printf("iterace\n");
        CamRecord *rec = it->second;
        string mac_str = rec->mac.str();
        printf("%-16s %-5s %ld\n", mac_str.c_str(), rec->port->name.c_str(), (cur_time - rec->last_used));
        int x = 0;
        for (it2=this->records.begin(); it2 != this->records.end(); it2++) {
            if (it == it2) {
                continue;
            }
/*            MacAddress m1 = (MacAddress) it->first;
            MacAddress m2 = (MacAddress) it2->first;
            if (m1 == m2) {
                printf("JSOU STEJNE!!!\n");
                if (! (m1 < m2)) {
                    printf("OK\n");
                }
            }
            */
        }
    }


    RecordTable::reverse_iterator rit;
    for (rit = this->records.rbegin(); rit != this->records.rend(); rit++) {
        printf("##\n");
    }


    pthread_mutex_unlock(&(this->mutex));
}


CamRecord *CamTable::get_record(MacAddress &mac)
{
    CamRecord * ret = NULL;
    RecordTable::iterator it;
    pthread_mutex_lock(&(this->mutex));
    it = this->records.find(mac.str());
    if (! (it == this->records.end())) {
        ret = it->second;
    }
    pthread_mutex_unlock(&(this->mutex));
    return ret;
}


void CamTable::broadcast(Port *source_port, const void *buf, size_t size)
{
    for (unsigned int i=0; i < this->ports.size(); i++) {
        if (this->ports[i] != source_port) {
            this->ports[i]->send(buf, size);
            printf("Broadcast from: %s\n", this->ports[i]->name.c_str());
        }
    }
}


void CamTable::purge()
{
    RecordTable::iterator it;
    time_t cur_time = time(NULL);   
    pthread_mutex_lock(&(this->mutex));
    for (it=this->records.begin(); it != this->records.end(); ) {
        CamRecord *rec = it->second;
        if ((cur_time - rec->last_used) > PURGE_TIMEOUT) {
            delete rec;
            this->records.erase(it++);
        } else {
            ++it;
        }
    }
    pthread_mutex_unlock(&(this->mutex));
}


