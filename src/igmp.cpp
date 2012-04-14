#include <pcap.h>
#include <cstdio>
#include <assert.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/igmp.h>
#include "igmp.h"
#include "camtable.h"


#define IGMP_PROTOCOL   2


IgmpTable::IgmpTable()
{
    pthread_mutex_init(&(this->mutex), NULL);
}


IgmpTable::~IgmpTable()
{
    pthread_mutex_destroy(&(this->mutex));
}


void IgmpTable::set_ports(vector<Port*> ports)
{
    this->ports = ports;
}


void IgmpTable::add_group(__be32 group_id, Port *port)
{
    if (group_id == 0)
        return;


    pthread_mutex_lock(&(this->mutex));
    if(!this->records.count(group_id)) {
        IgmpRecord rec;
        rec.group_id = group_id;
        rec.igmp_querier = port;
        
        this->records[group_id] = rec;
    }
    pthread_mutex_unlock(&(this->mutex));
}


void IgmpTable::add_group_member(__be32 group_id, Port *port)
{
    if (group_id == 0)
        return;

    IgmpRecordTable::iterator it;
    pthread_mutex_lock(&(this->mutex));
    it = this->records.find(group_id);
    
    if (it == this->records.end()) {
        // Unknown group
        printf("%s: Multicastova skupina %s neexistuje!\n", __func__, print_ip(group_id).c_str());
        pthread_mutex_unlock(&(this->mutex));
        return;
    }
    
    ((IgmpRecord) it->second).ports.push_back(port);

    pthread_mutex_unlock(&(this->mutex));
    return;
}


void IgmpTable::remove_group_member(__be32 group_id, Port *port)
{
    if (group_id == 0)
        return;

    IgmpRecordTable::iterator it;
    pthread_mutex_lock(&(this->mutex));
    it = this->records.find(group_id);
    
    if (it == this->records.end()) {
        // Unknown group
        printf("%s: Multicastova skupina %s neexistuje!\n", __func__, print_ip(group_id).c_str());
        pthread_mutex_unlock(&(this->mutex));
        return;
    }

    IgmpRecord rec = (IgmpRecord) it->second;
    for (unsigned int i=0; i < ((IgmpRecord) it->second).ports.size(); i++) {
        if (((IgmpRecord) it->second).ports[i] == port) {
            printf("Odebiram port: %s\n", ((IgmpRecord) it->second).ports[i]->name.c_str());
            ((IgmpRecord) it->second).ports.erase(((IgmpRecord) it->second).ports.begin() + i);
            break;
        }
    }
    

    pthread_mutex_unlock(&(this->mutex));
    return;
}


int IgmpTable::send_to_group(__be32 group_id,  const u_char *packet, size_t size)
{
    IgmpRecordTable::iterator it;
    pthread_mutex_lock(&(this->mutex));
    it = this->records.find(group_id);
    
    assert(group_id != 0);
    
    if (it == this->records.end()) {
        // Unknown group
        printf("Multicastova skupina %s neexistuje!\n", print_ip(group_id).c_str());
        pthread_mutex_unlock(&(this->mutex));
        return MULT_BROADCAST;
    }
    
    IgmpRecord rec = (IgmpRecord) it->second;
    for (unsigned int i=0; i < rec.ports.size(); i++) {
        rec.ports[i]->send(packet, size);
        printf("Multicast to: %s\n", this->ports[i]->name.c_str());
    }

    pthread_mutex_unlock(&(this->mutex));
    return MULT_OK;
}



int IgmpTable::send_to_querier(__be32 group_id,  const u_char *packet, size_t size)
{
    IgmpRecordTable::iterator it;
    pthread_mutex_lock(&(this->mutex));
    it = this->records.find(group_id);
    
    assert(group_id != 0);
    
    if (it == this->records.end()) {
        // Unknown group
        printf("Multicastova skupina %s neexistuje!\n", print_ip(group_id).c_str());
        pthread_mutex_unlock(&(this->mutex));
        return MULT_BROADCAST;
    }
    
    IgmpRecord rec = (IgmpRecord) it->second;
    rec.igmp_querier->send(packet, size);

    pthread_mutex_unlock(&(this->mutex));
    return MULT_OK;
}



string IgmpTable::print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;        
    
    char buffer[16];
    snprintf(buffer, 16, "%3d.%3d.%3d.%3d", bytes[3], bytes[2], bytes[1], bytes[0]);
    return string(buffer);
}


int IgmpTable::process_igmp_packet(Port *source_port, const u_char *packet, size_t size, struct igmphdr *igmp_hdr)
{
    // Membership query
    if (igmp_hdr->type == IGMP_HOST_MEMBERSHIP_QUERY) {
        add_group(igmp_hdr->group, source_port);
        return MULT_BROADCAST;
    }

    // Membership report
    if (igmp_hdr->type == IGMPV2_HOST_MEMBERSHIP_REPORT || igmp_hdr->type == IGMPV3_HOST_MEMBERSHIP_REPORT) {
        add_group_member(igmp_hdr->group, source_port);
        return send_to_querier(igmp_hdr->group, packet, size);
    }

    // Membership leave group
    if (igmp_hdr->type == IGMP_HOST_LEAVE_MESSAGE) {
        remove_group_member(igmp_hdr->group, source_port);
        return send_to_querier(igmp_hdr->group, packet, size);
    }
    
    printf("Neznamy typ (%d) IGMP packetu\n", igmp_hdr->type);
    
    return MULT_OK;
}



int IgmpTable::process_multicast_packet(Port *source_port, const u_char *packet, size_t size)
{
    struct ethhdr  *eth_hdr;
    struct iphdr   *ip_hdr;
    struct igmphdr *igmp_hdr;
    
    size_t eth_hdr_len;
    size_t ip_hdr_len;
    size_t igmp_hdr_len;

    eth_hdr = (struct ethhdr *) packet;
    eth_hdr_len = sizeof(struct ethhdr);

    if (eth_hdr_len > size) {
        // Bad packet
        return MULT_ERR;
    }

    MacAddress dst_mac(eth_hdr->h_dest);
    printf(">>>> Paket na adresu: %s\n", dst_mac.str().c_str());

    if (eth_hdr->h_proto != ETH_P_IP) {
        printf(">>>> Multicast packet ale ne IP (%d)\n", eth_hdr->h_proto);
        return MULT_BROADCAST;
    }

    ip_hdr    = (struct iphdr *)  packet + sizeof(struct ethhdr);

    if ((eth_hdr_len + sizeof(struct iphdr)) > size) {
        // Bad packet
        return MULT_ERR;
    }

    ip_hdr_len = (ip_hdr->ihl * 4);

    if ((eth_hdr_len + ip_hdr_len) > size) {
        // Bad packet
        return MULT_ERR;
    }

    printf(">>>> Multicast packet do %s (velikost: %d)\n", print_ip(ip_hdr->daddr).c_str(), ip_hdr_len);


    // IGMP packet

    if (ip_hdr->protocol == IGMP_PROTOCOL) {
        igmp_hdr  = (struct igmphdr *) packet + eth_hdr_len + ip_hdr_len;
        igmp_hdr_len = sizeof(struct igmphdr);
        
        if ((eth_hdr_len + ip_hdr_len + igmp_hdr_len) > size) {
            // Bad packet
            return MULT_ERR;
        }
        
        return this->process_igmp_packet(source_port, packet, size, igmp_hdr);
    }
    
    
    // Datovy packet
    
    if (ip_hdr->daddr == 0) {
        // General query - send to all
        return MULT_BROADCAST;
    }
    
    return send_to_group(ip_hdr->daddr, packet, size);
}


void IgmpTable::print_table()
{
    IgmpRecordTable::iterator it;

    printf("GroupAddr\tIfaces\n");

    pthread_mutex_lock(&(this->mutex));

    for (it=this->records.begin(); it != this->records.end(); it++) {
        IgmpRecord rec = (IgmpRecord) it->second;
        printf("%s*", print_ip(rec.group_id).c_str());
        for (size_t i=0; i < rec.ports.size();) {
            printf("%s", rec.ports[i]->name.c_str());
            i++;
            if (i < rec.ports.size())
                printf(", ");
            else
                printf("\n");
        }
    }

    pthread_mutex_unlock(&(this->mutex));
}

