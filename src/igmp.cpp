#include <pcap.h>
#include <cstdio>
#include <assert.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/igmp.h>
#include <arpa/inet.h>
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
        IgmpRecord *irc = new IgmpRecord;
        irc->group_id = group_id;
        irc->igmp_querier = port;
        
        this->records[group_id] = irc;
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
        pthread_mutex_unlock(&(this->mutex));
        return;
    }
    
    // Add multicast group member or refres if exists
    
    bool found = false;
    IgmpRecord *irc = (IgmpRecord *) it->second;
    for (unsigned int i=0; i < irc->ports.size(); i++) {
        if (irc->ports[i] == port) {
            irc->last_used_vector[i] = time(NULL);
            found = true;
            break;
        }
    }
    
    if (!found) {
        irc->ports.push_back(port);
        irc->last_used_vector.push_back(time(NULL));
    }

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
        pthread_mutex_unlock(&(this->mutex));
        return;
    }

	// Remove group member
    IgmpRecord *irc = (IgmpRecord *) it->second;
    for (unsigned int i=0; i < irc->ports.size(); i++) {
        if (irc->ports[i] == port) {
            irc->ports.erase(irc->ports.begin() + i);
            irc->last_used_vector.erase(irc->last_used_vector.begin() + i);
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
        pthread_mutex_unlock(&(this->mutex));
        return MULT_OK;
    }

	// Send packet to goup members
    IgmpRecord *irc = (IgmpRecord *) it->second;
    for (unsigned int i=0; i < irc->ports.size(); i++) {
        irc->ports[i]->send(packet, size);
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
        pthread_mutex_unlock(&(this->mutex));
        return MULT_OK;
    }

    // Send to querier
    IgmpRecord *irc = (IgmpRecord *) it->second;
    irc->igmp_querier->send(packet, size);

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
    snprintf(buffer, 16, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
    return string(buffer);
}


int IgmpTable::process_igmp_packet(Port *source_port, const u_char *packet, size_t size, struct igmphdr *igmp_hdr)
{
    // Membership query
    if (igmp_hdr->type == IGMP_HOST_MEMBERSHIP_QUERY) {
//        printf("Membership query: %s od %s\n", print_ip(ntohl(igmp_hdr->group)).c_str(), source_port->name.c_str());
        if (ntohl(igmp_hdr->group) != 0) {
            // Group specific query
            add_group(ntohl(igmp_hdr->group), source_port);
            return MULT_BROADCAST;
        } else {
            // General query
            return send_to_group(ntohl(igmp_hdr->group), packet, size);
        }
    }

    // Membership report
    if (igmp_hdr->type == IGMPV2_HOST_MEMBERSHIP_REPORT || igmp_hdr->type == IGMPV3_HOST_MEMBERSHIP_REPORT) {
//        printf("Membership report: %s od %s\n", print_ip(ntohl(igmp_hdr->group)).c_str(), source_port->name.c_str());
        add_group_member(ntohl(igmp_hdr->group), source_port);
        return send_to_querier(ntohl(igmp_hdr->group), packet, size);
    }

    // Membership leave group
    if (igmp_hdr->type == IGMP_HOST_LEAVE_MESSAGE) {
//        printf("Membership leave group: %s od %s\n", print_ip(ntohl(igmp_hdr->group)).c_str(), source_port->name.c_str());
        remove_group_member(ntohl(igmp_hdr->group), source_port);
        return send_to_querier(ntohl(igmp_hdr->group), packet, size);
    }
    
//    printf("Neznamy typ (0x%02x) IGMP packetu\n", igmp_hdr->type);
    
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

    if (ntohs(eth_hdr->h_proto) != ETH_P_IP) {
		// Multicast packet but not a IP protocol
        return MULT_BROADCAST;
    }

    ip_hdr    = (struct iphdr *)  (packet + sizeof(struct ethhdr));

    if ((eth_hdr_len + sizeof(struct iphdr)) > size) {
        // Bad packet
        return MULT_ERR;
    }

    ip_hdr_len = (ip_hdr->ihl * 4);

    if ((eth_hdr_len + ip_hdr_len) > size) {
        // Bad packet
        return MULT_ERR;
    }

    // IGMP packet

    if (ip_hdr->protocol == IGMP_PROTOCOL) {
        igmp_hdr  = (struct igmphdr *) (packet + eth_hdr_len + ip_hdr_len);
        igmp_hdr_len = sizeof(struct igmphdr);
        
        if ((eth_hdr_len + ip_hdr_len + igmp_hdr_len) > size) {
            // Bad packet
            return MULT_ERR;
        }
        
        return this->process_igmp_packet(source_port, packet, size, igmp_hdr);
    }
    
    
    // Datovy packet
    
    if (ntohl(ip_hdr->daddr) == 0) {
        // General query - send to all
        return MULT_BROADCAST;
    }
    
    return send_to_group(ntohl(ip_hdr->daddr), packet, size);
}


void IgmpTable::print_table()
{
    IgmpRecordTable::iterator it;
    printf("GroupAddr\tIfaces\n");

    pthread_mutex_lock(&(this->mutex));

    for (it=this->records.begin(); it != this->records.end(); it++) {
        IgmpRecord *irc = (IgmpRecord *) it->second;
        printf("%s\t*%s", print_ip(irc->group_id).c_str(), irc->igmp_querier->name.c_str());
        for (size_t i=0; i < irc->ports.size();) {
            //printf(", %s", irc->ports[i]->name.c_str());
            printf(", %s(%ld)", irc->ports[i]->name.c_str(), (time(NULL) - irc->last_used_vector[i]));
            i++;
        }
        printf("\n");
    }

    pthread_mutex_unlock(&(this->mutex));
}

