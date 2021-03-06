#include <pcap.h>
#include <linux/if_ether.h>
#include "port_thread.h"
#include "camtable.h"
#include "igmp.h"


void handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    PortThreadData *tdata = (PortThreadData *) args;
    tdata->port->recv_b += header->len;
    tdata->port->recv_f++;

    struct ethhdr *frame_hdr;
    frame_hdr = (struct ethhdr *) packet;
    MacAddress src_mac(frame_hdr->h_source);
    MacAddress dest_mac(frame_hdr->h_dest);
    
    // Update CAM table (update age of record or add if new) by source address on the port
    tdata->camtable->update(src_mac, tdata->port);
    
    if (dest_mac.is_broadcast()) {
        // Broadcast - Send out via all ports except incoming
        tdata->camtable->broadcast(tdata->port, packet, header->caplen);

    } else if (dest_mac.is_multicast()) {
        // Multicast - Send out via right port
        if (tdata->igmptable->process_multicast_packet(tdata->port, packet, header->caplen) == MULT_BROADCAST) {
            // Send packet via all interfaces except the incoming interface
            tdata->camtable->broadcast(tdata->port, packet, header->caplen);
        }
        
    } else {
        // Unicast - Send packet out via right port
        CamRecord *rec;
        if ((rec = tdata->camtable->get_record(dest_mac)) != NULL) {
			// Send to target host
            if (rec->port != tdata->port) {
				//But only if destination and source MAC are different
                rec->port->send(packet, header->caplen);
            }
        } else {
			// Unknown destination MAC
            tdata->camtable->broadcast(tdata->port, packet, header->caplen);
        }
    }
}


void *port_thread(void *arg)
{
    int ret;
    PortThreadData *tdata = (PortThreadData *) arg;

    ret = pcap_loop(tdata->port->descriptor, -1, handler, (u_char *) tdata);
    if (ret == -1) {
        fprintf(stderr, "pcap_loop() error");
    }

    return NULL;
}

