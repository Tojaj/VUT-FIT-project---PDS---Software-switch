#include <new>
#include <vector>
#include <pthread.h>
#include <pcap.h>
#include <string.h>
#include "port.h"
#include "port_thread.h"

using namespace std;


int main(int argc, char **argv) {
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
   
    // Find all suitable devices

    pcap_if_t *all_devices, *next;
    if (pcap_findalldevs(&all_devices, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs() error: %s\n", errbuf);
        return 1;
    }


    // Create port object and thread for every interface

    CamTable camtable;
    vector<pthread_t*> threads;
    vector<Port*> ports;
    vector<PortThreadData*> thread_data_table;
    pthread_attr_t attr;

    // Prepare thread attributes
    if ((ret = pthread_attr_init(&attr)) != 0) {
        fprintf(stderr, "pthread_attr_init() err %d\n", ret);
        return 1;
    }
    if ((ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE)) != 0) {
        fprintf(stderr, "pthread_attr_setdetachstate() error: %d\n", ret);
        return 1;
    }

    next = all_devices;
    while (next) {
        if (strncmp(next->name, "eth", 3)) {
            // Skip non eth devices (any, lo, usbmon[0-9], ...)
            next = next->next;
            continue;
        }
        printf("Found device: %s\n", next->name);
        Port *port = new Port(next->name);
        PortThreadData *tdata = new PortThreadData;
        ports.push_back(port);
        thread_data_table.push_back(tdata);
        
        tdata->port = port;
        tdata->camtable = &camtable;
        
        // Create new thread
        pthread_t *thread = new pthread_t;
        threads.push_back(thread);

        ret = pthread_create(thread, &attr, port_thread, (void *) tdata);
        if (ret) {
            fprintf(stderr, "pthread_create() error: %d\n", ret);
            return 1;
        }
        
        next = next->next;
    }

    printf("HERE\n");

    // Switch command line interface
    // TODO
    puts("Switch is running");
    while (getc(stdin) != 'x') {
        camtable.print_table();
        //camtable.purge();
        //camtable.print_table();
        //printf("#################\n");
    }
    

    // Clean up

    // Tell all threads to stop
    for (unsigned int i=0; i < ports.size(); i++) {
        pcap_breakloop(ports[i]->descriptor);
    }

    // Join all threads
    while (!threads.empty()) {
        void *result;
        if ((ret = pthread_join(*(threads.back()), &result)) != 0) {
            fprintf(stderr, "pthread_join() err %d\n", ret);
        }
        threads.pop_back();
    }
    
    pthread_attr_destroy(&attr);

    while (!ports.empty()) {
        delete ports.back();
        ports.pop_back();
    }

    while (!thread_data_table.empty()) {
        delete thread_data_table.back();
        thread_data_table.pop_back();
    }


    return 0;
}
