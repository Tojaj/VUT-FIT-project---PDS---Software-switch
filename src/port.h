#ifndef __SWITCH_PORT_H__
#define __SWITCH_PORT_H__

#include <iostream>
#include <pcap.h>


class Port {
    private:
        pthread_mutex_t mutex;

    public:
        Port();
        Port(const char *name);
        ~Port();
        std::string name;
        size_t send_b;
        size_t send_f;
        size_t recv_b;
        size_t recv_f;
        pcap_t *descriptor;

        int send(const void *buf, size_t size); // lock + refresh values + send + unlock
        void print_stat();
        void stop();
        bool operator==(const Port &) const;
        bool operator!=(const Port &) const;
};

#endif /* __SWITCH_PORT_H__ */

