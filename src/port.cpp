#include <assert.h>
#include "port.h"

using namespace std;


Port::Port()
{
    pthread_mutex_init(&(this->mutex), NULL);
    this->name = "";
    this->send_b = 0;
    this->send_f = 0;
    this->recv_b = 0;
    this->recv_f = 0;
    this->descriptor = NULL;
}


Port::Port(const char *name)
{
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */

    pthread_mutex_init(&(this->mutex), NULL);
    this->name = name;
    this->send_b = 0;
    this->send_f = 0;
    this->recv_b = 0;
    this->recv_f = 0;
    this->descriptor = pcap_open_live(name, BUFSIZ, 1, 50, errbuf);
    if (this->descriptor == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", name, errbuf);
		return;
	}
	if (pcap_setdirection(this->descriptor, PCAP_D_IN)) {
    	fprintf(stderr, "Couldn't set right direction on %s descriptor\n", name);
		return;
	}
}


Port::~Port()
{
    pthread_mutex_destroy(&(this->mutex));
    if (this->descriptor) {
        pcap_close(this->descriptor);
    }
}


int Port::send(const void *buf, size_t size)
{
    int ret;
    assert(this->descriptor);

    pthread_mutex_lock(&(this->mutex));
    ret = pcap_inject(this->descriptor, buf, size);
    if (ret < 0) {
        return ret;
    }

    this->send_b += size;
    this->send_f++;
    pthread_mutex_unlock(&(this->mutex));
    return ret;
}


void Port::print_stat()
{
    printf("%s\t%d\t%d\t%d\t%d\n", this->name.c_str(), this->send_b, this->send_f, this->recv_b, this->recv_f);
}


void Port::stop()
{
    assert(this->descriptor);
    pcap_breakloop(this->descriptor);
}


bool Port::operator==(const Port &second) const
{
    return (second.descriptor == this->descriptor);
}


bool Port::operator!=(const Port &second) const
{
    return !(*this == second);
}

