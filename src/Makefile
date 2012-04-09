CC=g++

CFLAGS=-Wall -Wextra -g -O2 -pthread


main:
	$(CC) $(CFLAGS) main.cpp port.cpp port_thread.cpp camtable.cpp -l pcap -o switch

clean:
	rm -f switch

