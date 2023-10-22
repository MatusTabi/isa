CC = g++
CFLAGS = -Wall -Wextra -Werror
LDLIBS = -lpcap

all: dhcp-stats

dhcp-stats: dhcp-stats.cpp dhcp-stats.h
	$(CC) $(CFLAGS) -o dhcp-stats dhcp-stats.cpp $(LDLIBS)

clean: 
	rm dhcp-stats