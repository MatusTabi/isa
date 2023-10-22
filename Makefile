CC = g++
CFLAGS = -Wall -Wextra -Werror
LDLIBS = -lpcap

dhcp-stats: dhcp-stats.cpp
	$(CC) $(CFLAGS) -o dhcp-stats dhcp-stats.cpp $(LDLIBS)

clean: 
	rm dhcp-stats