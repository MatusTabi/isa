#ifndef DHCP_STATS_H
#define DHCP_STATS_H

#include <stdint.h>
#include <arpa/inet.h>

struct options {

};

struct dhcp_header {
    uint8_t Op;
    uint8_t HType;
    uint8_t HLen;
    uint8_t Hops;
    uint32_t XID;
    uint16_t Secs;
    uint16_t Flags;
    struct in_addr CIAddr;
    struct in_addr YIAddr;
    struct in_addr SIAddr;
    struct in_addr GIAddr;
    uint8_t CHAddr[16];
    uint8_t SName[64];
    uint8_t File[128];

};

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

dhcp_header* create_dhcp_struct(const unsigned char *packet);

#endif