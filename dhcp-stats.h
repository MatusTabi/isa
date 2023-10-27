#ifndef DHCP_STATS_H
#define DHCP_STATS_H

#include <stdint.h>
#include <arpa/inet.h>
#include <vector>

struct ip_prefixes {
    std::vector<std::string> *prefixes;
};

struct dhcp_options {
    size_t code;
    size_t len;
    std::vector<char> data;
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
    std::vector<struct dhcp_options> *options;
};

void get_prefixes(int argc, char **argv);

std::tuple<int, std::string> get_command_arguments(int argc, char **argv);

pcap_t *get_handle(std::tuple<int, std::string> file_device_tuple, char *errbuf);

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

size_t get_payload_offset(struct ip *ip_header);

size_t get_payload_length(const struct pcap_pkthdr *header, size_t payload_offset);

const unsigned char *get_payload_options(size_t payload_offset, const unsigned char *packet);

void set_options(const unsigned char *dhcp_options, const unsigned char *packet, 
                    const struct pcap_pkthdr *header, struct dhcp_header *dhcp);

void delete_dhcp(struct dhcp_header *dhcp);

#endif