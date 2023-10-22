#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <iomanip>
#include "dhcp-stats.h"

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void) args;
    (void) header;
    struct dhcp_header *dhcp_packet = create_dhcp_struct(packet);
}

dhcp_header* create_dhcp_struct(const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + (ip_header->ip_hl << 2));

    unsigned char *udp_payload = (unsigned char *)udp_header + sizeof(struct udphdr);
    // struct dhcp_header *dhcp = (struct dhcp_header *)udp_payload;
    return (struct dhcp_header *)udp_payload;
}

int main(int argc, char **argv) {
    (void) argc;
    char *device, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program bf;

    device = argv[1];

    std::cout << device << std::endl;

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open the device!\n");
        exit(EXIT_FAILURE);
    }

    std::string filter_string = "udp and port 67 or port 68";
    const char *filter = filter_string.c_str();
    if (pcap_compile(handle, &bf, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error at pcap_compile!\n");
        exit(EXIT_FAILURE);
    }

    
    if (pcap_setfilter(handle, &bf) == -1) {
        fprintf(stderr, "Error at pcap_setfilter!\n");
        exit(EXIT_FAILURE);
    }

    std::cout << "HERE I AM" << std::endl;

    pcap_loop(handle, -1, packet_handler, NULL);

    
    return 0;
}