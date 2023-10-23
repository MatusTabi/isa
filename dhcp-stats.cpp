#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <iomanip>
#include <cstring>
#include <vector>

#include "dhcp-stats.h"

#define ETHER_HEADER_OFFSET sizeof(struct ethhdr)
#define UDP_HEADER_OFFSET sizeof(struct udphdr)

#define DHCP_OPTIONS_OFFSET 236
#define DHCP_OPTIONS_MAGIC_COOKIE_OFFSET 4

#define DHCP_OPTIONS_PAD 0
#define DHCP_OPTIONS_END 255

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void) args;
    (void) header;

    struct ip *ip_header = (struct ip *)(packet + ETHER_HEADER_OFFSET);

    size_t payload_offset = get_payload_offset(ip_header);

    struct dhcp_header *dhcp = new dhcp_header;

    const unsigned char *dhcp_options = get_payload_options(payload_offset, packet);

    set_options(dhcp_options, packet, header, dhcp);

}

size_t get_payload_offset(struct ip *ip_header) {
    return ETHER_HEADER_OFFSET + ip_header->ip_hl * 4 + UDP_HEADER_OFFSET;
}

size_t get_payload_length(const struct pcap_pkthdr *header, size_t payload_offset) {
    return header->len - payload_offset;
}

const unsigned char *get_payload_options(size_t payload_offset, const unsigned char *packet) {
    return packet + payload_offset + DHCP_OPTIONS_OFFSET + DHCP_OPTIONS_MAGIC_COOKIE_OFFSET;
}

void set_options(const unsigned char *dhcp_options, const unsigned char *packet, 
                        const struct pcap_pkthdr *header, struct dhcp_header *dhcp) {                     
    // size_t no_options = 0;
    while (dhcp_options < packet + header->len) {
        size_t length = 0;
        if (dhcp_options[0] == DHCP_OPTIONS_END) {
            std::cout << "End of options." << std::endl;
            break;
        }
        if (dhcp_options[0] != DHCP_OPTIONS_PAD) {
            size_t code = dhcp_options[0];
            length = dhcp_options[1];
            struct dhcp_options temp = {
                .code = code,
                .len = length,
                .data = std::vector<char>(dhcp_options + 2, dhcp_options + 2 + length)
            };
            dhcp->options.push_back(temp);
        }
        dhcp_options += 2 + length;
    }
}

// dhcp_header *create_dhcp_struct(const unsigned char *packet, uint32_t packet_size) {
    



    // struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + (ip_header->ip_hl << 2));

    // size_t option_length = calculate_options_size(packet, packet_size);
    // (void) option_length;
    // std::cout << option_length << std::endl;

    // for (size_t i = 0; i < option_length; ++i) {
    //     dhcp->options[i].code = 
    // }

    // unsigned char *udp_payload = (unsigned char *)udp_header + sizeof(struct udphdr);
    // return (struct dhcp_header *)udp_payload;
// }

size_t calculate_options_size(const unsigned char *packet, uint32_t packet_size) {
    // dhcp_header *dhcp = new dhcp_header;
    // dhcp_header *dhcp = new dhcp_header;
    // size_t option_total_lenght = 0;
    (void) packet_size;
    const unsigned char *packet_options_ptr = packet + DHCP_OPTIONS_OFFSET + 2;
    std::cout << std::to_string(packet_options_ptr[0]) << std::endl;
    return 0;
    // while (packet_options_ptr < packet + packet_size) {
    //     if (packet_options_ptr[0] == DHCP_OPTIONS_END) {
    //         break;
    //     }
    //     if (packet_options_ptr + 2 < packet + packet_size) {
    //         size_t option_lenght = packet_options_ptr[1];
    //         // size_t code = packet_options_ptr[0];
    //         // std::cout << "Code: " << code << std::endl;
    //         // std::cout << "Length: " << option_lenght << std::endl;
    //         option_total_lenght += 2 + option_lenght;
    //         packet_options_ptr += 2 + option_lenght;
    //     }
    //     else {
    //         std::cout << "Error occured when calculating option size." << std::endl;
    //     }
    // }
    // dhcp->options = new dhcp_options[option_total_lenght];
    // packet_options_ptr = packet + DHCP_OPTIONS_OFFSET;
    // for (size_t i = 0; i < option_total_lenght; ++i) {
    //     dhcp->options[i].code = packet_options_ptr[0];
    //     dhcp->options[i].len = packet_options_ptr[1];
    //     dhcp->options[i].data = new uint8_t[dhcp->options[i].len];
    //     std::memcpy(dhcp->options[i].data, packet_options_ptr + 2, dhcp->options[i].len);
    //     packet_options_ptr += 2 + dhcp->options[i].len;
    // }
    // for (size_t i = 0; i < option_total_lenght; ++i) {
    //     if (dhcp->options[i].code != 0) {
    //         std::cout << "Code: " << std::to_string(dhcp->options[i].code) << std::endl;
    //         std::cout << "Length: " << std::to_string(dhcp->options[i].len) << std::endl;
    //         std::cout << "Data: " << dhcp->options[i].data << std::hex << std::endl;
    //     }
    // }   
    // return option_total_lenght;
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