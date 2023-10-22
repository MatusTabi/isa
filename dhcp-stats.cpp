#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <iomanip>

struct dhcp_header {
    uint8_t opcode;
};

void packetHandler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void) args;
    (void) header;
    struct ethhdr *ether_header = (struct ethhdr *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + (ip_header->ip_hl << 2));

    unsigned char *udp_payload = (unsigned char *)udp_header + sizeof(struct udphdr);
    struct dhcp_header *dhcp = (struct dhcp_header *)udp_payload;

    // std::cout << dhcp->opcode << std::endl;

    // int udp_length = ntohs(udp_header->len) - sizeof(struct udphdr);

    if (dhcp->opcode == 0x01) {
        std::cout << "Packet is 0x01";
    }
    else if (dhcp->opcode == 0x02) {
        std::cout << "Packet is 0x02";
    }
    else {
        std::cout << "Something else";
    }

    // int udp_payload_length = udp_length - sizeof(struct udphdr);

    // for (int i = 0; i < udp_length; i++) {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(udp_payload[i]) << " "; // Print the byte in hexadecimal

    //     // Print an ASCII representation of the character (replace unprintable characters with '.')
    //     if (std::isprint(udp_payload[i])) {
    //         std::cout << " '" << udp_payload[i] << "'";
    //     } else { 
    //         std::cout << " '.'";
    //     }

    //     if ((i + 1) % 16 == 0) {
    //         std::cout << std::endl; // Print a new line every 16 bytes for readability
    //     }
    // }

    (void) ether_header;
    // (void) udp_header;
    // std::cout << inet_ntoa(ip_header->ip_src);
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

    std::string filter_string = "udp port 67 or udp port 68";
    const char *filter = filter_string.c_str();
    if (pcap_compile(handle, &bf, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error at pcap_compile!\n");
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &bf) == -1) {
        fprintf(stderr, "Error at pcap_setfilter!\n");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, packetHandler, NULL);

    
    return 0;
}