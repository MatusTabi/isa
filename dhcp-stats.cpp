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
#include <curses.h>
#include <unistd.h>

#include "dhcp-stats.h"

#define ETHER_HEADER_OFFSET sizeof(struct ethhdr)
#define UDP_HEADER_OFFSET sizeof(struct udphdr)

#define DHCP_OPTIONS_OFFSET 236
#define DHCP_OPTIONS_MAGIC_COOKIE_OFFSET 4

#define DHCP_OPTIONS_PAD 0
#define DHCP_OPTIONS_END 255

std::tuple<int, std::string> get_command_arguments(int argc, char **argv) {
    int c;
    while ((c = getopt(argc, argv, ":i:r:")) != -1) {
        switch (c) {
            case 'i': 
                return std::tuple<int, std::string>{0x01, (std::string)optarg};
            case 'r':
                return std::tuple<int, std::string>{0x02, (std::string)optarg};
            case '?':
                fprintf(stderr, "Got unknown option.\n");
                exit(EXIT_FAILURE);
            default:
                if (optopt == 'i') {
                    fprintf(stderr, "-i option requires an argument.\n");
                }
                else if (optopt == 'r') {
                    fprintf(stderr, "-r option requires an argument.\n");
                }
                else {
                    fprintf(stderr, "Got unknown option.\n");
                }
                exit(EXIT_FAILURE);
        }
    }
    return std::tuple<int, std::string>{0x00, NULL};
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void) args;
    struct ip *ip_header = (struct ip *)(packet + ETHER_HEADER_OFFSET);
    size_t payload_offset = get_payload_offset(ip_header);
    struct dhcp_header *dhcp = (struct dhcp_header *)packet + payload_offset;
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
    while (dhcp_options < packet + header->len) {
        size_t length = 0;
        if (dhcp_options[0] == DHCP_OPTIONS_END) {
            std::cout << "End of options." << std::endl << std::endl;
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

int main(int argc, char **argv) {
    std::tuple<int, std::string> file_device_tuple = get_command_arguments(argc, argv);
    // std::string device;
    // std::string file;
    char errbuf[PCAP_ERRBUF_SIZE];
    // char *file;
    (void) errbuf;
    // pcap_t *handle;
    // struct bpf_program bf;

    // initscr();                          // initialization of ncruses window
    // mvprintw(10, 20, "Tu som");         // move cursor and print 
    // refresh();                          // refresh after every move or print to flush memory
    // mvprintw(12, 10, "Teraz som tu");
    // getch();                            // waiting for user input

    if (argc < 2) {
        fprintf(stderr, "Enter at least some arguments please..\n");
        return EXIT_FAILURE;
    }
    

    // device = argv[1];

    // handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    // handle = pcap_open_offline(device, errbuf);
    // if (handle == NULL) {
    //     fprintf(stderr, "Couldn't open the device!\n");
    //     exit(EXIT_FAILURE);
    // }

    // std::string filter_string = "udp and port 67 or port 68";
    // const char *filter = filter_string.c_str();
    // if (pcap_compile(handle, &bf, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    //     fprintf(stderr, "Error at pcap_compile!\n");
    //     exit(EXIT_FAILURE);
    // }

    
    // if (pcap_setfilter(handle, &bf) == -1) {
    //     fprintf(stderr, "Error at pcap_setfilter!\n");
    //     exit(EXIT_FAILURE);
    // }

    // pcap_loop(handle, -1, packet_handler, NULL);
    
    endwin();

    return 0;
}
