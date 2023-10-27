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
#include <regex>
#include <math.h>

#include "dhcp-stats.h"

#define ETHER_HEADER_OFFSET sizeof(struct ethhdr)
#define UDP_HEADER_OFFSET sizeof(struct udphdr)

#define DHCP_OPTIONS_OFFSET 236
#define DHCP_OPTIONS_MAGIC_COOKIE_OFFSET 4

#define DHCP_OPTIONS_PAD 0
#define DHCP_OPTIONS_END 255

std::vector<struct ip_prefixes> ip_addresses;

void get_prefixes(int argc, char **argv) {
    for (int i = 0; i < argc; ++i) {
        if (std::regex_match(argv[i], std::regex("\\b\\d{1,3}(?:\\.\\d{1,3}){3}/\\d{1,2}\\b"))) {
            struct ip_prefixes temp = {
                .prefix = argv[i],
                .max_hosts = count_max_hosts(argv[i]),
                .allocated_addresses = 0,
                .utilization = 0
            };
            ip_addresses.push_back(temp);
        }  
    }
}

int count_max_hosts(std::string ip_prefix) {
    size_t size = ip_prefix.size();
    int prefix = std::stoi(ip_prefix.substr(size - 2, 2));
    return (int)(pow(2, 32 - prefix) - 2);
}

void print_app_header() {
    printw("IP-Prefix");
    mvprintw(0, 20, "Max-hosts");
    mvprintw(0, 35, "Allocated addresses");
    mvprintw(0, 55, "Utilization");
    refresh();
}

void print_info() {
    for (size_t i = 0; i < ip_addresses.size(); ++i) {
        mvprintw(i + 1, 0, (ip_addresses[i].prefix.c_str()));
        mvprintw(i + 1, 20, (std::to_string(ip_addresses[i].max_hosts).c_str()));
        refresh();
    }
}

std::tuple<int, std::string> get_command_arguments(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Enter at least some arguments please..\n");
        exit(EXIT_FAILURE);
    }
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

pcap_t *get_handle(std::tuple<int, std::string> file_device_tuple, char *errbuf) {
    if (std::get<0>(file_device_tuple) == 0x01) {
        return pcap_open_live(std::get<1>(file_device_tuple).c_str(), BUFSIZ, 1, 1000, errbuf);
    }
    else if (std::get<0>(file_device_tuple) == 0x02) {
        return pcap_open_offline(std::get<1>(file_device_tuple).c_str(), errbuf);
    }
    else if (std::get<0>(file_device_tuple) == 0x00) {
        fprintf(stderr, "No arguments were specified.\n");
        exit(EXIT_FAILURE);
    }
    else {
        return NULL;
    }
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void) args;
    struct ip *ip_header = (struct ip *)(packet + ETHER_HEADER_OFFSET);
    size_t payload_offset = get_payload_offset(ip_header);
    struct dhcp_header *dhcp = new dhcp_header;
    memcpy(dhcp, packet + payload_offset, sizeof(dhcp_header));
    const unsigned char *dhcp_options = get_payload_options(payload_offset, packet);
    set_options(dhcp_options, packet, header, dhcp);
    delete_dhcp(dhcp);
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
    dhcp->options = new std::vector<struct dhcp_options>;                   
    while (dhcp_options < packet + header->len) {
        size_t length = 0;
        if (dhcp_options[0] == DHCP_OPTIONS_END) {
            // std::cout << "End of options." << std::endl << std::endl;
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
            dhcp->options->push_back(temp);
        }
        dhcp_options += 2 + length;
    }
}

void delete_dhcp(struct dhcp_header *dhcp) {
    delete dhcp->options;
    delete dhcp;
}

int main(int argc, char **argv) {
    initscr();                          // initialization of ncruses window
    print_app_header();
    get_prefixes(argc, argv);
    print_info();
    std::tuple<int, std::string> file_device_tuple = get_command_arguments(argc, argv);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = get_handle(file_device_tuple, errbuf);
    struct bpf_program bf;                          // waiting for user input
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

    pcap_loop(handle, -1, packet_handler, NULL);


    getch();
    endwin();
    return 0;
}
