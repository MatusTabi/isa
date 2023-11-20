/**
 * Project: Monitoring of DHCP communication
 * Author: Matúš Tábi
 * Login: xtabim01
*/

#include <iostream>
#include <pcap/pcap.h>
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
#include <math.h>
#include <csignal>
#include <syslog.h>

#include "dhcp-stats.h"

#define ETHER_HEADER_OFFSET sizeof(struct ethhdr)
#define UDP_HEADER_OFFSET sizeof(struct udphdr)

#define DHCP_OPTIONS_OFFSET 236
#define DHCP_OPTIONS_MAGIC_COOKIE_OFFSET 4

#define DHCP_OPTIONS_PAD 0
#define DHCP_OPTIONS_END 255
#define DHCP_MESSAGE_TYPE 53
#define DHCP_OPTIONS_OVERLOAD 52

#define SNAME_SIZE 64
#define FILE_SIZE 128

pcap_t *handle;
std::vector<struct ip_prefixes> ip_addresses;
std::vector<struct in_addr> used_ips;

void print_usage() {
    std::cerr << 
        "USAGE:\n\n"
        "./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n\n"

        "-r <filename> - statistics will be created from pcap files\n"
        "-i <interface> - interface on which the program can listen\n\n"

        "<ip-prefix> - the network range for which statistics will be created" << std::endl;
}

void signal_handler(int) {
    endwin();
    pcap_close(handle);
    closelog();
    print_exceeded();
    exit(EXIT_SUCCESS);
}

void get_prefixes(int argc, char **argv) {
    int id = 0;
    for (int i = 0; i < argc; ++i) {
        struct sockaddr_in sa;
        std::string ip = (std::string)argv[i];
        std::string correct_ip = ip.substr(0, ip.find('/'));
        if (inet_pton(AF_INET, correct_ip.c_str(), &(sa.sin_addr))) {
            int prefix = atoi((ip.substr(ip.find('/') + 1, ip.length()).c_str()));
            if (prefix < 31) {
                id++;
                struct ip_prefixes temp = {
                    .id = id,
                    .prefix = argv[i],
                    .max_hosts = count_max_hosts(argv[i]),
                    .allocated_addresses = 0,
                    .utilization = 0,
                    .exceeded = false
                };
                ip_addresses.push_back(temp);
            }
        }  
    }
}

uint64_t count_max_hosts(std::string ip_prefix) {
    int prefix = std::stoi(ip_prefix.substr(ip_prefix.find('/') + 1, ip_prefix.length()));
    return (uint64_t)(pow(2, 32 - prefix) - 2);
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
        mvprintw(ip_addresses[i].id, 0, (ip_addresses[i].prefix.c_str()));
        mvprintw(ip_addresses[i].id, 20, "%ld", ip_addresses[i].max_hosts);
        mvprintw(ip_addresses[i].id, 35, "%ld", ip_addresses[i].allocated_addresses);
        mvprintw(ip_addresses[i].id, 55, "%.2f%%", ip_addresses[i].utilization);
        refresh();
    }
}

std::tuple<int, std::string> get_command_arguments(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        closelog();
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
                print_usage();
                closelog();
                exit(EXIT_FAILURE);
            default:
                print_usage();
                closelog();
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
        print_usage();
        closelog();
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
    struct dhcp_header *dhcp = (struct dhcp_header *)(packet + payload_offset);
    const unsigned char *dhcp_options = get_payload_options(payload_offset, packet);
    std::vector<struct dhcp_options> options;
    set_options(dhcp_options, packet, header, &options, dhcp);
    ack_handle(dhcp, &options);
}

void ack_handle(struct dhcp_header *dhcp, std::vector<struct dhcp_options> *options) {
    for (size_t i = 0; i < options->size(); ++i) {   
        if ((*options)[i].code == DHCP_MESSAGE_TYPE && (*options)[i].data[0] == 0x05) {
            assign_address_to_prefix(dhcp->YIAddr);
        }
    }
}

bool is_ip_assigned(struct in_addr ip_address) {
    for (size_t i = 0; i < used_ips.size(); ++i) {
        if (used_ips[i].s_addr == ip_address.s_addr) {
            return true;
        }
    }
    return false;
}

void assign_address_to_prefix(struct in_addr ip_address) {
    if (is_ip_assigned(ip_address)) {
        return;
    }        
    used_ips.push_back(ip_address);
    for (size_t i = 0; i < ip_addresses.size(); ++i) {
        std::string ip = ip_addresses[i].prefix;
        struct in_addr range, netmask;
        if (inet_pton(AF_INET, ip.substr(0, ip.find('/')).c_str(), &range) <= 0) {
            std::cerr << "Invalid ip prefix!" << std::endl;
            pcap_close(handle);
            closelog();
            exit(EXIT_FAILURE);
        }
        int prefix = std::stoi(ip.substr(ip.find('/') + 1));
        uint32_t mask = (0xFFFFFFFFu << (32 - prefix));
        mask = htonl(mask);
        memcpy(&netmask, &mask, sizeof(netmask));
        if ((ip_address.s_addr & netmask.s_addr) == (range.s_addr & netmask.s_addr)) {
            if (ip_address.s_addr != range.s_addr && ip_address.s_addr != (range.s_addr | ~netmask.s_addr)) {
                ip_addresses[i].allocated_addresses++;
                ip_addresses[i].utilization = (float)((float)ip_addresses[i].allocated_addresses
                                                * 100.0f / (float)ip_addresses[i].max_hosts);
                log_message(&ip_addresses[i], ip_addresses.size());
                mvprintw(ip_addresses[i].id, 35, "%ld", ip_addresses[i].allocated_addresses);
                mvprintw(ip_addresses[i].id, 55, "%.2f%%", ip_addresses[i].utilization);
                refresh();
            }
        }
    }
}

void log_message(struct ip_prefixes *ip_stats, size_t size) {
    if (ip_stats->utilization >= 50.0f && !ip_stats->exceeded) {
        syslog(LOG_WARNING, "prefix %s exceeded 50%% of allocations.\n", ip_stats->prefix.c_str());
        mvprintw(size + ip_stats->id + 2, 0, "prefix %s exceeded 50%% of allocations.\n", ip_stats->prefix.c_str());
        ip_stats->exceeded = true;
    }
}

size_t get_payload_offset(struct ip *ip_header) {
    return ETHER_HEADER_OFFSET + ip_header->ip_hl * 4 + UDP_HEADER_OFFSET;
}

const unsigned char *get_payload_options(size_t payload_offset, const unsigned char *packet) {
    return packet + payload_offset + DHCP_OPTIONS_OFFSET + DHCP_OPTIONS_MAGIC_COOKIE_OFFSET;
}

void set_options(const unsigned char *dhcp_options, const unsigned char *packet, 
                    const struct pcap_pkthdr *header, std::vector<struct dhcp_options> *options,
                    struct dhcp_header *dhcp) { 
    bool overload = false;     
    char overload_code;
    while (dhcp_options < packet + header->len) {
        size_t length = 0;
        if (dhcp_options[0] == DHCP_OPTIONS_END) {
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
            overload = options_overload(code, overload, &overload_code, temp.data);
            options->push_back(temp);
            dhcp_options += 2 + length;
        }
        else {
            dhcp_options += 1;
        }
    }
    overload_options(overload, overload_code, options, dhcp);
}

bool options_overload(size_t code, bool overload, char *overload_code,  std::vector<char> data) {
    if (overload) {
        return true;
    }
    if (code == DHCP_OPTIONS_OVERLOAD) {
        *overload_code = data[0];
        return true;
    }
    return false;
}

void overload_options(bool overload, char overload_code, std::vector<struct dhcp_options> *options,
                    struct dhcp_header *dhcp) {
    if (overload) {
        switch (overload_code) {
            case 0x01:
                set_overload_options(options, dhcp->File, FILE_SIZE);
                break;
            case 0x02:
                set_overload_options(options, dhcp->SName, SNAME_SIZE);
                break;
            case 0x03:
                set_overload_options(options, dhcp->SName, SNAME_SIZE);
                set_overload_options(options, dhcp->File, FILE_SIZE);
                break;
        }
    }
}

void set_overload_options(std::vector<struct dhcp_options> *options, uint8_t *place, int size) {
    int i = 0;
    while (i < size) {
        if (place[i] == DHCP_OPTIONS_END) {
            break;
        }
        if (place[i] != DHCP_OPTIONS_PAD) {
            size_t code = place[i];
            size_t length = place[i + 1];
            struct dhcp_options temp = {
                .code = code,
                .len = length,
                .data = std::vector<char>(place + i + 2, place + i + 2 + length)
            };
            options->push_back(temp);
            i += 2 + length;
        }
        else {
            i += 1;
        }
    }
}

void print_exceeded() {
    for (size_t i = 0; i < ip_addresses.size(); ++i) {
        if (ip_addresses[i].exceeded) {
            std::cout << "prefix " << ip_addresses[i].prefix << " exceeded 50% of allocations." << std::endl;
        }
    }
}

int main(int argc, char **argv) {
    openlog(NULL, LOG_PID | LOG_CONS, LOG_USER);
    std::tuple<int, std::string> file_device_tuple = get_command_arguments(argc, argv);
    initscr();        
    print_app_header();
    get_prefixes(argc, argv);
    print_info();
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = get_handle(file_device_tuple, errbuf);
    if (handle == NULL) {
        std::cerr << "Could not create packet capture descriptor\n";
        std::cerr << errbuf << std::endl;
        closelog();
        exit(EXIT_FAILURE);
    }
    struct bpf_program bf;
    std::string filter_string = "udp and port 67 or port 68";
    const char *filter = filter_string.c_str();
    if (pcap_compile(handle, &bf, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Could not compile specified filter" << std::endl;
        pcap_close(handle);
        closelog();
        endwin();
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &bf) == -1) {
        std::cerr << "Error when setting filter" << std::endl;
        pcap_close(handle);
        closelog();
        endwin();
        exit(EXIT_FAILURE);
    }
    noecho();
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_freecode(&bf);
    while (getch() != KEY_RESIZE);
    endwin();
    pcap_close(handle);
    closelog();
    return 0;
}
