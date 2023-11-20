/**
 * Project: Monitoring of DHCP communication
 * Author: Matúš Tábi
 * Login: xtabim01
*/

#ifndef DHCP_STATS_H
#define DHCP_STATS_H

#include <stdint.h>
#include <arpa/inet.h>
#include <vector>

/**
 * @struct ip_prefixes
 * 
 * @brief Struct containing prefix utilization statistics members.
*/
struct ip_prefixes {
    // ID of IP prefix.
    int id;
    // IP prefix.
    std::string prefix;
    // Maximum hosts for prefix.
    uint64_t max_hosts;
    // Number of allocated addresses for prefix.
    uint64_t allocated_addresses;
    // Utilization
    float utilization;
    bool exceeded;
};

/**
 * @struct dhcp_options
 * 
 * @brief Struct containing information for each DHCP option.
*/
struct dhcp_options {
    // Code for option.
    size_t code;
    // Length of data in option.
    size_t len;
    // Data
    std::vector<char> data;
};

/**
 * @struct DHCP packter
 * 
 * @brief Struct containing members of DHCP packet.
*/
struct dhcp_header {
    uint8_t Op;
    uint8_t HType;
    uint8_t HLen;
    uint8_t Hops;
    uint32_t XID;
    uint16_t Secs;
    uint16_t Flags;
    struct in_addr CIAddr;
    // Obtained ip address.
    struct in_addr YIAddr;
    struct in_addr SIAddr;
    struct in_addr GIAddr;
    uint8_t CHAddr[16];
    uint8_t SName[64];
    uint8_t File[128];
};

/**
 * @brief Prints usage of application.
 * 
 * @return void
*/
void print_usage();

/**
 * @brief Function for handling CTRL+C signal.
 * 
 * @param int Signal handle
 * @return void
*/
void signal_handler(int);

/**
 * @brief Process each command line argument and looks for ip prefixes.
 * 
 * Each command line argument is divided by a delimeter '/'. Firstly, ip 
 * address is checked, if it is in a correct form, it will then proceed
 * to ip prefix checking. If any of these conditions are not met, the
 * command line argument will be skipped. Correct ip address will be
 * saved into a vector for later processing.
 * 
 * @param argc Number of command line arguments.    
 * @param argv Command line arguments.   
 * @return void
*/
void get_prefixes(int argc, char **argv);

/**
 * @brief Counting the maximum number of hosts from ip.
 * 
 * The number of max hosts is calculated using the formula:
 * 2^(32 - prefix) - 2 (minus network address and broadcast).
 * 
 * @param ip_prefix Ip address.
 * @return Maximum number of hosts for ip address.
*/
uint64_t count_max_hosts(std::string ip_prefix);

/**
 * @brief Prints network prefix utilization statistics.
 * 
 * @return void
*/
void print_info();

/**
 * @brief Prints table header for prefix utilization statistics with
 * columns: IP-Prefix, Max-Hosts, Allocated addresses and Utilization.
 * 
 * @return void
*/
void print_app_header();

/**
 * @brief Getting and checking command line arguments.
 * 
 * Function will check if entered command line arguments are correct
 * and have correct corresponding argument. Function returns 0x01
 * identifier for capturing packets from interface, 0x02 from file and
 * 0x00 for possible error.
 * 
 * @param argc Number of command line arguments.
 * @param argv Command line arguments.
 * @return Tuple containing integer identifier and option argument.
*/
std::tuple<int, std::string> get_command_arguments(int argc, char **argv);

/**
 * @brief Getting packet capture descriptor depending on whether user
 * wants to read packets from file or from interface.
 * 
 * If identifier is 0x01, function will return packet capture descriptor
 * that will read packets from interface, 0x02 from file.
 * 
 * @param file_device_tuple Tuple containing identifier and argument from
 * get_command_arguments function.
 * @param errbuf Error buffer.
 * 
 * @return Packet capture descriptor or exits on error.
*/
pcap_t *get_handle(std::tuple<int, std::string> file_device_tuple, char *errbuf);

/**
 * @brief Main packet handling function.
 * 
 * Firstly, ip header must be obtained from packet using pre-defined
 * ip struct. Ip header is offsetted by a ETHER_HEADER_OFFSET. Then 
 * function will create dhcp packet containing all informations about
 * this packet, create and set dhcp packet options and handling
 * DHCP Acknowledgment message.
 * 
 * @param args Custom data passed to packet handling function.
 * @param header Packet information header.
 * @param packet Pointer to packet.
 * @return void
*/
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

/**
 * @brief Handling DHCP Acknowledgment message.
 * 
 * Function will go through all options within DHCP packet. If option 53,
 * which is DHCP message type, is present and its value is set to 5 
 * (DHCP Acknowledgement), program will assign obtained ip address.
 * 
 * 
 * @param dhcp Pointer to DHCP packet.
 * @param options DHCP options for DHCP packet.
 * @return void
*/
void ack_handle(struct dhcp_header *dhcp, std::vector<struct dhcp_options> *options);

/**
 * @brief Checking if ip address was already assigned for displaying
 * prefix utilization statistics.
 * 
 * @param ip_address Controlled ip address.
 * @return True if it was assigned, false if it was not.
*/
bool is_ip_assigned(struct in_addr ip_address);

/**
 * @brief Assigning and updating utilization statistics.
 * 
 * Function will first check, if obtained ip address was already
 * assigned in utilization statistics. If it was not, it will assign
 * this ip address to vector of used ip addresses.
 * 
 * For each ip prefix specified in command line, function will copute
 * mask and use it for ip prefix and obtained ip from dhcp. If those two
 * ip addresses are equal and assigned ip is not network address or broadcast, 
 * function will update prefix utilization statistics.
 * 
 * @param ip_address Obtained ip address.
 * @return void
*/
void assign_address_to_prefix(struct in_addr ip_address);

/**
 * @brief Computing udp payload offset.
 * 
 * @param ip_header Ip header.
 * @return UDP payload offset.
*/
size_t get_payload_offset(struct ip *ip_header);

/**
 * @brief Getting DHCP options where all dhcp information are
 * stored.
 * 
 * @param payload_offset UDP payload offset.
 * @param packet Pointer to packet.
 * @return Pointer to DHCP options.
*/
const unsigned char *get_payload_options(size_t payload_offset, const unsigned char *packet);

/**
 * @brief Setting every option to a vector of options.
 * 
 * Function will create struct that consists of code, length and
 * data and store it into a vector of options. This process is inside
 * a cycle, that will last until dhcp_options pointer is equal to 
 * length of packet. At the end of cycle, 2 bytes (one byte for code and
 * one byte for length) and length of data are added to the dhcp_options 
 * pointer.
 * 
 * @param dhcp_options Pointer to DHCP options.
 * @param packet Pointer to packet.
 * @param header Packet information header.
 * @param options Vector of dhcp options.
 * @param dhcp Dhcp packet.
 * @return void
*/
void set_options(const unsigned char *dhcp_options, const unsigned char *packet, 
                    const struct pcap_pkthdr *header, std::vector<struct dhcp_options> *options,
                    struct dhcp_header *dhcp);

/**
 * @brief Checking if DHCP packet contains overload option.
 * 
 * If DHCP packet contains overload option, function will set overload_code
 * to value, where additional options are stored (File or SName).
 * 
 * @param code Code of option.
 * @param overload DHCP packet contains overload option or not.
 * @param overload_code Pointer to value, where options are stored.
 * @param data Data of option.
 * @return True if DHCP overload option is set, else false.
*/
bool options_overload(size_t code, bool overload, char *overload_code, std::vector<char> data);

/**
 * @brief Setting options from SName and File.
 * 
 * Function will store every option into a vector of options depending on
 * value stored in overload_code. If value is set to 0x01, function will
 * set options from File, 0x02 from SName and 0x03 from both.
 * 
 * @param overload DHCP packet contains overload option or not. 
 * @param overload_code Value where options are stored.
 * @param options Pointer to vector of options.
 * @param dhcp DHCP packet containing SName and File.
 * @return void
*/
void overload_options(bool overload, char overload_code, std::vector<struct dhcp_options> *options,
                        struct dhcp_header *dhcp);

/**
 * @brief Setting options from specific DHCP attribute.
 * 
 * Function will set each option from specified DHCP attribute.
 * 
 * @param options Pointer to vector of options.
 * @param place DHCP attribute from which options will be read.
 * @param size Fixed size of DHCP attribute. (SName is 64 bytes large, File is 128 bytes large).
 * @return void
*/
void set_overload_options(std::vector<struct dhcp_options> *options, uint8_t *place, int size);

/**
 * @brief Logging syslog message after exceeding 50% of allocations.
 * 
 * After exceeding 50% of allocations, function will log message into
 * syslog and set boolean value so after assigning more ip addresses
 * to given ip prefix program won't be spamming syslog.
 * 
 * @param ip_stats Ip prefix for which the 50% threshold will be checked.
 * @param size Size of ip prefixes vector.
 * @return void
*/
void log_message(struct ip_prefixes *ip_stats, size_t size);

/**
 * @brief Printing exceeding prefixes to standard output.
 * 
 * @return void
*/
void print_exceeded();

#endif
