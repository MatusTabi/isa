# ISA - Monitoring of DHCP communication

## Basic information
Author: Matúš Tábi
Login: xtabim01
Created: 20/11/2023

## Brief description

This project was created as a console application, which will be displaying IP prefix utilization statistics. When the prefix is filled with more that 50%, the application informs the administrator on the standard output and by logging through the syslog server. Program can listen on a given interface and will be displaying utilization statistics or can read communication from a pcap file. Each of these options must be specified in command line arguments, see *usage* below. Application also handles option overloading (option 52 in options field).

## Usage

./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]

-r <filename> : specifies file from which will be IP prefix utilization statistics created.
-i <interface> : specifies an interface on which will program listen and display IP prefix utilization statistics.
[<ip-prefix>] : the network range for which statistics will be created. Unlimited number of IP prefixes can be      specified. IP prefix must be in correct form, e.g. 192.168.1.0/24 .

## List of uploaded files

Makefile
README.md
dhcp-stats.1
dhcp-stats.cpp
dhcp-stats.h
manual.pdf
