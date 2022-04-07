#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

#include <string>

struct arguments {
    std::string interface = "all";
    int port = -1;
    bool tcp = false;
    bool udp = false;
    bool icmp = false;
    bool arp = false;
    int packet_number = 1;
};

const char *args_list[9] = {"-i", "-p", "-t", "--tcp", "-u", \
                      "--udp", "--icmp", "--arp", "-n"};

void list_all_interfaces();
#endif