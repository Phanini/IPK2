#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

#include <string>
#include <vector>

struct arguments {
    std::string interface = "all";
    int port = -1; // if port == -1, then scan ALL ports 
    bool tcp = false;
    bool udp = false;
    bool icmp = false;
    bool arp = false;
    int packet_number = 1;
};

std::vector<std::string> args_list = {"-i", "-p", "-t", "--tcp", "-u", \
                      "--udp", "--icmp", "--arp", "-n"};

void list_all_interfaces();
bool isMember(const std::string &value, const std::vector<std::string> &array);
#endif