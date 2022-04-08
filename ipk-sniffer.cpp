#include <iostream>
#include "ipk-sniffer.hpp"
#include <string.h>
#define HAVE_REMOTE
#include <pcap.h>
#include <arpa/inet.h>
#include <array>
#include <vector>
#include <algorithm> //std::find()


using namespace std;

int main(int argc, char* argv[]) {
    arguments arg;
    for (int i = 1; i < argc; i++) {
        string argum = argv[i];
        if ((argum.compare("-i")==0) || (argum.compare("--interface")==0)) {
            int next_index = i+1;
            // -i/--interface listed as last arg, defaulting to listing ALL interfaces
            if (next_index == argc) {
                list_all_interfaces();
            }
            // checking next optional argument for -i/--interface
            else {
                string opt_arg = argv[next_index];
                if (!isMember(opt_arg, args_list)) {
                    arg.interface = opt_arg;
                    i++;
                }
            }
        }
        else if (argum.compare("-p")==0) {
            // if not given as argument
            if ((i+1) != argc) {
                if (!isMember(argv[i+1], args_list)) {
                    arg.port = stoi(argv[i+1]);
                    i++;
                }
            }
        }
        else if (argum.compare("-n")==0) {
            // if not given as argument
            if ((i+1)!=argc) {
                if (!isMember(argv[i+1], args_list)) {
                    arg.packet_number = stoi(argv[i+1]);
                    i++;
                }
            }
            cout << "n\n";
        }
        else if ((argum.compare("-t")==0) || (argum.compare("--tcp")==0)) {
            arg.tcp = true;
            cout << "tcp\n";
        }
        else if ((argum.compare("-u")==0) || (argum.compare("--udp")==0)) {
            arg.udp = true;
            cout << "tcp\n";
        }
        else if (argum.compare("--icmp")==0) {
            arg.icmp = true;
            cout << "icmp\n";
        }
        else if (argum.compare("--arp")==0) {
            arg.arp = true;
            cout << "arp\n";
        }
        else {
            cout << "unknown command\n";
        }
    }
    return 0;
}

void list_all_interfaces() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Retrieve the device list from the local machine
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    // Print the list
    for(d= alldevs; d != NULL; d= d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description) {
            printf(" (%s)\n", d->description);
        }
        else {
            printf(" (No description available)\n");
        }
    }
    
    if (i == 0) {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return;
    }
    
    pcap_freealldevs(alldevs);
}

// Check if value if member of array of strings
bool isMember(const std::string &value, const std::vector<std::string> &array) {
    return std::find(array.begin(), array.end(), value) != array.end();
}