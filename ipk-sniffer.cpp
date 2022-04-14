#include <iostream>
#include <stdio.h>
#include "ipk-sniffer.hpp"
#include <string.h>
#define HAVE_REMOTE
#include <pcap.h>
#include <arpa/inet.h>
#include <array>
#include <vector>
#include <algorithm> //std::find()

using namespace std;

// Creates a sniffing session
bool create_session(char *dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "port 23";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return false;
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	    return false;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return false;
    }

    cout << "Success creating session for interface: "<< dev << "\n";
}

// Prints out all avaible interfaces
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

// Parses input and stores it into argmuments struct
arguments parse_args(arguments arg, int arg_c, char*arg_v[]) {
    for (int i = 1; i < arg_c; i++) {
        string argum = arg_v[i];
        if ((argum.compare("-i")==0) || (argum.compare("--interface")==0)) {
            int next_index = i+1;
            // -i/--interface listed as last arg, defaulting to listing ALL interfaces
            if (next_index == arg_c) {
                list_all_interfaces();
            }
            // checking next optional argument for -i/--interface
            else {
                char *opt_arg = arg_v[next_index];
                if (!isMember(opt_arg, args_list)) {
                    arg.interface = opt_arg;
                    i++;
                }
            }
        }
        else if (argum.compare("-p")==0) {
            // if not given as argument
            if ((i+1) != arg_c) {
                //if next value is not a flag
                if (!isMember(arg_v[i+1], args_list)) {
                    arg.port = stoi(arg_v[i+1]);
                    i++;
                }
            }
        }
        else if (argum.compare("-n")==0) {
            // if not given as argument
            if ((i+1)!=arg_c) {
                // if next value is not a flag
                if (!isMember(arg_v[i+1], args_list)) {
                    arg.packet_number = stoi(arg_v[i+1]);
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
    return arg;
}

int main(int argc, char* argv[]) {
    arguments arg;
    arg = parse_args(arg, argc, argv);
    create_session(arg.interface);
    return 0;
}