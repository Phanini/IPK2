#include <stdlib.h>
#include <stdio.h>
#define HAVE_REMOTE
#include <pcap.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h> //for optarg in getopt
#include <ctype.h>

#define HAVE_REMOTE

int main(int argc, char* argv[]) {
    bool TCPFlag = false;
    bool UDPFlag = false;
    bool ARPFlag = false;
    bool ICMPFlag= false;

    char interface_buffer[128] = "";
    char port_buffer[16] = "";
    int number_of_packets;

    // Handle full word arguments
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--tcp")==0){
            TCPFlag = true;
            printf("TCP flag was given\n");
            break;
        }
        else if (strcmp(argv[i], "--udp")==0) {
            UDPFlag = true;
            printf("UDP flag was given\n");
            break;
        }
        else if (strcmp(argv[i], "--arp")==0) {
            ARPFlag = true;
            printf("ARP flag was given\n");
            break;
        }
        else if (strcmp(argv[i], "--icmp")==0) {
            ICMPFlag = true;
            printf("ICMP flag was given\n");
            break;
        }
    }

    // Handle single character flags
    int opt;
    while ((opt = getopt(argc, argv, "i:p:tun:") != -1)) {
        switch (opt) {
            case 'i':
                strcpy(interface_buffer, optarg);
                printf("-i %s GIVEN\n", interface_buffer);
                break;
            case 'p':
                printf("p: %s\n", port_buffer);
                strcpy(port_buffer, optarg);
                break;
            case 't':
                printf("t given\n");
                TCPFlag = true;
                break;
            case 'u':
                printf("u given\n");
                UDPFlag = true;
                break;
            case 'n':
                printf("n: given\n");
                number_of_packets = atoi(optarg);
                break;
        }
    }
    list_interfaces();
}

void list_interfaces() {
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