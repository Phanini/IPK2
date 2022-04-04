#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h> //for optarg in getopt

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
                break;
            case 'p':
                strcpy(port_buffer, optarg);
                break;
            case 't':
                TCPFlag = true;
                break;
            case 'u':
                UDPFlag = true;
                break;
            case 'n':
                number_of_packets = atoi(optarg);
                break;
        }
    }
}