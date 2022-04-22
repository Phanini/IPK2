#include "ipk-sniffer.hpp"

using namespace std;

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

// DELETE LATER
string format_timestamp(const timeval * timer) {
    // format time as string:   YYYY-MM-DD\THH:MM:SS+offset
    string timestamp;
    char buf[50];

    // get local time from packet timestamp
    struct tm *timeptr = localtime(&timer->tv_sec);
    // get date & time
    strftime(buf, sizeof(buf)-1, "%FT%T", timeptr);
    timestamp = buf;

    // append decimal part of seconds
    timestamp += '.' + to_string(timer->tv_usec).substr(0, 3);

    // append timezone offset as +HH:MM
    size_t len = strftime(buf, sizeof(buf)-1, "%z", timeptr);
    if (len < 2) return timestamp;   // tz might be unavailable
    timestamp += buf;
    timestamp.insert(timestamp.length()-2, ":");

    return timestamp;
}

// Creates a sniffing session
bool create_session(arguments arg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    const u_char *packet;

    // Define the device 
	/*dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return false;
	}*/

    // Find properties of device 
    if (pcap_lookupnet(arg.interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", arg.interface);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(arg.interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", arg.interface, errbuf);
        return false;
    }
    //cout << "pcap_open_live\n";
    if (pcap_compile(handle, &fp, /*arg.port*/ "udp or tcp", 0, net) == -1) {
	    fprintf(stderr, "Couldn't parse filter %s: %s\n", /*arg.port*/ "udp", pcap_geterr(handle));
	    return false;
    }
    //cout << "pcap_compile\n";
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", /*arg.port*/ "udp", pcap_geterr(handle));
        return false;
    }

    /* Grab a packet
	packet = pcap_next(handle, &header);
	 Print its length 
	printf("Jacked a packet with length of [%d]\n", header.len);
	And close the session */
	
    pcap_loop(handle, arg.packet_number, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    cout << "Success creating session for interface: "<< arg.interface << "\n";
	return true;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct pcap_pkthdr header;
    static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;

	// DELETE STOLEN CODE LATER
	//cout << format_timestamp(&header.ts) << "\n";

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return; 
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	/* define/compute tcp payload (segment) offset */
	payload = (const u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}

return;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
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
arguments parse_args(arguments arg, int arg_c, char* arg_v[]) {
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
                    char temp[16] = "port ";
                    strcat(temp, arg_v[i+1]);
                    arg.port = temp;
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
            cout << "udp\n";
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

void print_arg_struct(arguments argdata) {
    cout << argdata.port << "\n ";
}



int main(int argc, char* argv[]) {
    arguments arg;
    arg = parse_args(arg, argc, argv);
    create_session(arg);
    return 0;
}