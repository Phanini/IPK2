#include <iostream>
#include "ipk-sniffer.hpp"
#include <string.h>

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
                cout << "-i ARG: " + opt_arg + "\n";
            }
        }
        else if (argum.compare("-p")==0) {
            cout << "port\n";
        }
        else if ((argum.compare("-t")==0) || (argum.compare("--tcp")==0)) {
            cout << "tcp\n";
        }
        else if ((argum.compare("-u")==0) || (argum.compare("--udp")==0)) {
            cout << "tcp\n";
        }
        else if (argum.compare("--icmp")==0) {
            cout << "icmp\n";
        }
        else if (argum.compare("--arp")==0) {
            cout << "arp\n";
        }
        else if (argum.compare("-n")==0) {
            cout << "n\n";
        }
    }
    return 0;
}
void list_all_interfaces() {

}