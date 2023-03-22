# Author

Jakub Phan  
FIT VUT  
2022

# IPK 2 - Packet Sniffer (UNFINISHED)

Second project of Computer Communications and Networks - Packet Sniffer

## Project description

Make and implement a network analyzer in C/C++/C# that can catch and filter packets on given network interface.

## Usage

```
./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} 
```
where:

- **-i eth0** (on which interface should the program listen, if no further arg of 'eth0' is given, the program will list out all active interfaces)  
- **-p 23** (will filter out all other ports except given one, if no port number is given then all ports are filtered; if argument is given then the port can be in source and in destinaton part)  
- **-t** or **--tpc** (shows only TCP packets)  
- **-u** or **--udp** (shows only UDP packets)  
- **--icmp** (shows only ICMPv4 and ICMPv6 packets)  
- **--arp** (shows only ARP)  
- If the protocol is not specified, then all will be printed out
- **-n 10** (sets number of packets to be shown, if nothing is given then only one packet is shown as of **-n 1**)  
Arguments can be in any order  

# Example calls
First list out your interfaces with:

```./ipk-sniffer -i```
Then proceed to call some of these examples:

Shows 5 first packets from any interface:

```./ipk-sniffer -i any -n 5```

Shows 3 udp packets from any interface:

```./ipk-sniffer -i any --udp -n 3```
