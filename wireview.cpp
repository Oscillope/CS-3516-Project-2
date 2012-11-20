//libraries
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
//internet packet utilities
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
//network packet utilities
#include <net/if_arp.h>
#include <net/ethernet.h>
//C++ includes
#include <list>
#include <map>
#include <iostream>
#include <sstream>
using namespace std;
//constants
#define MAX_SIZE 102400 //100KB should be enough.
//functions
char* openFile(char* path, char data[MAX_SIZE]);
void printCap(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
void printMac(const u_char* data, string *str);
bool findInList(list<short> checkList, short checkPort);
bool findInMap(map<string, int> checkMap, string checkString);
void printShortList(list<short> toPrint);
void printMap(map<string, int> toPrint);
void bold();
void underline();
void color(int col);
void unattr();
//global variables
int numpackets = 0;
map<string, int> srcMacs;
map<string, int> destMacs;
map<string, int> srcIPs;
map<string, int> destIPs;
map<string, list<string> > srcARP;
map<string, list<string> > dstARP;

list<short> srcPorts;
list<short> destPorts;

int main(int argc, char** argv) {
	if(argc < 2) {
		fprintf(stderr, "You must provide a packet capture file.\n");
		exit(1);
	}
	char* path = argv[1];
	pcap_t *cap;
	cap = pcap_open_offline(path, NULL);
	int datalink = pcap_datalink(cap);
	if(datalink==DLT_EN10MB){
		#ifdef DEBUG
			printf("This is an ethernet capture! Yay!\n");
	    #endif
	    pcap_loop(cap, -1, printCap, NULL);
	}
	else {
			printf("This isn't ethernet!\n");
	}
    pcap_close(cap);
    underline();
    color(31);
    printf("Unique Ethernet Senders:\n");
    unattr();
    printMap(srcMacs);
    underline();
    color(32);
    printf("Unique Ethernet Receivers:\n");
    unattr();
    printMap(destMacs);
    underline();
    color(33);
    printf("Unique IP Senders:\n");
    unattr();
    printMap(srcIPs);
    underline();
    color(34);
    printf("Unique IP Receivers:\n");
    unattr();
    printMap(destIPs);
    underline();
    color(35);
    printf("Unique UDP Source Ports:\n");
    unattr();
    printShortList(srcPorts);
    underline();
    color(36);
    printf("Unique UDP Destination Ports:\n");
    unattr();
    printShortList(destPorts);
	printf("You captured %d packets.\n", numpackets);
	return 0;
}

void printCap(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {
	struct timeval pkt_time = header->ts;
	if(numpackets < 1) {
		time_t timesec = pkt_time.tv_sec;
		struct tm* secinfo = localtime(&timesec);
		bold();
		printf("Packet capture started at %s", asctime(secinfo));
		unattr();
	}
	struct ether_header* ethernet = (struct ether_header *)pkt;
	string shost, dhost;
	printMac(ethernet->ether_shost, &shost);
	printMac(ethernet->ether_dhost, &dhost);
	if(!findInMap(srcMacs, shost)) srcMacs.insert(std::make_pair(shost,1));
	else srcMacs[shost]++;
	if(!findInMap(destMacs, dhost)) destMacs.insert(std::make_pair(dhost,1));
	else destMacs[dhost]++;
	if(ntohs(ethernet->ether_type)==ETHERTYPE_IP){
		#ifdef DEBUG
			printf("This is an IP packet.\n");
		#endif
	    struct iphdr* ip = (struct iphdr*)(pkt+sizeof(struct ether_header));
	    char srcstr[INET_ADDRSTRLEN], dststr[INET_ADDRSTRLEN];
	    string srcip, dstip;
	    inet_ntop(AF_INET, &(ip->saddr), srcstr, INET_ADDRSTRLEN);
	    inet_ntop(AF_INET, &(ip->daddr), dststr, INET_ADDRSTRLEN);
	    stringstream sstream, dstream;
	    sstream << srcstr;
	    sstream >> srcip;
	    if(!findInMap(srcIPs, srcip)) srcIPs.insert(std::make_pair(srcip,1));
		else srcIPs[srcip]++;
	    dstream << dststr;
	    dstream >> dstip;
		if(!findInMap(destIPs, dstip)) destIPs.insert(std::make_pair(dstip,1));
		else destIPs[dstip]++;
	    #ifdef DEBUG
			printf("src: %s dst: %s protocol: %d\n", srcstr, dststr, ip->protocol);
	    #endif
	    if(ip->protocol==IPPROTO_UDP){
			#ifdef DEBUG
				printf("This is a UDP packet.\n");
	        #endif
	        struct udphdr* udp = (struct udphdr*)(pkt+sizeof(struct ether_header)+sizeof(iphdr));
	        short sport = ntohs(udp->source);
	        short dport = ntohs(udp->dest);
	        if(!findInList(srcPorts, sport)) {
				srcPorts.push_back(sport);
			}
			#ifdef DEBUG
				else printf("Duplicate port detected. Not adding to the list.\n");
			#endif
			if(!findInList(destPorts, dport)) {
				destPorts.push_back(dport);
			}
			#ifdef DEBUG
				else printf("Duplicate port detected. Not adding to the list.\n");
				printf("src port: %d dst port: %d\n", sport, dport);
			#endif
	    }
	}
	else if(ntohs(ethernet->ether_type)==ETHERTYPE_ARP) {
			string shostmac, dhostmac, shostip, dhostip;
			printMac(ethernet->ether_shost, &shostmac);
			printMac(ethernet->ether_dhost, &dhostmac);
			//TODO get ips
			shostip = "dummy";
			dhostip = "dummy";
			//get or make ip lists
			if(srcARP.find(shostmac)!=srcARP.end()){
			    (srcARP[shostmac]).push_back(shostip);
			} else {
			    list<string> srcips;
			    srcips.push_back(shostip);
			    srcARP.insert(std::make_pair(shostmac,srcips));
			}
			if(dstARP.find(dhostmac)!=dstARP.end()){
			    (dstARP[dhostmac]).push_back(dhostip);
			} else {
			    list<string> dstips;
			    dstips.push_back(dhostip);
			    dstARP.insert(std::make_pair(shostmac,dstips));
			}
			    
		#ifdef DEBUG
			printf("This is an ARP packet.\n");			
			cout << "Source MAC: " << shost << endl;
			cout << "Destination MAC: " << dhost << endl;
		#endif
	}
	#ifdef DEBUG
		printf("Received packet at time %ld    %ld.\n", pkt_time.tv_sec, pkt_time.tv_usec);
	#endif
	numpackets++;
}

void printMac(const u_char* data, string *str) {
	char chars[3] = "";
    for(int i = 0; i < 5; i++) {
		sprintf(chars, "%.2x", data[i]);
		if(i < 4) sprintf(chars, "%s:", chars);
		(*str).append(chars);
	}
}

bool findInList(list<short> checkList, short checkPort) {
	list<short>::iterator i;
	for(i = checkList.begin(); i != checkList.end(); i++) {
		if(*i == checkPort) return true;
	}
	return false;
}

bool findInMap(map<string, int> checkMap, string checkString) {
	return checkMap.find(checkString)!=checkMap.end();
}

void printShortList(list<short> toPrint) {
	list<short>::iterator i;
	for(i = toPrint.begin(); i != toPrint.end(); i++) {
		cout << *i << endl;
	}
	cout << endl;
}

void printMap(map<string, int> toPrint) {
	map<string, int>::iterator i;
	for(i = toPrint.begin(); i != toPrint.end(); i++) {
		cout << "|  " << (*i).first << "  | " << (*i).second << " |" << endl;
	}
	cout << endl;
}

void bold() {
	char ESC = 27;
	printf("%c[1m", ESC);
}

void underline() {
	char ESC = 27;
	printf("%c[4m", ESC);
}

void color(int col) {
	char ESC = 27;
	printf("%c[%dm", ESC, col);
}

void unattr() {
	char ESC = 27;
	printf("%c[0m", ESC);
}
