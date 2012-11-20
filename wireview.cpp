//libraries
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <list>
#include <map>
#include <iostream>
//internet packet utilities
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
//network packet utilities
#include <net/if_arp.h>
#include <net/ethernet.h>
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
//global variables
int numpackets = 0;
map<string, int> srcMacs;
map<string, int> destMacs;
map<string, int> srcIPs;
map<string, int> destIPs;
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
	    printf("This is an ethernet capture! Yay!\n");
	    pcap_loop(cap, -1, printCap, NULL);
	} else {
			printf("This isn't ethernet!\n");
	}
    pcap_close(cap);
    printf("Unique Source Ports:\n");
    printShortList(srcPorts);
    printf("Unique Destination Ports:\n");
    printShortList(destPorts);
    printf("Unique Ethernet Senders:\n");
    printMap(srcMacs);
	printf("You captured %d packets.\n", numpackets);
	return 0;
}

void printCap(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {
	struct timeval pkt_time = header->ts;
	if(numpackets < 1) {
		time_t timesec = pkt_time.tv_sec;
		struct tm* secinfo = localtime(&timesec);
		printf("Packet capture started at %s", asctime(secinfo));
	}
	struct ether_header* ethernet = (struct ether_header *)pkt;
	string shost, dhost;
	printMac(ethernet->ether_shost, &shost);
	printMac(ethernet->ether_dhost, &dhost);
	if(!findInMap(srcMacs, shost)) srcMacs.insert(std::make_pair(shost,1));
	else srcMacs[shost]++;
	if(ntohs(ethernet->ether_type)==ETHERTYPE_IP){
	    printf("This is an IP packet.\n");
	    struct iphdr* ip = (struct iphdr*)(pkt+sizeof(struct ether_header));
	    char srcstr[INET_ADDRSTRLEN], dststr[INET_ADDRSTRLEN];
	    inet_ntop(AF_INET, &(ip->saddr), srcstr, INET_ADDRSTRLEN);
	    inet_ntop(AF_INET, &(ip->daddr), dststr, INET_ADDRSTRLEN);
	    printf("src: %s dst: %s protocol: %d\n", srcstr, dststr, ip->protocol);
	    if(ip->protocol==IPPROTO_UDP){
	        printf("This is a UDP packet.\n");
	        struct udphdr* udp = (struct udphdr*)(pkt+sizeof(struct ether_header)+sizeof(iphdr));
	        short sport = ntohs(udp->source);
	        short dport = ntohs(udp->dest);
	        if(!findInList(srcPorts, sport)) {
				srcPorts.push_back(sport);
			}
			else printf("Duplicate port detected. Not adding to the list.\n");
			if(!findInList(destPorts, dport)) {
				destPorts.push_back(dport);
			}
			else printf("Duplicate port detected. Not adding to the list.\n");
            printf("src port: %d dst port: %d\n", sport, dport);
	    }
	}
	//else if(ntohs(ethernet->ether_type)==ETHERTYPE_ARP) {
	//    printf("This is an ARP packet.\n");
	    //printf("Source MAC: %s\n",printMac(ethernet->ether_shost));
	    //printf("Destination MAC: %s\n",printMac(ethernet->ether_dhost));
	//}
	printf("Received packet at time %ld    %ld.\n", pkt_time.tv_sec, pkt_time.tv_usec);
	numpackets++;
}

void printMac(const u_char* data, string *str) {
	char chars[20] = "";
	for(int i = 0; i < 5; i++) {
		sprintf(chars, "%s%.2x", chars, data[i]);
		if(i < 4) sprintf(chars, "%s:", chars);
	}
    for(int i = 0; chars[i] != 0; i++)
        (*str) += chars[i];
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
}

void printMap(map<string, int> toPrint) {
	map<string, int>::iterator i;
	for(i = toPrint.begin(); i != toPrint.end(); i++) {
		cout << (*i).first << ": " << (*i).second << endl;
	}
}
