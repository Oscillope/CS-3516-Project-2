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
//constants
#define MAX_SIZE 102400 //100KB should be enough.
//functions
char* openFile(char* path, char data[MAX_SIZE]);
void printCap(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
char* printMac(const u_char* data);
int findPortInList(struct mydnsnode* curnode, short testport);
//global variables
int numpackets = 0;
int lendnslist = 0;

typedef struct myipnode{
    //TODO determine what size this buffer should actually be
    char data[INET_ADDRSTRLEN];
    struct mynode *next, *last;
} ipnode;
typedef struct mydnsnode{
    short port;
    struct mydnsnode *next;
} node;
mydnsnode *unique_ports_head;
mydnsnode *unique_ports_cur;
int main(int argc, char** argv) {
	unique_ports_head = new mydnsnode;
	malloc(1000*sizeof(mydnsnode));
	unique_ports_head->next = 0;
	unique_ports_cur = unique_ports_head;
	if(argc < 2) {
		fprintf(stderr, "You must provide a packet capture file.\n");
		#ifdef VULGAR
			printf("Fucking idiot.\n");
		#endif
		exit(1);
	}
	char* path = argv[1];
	pcap_t *cap;
	cap = pcap_open_offline(path, NULL);
	int datalink = pcap_datalink(cap);
	if(datalink==DLT_EN10MB){
	    #ifdef VULGAR
			printf("This is an ethernet capture! Fuck yeah!\n");
		#else
	        printf("This is an ethernet capture! Yay!\n");
	    #endif
	    pcap_loop(cap, -1, printCap, NULL);
	} else {
			printf("This isn't ethernet!\n");
		#ifdef VULGAR
			printf("Why are you giving me this bullshit?\n");
		#endif
	}
    pcap_close(cap);
    unique_ports_cur = unique_ports_head;
    while(unique_ports_cur->next != 0) {
		printf("Unique port: %d\n",unique_ports_cur->port);
		unique_ports_cur += sizeof(mydnsnode);
	}
	#ifdef VULGAR
		printf("You captured %d shitty-ass packets.\n", numpackets);
	#else
		printf("You captured %d packets.\n", numpackets);
	#endif
	return 0;
}

void printCap(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {
	struct timeval pkt_time = header->ts;
	if(numpackets < 1) {
		time_t timesec = pkt_time.tv_sec;
		struct tm* secinfo = localtime(&timesec);
		printf("Packet capture started at %s", asctime(secinfo));
		#ifdef VULGAR
			printf("You fucker.\n");
		#endif
	}
	struct ether_header* ethernet = (struct ether_header *)pkt;
	if(ntohs(ethernet->ether_type)==ETHERTYPE_IP){
	    printf("This is a fucking IP packet.\n");
	    struct iphdr* ip = (struct iphdr*)(pkt+sizeof(struct ether_header));
	    char srcstr[INET_ADDRSTRLEN], dststr[INET_ADDRSTRLEN];
	    inet_ntop(AF_INET, &(ip->saddr), srcstr, INET_ADDRSTRLEN);
	    inet_ntop(AF_INET, &(ip->daddr), dststr, INET_ADDRSTRLEN);
	    printf("src: %s dst: %s protocol: %d\n", srcstr, dststr, ip->protocol);
	    if(ip->protocol==IPPROTO_UDP){
	        printf("This fucker is a UDP packet.\n");
	        struct udphdr* udp = (struct udphdr*)(pkt+sizeof(struct ether_header)+sizeof(iphdr));
	        short sport = ntohs(udp->source);
	        short dport = ntohs(udp->dest);
	        //while(unique_ports_cur->next != 0) unique_ports_cur = unique_ports_cur->next;
	        unique_ports_cur->next = new mydnsnode;
	        if(!findPortInList(unique_ports_cur, sport)) {
				printf("Unique port found... Adding!\n");
				#ifdef VULGAR
					printf("You bitch.\n");
				#endif
				unique_ports_cur->port = sport;
				unique_ports_cur += sizeof(mydnsnode);
			}
            printf("src port: %d dst port: %d\n", sport, dport);
	    }
	}
	else if(ntohs(ethernet->ether_type)==ETHERTYPE_ARP) {
	    printf("This is a fucking ARP packet.\n");
	    printf("Source MAC: %s\n",printMac(ethernet->ether_shost));
	    printf("Destination MAC: %s\n",printMac(ethernet->ether_dhost));
	}
	printf("Received packet at time %ld    %ld.\n", pkt_time.tv_sec, pkt_time.tv_usec);
	numpackets++;
}

char* printMac(const u_char* data) {
	char string[20] = "";
	for(int i = 0; i < 5; i++) {
		sprintf(string, "%s%.2x", string, data[i]);
		if(i < 4) sprintf(string, "%s:", string);
	}
	return string;
}

int findPortInList(struct mydnsnode* curnode, short testport) {
	int occurrences = 0;
	while(curnode->next != 0) {
		printf("Testing port %d\n",curnode->port);
		if(curnode->port == testport) occurrences++;
		else {
			printf("That's unique, you retard!\n");
			curnode += sizeof(mydnsnode);
		}
		printf("Current occurrences of port: %d\n", occurrences);
	}
	curnode = unique_ports_head;
	return occurrences;
}
