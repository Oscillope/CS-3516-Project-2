//libraries
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
//internet packet utilities
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
//network packet utilities
#include <net/if_arp.h>
#include <net/ethernet.h>
//constants
#define MAX_SIZE 102400 //100KB should be enough.
#define ADDR_LEN 128
char* openFile(char* path, char data[MAX_SIZE]);
void printCap(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);

int numpackets = 0;
 
typedef struct mynode{
    //TODO determine what size this buffer should actually be
    char data[ADDR_LEN];
    struct mynode *next, *last;
} node;

int main(int argc, char** argv) {
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
	    printf("This isn't ethernet!");
		#ifdef VULGAR
			printf("Why are you giving me this bullshit?\n");
		#endif
	}
    pcap_close(cap);
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
	}
	else if(ntohs(ethernet->ether_type)==ETHERTYPE_ARP) {
	    printf("This is a fucking ARP packet.\n");
	}
	printf("Received packet at time %ld    %ld.\n", pkt_time.tv_sec, pkt_time.tv_usec);
	numpackets++;
}
