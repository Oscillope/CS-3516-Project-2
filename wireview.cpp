//libraries
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
//internet packet utilities
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
//network packet utilities
#include <net/if_arp.h>
//constants
#define MAX_SIZE 102400 //100KB should be enough.
#define ADDR_LEN 128
char* openFile(char* path, char data[MAX_SIZE]);
void printCap(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);

int numpackets = 0; 
class node {
    //TODO determine what size this buffer should actually be
    char data[ADDR_LEN];
    node *next, *last;
}
int main(int argc, char** argv) {
	if(argc < 2) {
		fprintf(stderr, "You must provide a packet capture file, you fucking idiot.\n");
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
	    printf("This isn't ethernet... Why are you giving me this bullshit?\n");
	}
    pcap_close(cap);
    printf("You captured %d shitty-ass packets.\n", numpackets);
	return 0;
}

void printCap(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {
    numpackets++;
	struct timeval pkt_time = header->ts;
	printf("Received packet at time %ld    %ld.\n", pkt_time.tv_sec, pkt_time.tv_usec);
}
