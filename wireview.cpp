#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#define MAX_SIZE 102400 //100KB should be enough.

char* openFile(char* path, char data[MAX_SIZE]);
void printCap();

int main(int argc, char** argv) {
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
	return 0;
}

void printCap(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) {
	struct timeval pkt_time = header->ts;
	printf("Received packet at time %ld    %ld.\n", pkt_time.tv_sec, pkt_time.tv_usec);
}
