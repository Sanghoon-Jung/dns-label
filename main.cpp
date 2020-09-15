#include <pcap.h>
#include <cstdio>
#include "classifier.h"

void usage();

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* fname = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(fname, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_offline(%s) return nullptr - %s\n", fname, errbuf);
        return -1;
    }
    
    printf("Packet Capturing Start...\n");
    printf("filename: %s\n\n", fname);

    Classifier cf = Classifier();
    int total = 0, tcpudp = 0;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        if(res == -1) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if(res == -2){
            printf("\nEnd of packets\n");
            printf("total: %d packets\n", total);
            printf("TCP/UDP: %d packets\n\n", tcpudp);
            break;
        }
        
        total++;
        printf("#%d packet captured\n", total);
        
        if(cf.classify(header, packet) == -1) continue;
        tcpudp++;
    }
    cf.printDNSInfo();
    cf.printConversation();
    pcap_close(handle);

    return 0;
}

void usage() {
    printf("syntax: dns-label <pcap filename>\n");
    printf("sample: dns-label demo.pcap\n");
}