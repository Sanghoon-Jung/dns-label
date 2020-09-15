#pragma once
#include <cstdio>
#include <map>
#include <pcap.h>
#include "flow.h"
#include "dns.h"

typedef std::map<PacketFlow, FlowInfo> FlowMap;
typedef std::map<in_addr_t, std::string> DNSMap;

class Classifier{
    private:
        FlowMap Flows;
        DNSMap DNSs;
        
        // flow 정보는 모두 network byte order 그대로 저장.
        int getPacketFlow(const u_char* packet, PacketFlow &flow);
        int getIPv4Info(libnet_ipv4_hdr* ipv4_hdr, PacketFlow &flow);
        int getIPv6Info(libnet_ipv6_hdr* ipv6_hdr, PacketFlow &flow);
        void getTCPInfo(libnet_tcp_hdr* tcp_hdr, PacketFlow &flow);
        void getUDPInfo(libnet_udp_hdr* udp_hdr, PacketFlow &flow);
        void updateFlowMap(PacketFlow &tmp, uint32_t len);

        // DNS 정보 관련 함수
        void updateUDPDNS(libnet_dnsv4udp_hdr* dns_hdr);
        void updateTCPDNS(libnet_dnsv4_hdr* dns_hdr);

        // 연결 종료된 session 삭제
        void removeUDPFlow();
        
        bool isTCPRemoved();
        void removeTCPFlow();
        
    public:
        Classifier();
        ~Classifier();
        int classify(struct pcap_pkthdr* header, const u_char* packet);
        void printConversation();
        void printDNSInfo();
};