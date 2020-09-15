#include "classifier.h"

Classifier::Classifier(){ }

Classifier::~Classifier(){
    
}

void Classifier::printConversation(){
    printf("---------------------------------------------------------------------- Conversations ----------------------------------------------------------------------\n\n");
    
    printf("%-12s%-18s%-12s%-18s%-12s%-12s%-12s%-16s%-16s%-16s%-16s\n", 
        "PROTOCOL", "Address A", "Port A", "Address B", "Port B", "Packets", "Bytes",
        "Packets A->B", "Bytes A->B", "Packets B->A", "Bytes B->A");
    
    std::string protocol;
    char addrA[MAXINADDRSTR], addrB[MAXINADDRSTR];
    int portA, portB;
    uint32_t pktsAtoB, pktsBtoA;
    uint64_t bytesAtoB, bytesBtoA;


    while(Flows.size()){
        FlowMap::iterator iter = Flows.begin();

        PacketFlow f1 = iter->first;
        
        switch(f1.protocol){
            case TCP: protocol = "TCP"; break;
            case UDP: protocol = "UDP"; break;
            default: protocol = "INVALID"; break;
        }

        inet_ntop(AF_INET, &f1.src_ip.s_addr, addrA, sizeof(addrA));
        inet_ntop(AF_INET, &f1.dst_ip.s_addr, addrB, sizeof(addrB));
        portA = f1.src_port;
        portB = f1.dst_port;
        pktsAtoB = Flows[f1].packets;
        bytesAtoB = Flows[f1].bytes;

        PacketFlow f2 = f1.ReverseFlow();

        if(Flows.count(f2)){
            pktsBtoA = Flows[f2].packets;
            bytesBtoA = Flows[f2].bytes;
        }
        else{
            pktsBtoA = 0;
            bytesBtoA = 0;
        }

        printf("%-12s%-18s%-12d%-18s%-12d%-12u%-12u%-16u%-16u%-16u%-16u\n", 
            protocol.c_str(), addrA, portA, addrB, portB, pktsAtoB + pktsBtoA,
            bytesAtoB + bytesBtoA, pktsAtoB, bytesAtoB, pktsBtoA, bytesBtoA);
        
        Flows.erase(f1);
        Flows.erase(f2);
    }
}

void Classifier::printDNSInfo(){

    printf("%-18s%-20s\n", "IP Address", "Domain Name String");

    DNSMap::iterator iter;
    for(iter = DNSs.begin(); iter != DNSs.end(); iter++){
        in_addr tmp;
        tmp.s_addr = iter->first;
        printf("%-18s%s\n", inet_ntoa(tmp), iter->second.c_str());
    }
}

/* DNS 패킷을 통해 DNS 정보 업데이트 */
void Classifier::updateUDPDNS(libnet_dnsv4udp_hdr* dns_hdr){
    uint16_t dns_flags = ntohs(dns_hdr->flags);
    
    // check if dns response
    // 나중에 truncated되었는지도 확인 필요(미완료)
    if(dns_flags >> 7){
        
        // query 정보만큼 jump
        uint8_t* dnsdataptr = (uint8_t*)dns_hdr + LIBNET_DNS_H;
        uint16_t querynum = ntohs(dns_hdr->num_q);
        for(int i = 0; i < querynum; i++){
            DNSQuery q = DNSQuery(dnsdataptr);
            dnsdataptr += q.querysize();          
        }

        // answer 정보 얻어오기
        uint16_t ansnum = ntohs(dns_hdr->num_answ_rr);
        for(int i = 0; i < ansnum; i++){
            DNSAns ans = DNSAns(dnsdataptr);
            dnsdataptr += ans.anssize();
            
            if(ans.ans_type != DNSTYPE_A) continue;
            DNSs.insert(std::make_pair(ans.getIPv4Addr(), ans.getDNSName(dns_hdr)));
        }
    }
};

/* TCP header에서 정보 가져오기 
 * 특수한 경우 DNS가 TCP로 동작하기도 함 */
void Classifier::getTCPInfo(libnet_tcp_hdr* tcp_hdr, PacketFlow &flow){
    flow.src_port = ntohs(tcp_hdr->th_sport);
    flow.dst_port = ntohs(tcp_hdr->th_dport);

    /* TODO: TCP DNS 추가 필요
    if(flow.src_port == DNSPORT)
    */
}

/* UDP header에서 정보 가져오기 */
void Classifier::getUDPInfo(libnet_udp_hdr* udp_hdr, PacketFlow &flow){
    flow.src_port = ntohs(udp_hdr->uh_sport);
    flow.dst_port = ntohs(udp_hdr->uh_dport);

    if(flow.src_port == DNSPORT)
        updateUDPDNS((libnet_dnsv4udp_hdr*)((uint8_t*)udp_hdr + LIBNET_UDP_H));
}

/* IPv4 header에서 정보 가져오기 */
int Classifier::getIPv4Info(libnet_ipv4_hdr* ipv4_hdr, PacketFlow &flow){

    flow.src_ip = ipv4_hdr->ip_src;
    flow.dst_ip = ipv4_hdr->ip_dst;

    uint8_t* L4_hdr = (uint8_t*)ipv4_hdr + ((ipv4_hdr->ip_hl) << 2);

    switch(flow.protocol = ipv4_hdr->ip_p){
        case TCP:
            getTCPInfo((libnet_tcp_hdr*)(L4_hdr), flow);
            break;

        case UDP:
            getUDPInfo((libnet_udp_hdr*)(L4_hdr), flow);
            break;

        default:
            return -1;      // other protocols -> return -1 확인할 필요 없기 때문.
    }

    return 0;
}

/* IPv6 header에서 정보 가져오기(미완성) */
int Classifier::getIPv6Info(libnet_ipv6_hdr* ipv6_hdr, PacketFlow &flow){

    return 0;
}

int Classifier::getPacketFlow(const u_char* packet, PacketFlow &flow){

    libnet_ethernet_hdr* eth_hdr = (libnet_ethernet_hdr*) packet;
    int res;

    switch(ntohs(eth_hdr->ether_type)){
        case IPv4:
            res = getIPv4Info((libnet_ipv4_hdr*)((uint8_t*)eth_hdr + LIBNET_ETH_H), flow);
            break;

        case IPv6:
            res = getIPv6Info((libnet_ipv6_hdr*)((uint8_t*)eth_hdr + LIBNET_ETH_H), flow);
            break;

        default:
            res = -1; break;   // 다른 eth_type은 확인 필요 없음.
    }
    
    return res;
}

void Classifier::updateFlowMap(PacketFlow &flow, uint32_t len){

    // 내가 잡은 flow가 존재 x -> 새로운 FlowInfo를 초기화하여 맵에 추가
    if(!Flows.count(flow)){
        FlowInfo newinfo = FlowInfo();
        Flows.insert(std::make_pair(flow, newinfo));
    }
    
    Flows[flow].update(len);
}

/* 실질적으로 외부에서 사용할 수 있는 함수. 패킷 분류 기능 */
int Classifier::classify(struct pcap_pkthdr* header, const u_char* packet){
    
    // flow information 저장
    PacketFlow flow;
    if(getPacketFlow(packet, flow) == -1) return -1;            // 확인할 필요 없는 패킷인 경우 -1리턴

    updateFlowMap(flow, header->caplen);     // 패킷 정보를 map에 업데이트

    return 0;
}