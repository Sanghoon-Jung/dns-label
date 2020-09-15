#include "dns.h"

/*
 * DNS Query structure 
 */

DNSQuery::DNSQuery(uint8_t* queryptr){
    q_name = (char*)(queryptr);
    queryptr += q_name.size() + 1;
    
    q_type = ntohs(*(uint16_t*)queryptr);
    queryptr += sizeof(q_type);

    q_class = ntohs(*(uint16_t*)queryptr);
}

size_t DNSQuery::querysize(){
    return q_name.size() + 1 + sizeof(q_type) + sizeof(q_class);
}


/*
 *  DNS Answer structure
 */

DNSAns::DNSAns(uint8_t* ansptr){
    ans_nameinfo = ntohs(*(uint16_t*)ansptr);        // 주로 c0 0c -> c: pointer type / 00c: position (0부터)
    ansptr += sizeof(ans_nameinfo);
    
    ans_type = ntohs(*(uint16_t*)ansptr);
    ansptr += sizeof(ans_type);
    
    ans_class = ntohs(*(uint16_t*)ansptr);
    ansptr += sizeof(ans_class);

    ans_ttl = ntohl(*(uint32_t*)ansptr);
    ansptr += sizeof(ans_ttl);

    ans_datalen = ntohs(*(uint16_t*)ansptr);
    ansptr += sizeof(ans_datalen);

    dataptr = ansptr;
}

size_t DNSAns::anssize(){
    return sizeof(ans_nameinfo) + sizeof(ans_type) + sizeof(ans_class)
            + sizeof(ans_ttl) + sizeof(ans_datalen) + ans_datalen;
}

bool DNSAns::checkifNameIsPtr(uint8_t* data){
    return ((*data) >> 4 == NAMEISPTR);
}

uint16_t DNSAns::getNameOffset(uint16_t* data){
    uint16_t offset = ntohs(*data);
    offset &= 0x0FFF;
    return offset; 
}

std::string DNSAns::getDNSName(libnet_dnsv4udp_hdr* dns_hdr){
    uint16_t offset = ans_nameinfo & 0x0FFF;
    char name[BUFSIZ];
    
    /* 시작위치 : ans_nameinfo에서의 offset 으로 결정
     * 종료: 0x00 만날 때
     * 하나씩 ++
     * 도중에 ptr이라는 정보를 만나면 그곳으로 점프
     */
    uint8_t* charptr = (uint8_t*)dns_hdr + offset + 1;
    int i = 0;
    while(*charptr){
        if(checkifNameIsPtr(charptr))
            charptr = (uint8_t*)dns_hdr + getNameOffset((uint16_t*)charptr);
        
        if(*charptr >= 0x20) name[i] = *charptr;
        else name[i] = '.';
        i++; charptr++;
    }
    name[i] = '\0';
    
    return std::string(name);
}

in_addr_t DNSAns::getIPv4Addr(){
    
    /* address is nbo type */
    in_addr_t addr;
    uint8_t* addrptr = (uint8_t*)&addr;
    for(int i = 0; i < ans_datalen; i++)
        *(addrptr + i) = *(dataptr + i);
    
    return addr;
}