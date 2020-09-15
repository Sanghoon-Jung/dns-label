#pragma once
#include <string>
#include <arpa/inet.h>
#include <libnet.h>

#define DNSTYPE_A 0x0001
#define DNSTYPE_AAAA 0x001c
#define DNSCLASS_IN 0x0001
#define NAMEISPTR 0xC


struct DNSQuery{
    std::string q_name;
    uint16_t q_type;
    uint16_t q_class;

    DNSQuery(uint8_t* queryptr);
    size_t querysize();
};

struct DNSAns{
    uint16_t ans_nameinfo;
    uint16_t ans_type;
    uint16_t ans_class;
    uint32_t ans_ttl;
    uint16_t ans_datalen;
    uint8_t* dataptr;
    
    DNSAns(uint8_t* ansptr);
    size_t anssize();
    std::string getDNSName(libnet_dnsv4udp_hdr* dns_hdr);
    bool checkifNameIsPtr(uint8_t* data);
    uint16_t getNameOffset(uint16_t* data);
    in_addr_t getIPv4Addr();
};