#pragma once

#include <libnet.h>

#define DNSPORT 53
#define HTTPPORT 80
#define HTTPSPORT 443
#define MAXINADDRSTR 16

typedef uint8_t in_proto_t;

enum ETHERTYPE{
    IPv4 = ETHERTYPE_IP,
    IPv6 = ETHERTYPE_IPV6
};

enum IPPROTO{
    TCP = IPPROTO_TCP,
    UDP = IPPROTO_UDP
};

enum TCPFLG{
    SYN = TH_SYN,
    ACK = TH_ACK,
    SYNACK = TH_SYN | TH_ACK,
    FIN = TH_FIN,
    FINACK = TH_FIN | TH_ACK
};