#pragma once
#include <cstdint>
#include "types.h"

struct PacketFlow{
    in_proto_t protocol;
    in_addr src_ip;
    in_port_t src_port;
    in_addr dst_ip;
    in_port_t dst_port;

    bool operator<(const PacketFlow& other) const;
    PacketFlow ReverseFlow();
};

struct FlowInfo{
    uint32_t packets;
    uint64_t bytes;

    FlowInfo();
    void update(uint32_t pktlen);
};