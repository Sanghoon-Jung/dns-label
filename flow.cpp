#include "flow.h"

bool PacketFlow::operator<(const PacketFlow& other) const{
    if(this->protocol != other.protocol) return this->protocol < other.protocol;
    if(this->src_ip.s_addr != other.src_ip.s_addr) return this->src_ip.s_addr < other.src_ip.s_addr;
    if(this->src_port != other.src_port) return this->src_port < other.src_port;
    if(this->dst_ip.s_addr != other.dst_ip.s_addr) return this->dst_ip.s_addr < other.dst_ip.s_addr;
    return this->dst_port < other.dst_port;
};

PacketFlow PacketFlow::ReverseFlow(){
    PacketFlow reverse;
    reverse.protocol = this->protocol;
    reverse.src_ip = this->dst_ip;
    reverse.src_port = this->dst_port;
    reverse.dst_ip = this->src_ip;
    reverse.dst_port = this->src_port;

    return reverse;
};

/* FlowInfo structure functions */
FlowInfo::FlowInfo(){
    this->packets = 0;
    this->bytes = 0;
};


void FlowInfo::update(uint32_t pktlen){
    this->packets += 1;
    this->bytes += pktlen;
}