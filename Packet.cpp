#include "Packet.h"


Packet::Packet(const Byte *newdata,uint32_t packetlen){
    ethernet = NULL;
    ip = NULL;
    tcp = NULL;
    udp = NULL;
    direct = Cli2Ser;

    datalen = packetlen;
    data = new Byte[packetlen];
    memcpy(data,newdata,packetlen);        // memory copy
    parse();
}

Packet::~Packet(){
    if(data){
        delete []data;
    }
}

// must have prepare data and datalen
void Packet::parse(){
    ethernet=(eth_hdr *)data;
    if(ntohs(ethernet->eth_type)==0x0800){
        ip=(ip_hdr *)(data+ETH_HEADER_LENGTH);
        tuple5.saddr = ntohl(*(uint32_t *)ip->sourceIP);
        tuple5.daddr = ntohl(*(uint32_t *)ip->destIP);

        if(ip->protocol==TCP_PROTOCOL_ID){
            tcp=(tcp_hdr *)(data+ETH_HEADER_LENGTH+IP_HEADER_LENGTH);
            tuple5.sport = ntohs(tcp->sport);
            tuple5.dport = ntohs(tcp->dport);
            tuple5.tranType = TranType_TCP;
        }
        else if(ip->protocol==UDP_PROTOCOL_ID){
            udp=(udp_hdr *)(data+ETH_HEADER_LENGTH+IP_HEADER_LENGTH);
            tuple5.sport = ntohs(udp->sport);
            tuple5.dport = ntohs(udp->dport);
            tuple5.tranType = TranType_UDP;
        }
        // ! necessary, make sure tuple dport is less then sport(server always small port just like 80 8080 21 22 etc)
        if(tuple5.sport<tuple5.dport){
            tuple5.Reverse();
            direct = Ser2Cli;
        }
    }
}