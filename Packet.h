#ifndef PACKET_H
#define PACKET_H

#include "StructDefine.h"

#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <pcap.h>

typedef unsigned char Byte;

enum Direct{
    Cli2Ser,
    Ser2Cli
};

// aaaaaaaa bbbbbbbb cccccccc dddddddd
// dddddddd cccccccc bbbbbbbb aaaaaaaa
static uint32_t swap32(uint32_t a){
    return (((a>>24)&0xFF)<<0) | (((a>>16)&0xFF)<<8) | (((a>>8)&0xFF)<<16) | (((a>>0)&0xFF)<<24);
}

class Packet{
public:
    Packet(const Byte *newdata,uint32_t packetlen);

    ~Packet();

    void parse();

    uint32_t getSeq(){
        assert(tcp);
        return swap32(tcp->seq);
    }

    uint32_t getAck(){
        assert(tcp);
        return swap32(tcp->ack);
    }

    uint16_t getHeadlen(){
        assert(tcp);
        return tcp->reserved;
    }

    uint16_t getWinsize(){
        assert(tcp);
        return ntohs(tcp->wind_size);
    }

    uint16_t getChecksun(){
        assert(tcp);
        return ntohs(tcp->check_sum);
    }

    uint32_t getDatalen(){
        return datalen - (34 + getHeadlen()*4);
    }

    Byte *data;
    uint32_t datalen;
    eth_hdr *ethernet;
    ip_hdr *ip;
    tcp_hdr *tcp;
    udp_hdr *udp;
    NetTuple5 tuple5;
    Direct direct;
};

#endif