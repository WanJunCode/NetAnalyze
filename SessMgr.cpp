#include "StructDefine.h"
#include "Packet.h"
#include "SessMgr.h"
#include <stdio.h>
#include <pcap.h>
#include <assert.h>


SessMgr::SessMgr(uint32_t hashnum){
    hashCalc.Init(hashnum);
    allPktnum = 0;
    tcpPktNum = 0;
    udpPktNum = 0;
    tcpSession = 0;
    otherPktNum = 0;
    noethNum = 0;
}

SessMgr::~SessMgr(){
    LOG_DEBUG("all packet %d\nno eth num %d\ntcp packet %d\nudp packet num %d\nother packet %d\n",allPktnum,noethNum,tcpPktNum,udpPktNum,otherPktNum);

    int numOfNode=0;
    int numTcpPkt=0;
    for(auto i : TCPSessMap){
        numOfNode+=i.second->numNode;
        numTcpPkt+=i.second->numPkt;
        delete i.second;
    }
    LOG_DEBUG("tcp session %d\ntcp session node %d\ntcp packet %d\n",tcpSession,numOfNode,numTcpPkt);
    for(auto i : UDPSessMap){
        delete i.second;
    }
}

uint32_t SessMgr::getMapCount() const{
    return 0;
}

void SessMgr::feedPkt(const struct pcap_pkthdr *packet_header, const unsigned char *packet_content){
    allPktnum++;
    LOG_DEBUG("No.%d\n",allPktnum);
    // parse Packet
    Packet *packet = new Packet(packet_content,packet_header->caplen);
    if(packet){
        auto hashkey = hashCalc.CalcHashValue(packet->tuple5);
        packet->tuple5.iHashValue = hashkey;

        if(packet->tuple5.tranType == TranType_TCP){
            tcpPktNum++;
            if(TCPSessMap.find(hashkey) == TCPSessMap.end()){
                tcpSession++;
                TCPSessMap[hashkey] = new HashSlot();
            }
            TCPSessMap[hashkey]->process(packet);
        }else if(packet->tuple5.tranType == TranType_UDP){
            udpPktNum++;
            if(UDPSessMap.find(hashkey) == UDPSessMap.end()){
                UDPSessMap[hashkey] = new HashSlot();
            }
            UDPSessMap[hashkey]->process(packet);
        }else{
            otherPktNum++;
        }

        delete packet;
    }else{
        LOG_DEBUG("create new Packet fail\n");
    }
    
#if 0
    LOG_DEBUG("Packet length : %d\n",packet_header->len);
    LOG_DEBUG("Number of bytes : %d\n",packet_header->caplen);
    LOG_DEBUG("Received time : %s\n",ctime((const time_t*)&packet_header->ts.tv_sec));
    for(int i=0;i<packet_header->caplen;i++){
        LOG_DEBUG(" %02x",packet_content[i]);
        if((i+1)%16==0){
            LOG_DEBUG("\n");
        }
    }
    LOG_DEBUG("\n\n");
    LOG_DEBUG("analyse information:\n\n");
    LOG_DEBUG("ethernet header information:\n");
    LOG_DEBUG("src_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->src_mac[0],ethernet->src_mac[1],ethernet->src_mac[2],ethernet->src_mac[3],ethernet->src_mac[4],ethernet->src_mac[5]);
    LOG_DEBUG("dst_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->dst_mac[0],ethernet->dst_mac[1],ethernet->dst_mac[2],ethernet->dst_mac[3],ethernet->dst_mac[4],ethernet->dst_mac[5]);
    LOG_DEBUG("ethernet type : %u\n",ethernet->eth_type);

        LOG_DEBUG("IPV4 is used\n");
        LOG_DEBUG("IPV4 header information:\n");
        // 偏移获得 ip 数据包头
        LOG_DEBUG("source ip : %d.%d.%d.%d\n",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
        LOG_DEBUG("dest ip : %d.%d.%d.%d\n",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);
            LOG_DEBUG("urg_ptr : %u\n",ntohs(tcp->urg_ptr));
#endif

}


// ===============================================================
static void printPacket(Packet *packet){
    if(packet->tuple5.tranType == TranType_TCP){
        LOG_DEBUG(" %s packet seq [%u] ack [%u] datalen [%u] headlen [%d]\n", (packet->direct == Cli2Ser)?"===>":"<===" 
            ,packet->getSeq(),packet->getAck(),packet->getDatalen(),packet->getHeadlen());
    }
}

SessionNode::SessionNode(Packet *pkt):_tuple(pkt->tuple5),numberPkt(0){
    fd = fopen(_tuple.getName().c_str(),"a");
    if(fd == NULL){
        LOG_DEBUG("fd create fail\n");
    }

    // judge client and server
    pSessAsmInfo = new SessAsmInfo();
}

SessionNode::~SessionNode(){
    fclose(fd);

    if(pSessAsmInfo){
        delete pSessAsmInfo;
        pSessAsmInfo = NULL;
    }
}

bool SessionNode::match(NetTuple5 tuple){
    if(memcmp(&_tuple,&tuple,sizeof(NetTuple5))==0 || (tuple.saddr==_tuple.daddr && tuple.sport==_tuple.dport)){
        return true;
    }
    return false;
}

void SessionNode::process(Packet *pkt){
    printPacket(pkt);
    numberPkt++;
    assert(pSessAsmInfo != NULL);
    // source port greater then destination port

    if( (pkt->direct == Cli2Ser && pSessAsmInfo->pClientAsmInfo == NULL) ||
        (pkt->direct == Ser2Cli && pSessAsmInfo->pServerAsmInfo == NULL) ){
        CreateAsmInfo(pkt);
    }

    if(_tuple.tranType==TranType_TCP){
        AssembPacket(pkt);
    }else if(_tuple.tranType==TranType_UDP){
        fwrite(pkt->data,1,pkt->datalen,fd);
    }else{
        LOG_DEBUG("other transport protocol\n");
    }
}

void SessionNode::CreateAsmInfo(Packet *packet){
    AssemableInfo *info = NULL;
    if(packet->direct == Cli2Ser){
        pSessAsmInfo->pClientAsmInfo = new AssemableInfo();
        info = pSessAsmInfo->pClientAsmInfo;
    }else{
        pSessAsmInfo->pServerAsmInfo = new AssemableInfo();
        info = pSessAsmInfo->pServerAsmInfo;
    }

    // info could be clientInfo or serverInfo
    if( packet->tcp ){
        info->first_data_seq  = info->seq = packet->getSeq();
        info->ack_seq = packet->getAck();
        info->tcpState = TCP_ESTABLED;
    }

    if(packet->tuple5.tranType == TranType_TCP){
        if(packet->direct == Cli2Ser){
            LOG_DEBUG("first Packet ===> first data seq [%u] ack [%u]\n",packet->getSeq(),packet->getAck());
        }else{
            LOG_DEBUG("first Packet <=== first data seq [%u] ack [%u]\n",packet->getSeq(),packet->getAck());
        }
    }
}

int SessionNode::AssembPacket(Packet *packet){
    if(packet->getDatalen()>0){
        LOG_DEBUG("%s new data [%u]\n",(packet->direct == Cli2Ser)?"===>":"<===", packet->getDatalen())
        fwrite(packet->data + (packet->getHeadlen() * 4),1,packet->getDatalen(),fd);
    }

    if(packet->direct == Cli2Ser){

    }else{

    }
    return 0;
}

//=================================================================================
HashSlot::HashSlot(){
    numNode = 0;
    numPkt = 0;
}

HashSlot::~HashSlot(){
    for(auto node: nodelist){
        delete node;
    }
}

// packet into the right hashkey Session process
void HashSlot::process(Packet *packet){
    numPkt++;
    auto node = match(packet->tuple5);   // traverse to find correct Session Node
    if(node == NULL){
        // can't find node, create new one and put into nodelist
        node = createSessionNode(packet);
    }
    // process pkt and delete
    node->process(packet);
}

SessionNode *HashSlot::match(NetTuple5 tuple){
    for(auto node : nodelist){
        if(node->match(tuple)){
            return node;
        }
    }
    return NULL;
}

SessionNode *HashSlot::createSessionNode(Packet *pkt){
    numNode++;
    auto node = new SessionNode(pkt);
    nodelist.push_back(node);
    return node;
}
