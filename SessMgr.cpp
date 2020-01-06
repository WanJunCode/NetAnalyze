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
    LOG_DEBUG("\n\n",allPktnum);
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
        LOG_DEBUG(" %s packet seq [%u] ack [%u] datalen [%u]\n", (packet->direct == Cli2Ser)?"===>":"<===" 
            ,packet->getSeq(),packet->getAck(),packet->getDatalen());
    }
}

SessionNode::SessionNode(Packet *pkt):_tuple(pkt->tuple5),numberPkt(0),datalen(0){
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
    assert(pSessAsmInfo != NULL);
    if(!pkt){
        return;
    }

    if(pkt->isSyn()){
        LOG_DEBUG("三次握手\n");
    }

    printPacket(pkt);
    numberPkt++;

    // first package
    if( (pkt->direct == Cli2Ser && pSessAsmInfo->pClientAsmInfo == NULL) ||
        (pkt->direct == Ser2Cli && pSessAsmInfo->pServerAsmInfo == NULL) ){
        CreateAsmInfo(pkt);
    }

    if(_tuple.tranType == TranType_TCP){
        AssembPacket(pkt);
    }else if(_tuple.tranType == TranType_UDP){
        // fwrite(pkt->data,1,pkt->datalen,fd);
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

    // info could be clientInfo or serverInfo, set [first seq、 seq 、 ack]
    if( packet->tcp ){
        info->first_data_seq  = info->seq = packet->getSeq() + 1;
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

// only work for TCP 将新数据读取并复制到  client->data 缓存中
// return -2 没有数据
// return -1 接受到乱序数据
// return 0  接受到新数据
int SessionNode::AssembPacket(Packet *packet){
    assert(packet->tuple5.tranType == TranType_TCP);

    AssemableInfo *sender = NULL;
    if(packet->direct == Cli2Ser){
        assert(pSessAsmInfo->pClientAsmInfo);
        sender = pSessAsmInfo->pClientAsmInfo;
    }else{
        assert(pSessAsmInfo->pServerAsmInfo);
        sender = pSessAsmInfo->pServerAsmInfo;
    }

    // update TCP ack
    if(packet->getAck() > sender->ack_seq){
        sender->ack_seq = packet->getAck();
    }

    // update TCP seq
    if(packet->getSeq() > sender->seq){
        sender->seq = packet->getSeq();
    }

    // judge fin package
    if(packet->isFin()){
        sender->tcpState = TCP_FIN;
        LOG_DEBUG("四次挥手\n");
    }

    // pkg has data 
    if(packet->getDatalen()>0){
        uint32_t iExpSeq = sender->first_data_seq + sender->count;
        LOG_DEBUG("iExpSeq = [%u] SEQ = [%u]\n",iExpSeq,packet->getSeq());
        // retransfer or normal package
        if (packet->getSeq() <= iExpSeq){
            uint32_t iReTranPktBufLen = iExpSeq - packet->getSeq();
            // ! 判断数据包中是否有新的数据,去除重传数据,有可能出现负数
            int newDataLen = packet->getDatalen() - iReTranPktBufLen;
            LOG_DEBUG("iReTranPktBufLen = [%u]\n",iReTranPktBufLen);
	        if(newDataLen > 0){
                if(newDataLen + sender->count - sender->offset > sender->bufsize){
                    // not enough buffer
                    uint32_t iAssembleBufLen = 0;
                    if(!sender->data){
                        if(newDataLen < 8192)	// 新的数据是否小于 8192 = 4K
                        {
                            iAssembleBufLen = 24576;	// 24576 = 8192*3
                        }else{
                            iAssembleBufLen = newDataLen * 3;
                        }
                        sender->data = new char[iAssembleBufLen];		//预申请拼包缓存空间
                        sender->bufsize = iAssembleBufLen;				//更新缓冲区长度
                    }else{
                        //当前拼包缓存已经分配空间,但缓存空间不够,需要扩大缓存空间
                        if (newDataLen < sender->bufsize)
                        {
                            iAssembleBufLen = 3 * (sender->bufsize);
                        }else{
                            iAssembleBufLen = (sender->bufsize) + 3*newDataLen;
                        }
                        // new 创建的内存不足，使用realloc重新创建可能会有问题
                        char *tmpData = new char[iAssembleBufLen];
                        memcpy(tmpData,sender->data,sender->count - sender->offset);    // copy origin data
                        delete []sender->data;
                        sender->data = tmpData;
                        sender->bufsize = iAssembleBufLen;
                    }
                    LOG_DEBUG("new sender bufsize = [%u]\n",sender->bufsize);
                }
                memcpy(sender->data + sender->count - sender->offset, packet->data + iReTranPktBufLen, newDataLen);//根据seq偏移,进行报文拼包
                sender->count_new = newDataLen;     //最新增加的数据长度
                sender->count += newDataLen;
            }else{
                LOG_DEBUG("there is no new data in package\n");
            }
        }else{
            // TODO get disorder pkg
            LOG_DEBUG("GET disorder package seq[%u] but expect seq[%u]\n",packet->getSeq(),iExpSeq);
        }
    }else{
        return -2;
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
    if(node){
        node->process(packet);
    }
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
    if(node){
        nodelist.push_back(node);
    }else{
        LOG_ERROR("create Session Node fail\n");
    }
    return node;
}
