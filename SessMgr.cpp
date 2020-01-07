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
    // parse Packet
    Packet *packet = new Packet(packet_content,packet_header->caplen);

    if(packet){
        // filter http package : TCP and PORT [80]
        if( packet->tuple5.tranType != TranType_TCP || (packet->tuple5.sport != 80 && packet->tuple5.dport != 80) ){
            return;
        }
        tcpPktNum++;
        auto hashkey = hashCalc.CalcHashValue(packet->tuple5);
        packet->tuple5.iHashValue = hashkey;

        if(TCPSessMap.find(hashkey) == TCPSessMap.end()){
            tcpSession++;
            TCPSessMap[hashkey] = new HashSlot();
        }
        TCPSessMap[hashkey]->process(packet);           // input

        delete packet;
    }else{
        LOG_DEBUG("create new Packet fail\n");
    }

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
    static uint32_t num = 1;
    LOG_DEBUG("NO.%u\n",num++);

    // check
    assert(pSessAsmInfo != NULL);
    if(!pkt){
        return;
    }

    printPacket(pkt);
    numberPkt++;

    // direct first package
    if( (pkt->direct == Cli2Ser && pSessAsmInfo->pClientAsmInfo == NULL) ||
        (pkt->direct == Ser2Cli && pSessAsmInfo->pServerAsmInfo == NULL) ){
        CreateAsmInfo(pkt);
    }

    int ret = AssembPacket(pkt);
    if(ret == 0){
        // 收到新数据
        LOG_DEBUG("reveive new data\n");
    }else if(ret == -1){
        // 收到乱序数据
        LOG_DEBUG("reveive disorder data\n");
    }else if(ret == -2){
        // 没有收到数据
        LOG_DEBUG("no data\n");
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
        LOG_DEBUG("FIN package\n");
    }

    // pkg has data 
    if(packet->getDatalen()>0){
        LOG_DEBUG("iExpSeq = [%u] SEQ = [%u]\n",sender->getExcept(),packet->getSeq());
        // retransfer or normal package
        if (packet->getSeq() <= sender->getExcept()){
            uint32_t iReTranPktBufLen = sender->getExcept() - packet->getSeq();
            // ! 判断数据包中是否有新的数据,去除重传数据,有可能出现负数
            int newDataLen = packet->getDatalen() - iReTranPktBufLen;
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
                }
                LOG_DEBUG("new data [%d]\n",newDataLen);
                memcpy(sender->data+sender->count-sender->offset, packet->data+iReTranPktBufLen, newDataLen);//根据seq偏移,进行报文拼包
                sender->count_new = newDataLen;     //最新增加的数据长度
                sender->count += newDataLen;
                
                // 写入文件
                fwrite(packet->data+iReTranPktBufLen,1,newDataLen,fd);

                // TODO 处理乱序报文

            }else{
                // TODO 重传数据包

            }
        }else{
            // TODO get disorder pkg
            LOG_DEBUG("GET disorder package seq[%u] but expect seq[%u]\n",packet->getSeq(),sender->getExcept());
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
