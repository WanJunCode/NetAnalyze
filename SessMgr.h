#ifndef SESSION_MANAGER
#define SESSION_MANAGER

#include <map>
#include <list>

#include "HashCalc.h"
#include "Packet.h"
#include "Log.h"
#include "StructDefine.h"

// SessMgr  HashSlot  SessionNode
//        1:n     1:n
//    std::map   std::list

// packet process flow
// SessMgr::feedPkt -> HashSlot::process -> SessionNode::process

class SessionNode{
public:
    SessionNode(Packet *pkt);

    ~SessionNode();

    bool match(NetTuple5 tuple);

    void process(Packet *pkt);

    void CreateAsmInfo(Packet *packet);

    int AssembPacket(Packet *packet);

    SessAsmInfo *pSessAsmInfo;
    uint32_t numberPkt;
    NetTuple5 _tuple;
    FILE *fd;                   // for saving packet data into file
};

// session use to recombine TCP stream
class HashSlot{
public:
    HashSlot();

    ~HashSlot();

    // packet into the right hashkey Session process
    void process(Packet *packet);

    SessionNode *match(NetTuple5 tuple);

    SessionNode *createSessionNode(Packet *pkt);
    
    uint32_t numNode;
    uint32_t numPkt;
    std::list<SessionNode *> nodelist;
};

class SessMgr{
public:
    SessMgr(uint32_t hashnum);

    ~SessMgr();

    void feedPkt(const struct pcap_pkthdr *packet_header, const unsigned char *packet_content);

    uint32_t getMapCount() const;

private:
    std::map<uint32_t,HashSlot *> TCPSessMap;
    std::map<uint32_t,HashSlot *> UDPSessMap;

    HashCalc hashCalc;

    int allPktnum;
    int noethNum;
    int tcpPktNum;
    int udpPktNum;
    int otherPktNum;
    int tcpSession;
    int tcpSessionNode;
};

#endif //SESSION_MANAGER