#include "SessMgr.h"
#include "Log.h"

#include <pcap.h>


// HashCalc hashCalc;
// std::map<uint32_t,uint32_t> SessMap;
SessMgr *sessmgr;

// const struct pcap_pkthdr *packet_header  传入数据包的pcap头
// const unsigned char *packet_content      传入数据包的实际内容
void parse_callback(unsigned char *arg, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content){
   
    // input
    sessmgr->feedPkt(packet_header, packet_content);
}

int main(int argc, char *argv[]){
    SessMgr mgr(100000);
    sessmgr=&mgr;
    
    LOG_DEBUG("PCAP start...\n");
    char errBuf[PCAP_ERRBUF_SIZE];

    pcap_t *device = pcap_open_offline(argv[1],errBuf);
  
    if(!device){
        LOG_DEBUG("error: pcap_open_offline(): %s\n", errBuf);
        exit(1);
    }

    /* wait loop forever */
    pcap_loop(device, -1, parse_callback, NULL);
  
    pcap_close(device);

    return 0;
}
