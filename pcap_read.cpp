#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <string.h>


struct Pcap_pkthdr 
{
	uint32_t tv_sec;  /* time stamp */
	uint32_t tv_usec;
	uint32_t caplen; /* length of portion present */
	uint32_t len;	 /* length this packet (off wire) */
	uint32_t pad;
	// ..
};

int main(int argc,char *argv[])
{
    FILE *file;
    file = fopen(argv[1], "r");
	// pcap文件头部结构体
	struct pcap_file_header fileHdr;
	// 报文头部结构体
	struct Pcap_pkthdr pktHdr;

	// 存储报文内容
	char *pPktBuf = NULL;
    int iBufLen = 0;
    
    // 读取数据包头部
	fread((char*)&fileHdr, 1, sizeof(struct pcap_file_header), file);
	if(feof(file) || ferror(file))
	{
		printf("Read Pcap File %s Header Error, Packet Check!\n", argv[1]);
		return 0;
	}

	while(1)
	{
        // 读取 pkt header
		fread((char*)&pktHdr, 1, sizeof(struct Pcap_pkthdr), file);
		if(feof(file) || ferror(file))
		{
			break;
		}

		// 动态开辟内存
		pPktBuf = (char *)malloc(pktHdr.caplen);
        printf("pktHdr.caplen = [%lu]\n",pktHdr.caplen);
		fread(pPktBuf, 1, pktHdr.caplen, file);

		if(feof(file) || ferror(file))
		{
			free(pPktBuf);
			pPktBuf = NULL;
			break;
		}

		free(pPktBuf);
		pPktBuf = NULL;
    }

    return 0;
}