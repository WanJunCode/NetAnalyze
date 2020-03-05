#define LOG_MODULE PacketLogModuleTcpLayer

#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "HttpLayer.h"
#include "SSLLayer.h"
#include "SipLayer.h"
#include "IpUtils.h"
#include "Logger.h"
#include <string.h>
#include <sstream>

namespace pcpp
{

#define TCPOPT_DUMMY 0xff

/// ~~~~~~~~~~~~~~~~
/// TcpOptionBuilder   TCP选项构建器
/// ~~~~~~~~~~~~~~~~

// NOP or EOL
TcpOptionBuilder::TcpOptionBuilder(NopEolOptionTypes optionType)
{
	switch (optionType)
	{
	case EOL:
		init((uint8_t)PCPP_TCPOPT_EOL, NULL, 0);
		break;
	case NOP:
	default:
		init((uint8_t)PCPP_TCPOPT_NOP, NULL, 0);
		break;
	}
}

// 建造者模式
// 根据内部的TLV创建并返回 TcpOption
TcpOption TcpOptionBuilder::build() const
{
	// 记录选项的大小
	size_t optionSize = m_RecValueLen + 2*sizeof(uint8_t);		// L + TV

	if (m_RecType == (uint8_t)PCPP_TCPOPT_EOL || m_RecType == (uint8_t)PCPP_TCPOPT_NOP)
	{
		if (m_RecValueLen != 0)
		{
			LOG_ERROR("TCP NOP and TCP EOL options are 1-byte long and don't have option value. Tried to set option value of size %d", m_RecValueLen);
			return TcpOption(NULL);
		}

		optionSize = 1;
	}

	uint8_t* recordBuffer = new uint8_t[optionSize];
	memset(recordBuffer, 0, optionSize);
	recordBuffer[0] = m_RecType;										// 设置 T
	if (optionSize > 1)
	{
		recordBuffer[1] = (uint8_t)optionSize;							// 设置 L
		if (optionSize > 2 && m_RecValue != NULL)
			memcpy(recordBuffer+2, m_RecValue, m_RecValueLen);			// 设置 V
	}

	return TcpOption(recordBuffer);
}



/// ~~~~~~~~
/// TcpLayer
/// ~~~~~~~~

// 根据选项类型获取TCP option
TcpOption TcpLayer::getTcpOption(TcpOptionType option) const
{
	return m_OptionReader.getTLVRecord((uint8_t)option, getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
}

// 获取第一个 TCP option
TcpOption TcpLayer::getFirstTcpOption() const
{
	return m_OptionReader.getFirstTLVRecord(getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
}

// 根据已获取的 TcpOption 获取下一个 Tcp option
TcpOption TcpLayer::getNextTcpOption(TcpOption& tcpOption) const
{
	TcpOption nextOpt = m_OptionReader.getNextTLVRecord(tcpOption, getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
	if (nextOpt.isNotNull() && nextOpt.getType() == TCPOPT_DUMMY)
		return TcpOption(NULL);

	return nextOpt;
}

// 获取 tcp option 的数量
size_t TcpLayer::getTcpOptionCount() const
{
	return m_OptionReader.getTLVRecordCount(getOptionsBasePtr(), getHeaderLen() - sizeof(tcphdr));
}

// 添加 tcp option
TcpOption TcpLayer::addTcpOption(const TcpOptionBuilder& optionBuilder)
{
	return addTcpOptionAt(optionBuilder, getHeaderLen()-m_NumOfTrailingBytes);
}

TcpOption TcpLayer::addTcpOptionAfter(const TcpOptionBuilder& optionBuilder, TcpOptionType prevOptionType)
{
	int offset = 0;

	if (prevOptionType == TCPOPT_Unknown)
	{
		offset = sizeof(tcphdr);			// 直接增加在tcp头部后面
	}
	else
	{
		// 遍历所有的 tcp 选项
		TcpOption prevOpt = getTcpOption(prevOptionType);
		if (prevOpt.isNull())
		{
			LOG_ERROR("Previous option of type %d not found, cannot add a new TCP option", (int)prevOptionType);
			return TcpOption(NULL);
		}

		offset = prevOpt.getRecordBasePtr() + prevOpt.getTotalSize() - m_Data;
	}
	return addTcpOptionAt(optionBuilder, offset);
}

bool TcpLayer::removeTcpOption(TcpOptionType optionType)
{
	TcpOption opt = getTcpOption(optionType);	// 遍历获取
	if (opt.isNull())
	{
		return false;
	}

	// calculate total TCP option size
	TcpOption curOpt = getFirstTcpOption();
	size_t totalOptSize = 0;
	while (!curOpt.isNull())
	{
		totalOptSize += curOpt.getTotalSize();
		curOpt = getNextTcpOption(curOpt);
	}
	totalOptSize -= opt.getTotalSize();		// 减去要删除的Opt的大小


	int offset = opt.getRecordBasePtr() - m_Data;

	if (!shortenLayer(offset, opt.getTotalSize()))		// 收缩Opt的长度
	{
		return false;
	}

	adjustTcpOptionTrailer(totalOptSize);				// 调整TCP选项尾部

	m_OptionReader.changeTLVRecordCount(-1);

	return true;
}

bool TcpLayer::removeAllTcpOptions()
{
	int offset = sizeof(tcphdr);

	if (!shortenLayer(offset, getHeaderLen()-offset))
		return false;

	getTcpHeader()->dataOffset = sizeof(tcphdr)/4;
	m_NumOfTrailingBytes = 0;
	m_OptionReader.changeTLVRecordCount(0-getTcpOptionCount());
	return true;
}

// 在指定偏移位置offset增加TCP选项
// TCP option由optionBuilder创建
TcpOption TcpLayer::addTcpOptionAt(const TcpOptionBuilder& optionBuilder, int offset)
{
	TcpOption newOption = optionBuilder.build();
	if (newOption.isNull())
		return newOption;

	// calculate total TCP option size  计算TCP选项的总长度
	TcpOption curOpt = getFirstTcpOption();
	size_t totalOptSize = 0;
	while (!curOpt.isNull())
	{
		totalOptSize += curOpt.getTotalSize();
		curOpt = getNextTcpOption(curOpt);
	}
	totalOptSize += newOption.getTotalSize();		// 获得增加TCP option后的总长度

	size_t sizeToExtend = newOption.getTotalSize();

	if (!extendLayer(offset, sizeToExtend))
	{
		LOG_ERROR("Could not extend TcpLayer in [%d] bytes", (int)sizeToExtend);
		newOption.purgeRecordData();
		return TcpOption(NULL);
	}

	// 将新的TCP option内存复制到 m_Data 中
	memcpy(m_Data + offset, newOption.getRecordBasePtr(), newOption.getTotalSize());

	newOption.purgeRecordData();

	adjustTcpOptionTrailer(totalOptSize);		// 调整 tcp option

	m_OptionReader.changeTLVRecordCount(1);

	uint8_t* newOptPtr = m_Data + offset;

	return TcpOption(newOptPtr);
}

// 调整TCP选项的尾部
// size_t totalOptSize  TCP选项的总长度
void TcpLayer::adjustTcpOptionTrailer(size_t totalOptSize)
{
	int newNumberOfTrailingBytes = 0;
	// 4字节对齐
	while ((totalOptSize + newNumberOfTrailingBytes) % 4 != 0)
		newNumberOfTrailingBytes++;

	if (newNumberOfTrailingBytes < m_NumOfTrailingBytes)
		shortenLayer(sizeof(tcphdr)+totalOptSize, m_NumOfTrailingBytes - newNumberOfTrailingBytes);
	else if (newNumberOfTrailingBytes > m_NumOfTrailingBytes)
		extendLayer(sizeof(tcphdr)+totalOptSize, newNumberOfTrailingBytes - m_NumOfTrailingBytes);

	m_NumOfTrailingBytes = newNumberOfTrailingBytes;

	for (int i = 0; i < m_NumOfTrailingBytes; i++)
		m_Data[sizeof(tcphdr) + totalOptSize + i] = TCPOPT_DUMMY;

	// 设置TCP头大小（4的倍数）
	getTcpHeader()->dataOffset = (sizeof(tcphdr) + totalOptSize + m_NumOfTrailingBytes)/4;
}

// 计算 总和校验码（计算之前需要重置check sum）
uint16_t TcpLayer::calculateChecksum(bool writeResultToPacket)
{
	tcphdr* tcpHdr = getTcpHeader();
	uint16_t checksumRes = 0;
	uint16_t currChecksumValue = tcpHdr->headerChecksum;

	if (m_PrevLayer != NULL)
	{
		tcpHdr->headerChecksum = 0;
		ScalarBuffer<uint16_t> vec[2];			// vec[0] 存储源数据指针和长度； vec[1] 
		LOG_DEBUG("data len =  %d", (int)m_DataLen);
		vec[0].buffer = (uint16_t*)m_Data;
		vec[0].len = m_DataLen;

		// 计算IP层的校验和
		if (m_PrevLayer->getProtocol() == IPv4)
		{	
			// TCP 从之前的 IPV4 layer 获得源、目的IP地址
			uint32_t srcIP = ((IPv4Layer*)m_PrevLayer)->getSrcIpAddress().toInt();
			uint32_t dstIP = ((IPv4Layer*)m_PrevLayer)->getDstIpAddress().toInt();
			uint16_t pseudoHeader[6];				// 假的 header
			pseudoHeader[0] = srcIP >> 16;
			pseudoHeader[1] = srcIP & 0xFFFF;		// 一个 F 表示 1111 四个bit
			pseudoHeader[2] = dstIP >> 16;
			pseudoHeader[3] = dstIP & 0xFFFF;
			pseudoHeader[4] = 0xffff & htons(m_DataLen);				// 主机字节序转网络字节序
			pseudoHeader[5] = htons(0x00ff & PACKETPP_IPPROTO_TCP);		// TCP在IP中的协议号，主机字节序转网络字节序
			vec[1].buffer = pseudoHeader;
			vec[1].len = 12;
			// 计算校验和
			checksumRes = compute_checksum(vec, 2);
			LOG_DEBUG("calculated checksum = 0x%4X", checksumRes);
		}
		else if (m_PrevLayer->getProtocol() == IPv6)
		{
			uint16_t pseudoHeader[18];
			((IPv6Layer*)m_PrevLayer)->getSrcIpAddress().copyTo((uint8_t*)pseudoHeader);
			((IPv6Layer*)m_PrevLayer)->getDstIpAddress().copyTo((uint8_t*)(pseudoHeader+8));
			pseudoHeader[16] = 0xffff & htons(m_DataLen);
			pseudoHeader[17] = htons(0x00ff & PACKETPP_IPPROTO_TCP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 36;
			checksumRes = compute_checksum(vec, 2);
			LOG_DEBUG("calculated checksum = 0x%4X", checksumRes);
		}
	}

	if(writeResultToPacket)
		tcpHdr->headerChecksum = htons(checksumRes);				// 主机字节序转网络字节序
	else
		tcpHdr->headerChecksum = currChecksumValue;

	return checksumRes;
}

void TcpLayer::initLayer()
{
	m_DataLen = sizeof(tcphdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = TCP;						// 标识当前协议类型为 TCP
	m_NumOfTrailingBytes = 0;
	getTcpHeader()->dataOffset = sizeof(tcphdr)/4;		// 默认是5
}

TcpLayer::TcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
{
	m_Protocol = TCP;
	m_NumOfTrailingBytes = 0;
}

TcpLayer::TcpLayer()
{
	initLayer();
}

TcpLayer::TcpLayer(uint16_t portSrc, uint16_t portDst)
{
	initLayer();
	// 设置 目标、源 端口号
	getTcpHeader()->portDst = htons(portDst);
	getTcpHeader()->portSrc = htons(portSrc);
}

void TcpLayer::copyLayerData(const TcpLayer& other)
{
	m_OptionReader = other.m_OptionReader;
	m_NumOfTrailingBytes = other.m_NumOfTrailingBytes;
}

TcpLayer::TcpLayer(const TcpLayer& other) : Layer(other)
{
	copyLayerData(other);
}

TcpLayer& TcpLayer::operator=(const TcpLayer& other)
{
	Layer::operator=(other);

	copyLayerData(other);

	return *this;
}

// 解析下一层协议
void TcpLayer::parseNextLayer()
{
	// 获得 TCP head 长度
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	uint8_t* payload = m_Data + headerLen;
	size_t payloadLen = m_DataLen - headerLen;
	tcphdr* tcpHder = getTcpHeader();
	// 网络字节序转主机字节序
	uint16_t portDst = ntohs(tcpHder->portDst);
	uint16_t portSrc = ntohs(tcpHder->portSrc);

	// TCP 下一层协议  HTTP SSL Sip

	if ((HttpMessage::getHTTPPortMap()->find(portDst) != HttpMessage::getHTTPPortMap()->end()) && HttpRequestFirstLine::parseMethod((char*)payload, payloadLen) != HttpRequestLayer::HttpMethodUnknown)
		m_NextLayer = new HttpRequestLayer(payload, payloadLen, this, m_Packet);
	else if ((HttpMessage::getHTTPPortMap()->find(portSrc) != HttpMessage::getHTTPPortMap()->end()) && HttpResponseFirstLine::parseStatusCode((char*)payload, payloadLen) != HttpResponseLayer::HttpStatusCodeUnknown)
		m_NextLayer = new HttpResponseLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	else if (SSLLayer::IsSSLMessage(portSrc, portDst, payload, payloadLen))
		m_NextLayer = SSLLayer::createSSLMessage(payload, payloadLen, this, m_Packet);
	else if (((portDst == 5060) || (portDst == 5061)) && (SipRequestFirstLine::parseMethod((char*)payload, payloadLen) != SipRequestLayer::SipMethodUnknown))
		m_NextLayer = new SipRequestLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	else if (((portDst == 5060) || (portDst == 5061)) && (SipResponseFirstLine::parseStatusCode((char*)payload, payloadLen) != SipResponseLayer::SipStatusCodeUnknown))
		m_NextLayer = new SipResponseLayer(payload, payloadLen, this, m_Packet);
	else
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
}

void TcpLayer::computeCalculateFields()
{
	tcphdr* tcpHdr = getTcpHeader();
	
	// 5*4 = 20 = 0001 0100 >> 2 = 0101 = 5
	tcpHdr->dataOffset = getHeaderLen() >> 2;
	calculateChecksum(true);						// 计算校验码并重写
}

// for debug
std::string TcpLayer::toString() const
{
	tcphdr* hdr = getTcpHeader();
	std::string result = "TCP Layer, ";
	if (hdr->synFlag)
	{
		if (hdr->ackFlag)
			result += "[SYN, ACK], ";
		else
			result += "[SYN], ";
	}
	else if (hdr->finFlag)
	{
		if (hdr->ackFlag)
			result += "[FIN, ACK], ";
		else
			result += "[FIN], ";
	}
	else if (hdr->ackFlag)
		result += "[ACK], ";

	std::ostringstream srcPortStream;
	srcPortStream << ntohs(hdr->portSrc);
	std::ostringstream dstPortStream;
	dstPortStream << ntohs(hdr->portDst);
	result += "Src port: " + srcPortStream.str() + ", Dst port: " + dstPortStream.str();

	return result;
}

} // namespace pcpp
