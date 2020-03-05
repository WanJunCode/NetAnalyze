#define LOG_MODULE PacketLogModuleRawPacket

#include "RawPacket.h"
#include <string.h>
#include "Logger.h"

namespace pcpp
{

void RawPacket::init()
{
	m_RawData = 0;
	m_RawDataLen = 0;
	m_FrameLength = 0;
	m_DeleteRawDataAtDestructor = true;			// 默认情况下需要负责删除 raw data
	m_RawPacketSet = false;
	m_LinkLayerType = LINKTYPE_ETHERNET;
}

// 未处理数据包 构造函数
RawPacket::RawPacket(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor, LinkLayerType layerType)
{
	init();
	m_DeleteRawDataAtDestructor = deleteRawDataAtDestructor;
	setRawData(pRawData, rawDataLen, timestamp, layerType);
}

RawPacket::RawPacket()
{
	init();
}

RawPacket::~RawPacket()
{
	if (m_DeleteRawDataAtDestructor)
	{
		delete[] m_RawData;
	}
}

// 拷贝构造函数
RawPacket::RawPacket(const RawPacket& other)
{
	m_RawData = NULL;
	copyDataFrom(other, true);
}

// 拷贝赋值函数
RawPacket& RawPacket::operator=(const RawPacket& other)
{
	if (m_RawData != NULL)
		delete [] m_RawData;

	m_RawPacketSet = false;

	copyDataFrom(other, true);

	return *this;
}

// allocateData 是否需要创建内存数据
void RawPacket::copyDataFrom(const RawPacket& other, bool allocateData)
{
	if (!other.m_RawPacketSet)
		return;

	m_TimeStamp = other.m_TimeStamp;

	if (allocateData)
	{
		m_DeleteRawDataAtDestructor = true;
		m_RawData = new uint8_t[other.m_RawDataLen];
		m_RawDataLen = other.m_RawDataLen;
	}

	memcpy(m_RawData, other.m_RawData, other.m_RawDataLen);
	m_LinkLayerType = other.m_LinkLayerType;
	m_FrameLength = other.m_FrameLength;
	m_RawPacketSet = true;
}

// 设置数据，该数据在外部通过new创建，需要RawPacket进行delete释放
bool RawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, LinkLayerType layerType, int frameLength)
{
	if(frameLength == -1)
		frameLength = rawDataLen;			// 如果没有设置 frameLength 则赋值为 rawDataLen
	m_FrameLength = frameLength;
	if (m_RawData != 0 && m_DeleteRawDataAtDestructor)
	{
		delete[] m_RawData;					// 删除之前的 raw data
	}

	m_RawData = (uint8_t*)pRawData;
	m_RawDataLen = rawDataLen;
	m_TimeStamp = timestamp;
	m_RawPacketSet = true;
	m_LinkLayerType = layerType;
	return true;
}

const uint8_t* RawPacket::getRawData() const
{
	return m_RawData;
}

const uint8_t* RawPacket::getRawDataReadOnly() const
{
	return m_RawData;
}
		
LinkLayerType RawPacket::getLinkLayerType() const
{
	return m_LinkLayerType;
}

int RawPacket::getRawDataLen() const
{
	return m_RawDataLen;
}

int RawPacket::getFrameLength() const
{
	return m_FrameLength;
}

timeval RawPacket::getPacketTimeStamp() const
{
	return m_TimeStamp;
}

void RawPacket::clear()
{
	if (m_RawData != 0)
		delete[] m_RawData;

	m_RawData = 0;
	m_RawDataLen = 0;
	m_FrameLength = 0;
	m_RawPacketSet = false;
}

// 添加数据到 raw data 后，需要确保 m_RawData 开辟的内存足够
void RawPacket::appendData(const uint8_t* dataToAppend, size_t dataToAppendLen)
{
	memcpy((uint8_t*)m_RawData+m_RawDataLen, dataToAppend, dataToAppendLen);
	m_RawDataLen += dataToAppendLen;
	m_FrameLength = m_RawDataLen;
}

// 插入数据，内部使用 memcpy 进行内存块的复制
// 插入位置 int atIndex
// 要插入的数据 const uint8_t* dataToInsert
// 插入的数据长度 size_t dataToInsertLen
void RawPacket::insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen)
{
	int index = m_RawDataLen-1;
	// 从 atIndex 开始都向后移动 dataToInsertLen 长度
	while (index >= atIndex)
	{
		m_RawData[index+dataToInsertLen] = m_RawData[index];
		index--;
	}

	memcpy((uint8_t*)m_RawData+atIndex, dataToInsert, dataToInsertLen);
	m_RawDataLen += dataToInsertLen;
	m_FrameLength = m_RawDataLen;
}

// 重新创建内存块
bool RawPacket::reallocateData(size_t newBufferLength)
{
	if ((int)newBufferLength == m_RawDataLen)
		return true;

	if ((int)newBufferLength < m_RawDataLen)
	{
		LOG_ERROR("Cannot reallocate raw packet to a smaller size. Current data length: %d; requested length: %d", m_RawDataLen, (int)newBufferLength);
		return false;
	}

	uint8_t* newBuffer = new uint8_t[newBufferLength];
	// 内存操作，速度更快
	memset(newBuffer, 0, newBufferLength);
	memcpy(newBuffer, m_RawData, m_RawDataLen);
	if (m_DeleteRawDataAtDestructor)
		delete [] m_RawData;

	m_DeleteRawDataAtDestructor = true;
	m_RawData = newBuffer;

	return true;
}

bool RawPacket::removeData(int atIndex, size_t numOfBytesToRemove)
{
	if ((atIndex + (int)numOfBytesToRemove) > m_RawDataLen)
	{
		LOG_ERROR("Remove section is out of raw packet bound");
		return false;
	}

	int index = atIndex;

	// ====================xxxxxxxxxxx======
	// ====================           ======  需要把后面的复制到前面
	while (index < (m_RawDataLen - (int)numOfBytesToRemove))
	{
		m_RawData[index] = m_RawData[index+numOfBytesToRemove];
		index++;
	}

	m_RawDataLen -= numOfBytesToRemove;
	m_FrameLength = m_RawDataLen;
	return true;
}

} // namespace pcpp
