#include "TextBasedProtocol.h"
#include "Logger.h"
#include "PayloadLayer.h"
#include <string.h>
#include <algorithm>
#include <stdlib.h>

namespace pcpp
{

// this implementation of strnlen is required since mingw doesn't have strnlen
size_t tbp_my_own_strnlen(const char* s, size_t n)
{
	const char* p = s;
	/* We don't check here for NULL pointers.  */
	for (;*p != 0 && n > 0; p++, n--)
		;
	return (size_t) (p - s);
}


// -------- Class TextBasedProtocolMessage -----------------


TextBasedProtocolMessage::TextBasedProtocolMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet),
						m_FieldList(NULL), m_LastField(NULL), m_FieldsOffset(0) {}

TextBasedProtocolMessage::TextBasedProtocolMessage(const TextBasedProtocolMessage& other) : Layer(other)
{
	copyDataFrom(other);
}

TextBasedProtocolMessage& TextBasedProtocolMessage::operator=(const TextBasedProtocolMessage& other)
{
	Layer::operator=(other);
	HeaderField* curField = m_FieldList;
	while (curField != NULL)
	{
		HeaderField* temp = curField;
		curField = curField->getNextField();
		delete temp;
	}

	copyDataFrom(other);

	return *this;
}

void TextBasedProtocolMessage::copyDataFrom(const TextBasedProtocolMessage& other)
{
	// copy field list
	if (other.m_FieldList != NULL)
	{
		m_FieldList = new HeaderField(*(other.m_FieldList));
		HeaderField* curField = m_FieldList;
		curField->attachToTextBasedProtocolMessage(this, other.m_FieldList->m_NameOffsetInMessage);
		HeaderField* curOtherField = other.m_FieldList;
		while (curOtherField->getNextField() != NULL)
		{
			HeaderField* newField = new HeaderField(*(curOtherField->getNextField()));
			newField->attachToTextBasedProtocolMessage(this, curOtherField->getNextField()->m_NameOffsetInMessage);
			curField->setNextField(newField);
			curField = curField->getNextField();
			curOtherField = curOtherField->getNextField();
		}

		m_LastField = curField;
	}
	else
	{
		m_FieldList = NULL;
		m_LastField = NULL;
	}

	m_FieldsOffset = other.m_FieldsOffset;

	// copy map
	for(HeaderField* field = m_FieldList; field != NULL; field = field->getNextField())
	{
		m_FieldNameToFieldMap.insert(std::pair<std::string, HeaderField*>(field->getFieldName(), field));
	}
}

// 解析 field 字段
void TextBasedProtocolMessage::parseFields()
{
	// 不同的文本协议分割符不同且名称之间是否可以带有空格也不一样
	// 字段分割符号，是否允许字段名和值之间有空格
	// 纯虚函数，可以在这里获取子类的实现
	char nameValueSeperator = getHeaderFieldNameValueSeparator();
	bool spacesAllowedBetweenNameAndValue = spacesAllowedBetweenHeaderFieldNameAndValue();

	HeaderField* firstField = new HeaderField(this, m_FieldsOffset, nameValueSeperator, spacesAllowedBetweenNameAndValue);
	LOG_DEBUG("Added new field: name='%s'; offset in packet=%d; length=%d", firstField->getFieldName().c_str(), firstField->m_NameOffsetInMessage, (int)firstField->getFieldSize());
	LOG_DEBUG("     Field value = %s", firstField->getFieldValue().c_str());

	// 判断是否为第一个字段field
	if (m_FieldList == NULL)
		m_FieldList = firstField;
	else
		m_FieldList->setNextField(firstField);

	std::string fieldName = firstField->getFieldName();
	std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);				// 将字段名小写
	m_FieldNameToFieldMap.insert(std::pair<std::string, HeaderField*>(fieldName, firstField));		// 将字段添加到 multimap 中

	// Last field will be empty and contain just "\n" or "\r\n". This field will mark the end of the header
	HeaderField* curField = m_FieldList;
	int curOffset = m_FieldsOffset;
	// last field can be one of:
	// a.) \r\n\r\n or \n\n marking the end of the header
	// b.) the end of the packet
	while (!curField->isEndOfHeader() && curOffset + curField->getFieldSize() < m_DataLen)
	{
		curOffset += curField->getFieldSize();
		HeaderField* newField = new HeaderField(this, curOffset, nameValueSeperator, spacesAllowedBetweenNameAndValue);
		if(newField->getFieldSize() > 0)
		{
			LOG_DEBUG("Added new field: name='%s'; offset in packet=%d; length=%d", newField->getFieldName().c_str(), newField->m_NameOffsetInMessage, (int)newField->getFieldSize());
			LOG_DEBUG("     Field value = %s", newField->getFieldValue().c_str());
			curField->setNextField(newField);
			curField = newField;
			fieldName = newField->getFieldName();
			std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);
			m_FieldNameToFieldMap.insert(std::pair<std::string, HeaderField*>(fieldName, newField));
		}
		else
		{
			delete newField;
			break;
		}
	}

	m_LastField = curField;
}


TextBasedProtocolMessage::~TextBasedProtocolMessage()
{
	while (m_FieldList != NULL)
	{
		HeaderField* temp = m_FieldList;
		m_FieldList = m_FieldList->getNextField();
		delete temp;
	}
}


HeaderField* TextBasedProtocolMessage::addField(const std::string& fieldName, const std::string& fieldValue)
{
	HeaderField newField(fieldName, fieldValue, getHeaderFieldNameValueSeparator(), spacesAllowedBetweenHeaderFieldNameAndValue());
	return addField(newField);
}

HeaderField* TextBasedProtocolMessage::addField(const HeaderField& newField)
{
	return insertField(m_LastField, newField);
}

HeaderField* TextBasedProtocolMessage::addEndOfHeader()
{
	HeaderField endOfHeaderField(PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER, "", '\0', false);
	return insertField(m_LastField, endOfHeaderField);
}


HeaderField* TextBasedProtocolMessage::insertField(HeaderField* prevField, const std::string& fieldName, const std::string& fieldValue)
{
	HeaderField newField(fieldName, fieldValue, getHeaderFieldNameValueSeparator(), spacesAllowedBetweenHeaderFieldNameAndValue());
	return insertField(prevField, newField);
}

HeaderField* TextBasedProtocolMessage::insertField(std::string prevFieldName, const std::string& fieldName, const std::string& fieldValue)
{
	if (prevFieldName == "")
	{
		return insertField(NULL, fieldName, fieldValue);
	}
	else
	{
		HeaderField* prevField = getFieldByName(prevFieldName);
		if (prevField == NULL)
			return NULL;

		return insertField(prevField, fieldName, fieldValue);
	}
}


HeaderField* TextBasedProtocolMessage::insertField(HeaderField* prevField, const HeaderField& newField)
{
	if (newField.m_TextBasedProtocolMessage != NULL)
	{
		LOG_ERROR("This field is already associated with another message");
		return NULL;
	}

	if (prevField != NULL && prevField->getFieldName() == PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER)
	{
		LOG_ERROR("Cannot add a field after end of header");
		return NULL;
	}

	HeaderField* newFieldToAdd = new HeaderField(newField);

	int newFieldOffset = m_FieldsOffset;
	if (prevField != NULL)
		newFieldOffset = prevField->m_NameOffsetInMessage + prevField->getFieldSize();

	// extend layer to make room for the new field. Field will be added just before the last field
	if (!extendLayer(newFieldOffset, newFieldToAdd->getFieldSize()))
	{
		LOG_ERROR("Cannot extend layer to insert the header");
		delete newFieldToAdd;
		return NULL;
	}

	HeaderField* curField = m_FieldList;
	if (prevField != NULL)
		curField = prevField->getNextField();

	// go over all fields after prevField and update their offsets
	shiftFieldsOffset(curField, newFieldToAdd->getFieldSize());

	// copy new field data to message
	memcpy(m_Data + newFieldOffset, newFieldToAdd->m_NewFieldData, newFieldToAdd->getFieldSize());

	// attach new field to message
	newFieldToAdd->attachToTextBasedProtocolMessage(this, newFieldOffset);

	// insert field into fields link list
	if (prevField == NULL)
	{
		newFieldToAdd->setNextField(m_FieldList);
		m_FieldList = newFieldToAdd;
	}
	else
	{
		newFieldToAdd->setNextField(prevField->getNextField());
		prevField->setNextField(newFieldToAdd);
	}

	// if newField is the last field, update m_LastField
	if (newFieldToAdd->getNextField() == NULL)
		m_LastField = newFieldToAdd;

	// insert the new field into name to field map
	std::string fieldName = newFieldToAdd->getFieldName();
	std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);
	m_FieldNameToFieldMap.insert(std::pair<std::string, HeaderField*>(fieldName, newFieldToAdd));

	return newFieldToAdd;
}

bool TextBasedProtocolMessage::removeField(std::string fieldName, int index)
{
	std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);

	HeaderField* fieldToRemove = NULL;

	std::pair <std::multimap<std::string,HeaderField*>::iterator, std::multimap<std::string,HeaderField*>::iterator> range;
	range = m_FieldNameToFieldMap.equal_range(fieldName);
	int i = 0;
	for (std::multimap<std::string,HeaderField*>::iterator iter = range.first; iter != range.second; ++iter)
	{
		if (i == index)
		{
			fieldToRemove = iter->second;
			break;
		}

		i++;
	}

	if (fieldToRemove != NULL)
		return removeField(fieldToRemove);
	else
	{
		LOG_ERROR("Cannot find field '%s'", fieldName.c_str());
		return false;
	}
}

bool TextBasedProtocolMessage::removeField(HeaderField* fieldToRemove)
{
	if (fieldToRemove == NULL)
		return true;

	if (fieldToRemove->m_TextBasedProtocolMessage != this)
	{
		LOG_ERROR("Field isn't associated with this message");
		return false;
	}

	std::string fieldName = fieldToRemove->getFieldName();

	// shorten layer and delete this field
	if (!shortenLayer(fieldToRemove->m_NameOffsetInMessage, fieldToRemove->getFieldSize()))
	{
		LOG_ERROR("Cannot shorten layer");
		return false;
	}

	// update offsets of all fields after this field
	HeaderField* curField = fieldToRemove->getNextField();
	shiftFieldsOffset(curField, 0-fieldToRemove->getFieldSize());
//	while (curField != NULL)
//	{
//		curField->m_NameOffsetInMessage -= fieldToRemove->getFieldSize();
//		if (curField->m_ValueOffsetInMessage != -1)
//			curField->m_ValueOffsetInMessage -= fieldToRemove->getFieldSize();
//
//		curField = curField->getNextField();
//	}

	// update fields link list
	if (fieldToRemove == m_FieldList)
		m_FieldList = m_FieldList->getNextField();
	else
	{
		curField = m_FieldList;
		while (curField->getNextField() != fieldToRemove)
			curField = curField->getNextField();

		curField->setNextField(fieldToRemove->getNextField());
	}

	// re-calculate m_LastField if needed
	if (fieldToRemove == m_LastField)
	{
		if (m_FieldList == NULL)
			m_LastField = NULL;
		else
		{
			curField = m_FieldList;
			while (curField->getNextField() != NULL)
				curField = curField->getNextField();
			m_LastField = curField;
		}
	}

	// remove the hash entry for this field
	std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);
	std::pair <std::multimap<std::string,HeaderField*>::iterator, std::multimap<std::string,HeaderField*>::iterator> range;
	range = m_FieldNameToFieldMap.equal_range(fieldName);
	for (std::multimap<std::string,HeaderField*>::iterator iter = range.first; iter != range.second; ++iter)
	{
		if (iter->second == fieldToRemove)
		{
			m_FieldNameToFieldMap.erase(iter);
			break;
		}
	}

	// finally - delete this field
	delete fieldToRemove;

	return true;
}

bool TextBasedProtocolMessage::isHeaderComplete() const
{
	if (m_LastField == NULL)
		return false;

	return (m_LastField->getFieldName() == PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER);
}

void TextBasedProtocolMessage::shiftFieldsOffset(HeaderField* fromField, int numOfBytesToShift)
{
	while (fromField != NULL)
	{
		fromField->m_NameOffsetInMessage += numOfBytesToShift;
		if (fromField->m_ValueOffsetInMessage != -1)
			fromField->m_ValueOffsetInMessage += numOfBytesToShift;
		fromField = fromField->getNextField();
	}
}

// 通过 name 获得 HeaderField
// 如果 name 出现多次，index表示获取第几次出现的 field
HeaderField* TextBasedProtocolMessage::getFieldByName(std::string fieldName, int index) const
{
	// 将字符串全部转化为小写
	std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);

	std::pair <std::multimap<std::string,HeaderField*>::const_iterator, std::multimap<std::string,HeaderField*>::const_iterator> range;
	// std::multimap 的查找使用 equal_range
	range = m_FieldNameToFieldMap.equal_range(fieldName);
	int i = 0;
	for (std::multimap<std::string,HeaderField*>::const_iterator iter = range.first; iter != range.second; ++iter)
	{
		if (i == index)
			return iter->second;
		i++;
	}

	return NULL;
}

// 获得 field 的数量
int TextBasedProtocolMessage::getFieldCount() const
{
	int result = 0;

	HeaderField* curField = getFirstField();
	while (curField != NULL)
	{
		if (!curField->isEndOfHeader())
			result++;
		curField = curField->getNextField();
	}

	return result;
}

void TextBasedProtocolMessage::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
}

size_t TextBasedProtocolMessage::getHeaderLen() const
{
	return m_LastField->m_NameOffsetInMessage + m_LastField->m_FieldSize;
}

void TextBasedProtocolMessage::computeCalculateFields()
{
	//nothing to do for now
}





// -------- Class HeaderField -----------------

// 创建字段
HeaderField::HeaderField(TextBasedProtocolMessage* TextBasedProtocolMessage, int offsetInMessage, char nameValueSeperator, bool spacesAllowedBetweenNameAndValue) :
		m_NewFieldData(NULL), m_TextBasedProtocolMessage(TextBasedProtocolMessage), m_NameOffsetInMessage(offsetInMessage), m_NextField(NULL),
		m_NameValueSeperator(nameValueSeperator), m_SpacesAllowedBetweenNameAndValue(spacesAllowedBetweenNameAndValue)
{
	char* fieldData = (char*)(m_TextBasedProtocolMessage->m_Data + m_NameOffsetInMessage);
	// 使用内存的检查
	char* fieldEndPtr = (char*)memchr(fieldData, '\n',m_TextBasedProtocolMessage->m_DataLen-(size_t)m_NameOffsetInMessage);
	if (fieldEndPtr == NULL)
		m_FieldSize = tbp_my_own_strnlen(fieldData, m_TextBasedProtocolMessage->m_DataLen-(size_t)m_NameOffsetInMessage);
	else
		m_FieldSize = fieldEndPtr - fieldData + 1;

	if ((*fieldData) == '\r' || (*fieldData) == '\n')
	{
		m_FieldNameSize = -1;
		m_ValueOffsetInMessage = -1;
		m_FieldValueSize = -1;
		m_FieldNameSize = -1;
		m_IsEndOfHeaderField = true;		// 如果字段是 \r 或 \n 表示为最后的字段
		return;
	}
	else
		m_IsEndOfHeaderField = false;		// 该字段不是最后的字段

	char* fieldValuePtr = (char*)memchr(fieldData, nameValueSeperator, m_TextBasedProtocolMessage->m_DataLen-(size_t)m_NameOffsetInMessage);
	// could not find the position of the separator, meaning field value position is unknown  如果找不到分隔符
	if (fieldValuePtr == NULL)
	{
		m_ValueOffsetInMessage = -1;
		m_FieldValueSize = -1;
		m_FieldNameSize = m_FieldSize;
	}
	else		// 找到字段名和字段值的分割符
	{
		m_FieldNameSize = fieldValuePtr - fieldData;		// 赋值字段名长度
		// Header field looks like this: <field_name>[separator]<zero or more spaces><field_Value>
		// So fieldValuePtr give us the position of the separator. Value offset is the first non-space byte forward
		fieldValuePtr++;

		if (spacesAllowedBetweenNameAndValue)	// 判断是否允许有空格在name和value之间
		{
			// advance fieldValuePtr 1 byte forward while didn't get to end of packet and fieldValuePtr points to a space char
			while ((size_t)(fieldValuePtr - (char*)m_TextBasedProtocolMessage->m_Data) <= m_TextBasedProtocolMessage->getDataLen() && (*fieldValuePtr) == ' ')
				fieldValuePtr++;
		}

		// reached the end of the packet and value start offset wasn't found
		if ((size_t)(fieldValuePtr - (char*)(m_TextBasedProtocolMessage->m_Data)) > m_TextBasedProtocolMessage->getDataLen())
		{
			// 没有找到值
			m_ValueOffsetInMessage = -1;
			m_FieldValueSize = -1;
		}
		else
		{
			m_ValueOffsetInMessage = fieldValuePtr - (char*)m_TextBasedProtocolMessage->m_Data;
			// couldn't find the end of the field, so assuming the field value length is from m_ValueOffsetInMessage until the end of the packet
			// 从当前headerField往后找不到 "\n" ,所以当前field的值是从m_ValueOffsetInMessage一直到数据包尾部
			if (fieldEndPtr == NULL)
				m_FieldValueSize = (char*)(m_TextBasedProtocolMessage->m_Data + m_TextBasedProtocolMessage->getDataLen()) - fieldValuePtr;
			else
			{
				m_FieldValueSize = fieldEndPtr - fieldValuePtr;
				// if field ends with \r\n, decrease the value length by 1
				if ((*(--fieldEndPtr)) == '\r')// name:value\r\n
					m_FieldValueSize--;
			}
		}
	}
}

HeaderField::HeaderField(std::string name, std::string value, char nameValueSeperator, bool spacesAllowedBetweenNameAndValue)
{
	m_NameValueSeperator = nameValueSeperator;
	m_SpacesAllowedBetweenNameAndValue = spacesAllowedBetweenNameAndValue;
	initNewField(name, value);
}

// 初始化一个新的 field
void HeaderField::initNewField(std::string name, std::string value)
{
	m_TextBasedProtocolMessage = NULL;
	m_NameOffsetInMessage = 0;
	m_NextField = NULL;

	// first building the name-value separator
	std::string nameValueSeparation(1, m_NameValueSeperator);
	if (m_SpacesAllowedBetweenNameAndValue)				// name 与 value 之间允许 空格作为分隔符
		nameValueSeparation += " ";

	// Field size is: name_length + separator_len + value_length + '\r\n'
	if (name != PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER)
		m_FieldSize = name.length() + nameValueSeparation.length() + value.length() + 2;
	else
	// Field is \r\n (2B)
		m_FieldSize = 2;

	m_NewFieldData = new uint8_t[m_FieldSize];
	std::string fieldData;

	if (name != PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER)
		fieldData = name + nameValueSeparation + value + "\r\n";
	else
		fieldData = "\r\n";

	// copy field data to m_NewFieldData
	memcpy(m_NewFieldData, fieldData.c_str(), m_FieldSize);

	// calculate value offset
	if (name != PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER)
		m_ValueOffsetInMessage = name.length() + nameValueSeparation.length();
	else
		m_ValueOffsetInMessage = 0;
	m_FieldNameSize = name.length();
	m_FieldValueSize = value.length();

	if (name != PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER)
		m_IsEndOfHeaderField = false;
	else
		m_IsEndOfHeaderField = true;
}

HeaderField::~HeaderField()
{
	if (m_NewFieldData != NULL)
		delete [] m_NewFieldData;
}

HeaderField::HeaderField(const HeaderField& other) : m_NameValueSeperator('\0'), m_SpacesAllowedBetweenNameAndValue(false)
{
	m_NameValueSeperator = other.m_NameValueSeperator;
	m_SpacesAllowedBetweenNameAndValue = other.m_SpacesAllowedBetweenNameAndValue;
	initNewField(other.getFieldName(), other.getFieldValue());
}

char* HeaderField::getData() const
{
	if (m_TextBasedProtocolMessage == NULL)
		return (char*)m_NewFieldData;
	else
		return (char*)(m_TextBasedProtocolMessage->m_Data);
}

void HeaderField::setNextField(HeaderField* nextField)
{
	m_NextField = nextField;
}

HeaderField* HeaderField::getNextField() const
{
	return m_NextField;
}

std::string HeaderField::getFieldName() const
{
	std::string result;

	if (m_FieldNameSize != (size_t)-1)
		result.assign((const char*)(((HeaderField*)this)->getData() + m_NameOffsetInMessage), m_FieldNameSize);

	return result;
}

std::string HeaderField::getFieldValue() const
{
	std::string result;
	if (m_ValueOffsetInMessage != -1)
		result.assign((const char*)(((HeaderField*)this)->getData() + m_ValueOffsetInMessage), m_FieldValueSize);
	return result;
}

bool HeaderField::setFieldValue(std::string newValue)
{
	// Field isn't linked with any message yet
	if (m_TextBasedProtocolMessage == NULL)
	{
		std::string name = getFieldName();
		delete [] m_NewFieldData;
		initNewField(name, newValue);
		return true;
	}

	std::string curValue = getFieldValue();
	int lengthDifference = newValue.length() - curValue.length();
	// new value is longer than current value
	if (lengthDifference > 0)
	{
		if (!m_TextBasedProtocolMessage->extendLayer(m_ValueOffsetInMessage, lengthDifference))
		{
			LOG_ERROR("Could not extend layer");
			return false;
		}
	}
	// new value is shorter than current value
	else if (lengthDifference < 0)
	{
		if (!m_TextBasedProtocolMessage->shortenLayer(m_ValueOffsetInMessage, 0 - lengthDifference))
		{
			LOG_ERROR("Could not shorten layer");
			return false;
		}
	}

	if (lengthDifference != 0)
		m_TextBasedProtocolMessage->shiftFieldsOffset(getNextField(), lengthDifference);

	// update sizes
	m_FieldValueSize += lengthDifference;
	m_FieldSize += lengthDifference;

	// write new value to field data
	memcpy(getData() + m_ValueOffsetInMessage, newValue.c_str(), newValue.length());

	return true;
}

// 将 header field 绑定到一个 TextBasedProtocolMessage
// condition：之前没有绑定 TextBasedProtocolMessage，并且 m_NewFieldData 不为空
void HeaderField::attachToTextBasedProtocolMessage(TextBasedProtocolMessage* message, int fieldOffsetInMessage)
{
	if (m_TextBasedProtocolMessage != NULL && m_TextBasedProtocolMessage != message)
	{
		LOG_ERROR("Header field already associated with another message");
		return;
	}

	if (m_NewFieldData == NULL)
	{
		LOG_ERROR("Header field doesn't have new field data");
		return;
	}

	delete [] m_NewFieldData;
	m_NewFieldData = NULL;
	m_TextBasedProtocolMessage = message;

	// value偏移量 - name偏移量 = value与name的距离
	int valueAndNameDifference = m_ValueOffsetInMessage - m_NameOffsetInMessage;
	// 根据传入参数 设置 name 偏移量
	m_NameOffsetInMessage = fieldOffsetInMessage;
	// 计算获得 value 偏移量
	m_ValueOffsetInMessage = m_NameOffsetInMessage + valueAndNameDifference;
}

}
