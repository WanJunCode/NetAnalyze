#ifndef WANJUN_TOOL_H
#define WANJUN_TOOL_H

#include <stdarg.h>
#include <iostream>
#include <stdio.h>
#include <string>

// 将 format 和 变参 转化为 std::string
std::string vform(const char* format, va_list args);
const char* StripFileName(const char *full_name);

char *textFileRead(const char* filename);

//字节流转换为十六进制字符串的另一种实现方式
int byte2hex(const void *sSrc, int nSrcLen, char *sDest, int destLen);
std::string byteTohex(const void *sSrc, int nSrcLen);

std::string TransferToIp(uint32_t src);

#endif // WANJUN_TOOL_H