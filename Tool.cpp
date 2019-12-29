#include "Tool.h"

#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <iostream>
#include <memory>

// 将 format 和 变参 转化为 std::string
std::string vform(const char* format, va_list args) {
    size_t size = 1024;
    char* buffer = new char[size];

    while (1) {
        va_list args_copy;
        // 将 args 复制到 args_copy
        va_copy(args_copy, args);

        int n = vsnprintf(buffer, size, format, args_copy);//function error,replace it

        va_end(args_copy);

        // If that worked, return a string.
        if ((n > -1) && (static_cast<size_t>(n) < size)) {
            // char 指针 装换为 std::string
            std::string s(buffer);
            delete [] buffer;
            return s;
        }

        // Else try again with more space.
        size = (n > -1) ?
               n + 1 :   // ISO/IEC 9899:1999
               size * 2; // twice the old size

        delete [] buffer;
        buffer = new char[size];
    }
}

	// 获得绝对路径中 最后的 文件名
const char* StripFileName(const char *full_name) {
	const char *pos = full_name + strlen(full_name);
	// full_name ------/----/--- pos
	while (pos != full_name) {
		-- pos;
		if (*pos == '/') {
			++ pos;
			break;
		}
	}
	return pos;
}

//std::string.c_str()
// 内部使用 malloc 开辟空间，外部需要使用 free 释放空间
char *textFileRead(const char* filename){
    FILE *pf = fopen(filename,"r");
    if(pf != NULL){
        fseek(pf,0,SEEK_END);
        long lsize = ftell(pf);

        rewind(pf);
        char *ptext = (char *)malloc(lsize + 1);
        if(NULL!=ptext){
            if(0<fread(ptext,sizeof(char),lsize,pf)){
                ptext[lsize] = '\0';
            }
        }
        fclose(pf);
        return ptext;
    }
    return NULL;
}

//字节流转换为十六进制字符串的另一种实现方式
int byte2hex(const void *sSrc, int nSrcLen, char *sDest, int destLen) {
    if (nSrcLen * 2 > destLen)
        return 0;

    char szTmp[3] = { 0x00 };
    char *ptr = (char *)sSrc;
    for (int i = 0; i < nSrcLen; i++) {
        // string printf
        sprintf(szTmp, "%02X", (unsigned char)ptr[i]);
        memcpy(&sDest[i * 2], szTmp, 2);
    }
    return nSrcLen * 2;
}

// 字符串转换成　16进制的字符串
std::string byteTohex(const void *sSrc, int nSrcLen) {
    // 获得　16 进制的长度
    int len = nSrcLen * 2 + 1;
    // 智能指针，防止　new 的　char 数组内存泄露
    std::unique_ptr<char> dst(new char[len]);
    // unique_ptr::get() 获得唯一指针内部原始指针
    memset(dst.get(),0x00,len);
    // sSrc => dst
    if (byte2hex(sSrc, nSrcLen, dst.get(), len)) {
        // char[] 隐式转换为　std::string
        return dst.get();
    }
    return "";
}

std::string TransferToIp(uint32_t src)
{
    using namespace std;
    int iNum[4]{ 0 };
    size_t sT = (src >> 8);
    for (int i = 0; i < 4; i++)
    {
        iNum[i] = src - (sT << 8);
        src = sT;
        sT = sT >> 8;
    }
    std::string sOut;
    for (int i = 3; i > 0 ; i--)
    {
        string temp = to_string(iNum[i]);
        sOut += temp + '.';
    }
    sOut += to_string(iNum[0]);
    return sOut;
}