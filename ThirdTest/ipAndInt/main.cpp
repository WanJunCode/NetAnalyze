//第三十三题 整数与IP地址间的转换
#include<iostream>
#include<string>

using namespace std;
void TransferIp(string src)
{
	int iNum[4]{ 0 };
	size_t sPosition = 0, ePsition;
	int k = 0;
	while ((ePsition = src.find('.', sPosition)) != string::npos)
	{
		string temp = src.substr(sPosition, ePsition);
		int iTemp = atoi(temp.data());
		if (iTemp > 255)
			return;
		else
			iNum[k] = iTemp;
		k++;
		sPosition = ePsition + 1;
	}
	if (k != 3)
		return;
	else
	{
		string temp = src.substr(sPosition, src.length()-sPosition);
		int iTemp = atoi(temp.data());
		if (iTemp > 255)
			return;
		else
			iNum[3] = iTemp;
	}
	size_t iOut = iNum[0];
	for (int i = 1; i < 4; i++)
	{
		iOut = iOut * 256 + iNum[i];
	}
	cout << iOut << endl;
	return;
}
void TransferToIp(size_t src)
{
	int iNum[4]{ 0 };
	size_t sT = (src >> 8);
	for (int i = 0; i < 4; i++)
	{
		iNum[i] = src - (sT << 8);
		src = sT;
		sT = sT >> 8;
	}
	string sOut;
	for (int i = 3; i > 0 ; i--)
	{
		string temp = to_string(iNum[i]);
		sOut += temp + '.';
	}
	sOut += to_string(iNum[0]);
	cout << sOut.c_str() << endl;
}

int main()
{
	string inStr;
	size_t sNum;
	while (cin >> inStr >> sNum)
	{
		TransferIp(inStr);
		TransferToIp(sNum);
	}
	return 0;
}
 