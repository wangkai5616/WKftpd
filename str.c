#include "str.h"
#include "common.h"

//这个模块是字符串工具模块

//去除\r\n
void str_trim_crlf(char *str)
{
	//指向最后一个字符
	char *p = &str[strlen(str)-1];
	while (*p == '\r' || *p == '\n')
		*p-- = '\0';

}

//字符串分割
void str_split(const char *str , char *left, char *right, char c)
{
	//查找第一个'c'所在的位置,也就是空格的位置
	char *p = strchr(str, c);
	//如果没有空格的话，说明命令没有参数
	if (p == NULL)
		//left里面是命令
		strcpy(left, str);
	//将空格之前的字符串保存到left中
	else {
		strncpy(left, str, p-str);
		strcpy(right, p+1);
	}
}

//判断字符串是否全是空白字符
int str_all_space(const char *str)
{
	while (*str) {
		if (!isspace(*str))
			return 0;
		str++;
	}
	return 1;
}

//字符串转化为大写格式
void str_upper(char *str)
{
	while (*str) {
		*str = toupper(*str);
		str++;
	}
}

//将字符串转化为long long型(长长整型)整数
long long str_to_longlong(const char *str)
{
	//return atoll(str);//系统提供的方法，可以使用
	long long result = 0;
	long long mult = 1;
	//字符串长度
	unsigned int len = strlen(str);
	int i;

	if (len > 15)
		return 0;

	for (i=len-1; i>=0; i--) {
		//定义一个字符等于最后一个字符 
		char ch = str[i];
		long long val;
		if (ch < '0' || ch > '9')
			return 0;

		val = ch - '0'; 
		val *= mult;
		result += val;
		mult *= 10;
	}

	return result;
}

//将字符串（八进制）转换为无符号整型
unsigned int str_octal_to_uint(const char *str)
{
	unsigned int result = 0;
	int seen_non_zero_digit = 0;

	while (*str) {
		int digit = *str;
		if (!isdigit(digit) || digit > '7')
			break;

		if (digit != '0')
			seen_non_zero_digit = 1;

		if (seen_non_zero_digit) {
			result <<= 3;
			result += (digit - '0');
		}
		str++;
	}
	return result;
}

