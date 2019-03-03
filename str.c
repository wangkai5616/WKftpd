#include "str.h"
#include "common.h"

//���ģ�����ַ�������ģ��

//ȥ��\r\n
void str_trim_crlf(char *str)
{
	//ָ�����һ���ַ�
	char *p = &str[strlen(str)-1];
	while (*p == '\r' || *p == '\n')
		*p-- = '\0';

}

//�ַ����ָ�
void str_split(const char *str , char *left, char *right, char c)
{
	//���ҵ�һ��'c'���ڵ�λ��,Ҳ���ǿո��λ��
	char *p = strchr(str, c);
	//���û�пո�Ļ���˵������û�в���
	if (p == NULL)
		//left����������
		strcpy(left, str);
	//���ո�֮ǰ���ַ������浽left��
	else {
		strncpy(left, str, p-str);
		strcpy(right, p+1);
	}
}

//�ж��ַ����Ƿ�ȫ�ǿհ��ַ�
int str_all_space(const char *str)
{
	while (*str) {
		if (!isspace(*str))
			return 0;
		str++;
	}
	return 1;
}

//�ַ���ת��Ϊ��д��ʽ
void str_upper(char *str)
{
	while (*str) {
		*str = toupper(*str);
		str++;
	}
}

//���ַ���ת��Ϊlong long��(��������)����
long long str_to_longlong(const char *str)
{
	//return atoll(str);//ϵͳ�ṩ�ķ���������ʹ��
	long long result = 0;
	long long mult = 1;
	//�ַ�������
	unsigned int len = strlen(str);
	int i;

	if (len > 15)
		return 0;

	for (i=len-1; i>=0; i--) {
		//����һ���ַ��������һ���ַ� 
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

//���ַ������˽��ƣ�ת��Ϊ�޷�������
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

