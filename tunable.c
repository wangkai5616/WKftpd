#include "tunable.h"

//�����ļ�ģ��ķ�װ
//��������ļ���û�����õĻ�����������ĳ�ʼֵ

//�Ƿ�������ģʽ
int tunable_pasv_enable = 1;
//�Ƿ�������ģʽ
int tunable_port_enable = 1;
//FTP�������˿�
unsigned int tunable_listen_port = 21;
//���������
unsigned int tunable_max_clients = 2000;
//ÿ��IP���������
unsigned int tunable_max_per_ip = 50;
//accept��ʱ��
unsigned int tunable_accept_timeout = 60;
//connect��ʱ��
unsigned int tunable_connect_timeout = 60;
//�������ӳ�ʱ��
unsigned int tunable_idle_session_timeout = 300;
//�������ӳ�ʱ��
unsigned int tunable_data_connection_timeout = 300;
//����
unsigned int tunable_local_umask = 077;
//����ϴ��ٶ�
unsigned int tunable_upload_max_rate = 0;
//��������ٶ�
unsigned int tunable_download_max_rate = 0;
//FTP������IP��ַ
const char *tunable_listen_address;

