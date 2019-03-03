#ifndef _SESSION_H_
#define _SESSION_H_

#include "common.h"

//�����˵�ǰ�Ự����Ҫ��һЩ����
typedef struct session
{
	// ��������
	uid_t uid;//��¼�û���uid
	int ctrl_fd;//�������׽��֣�Ҳ���ǿ��������׽���
	char cmdline[MAX_COMMAND_LINE];//������,�����С��common.h�ж���
	char cmd[MAX_COMMAND];//������������
	char arg[MAX_ARG];//�������Ĳ���

	// ��������
	//����һ����ַ�ṹ��Ҫ���ӵĵ�ַ����������
	//�������˽����ͻ��˷�������IP�Ͷ˿��ݴ��������Ա㽨����������
	struct sockaddr_in *port_addr;
	int pasv_listen_fd;//����ģʽ����·������ļ����׽���
	int data_fd;//���������׽��֣�ͨ������׽��ַ�������,���ڷ���connect
	int data_process;//��ǰ��û�д������ݴ����״̬

	// ����
	unsigned int bw_upload_rate_max;//�ϴ����������
	unsigned int bw_download_rate_max;//���ص��������
	long bw_transfer_start_sec;//��ʼ�����ʱ������
	long bw_transfer_start_usec;//��ʼ����ʱ���΢����


	// ���ӽ���ͨ��
	int parent_fd;
	int child_fd;

	// FTPЭ��״̬
	int is_ascii;  //�Ƿ���ASIIģʽ
	long long restart_pos;  //�ϵ���Ϣ
	char *rnfr_name;  //�����ļ������Ա㽫������
	int abor_received;  //�Ƿ��յ�abor����

	// ����������
	unsigned int num_clients;//d��ǰ�ܵ�������
	unsigned int num_this_ip;//��ǰip��������
} session_t;

//��ʼ�Ự
void begin_session(session_t *sess);

#endif /* _SESSION_H_ */

