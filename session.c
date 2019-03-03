#include "common.h"
#include "session.h"
#include "ftpproto.h"
#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"

//һ���Ự���������̹���
void begin_session(session_t *sess)
{
	//��������ͨ����fd�����ܹ����մ������ݵĹ��ܣ�Ҳ����ͨ������ģʽ��������
	activate_oobinline(sess->ctrl_fd);
	//���ӽ��̽���ͨ�ŵ��׽��ֵĴ���
	priv_sock_init(sess);

	pid_t pid;
	//�����������
	pid = fork();
	if (pid < 0)
		ERR_EXIT("fork");
	//�������̼��ͨ��ͨ��socketpair(�׽��ֶԣ�

	if (pid == 0) {
		// ftp������̣�����ftp��ص�һЩͨ��ϸ��
		//��������������ӻ�Ҫ������������
		//�����ӽ���״̬
		priv_sock_set_child_context(sess);
		//ftp��������ڲ���ʵ��
		handle_child(sess);
	} else {
		// ��������nobody����
		/*
		��һ���û���ʱ�򣬱���start����¼�ɹ�֮�󣬻Ὣftp������̵�
		�û�����Ϊstart�û���uid��gid����Ϊstart�û����Ӧuid,gid
		����ftp������̵�Ȩ�޾������˵�����ˡ�
		��û��Ȩ�����һЩ�����
		���񣬱����������ӵĽ�����portģʽ�Ƿ����������ӿͻ���
		��ʱ������������Ҫ��20�Ķ˿ںţ���20�Ķ˿ڲ�������ͨ�û�
		���󶨣�Ҳ����ftp�������û��Ȩ������20�˿ڣ����Ǿ���Ҫ
		nobody������Э����ɰ�20�˿ڲ��Һ�ftp�ͻ��˽������ӣ�nobody����
		Ȩ��Ҫ����ͨ���̸ߣ�nobody���̲�ֱ�������ͨ��
		*/
		//���ø�����״̬
		priv_sock_set_parent_context(sess);
		handle_parent(sess);
	}
}

