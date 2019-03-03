#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"
#include "tunable.h"

//���ģ����nobody��������һЩ��

static void privop_pasv_get_data_sock(session_t *sess);
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);

//����Ȩ�˿ڵ�Ȩ��
int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	//ϵͳ����
	return syscall(__NR_capset, hdrp, datap);
}

//��nobody��Ҫ����Ȩ
void minimize_privilege(void)
{
	//�������̱�ΪNobody���̣�ԭ����root
	//getpwnam��ȡ�û���¼�����Ϣ
	struct passwd *pw = getpwnam("nobody");
	if (pw == NULL)
		return;

	//û�и�֮ǰ�û�ID����ID��Ϊ0,��root�û�������
	//����ǰ���̵���Ч��ID��Ϊpw_gid
	if (setegid(pw->pw_gid) < 0)
		ERR_EXIT("setegid");
	//����ǰ���̵���Ч�û�ID��Ϊpw_uid
	if (seteuid(pw->pw_uid) < 0)
		ERR_EXIT("seteuid");


	struct __user_cap_header_struct cap_header;
	struct __user_cap_data_struct cap_data;

	memset(&cap_header, 0, sizeof(cap_header));
	memset(&cap_data, 0, sizeof(cap_data));

	//64λ��ϵͳѡ��_2
	cap_header.version = _LINUX_CAPABILITY_VERSION_2;
	//����Ҫ���� 
	cap_header.pid = 0;

	__u32 cap_mask = 0;
	//��ð���Ȩ�˿ڵ�Ȩ��
	//��1������10λ
	cap_mask |= (1 << CAP_NET_BIND_SERVICE);

	//Ҫ�������Ȩ
	cap_data.effective = cap_data.permitted = cap_mask;
	//������̳�
	cap_data.inheritable = 0;

	capset(&cap_header, &cap_data);
}

//���յ������Ǵ��ӽ��̷��͹����ģ�Э���������
void handle_parent(session_t *sess)
{
    //�ȸ�nobody��Ȩ
	minimize_privilege();

	char cmd;
	//��Ϊ����ѭ��������һֱ���ڽ����ӽ��������״̬���ӽ��̵��˳��ܹ�ʹ�ø�����Ҳ
	//�յ�֪ͨ�������˳�
	while (1) {
		//�ӽ���(ftp�������)������������
		cmd = priv_sock_get_cmd(sess->parent_fd);
		// �����ڲ�����
		// �����ڲ�����
		switch (cmd) {
		//4��������
		case PRIV_SOCK_GET_DATA_SOCK:
			privop_pasv_get_data_sock(sess);
			break;
		case PRIV_SOCK_PASV_ACTIVE:
			privop_pasv_active(sess);
			break;
		case PRIV_SOCK_PASV_LISTEN:
			privop_pasv_listen(sess);
			break;
		case PRIV_SOCK_PASV_ACCEPT:
			privop_pasv_accept(sess);
			break;
		
		}
	}
}
//������4��������
//��ʵӦ����PORT����ģʽ���׽���
static void privop_pasv_get_data_sock(session_t *sess)
{
	/*
	nobody���̽���PRIV_SOCK_GET_DATA_SOCK����
��һ������һ��������Ҳ����port
����һ���ַ�����Ҳ����ip

fd = socket 
bind(20)
connect(ip, port);

OK
send_fd
BAD
*/
	//���ն˿ں�
	unsigned short port = (unsigned short)priv_sock_get_int(sess->parent_fd);
	char ip[16] = {0};//255.255.255.255�ⲻ����16���ֽ���
	//����IP
	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));

	//nobody���̸������ӿͻ���
	//ע��nobody���̵�sess->addr��ftp������̵�sess->addr����һ���£���Ϊ��������ͬ�Ľ���
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	//��20�Ķ˿ں�
	int fd = tcp_client(20);
	//�����׽���ʧ�ܵĻ�����FTP�������Ӧ��
	if (fd == -1) {
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	//��������
	if (connect_timeout(fd, &addr, tunable_connect_timeout) < 0) {
		close(fd);
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}

	//�����׽��ֳɹ���Ӧ��
	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	//��FTP������̴����ļ����������Ӷ�ʵ����FTP���������ͻ���֮������ͨ���Ĵ���
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);
}

//�жϼ����׽����Ƿ��ڻ״̬
static void privop_pasv_active(session_t *sess)
{
	int active;
	if (sess->pasv_listen_fd != -1) {
		active = 1;
	} else {
		active = 0;
	}

	priv_sock_send_int(sess->parent_fd, active);
}

//�����׽��֣��󶨡�����
static void privop_pasv_listen(session_t *sess)
{
	char ip[16] = {0};
	getlocalip(ip);

	//����һ�������׽��ֲ��Ұ�һ����̬�˿ں�
	sess->pasv_listen_fd = tcp_server(ip, 0);
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	//��ȡʵ�ʰ󶨵Ķ˿ں�
	if (getsockname(sess->pasv_listen_fd, (struct sockaddr *)&addr, &addrlen) < 0) {
		ERR_EXIT("getsockname");
	}

	unsigned short port = ntohs(addr.sin_port);

	//�������˿ںŷ��͸�������̣������ɷ�����̷����ͻ���
	priv_sock_send_int(sess->parent_fd, (int)port);
}

//����ģʽ�����������ֽ���wangkai
static void privop_pasv_accept(session_t *sess)
{
	//�������ܿͻ�������
	//�õ�һ���������׽��֣�Ҳ���������׽���
	int fd = accept_timeout(sess->pasv_listen_fd, NULL, tunable_accept_timeout);
	close(sess->pasv_listen_fd);
	sess->pasv_listen_fd = -1;

	if (fd == -1) {
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}

	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	//�ش������׽���
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);
}

