#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"
#include "tunable.h"

//这个模块是nobody进程做的一些事

static void privop_pasv_get_data_sock(session_t *sess);
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);

//绑定特权端口的权限
int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	//系统调用
	return syscall(__NR_capset, hdrp, datap);
}

//给nobody必要的特权
void minimize_privilege(void)
{
	//将父进程变为Nobody进程，原来是root
	//getpwnam获取用户登录相关信息
	struct passwd *pw = getpwnam("nobody");
	if (pw == NULL)
		return;

	//没有改之前用户ID和组ID都为0,是root用户启动的
	//将当前进程的有效组ID改为pw_gid
	if (setegid(pw->pw_gid) < 0)
		ERR_EXIT("setegid");
	//将当前进程的有效用户ID改为pw_uid
	if (seteuid(pw->pw_uid) < 0)
		ERR_EXIT("seteuid");


	struct __user_cap_header_struct cap_header;
	struct __user_cap_data_struct cap_data;

	memset(&cap_header, 0, sizeof(cap_header));
	memset(&cap_data, 0, sizeof(cap_data));

	//64位的系统选择_2
	cap_header.version = _LINUX_CAPABILITY_VERSION_2;
	//不需要设置 
	cap_header.pid = 0;

	__u32 cap_mask = 0;
	//获得绑定特权端口的权限
	//把1左移了10位
	cap_mask |= (1 << CAP_NET_BIND_SERVICE);

	//要赋予的特权
	cap_data.effective = cap_data.permitted = cap_mask;
	//不允许继承
	cap_data.inheritable = 0;

	capset(&cap_header, &cap_data);
}

//接收的命令是从子进程发送过来的，协助完成任务
void handle_parent(session_t *sess)
{
    //先给nobody特权
	minimize_privilege();

	char cmd;
	//因为是死循环，所以一直处于接收子进程命令的状态，子进程的退出能够使得父进程也
	//收到通知，进而退出
	while (1) {
		//子进程(ftp服务进程)发送来的命令
		cmd = priv_sock_get_cmd(sess->parent_fd);
		// 解析内部命令
		// 处理内部命令
		switch (cmd) {
		//4个处理函数
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
//下面是4个处理函数
//其实应该是PORT主动模式的套接字
static void privop_pasv_get_data_sock(session_t *sess)
{
	/*
	nobody进程接收PRIV_SOCK_GET_DATA_SOCK命令
进一步接收一个整数，也就是port
接收一个字符串，也就是ip

fd = socket 
bind(20)
connect(ip, port);

OK
send_fd
BAD
*/
	//接收端口号
	unsigned short port = (unsigned short)priv_sock_get_int(sess->parent_fd);
	char ip[16] = {0};//255.255.255.255这不就是16个字节吗
	//接收IP
	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));

	//nobody进程负责连接客户端
	//注意nobody进程的sess->addr和ftp服务进程的sess->addr不是一回事，因为是两个不同的进程
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	//绑定20的端口号
	int fd = tcp_client(20);
	//创建套接字失败的话，给FTP服务进程应答
	if (fd == -1) {
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	//发起连接
	if (connect_timeout(fd, &addr, tunable_connect_timeout) < 0) {
		close(fd);
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}

	//创建套接字成功的应答
	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	//给FTP服务进程传输文件描述符，从而实现了FTP服务进程与客户端之间连接通道的创建
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);
}

//判断监听套接字是否处于活动状态
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

//创建套接字，绑定、监听
static void privop_pasv_listen(session_t *sess)
{
	char ip[16] = {0};
	getlocalip(ip);

	//创建一个监听套接字并且绑定一个动态端口号
	sess->pasv_listen_fd = tcp_server(ip, 0);
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	//获取实际绑定的端口号
	if (getsockname(sess->pasv_listen_fd, (struct sockaddr *)&addr, &addrlen) < 0) {
		ERR_EXIT("getsockname");
	}

	unsigned short port = ntohs(addr.sin_port);

	//将监听端口号发送给服务进程，进而由服务进程发给客户端
	priv_sock_send_int(sess->parent_fd, (int)port);
}

//被动模式的数据连接字交给wangkai
static void privop_pasv_accept(session_t *sess)
{
	//被动接受客户端连接
	//得到一个已连接套接字，也就是数据套接字
	int fd = accept_timeout(sess->pasv_listen_fd, NULL, tunable_accept_timeout);
	close(sess->pasv_listen_fd);
	sess->pasv_listen_fd = -1;

	if (fd == -1) {
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}

	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	//回传数据套接字
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);
}

