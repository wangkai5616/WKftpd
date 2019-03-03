#include "privsock.h"
#include "common.h"
#include "sysutil.h"

//内部进程间通信模块设计

//初始化内部进程间通信通道
void priv_sock_init(session_t *sess)
{
	int sockfds[2];
	//创建一个套接字对
	//Linux环境下使用socketpair函数创造一对未命名的、相互连接的UNIX域套接字
	//Unix域套接字往往比通信两端位于同一主机的TCP套接字快出一倍
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
		ERR_EXIT("socketpair");

	//对父子进程的套接字进行设置
	sess->parent_fd = sockfds[0];
	sess->child_fd = sockfds[1];
}

//关闭内部进程间通信通道
void priv_sock_close(session_t *sess)
{
	if (sess->parent_fd != -1) {
		close(sess->parent_fd);
		sess->parent_fd = -1;
	}

	if (sess->child_fd != -1) {
		close(sess->child_fd);
		sess->child_fd = -1;
	}
}

//设置父进程环境，只留下父进程的套接字
void priv_sock_set_parent_context(session_t *sess)
{
	if (sess->child_fd != -1) {
		//父进程不需要子进程的套接字
		close(sess->child_fd);
		sess->child_fd = -1;
	}
}

//设置子进程环境，只留下子进程的套接字
void priv_sock_set_child_context(session_t *sess)
{
	if (sess->parent_fd != -1) {
		//子进程不需要父进程的套接字
		close(sess->parent_fd);
		sess->parent_fd = -1;
	}
}

//发送命令（子->父）
void priv_sock_send_cmd(int fd, char cmd)
{
	int ret;
	//只发送一个字节，就是头文件中的4种命令中的一种
	ret = writen(fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		fprintf(stderr, "priv_sock_send_cmd error\n");
		exit(EXIT_FAILURE);
	}
}

//接收命令（父->子）
char priv_sock_get_cmd(int fd)
{
	char res;
	int ret;
	ret = readn(fd, &res, sizeof(res));
	//服务进程退出了
	if (ret == 0) {
		printf("ftp process exit\n");
		exit(EXIT_SUCCESS);
	}
	//只有1个字节
	if (ret != sizeof(res)) {
		fprintf(stderr, "priv_sock_get_cmd error\n");
		exit(EXIT_FAILURE);
	}

	return res;
}

//发送结果（父->子）
void priv_sock_send_result(int fd, char res)
{
	int ret;
	ret = writen(fd, &res, sizeof(res));
	if (ret != sizeof(res)) {
		fprintf(stderr, "priv_sock_send_result error\n");
		exit(EXIT_FAILURE);
	}
}

//接收结果（子->父）
char priv_sock_get_result(int fd)
{
	char res;
	int ret;
	ret = readn(fd, &res, sizeof(res));
	if (ret != sizeof(res)) {
		fprintf(stderr, "priv_sock_get_result error\n");
		exit(EXIT_FAILURE);
	}

	return res;
}

//发送一个整数（比如端口）
void priv_sock_send_int(int fd, int the_int)
{
	int ret;
	ret = writen(fd, &the_int, sizeof(the_int));
	if (ret != sizeof(the_int)) {
		fprintf(stderr, "priv_sock_send_int error\n");
		exit(EXIT_FAILURE);
	}
}

//接收一个整数
int priv_sock_get_int(int fd)
{
	int the_int;
	int ret;
	ret = readn(fd, &the_int, sizeof(the_int));
	if (ret != sizeof(the_int)) {
		fprintf(stderr, "priv_sock_get_int error\n");
		exit(EXIT_FAILURE);
	}

	return the_int;
}

//发送一个字符串（比如IP）
void priv_sock_send_buf(int fd, const char *buf, unsigned int len)
{
	//字符串是不定长的，先发送一个字符串长度	 
	priv_sock_send_int(fd, (int)len);
	//再发送实际的字符串
	int ret = writen(fd, buf, len);
	if (ret != (int)len) {
		fprintf(stderr, "priv_sock_send_buf error\n");
		exit(EXIT_FAILURE);
	}
}

//接收一个字符串
void priv_sock_recv_buf(int fd, char *buf, unsigned int len)
{
	//先接受字符串的长度
	unsigned int recv_len = (unsigned int)priv_sock_get_int(fd);
	if (recv_len > len)	{
		fprintf(stderr, "priv_sock_recv_buf error\n");
		exit(EXIT_FAILURE);
	}

	int ret = readn(fd, buf, recv_len);
	if (ret != (int)recv_len) {
		fprintf(stderr, "priv_sock_recv_buf error\n");
		exit(EXIT_FAILURE);
	}
}

//发送文件描述符
void priv_sock_send_fd(int sock_fd, int fd)
{
    //向sock_fd发送fd
	send_fd(sock_fd, fd);
}

//接收文件描述符
int priv_sock_recv_fd(int sock_fd)
{
	return recv_fd(sock_fd);
}

