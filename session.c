#include "common.h"
#include "session.h"
#include "ftpproto.h"
#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"

//一个会话由两个进程构成
void begin_session(session_t *sess)
{
	//控制连接通道的fd开启能够接收带外数据的功能，也就是通过紧急模式接收数据
	activate_oobinline(sess->ctrl_fd);
	//父子进程进行通信的套接字的创建
	priv_sock_init(sess);

	pid_t pid;
	//创建服务进程
	pid = fork();
	if (pid < 0)
		ERR_EXIT("fork");
	//两个进程间的通信通过socketpair(套接字对）

	if (pid == 0) {
		// ftp服务进程，处理ftp相关的一些通信细节
		//不仅处理控制连接还要处理数据连接
		//设置子进程状态
		priv_sock_set_child_context(sess);
		//ftp服务进程内部的实现
		handle_child(sess);
	} else {
		// 父进程是nobody进程
		/*
		当一个用户的时候，比如start，登录成功之后，会将ftp服务进程的
		用户名改为start用户，uid和gid都改为start用户相对应uid,gid
		这样ftp服务进程的权限就相对来说降低了。
		就没有权限完成一些特殊的
		任务，比如数据连接的建立，port模式是服务器端连接客户端
		此时，服务器端需要绑定20的端口号，而20的端口不能由普通用户
		来绑定，也就是ftp服务进程没有权限来绑定20端口，这是就需要
		nobody进程来协助完成绑定20端口并且和ftp客户端建立连接，nobody进程
		权限要比普通进程高，nobody进程不直接与外界通信
		*/
		//设置父进程状态
		priv_sock_set_parent_context(sess);
		handle_parent(sess);
	}
}

