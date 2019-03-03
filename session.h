#ifndef _SESSION_H_
#define _SESSION_H_

#include "common.h"

//保存了当前会话所需要的一些变量
typedef struct session
{
	// 控制连接
	uid_t uid;//登录用户的uid
	int ctrl_fd;//已连接套接字，也就是控制连接套接字
	char cmdline[MAX_COMMAND_LINE];//命令行,数组大小在common.h中定义
	char cmd[MAX_COMMAND];//解析出的命令
	char arg[MAX_ARG];//解析出的参数

	// 数据连接
	//构建一个地址结构，要连接的地址保存在其中
	//服务器端解析客户端发过来的IP和端口暂存起来，以便建立数据连接
	struct sockaddr_in *port_addr;
	int pasv_listen_fd;//被动模式情况下服务器的监听套接字
	int data_fd;//数据连接套接字，通过这个套接字发送数据,用于发起connect
	int data_process;//当前有没有处于数据传输的状态

	// 限速
	unsigned int bw_upload_rate_max;//上传的最大速率
	unsigned int bw_download_rate_max;//下载的最大速率
	long bw_transfer_start_sec;//开始传输的时间秒数
	long bw_transfer_start_usec;//开始传输时间的微秒数


	// 父子进程通道
	int parent_fd;
	int child_fd;

	// FTP协议状态
	int is_ascii;  //是否是ASII模式
	long long restart_pos;  //断点信息
	char *rnfr_name;  //保存文件名，以便将来更改
	int abor_received;  //是否收到abor命令

	// 连接数限制
	unsigned int num_clients;//d当前总的连接数
	unsigned int num_this_ip;//当前ip的连接数
} session_t;

//开始会话
void begin_session(session_t *sess);

#endif /* _SESSION_H_ */

