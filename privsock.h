#ifndef _PRIV_SOCK_H_
#define _PRIV_SOCK_H_

#include "session.h"


// 内部进程自定义协议
// 用于FTP服务进程与nobody进程进行通信

// FTP服务进程向nobody进程请求的命令
#define PRIV_SOCK_GET_DATA_SOCK     1  //向nobody进程获取PORT模式数据套接字
#define PRIV_SOCK_PASV_ACTIVE       2  //判断是否处于PASV模式
#define PRIV_SOCK_PASV_LISTEN       3  //获取PASV模式监听套接口，需要由wangkai返回给客户端
#define PRIV_SOCK_PASV_ACCEPT       4  //请求被动模式（PASV）数据套接字

// nobody进程对FTP服务进程的应答
#define PRIV_SOCK_RESULT_OK         1  //成功
#define PRIV_SOCK_RESULT_BAD        2  //失败



void priv_sock_init(session_t *sess);
void priv_sock_close(session_t *sess);
void priv_sock_set_parent_context(session_t *sess);
void priv_sock_set_child_context(session_t *sess);

void priv_sock_send_cmd(int fd, char cmd);
char priv_sock_get_cmd(int fd);
void priv_sock_send_result(int fd, char res);
char priv_sock_get_result(int fd);

void priv_sock_send_int(int fd, int the_int);
int priv_sock_get_int(int fd);
void priv_sock_send_buf(int fd, const char *buf, unsigned int len);
void priv_sock_recv_buf(int fd, char *buf, unsigned int len);
void priv_sock_send_fd(int sock_fd, int fd);
int priv_sock_recv_fd(int sock_fd);


#endif /* _PRIV_SOCK_H_ */

