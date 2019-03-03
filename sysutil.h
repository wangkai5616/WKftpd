#ifndef _SYS_UTIL_H_
#define _SYS_UTIL_H_

#include "common.h"

//一系列函数作为系统工具
int tcp_client(unsigned short port);
int tcp_server(const char *host, unsigned short port);

//获取本地IP地址
int getlocalip(char *ip);

//将一个文件描述符设置为非阻塞模式
void activate_nonblock(int fd);
//将一个文件描述符设置为阻塞模式
void deactivate_nonblock(int fd);

//读超时函数的封装
int read_timeout(int fd, unsigned int wait_seconds);
//写超时函数的封装
int write_timeout(int fd, unsigned int wait_seconds);
//接受连接超时函数
int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds);
//连接超时函数
int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds);

ssize_t readn(int fd, void *buf, size_t count);
ssize_t writen(int fd, const void *buf, size_t count);
ssize_t recv_peek(int sockfd, void *buf, size_t len);
//按行读取
ssize_t readline(int sockfd, void *buf, size_t maxline);

//发送文件描述符
void send_fd(int sock_fd, int fd);
//接收文件描述符
int recv_fd(const int sock_fd);

const char* statbuf_get_perms(struct stat *sbuf);
const char* statbuf_get_date(struct stat *sbuf);

int lock_file_read(int fd);
int lock_file_write(int fd);
int unlock_file(int fd);

long get_time_sec(void);
long get_time_usec(void);
void nano_sleep(double seconds);

void activate_oobinline(int fd);
void activate_sigurg(int fd);
#endif /* _SYS_UTIL_H_ */

