#include "sysutil.h"

//数据连接时创建的套接字，服务器端主动进行连接
int tcp_client(unsigned short port)
{
	int sock;
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		ERR_EXIT("tcp_client");

	if (port > 0) {
		int on = 1;
		if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on))) < 0)
			ERR_EXIT("setsockopt");

		char ip[16] = {0};
		//获取本机IP地址
		getlocalip(ip);
		struct sockaddr_in localaddr;
		memset(&localaddr, 0, sizeof(localaddr));
		localaddr.sin_family = AF_INET;
		localaddr.sin_port = htons(port);
		localaddr.sin_addr.s_addr = inet_addr(ip);
		if (bind(sock, (struct sockaddr*)&localaddr, sizeof(localaddr)) < 0)
			ERR_EXIT("bind");
	}

	return sock;
}

/**
 * tcp_server 启动 TCP 服务器
 * @host 服务器 IP 地址或服务器主机名
 * @port 服务器端口
 * 成功返回监听套接字
 */
int tcp_server(const char *host, unsigned short port)
{
	int listenfd;
	if ((listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		ERR_EXIT("tcp_server");

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	if (host != NULL) {
		//将点分十进制的ip地址转换为in_addr
		//if里面是主机名的情况
		//只有host是ip地址的时候,inet_aton才能正常发生转化
		if (inet_aton(host, &servaddr.sin_addr) == 0) {
			struct hostent *hp;
			//通过主机名获取主机上的所有ip地址
			hp = gethostbyname(host);
			if (hp == NULL)
				ERR_EXIT("gethostbyname");

			//主机上的第一个ip地址
			servaddr.sin_addr = *(struct in_addr*)hp->h_addr;
		}
	}
	else
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	servaddr.sin_port = htons(port);

	//设置地址重复利用
	int on = 1;
	if ((setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on))) < 0)
		ERR_EXIT("setsockopt");

	if (bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
		ERR_EXIT("bind");

	if (listen(listenfd, SOMAXCONN) < 0)
		ERR_EXIT("listen");

	return listenfd;
}

int getlocalip(char *ip)
{
	char host[100] = {0};
	if (gethostname(host, sizeof(host)) < 0)
		return -1;
	struct hostent *hp;
	if ((hp = gethostbyname(host)) == NULL)
	return -1;

	//h_addr The first address in h_addr_list for backward compatibility.
	strcpy(ip, inet_ntoa(*(struct in_addr*)hp->h_addr));
	return 0;
}


/**
 * 设置 IO 为非阻塞模式
 * @fd 文件描述符
 */
void activate_nonblock(int fd)
{
	int ret;
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		ERR_EXIT("fcntl");

	flags |= O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret == -1)
		ERR_EXIT("fcntl");
}

/**
 * 设置 IO 为阻塞模式
 * @fd 文件描述符
 */
void deactivate_nonblock(int fd)
{
	int ret;
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		ERR_EXIT("fcntl");

	flags &= ~O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret == -1)
		ERR_EXIT("fcntl");
}
/**
 * 读超时检测函数，不含读操作
 * @fd 文件描述符
 * @wait_seconds 等待超时秒数，如果为零表示不超时
 * 成功（未超时）返回 0
 * 失败返回 -1
 * 超时返回 -1 且 errno = ETIMEDOUT
 */
int read_timeout(int fd, unsigned int wait_seconds)
{
	int ret = 0;
	if (wait_seconds > 0) {
		fd_set read_fdset;
		struct timeval timeout;

		FD_ZERO(&read_fdset);
		FD_SET(fd, &read_fdset);

		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do {
			ret = select(fd + 1, &read_fdset, NULL, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);

		//经过了timeout等待后仍无文件满足要求，返回0
		if (ret == 0) {
			ret = -1;
			errno = ETIMEDOUT;
		}
		//正常情况下返回满足要求的文件描述符个数
		else if (ret == 1)
			ret = 0;
	}

	return ret;
}

/**
 * 写超时检测函数，不含写操作
 * @fd 文件描述符
 * @wait_seconds 等待超时秒数，如果为零表示不超时
 * 成功（未超时）返回 0
 * 失败返回 -1
 * 超时返回 -1 且 errno = ETIMEDOUT
 */
int write_timeout(int fd, unsigned int wait_seconds)
{
	int ret = 0;
	if (wait_seconds > 0) {
		fd_set write_fdset;
		struct timeval timeout;

		FD_ZERO(&write_fdset);
		FD_SET(fd, &write_fdset);

		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do {
			ret = select(fd + 1, NULL, &write_fdset, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);

		if (ret == 0) {
			ret = -1;
			errno = ETIMEDOUT;
		}
		else if (ret == 1)
			ret = 0;
	}

	return ret;
}

/**
 * 带超时的 accept
 * @fd 套接字
 * @addr 输出参数，返回对方地址
 * @wait_seconds 等待超时秒数，如果为零表示不超时
 * 成功（未超时）返回已连接套接字
 * 失败返回 -1 且 errno = ETIMEDOUT
 */
int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
	int ret;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	//超时检测
	if (wait_seconds > 0) {
		fd_set accept_fdset;
		struct timeval timeout;
		FD_ZERO(&accept_fdset);
		FD_SET(fd, &accept_fdset);
		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do {
			ret = select(fd + 1, &accept_fdset, NULL, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);
        if (ret == -1) {
			return -1;
        }
		else if (ret == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
	}

	if (addr != NULL)
		//返回已连接套接字
		ret = accept(fd, (struct sockaddr*)addr, &addrlen);
	else
		ret = accept(fd, NULL, NULL);

	return ret;
}

/**
 * 带超时的 connect
 * @fd 套接字
 * @addr 要连接的对方地址
 * @wait_seconds 等待超时秒数，如果为零表示不超时
 * 成功（未超时）返回 0
 * 失败返回 -1
 * 超时返回 -1 且 errno = ETIMEDOUT
 */

int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
	int ret;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	if (wait_seconds > 0)
		//将套接字fd变为非阻塞模式
		activate_nonblock(fd);

	ret = connect(fd, (struct sockaddr*)addr, addrlen);
	if (ret < 0 && errno == EINPROGRESS) {
		fd_set connect_fdset;
		struct timeval timeout;
		FD_ZERO(&connect_fdset);
		FD_SET(fd, &connect_fdset);
		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do {
			//一旦连接建立，套接字就可写
			ret = select(fd + 1, NULL, &connect_fdset, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);
		连接超时
		if (ret == 0) {
			ret = -1;
			errno = ETIMEDOUT;
		}
		else if (ret < 0)
			return -1;
		else if (ret == 1) {
			//printf("BBBBB\n");
			/* ret 返回为 1 有两种情况，一种是连接建立成功，一种是套接字产生错误
			此时错误信息不会保存在 errno 变量中，因此需要调用 getsockopt 来获取 */
			int err;//错误代码
			socklen_t socklen = sizeof(err);
			//获取套接字的错误代码到err中
			int sockoptret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &socklen);
			if (sockoptret == -1) {
				return -1;
			}
			//没有错误，说明建立成功
			if (err == 0) {
				//printf("DDDDDDD\n");
				ret = 0;
			}
			//产生错误
			else {
				//printf("CCCCCC\n");
				errno = err;
				ret = -1;
			}
		}
	}
	if (wait_seconds > 0) {
		deactivate_nonblock(fd);
	}
	return ret;
}

/**
 * 读取固定字节数
 * @fd 文件描述符
 * @buf 接收缓冲区
 * @count 要读取的字节数
 * 成功返回 count，失败返回 -1，读到 EOF 返回 < count
 */
ssize_t readn(int fd, void *buf, size_t count)
{
	size_t nleft = count;
	ssize_t nread;
	char *bufp = (char*)buf;

	while (nleft > 0) {
		if ((nread = read(fd, bufp, nleft)) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		else if (nread == 0)
			return count - nleft;

		bufp += nread;
		nleft -= nread;
	}

	return count;
}

/**
 * 发送固定字节数
 * @fd 文件描述符
 * @buf 发送缓冲区
 * @count 要发送的字节数
 * 成功返回 count，失败返回 -1
 */
ssize_t writen(int fd, const void *buf, size_t count)
{
	size_t nleft = count;
	ssize_t nwritten;
	char *bufp = (char*)buf;

	while (nleft > 0) {
		if ((nwritten = write(fd, bufp, nleft)) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		else if (nwritten == 0)
			continue;

		bufp += nwritten;
		nleft -= nwritten;
	}

	return count;
}

/**
 * 仅仅查看套接字缓冲区，但不移除数据
 * @sockfd 套接字
 * @buf 接收缓冲区
 * @len 长度
 * 成功返回 >= 0，失败返回 -1
 */
ssize_t recv_peek(int sockfd, void *buf, size_t len)
{
	while (1) {
		int ret = recv(sockfd, buf, len, MSG_PEEK);
		if (ret == -1 && errno == EINTR)
			continue;
		return ret;
	}
}

/**
 * 按行读取套接字
 * @sockfd 套接字
 * @buf 接收缓冲区
 * @maxline 每行最大长度
 * 成功返回 >= 0，失败返回 -1
 */
ssize_t readline(int sockfd, void *buf, size_t maxline)
{
	int ret;
	int nread;
	char *bufp = buf;
	int nleft = maxline;
	while (1) {
		ret = recv_peek(sockfd, bufp, nleft);
		if (ret < 0)
			return ret;
		else if (ret == 0)
			return ret;

		nread = ret;
		int i;
		for (i=0; i<nread; i++) {
			if (bufp[i] == '\n') {
				ret = readn(sockfd, bufp, i+1);
				if (ret != i+1)
					exit(EXIT_FAILURE);

				return ret;
			}
		}

		if (nread > nleft)
			exit(EXIT_FAILURE);

		nleft -= nread;
		ret = readn(sockfd, bufp, nread);
		if (ret != nread)
			exit(EXIT_FAILURE);

		bufp += nread;
	}

	return -1;
}

void send_fd(int sock_fd, int fd)
{
	int ret;
	struct msghdr msg;
	struct cmsghdr *p_cmsg;
	struct iovec vec;
	char cmsgbuf[CMSG_SPACE(sizeof(fd))];
	int *p_fds;
	char sendchar = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	p_cmsg = CMSG_FIRSTHDR(&msg);
	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	p_fds = (int*)CMSG_DATA(p_cmsg);
	*p_fds = fd;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	vec.iov_base = &sendchar;
	vec.iov_len = sizeof(sendchar);
	ret = sendmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("sendmsg");
}

int recv_fd(const int sock_fd)
{
	int ret;
	struct msghdr msg;
	char recvchar;
	struct iovec vec;
	int recv_fd;
	char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
	struct cmsghdr *p_cmsg;
	int *p_fd;
	vec.iov_base = &recvchar;
	vec.iov_len = sizeof(recvchar);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;

	p_fd = (int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
	*p_fd = -1;  
	ret = recvmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("recvmsg");

	p_cmsg = CMSG_FIRSTHDR(&msg);
	if (p_cmsg == NULL)
		ERR_EXIT("no passed fd");


	p_fd = (int*)CMSG_DATA(p_cmsg);
	recv_fd = *p_fd;
	if (recv_fd == -1)
		ERR_EXIT("no passed fd");

	return recv_fd;
}

//获取文件类型和权限的函数
const char* statbuf_get_perms(struct stat *sbuf)
{
	文件类型+9位的权限位
	static char perms[] = "----------";
	//文件类型，刚开始还不确定
	perms[0] = '?';

	//st_mode中保存了文件类型以及权限位
	mode_t mode = sbuf->st_mode;
	switch (mode & S_IFMT) {
	//总共有7种文件类型
	case S_IFREG:
		perms[0] = '-';
		break;
	case S_IFDIR:
		perms[0] = 'd';
		break;
	case S_IFLNK:
		perms[0] = 'l';
		break;
	case S_IFIFO:
		perms[0] = 'p';
		break;
	case S_IFSOCK:
		perms[0] = 's';
		break;
	case S_IFCHR:
		perms[0] = 'c';
		break;
	case S_IFBLK:
		perms[0] = 'b';
		break;
	}

	//9个权限位
	if (mode & S_IRUSR) {
		perms[1] = 'r';
	}
	if (mode & S_IWUSR) {
		perms[2] = 'w';
	}
	if (mode & S_IXUSR) {
		perms[3] = 'x';
	}
	if (mode & S_IRGRP) {
		perms[4] = 'r';
	}
	if (mode & S_IWGRP) {
		perms[5] = 'w';
	}
	if (mode & S_IXGRP) {
		perms[6] = 'x';
	}
	if (mode & S_IROTH) {
		perms[7] = 'r';
	}
	if (mode & S_IWOTH) {
		perms[8] = 'w';
	}
	if (mode & S_IXOTH) {
		perms[9] = 'x';
	}
	if (mode & S_ISUID) {
		perms[3] = (perms[3] == 'x') ? 's' : 'S';
	}
	if (mode & S_ISGID) {
		perms[6] = (perms[6] == 'x') ? 's' : 'S';
	}
	if (mode & S_ISVTX) {
		perms[9] = (perms[9] == 'x') ? 't' : 'T';
	}

	//返回权限
	return perms;
}

//获取日期的函数
const char* statbuf_get_date(struct stat *sbuf)
{
	static char datebuf[64] = {0};
	const char *p_date_format = "%b %e %H:%M";
	struct timeval tv;
	//获取当前时间
	gettimeofday(&tv, NULL);
	//取出秒
	time_t local_time = tv.tv_sec;
	if (sbuf->st_mtime > local_time || (local_time - sbuf->st_mtime) > 60*60*24*182) {
		p_date_format = "%b %e  %Y";
	}

	struct tm* p_tm = localtime(&local_time);
	//strftime()函数可以把YYYY-MM-DD HH:MM:SS格式的日期字符串转换成其它形式的字符串
	//datebuf是格式化后的字符串
	strftime(datebuf, sizeof(datebuf), p_date_format, p_tm);

	return datebuf;
}

static int lock_internal(int fd, int lock_type)
{
	int ret;
	//锁的结构体
	struct flock the_lock;
	memset(&the_lock, 0, sizeof(the_lock));
	the_lock.l_type = lock_type;//锁的类型
	the_lock.l_whence = SEEK_SET;//加锁的位置
	the_lock.l_start = 0;//头部的偏移位置开始加锁
	the_lock.l_len = 0;//加锁的字节数，0表示整个文件
	do {
		ret = fcntl(fd, F_SETLKW, &the_lock);
	}
	while (ret < 0 && errno == EINTR);//被信号中断了，继续加锁，直到成功为止

	return ret;
}

//加读锁
int lock_file_read(int fd)
{
	return lock_internal(fd, F_RDLCK);
}

//加写锁
int lock_file_write(int fd)
{
	return lock_internal(fd, F_WRLCK);
}

//解锁
int unlock_file(int fd)
{
	int ret;
	struct flock the_lock;
	memset(&the_lock, 0, sizeof(the_lock));
	the_lock.l_type = F_UNLCK;
	the_lock.l_whence = SEEK_SET;
	the_lock.l_start = 0;
	the_lock.l_len = 0;

	ret = fcntl(fd, F_SETLK, &the_lock);

	return ret;
}

//获取系统当前时间的秒数
static struct timeval s_curr_time;
long get_time_sec(void)
{
	if (gettimeofday(&s_curr_time, NULL) < 0) {
		ERR_EXIT("gettimeofday");
	}

	return s_curr_time.tv_sec;
}

//获取系统当前时间的微秒
long get_time_usec(void)
{
	return s_curr_time.tv_usec;
}

//进行睡眠一定的时间
void nano_sleep(double seconds)
{
	time_t secs = (time_t)seconds;					//整数部分
	double fractional = seconds - (double)secs;		// 小数部分

	struct timespec ts;
	ts.tv_sec = secs;//秒
	ts.tv_nsec = (long)(fractional * (double)1000000000);//纳秒
	
	int ret;
	//用一个循环来执行，因为有可能会被中断
	do {
		//nanosleep用来睡眠
		ret = nanosleep(&ts, &ts);
	}
	while (ret == -1 && errno == EINTR);//失败了而且是因为信号停止了
}

//紧急数据的接收
// 开启套接字fd接收带外数据的功能
void activate_oobinline(int fd)
{
	//表示开启
	int oob_inline = 1;
	int ret;
	ret = setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &oob_inline, sizeof(oob_inline));
	if (ret == -1) {
		ERR_EXIT("setsockopt");
	}
}

// 当套接字fd上有带外数据的时候，将产生SIGURG信号
// 该函数设定当前进程能够接收fd文件描述符所产生的SIGURG信号
void activate_sigurg(int fd)
{
	int ret;
	//设置异步I/O所有权
	/*
	F_SETOWN命令允许我们指定用于接收SIGIO和SIGURG信号的套接字属主（进程ID或进程组ID）。
	其中SIGIO信号是套接字被设置为信号驱动式I/O型后产生的，SIGURG信号是在新的带外数据
	到达套接字时产生的。
	*/
	ret = fcntl(fd, F_SETOWN, getpid());
	if (ret == -1) {
		ERR_EXIT("fcntl");
	}
}

