#include "common.h"
#include "sysutil.h"
#include "session.h"
#include "str.h"
#include "tunable.h"
#include "parseconf.h"
#include "ftpproto.h"
#include "ftpcodes.h"
#include "hash.h"

extern session_t *p_sess;
//当前的子进程数目
static unsigned int s_children;

//ip与对应连接数的哈希表
static hash_t *s_ip_count_hash;
//进程与ip对应关系的哈希表
static hash_t *s_pid_ip_hash;

void check_limits(session_t *sess);
void handle_sigchld(int sig);
//哈希函数的原型
unsigned int hash_func(unsigned int buckets, void *key);

unsigned int handle_ip_count(void *ip);
void drop_ip_count(void *ip);

int main(void)
{
	//加载配置文件，读取其中的信息
	parseconf_load_file(ICEFTP_CONF);
	//变成了守护进程
	//daemon(0, 0);

	printf("tunable_pasv_enable=%d\n", tunable_pasv_enable);
	printf("tunable_port_enable=%d\n", tunable_port_enable);

	printf("tunable_listen_port=%u\n", tunable_listen_port);
	printf("tunable_max_clients=%u\n", tunable_max_clients);
	printf("tunable_max_per_ip=%u\n", tunable_max_per_ip);
	printf("tunable_accept_timeout=%u\n", tunable_accept_timeout);
	printf("tunable_connect_timeout=%u\n", tunable_connect_timeout);
	printf("tunable_idle_session_timeout=%u\n", tunable_idle_session_timeout);
	printf("tunable_data_connection_timeout=%u\n", tunable_data_connection_timeout);
	printf("tunable_local_umask=0%o\n", tunable_local_umask);
	printf("tunable_upload_max_rate=%u\n", tunable_upload_max_rate);
	printf("tunable_download_max_rate=%u\n", tunable_download_max_rate);

	if (tunable_listen_address == NULL)
		printf("tunable_listen_address=NULL\n");
	else
		printf("tunable_listen_address=%s\n", tunable_listen_address);


	//只能由root用户启动ftp
	if (getuid() != 0) {
		fprintf(stderr, "iceftpd: must be started as root\n");
		exit(EXIT_FAILURE);
	}

    session_t sess =  {
		/* 控制连接 */
		0, -1, "", "", "",
		/* 数据连接 */
		NULL, -1, -1, 0,
		/* 限速 */
		0, 0, 0, 0,
		/* 父子进程通道 */
		-1, -1,
		/* FTP协议状态 */
		0, 0, NULL, 0,
		/* 连接数限制 */
		0, 0
	};

	p_sess = &sess;

	sess.bw_upload_rate_max = tunable_upload_max_rate;
	sess.bw_download_rate_max = tunable_download_max_rate;

	//创建hash表，256是桶的个数，hash_fun是哈希函数
	s_ip_count_hash = hash_alloc(256, hash_func);
	s_pid_ip_hash = hash_alloc(256, hash_func);

	//子进程退出时候的信号处理函数
	signal(SIGCHLD, handle_sigchld);
	//启动ftp服务器
	int listenfd = tcp_server(tunable_listen_address, tunable_listen_port);
	int conn;
	pid_t pid;
	struct sockaddr_in addr;

    //接受客户端的连接
	while (1) {
		//得到了当前连接过来的客户端的地址，并且保存到addr中
		//返回一个已连接套接字
		conn = accept_timeout(listenfd, &addr, 0);
		if (conn == -1)
			ERR_EXIT("accept_tinmeout");

		//取出ip，32位的整数
		unsigned int ip = addr.sin_addr.s_addr;

		//来了一个新的客户端，需要创建子进程出来
		++s_children;
		//当前连接数等于子进程数
		sess.num_clients = s_children;
		//更新并且返回当前ip对应的连接数
		sess.num_this_ip = handle_ip_count(&ip);

		pid = fork();
		if (pid == -1) {
			//如果创建失败了，就把前面的++进行--
			--s_children;
			ERR_EXIT("fork");
		}
		//有客户端连接过来创建一个服务进程	
		if (pid == 0) {
			//子进程不需要监听
			close(listenfd);
			sess.ctrl_fd = conn;
			//连接数限制的一个判断
			check_limits(&sess);
			//因为还有ftp服务进程与nobody进程的父子关系，所以要忽略信号
			signal(SIGCHLD, SIG_IGN);
			//处理连接的会话，可以将客户端与服务器端的通信过程抽象为一个会话
			//启动会话
			begin_session(&sess);
		} 
		else
		{
			//添加进程和ip的对应关系，这里的进程是子进程
			hash_add_entry(s_pid_ip_hash, &pid, sizeof(pid),
				&ip, sizeof(unsigned int));
			
			close(conn);
		}
	}
	return 0;
}

//连接数的判定
void check_limits(session_t *sess)
{
	//最大连接数配置项是否开启并且当前连接数超过了最大连接数
	if (tunable_max_clients > 0 && sess->num_clients > tunable_max_clients) {
		ftp_reply(sess, FTP_TOO_MANY_USERS, 
			"There are too many connected users, please try later.");

		//退出当前子进程
		exit(EXIT_FAILURE);
	}

    //最大连接数没有超过上限的情况下，再检查ip的连接数是否超过上限
	if (tunable_max_per_ip > 0 && sess->num_this_ip > tunable_max_per_ip) {
		ftp_reply(sess, FTP_IP_LIMIT, 
			"There are too many connections from your internet address.");

		exit(EXIT_FAILURE);
	}
}


void handle_sigchld(int sig)
{
	// 当一个客户端退出的时候，那么该客户端对应ip的连接数要减1，
	// 处理过程是这样的，首先是客户端退出的时候，
	// 父进程需要知道这个客户端的ip，这可以通过在s_pid_ip_hash查找得到，
	

	pid_t pid;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
		--s_children;
		//通过pid找到ip
		unsigned int *ip = hash_lookup_entry(s_pid_ip_hash, &pid, sizeof(pid));
		if (ip == NULL) {
			continue;
		}

		drop_ip_count(ip);
		//进程退出，进程和ip的表项就没有意义了
		hash_free_entry(s_pid_ip_hash, &pid, sizeof(pid));
	}

}

//哈希函数
unsigned int hash_func(unsigned int buckets, void *key)
{
	unsigned int *number = (unsigned int*)key;//void*转换为unsigned int*

	//返回桶号
	return (*number) % buckets;
}

//返回当前ip的连接数，进行加1操作
unsigned int handle_ip_count(void *ip)
{
	// 当一个客户登录的时候，要在s_ip_count_hash更新这个表中的对应表项,
	// 即该ip对应的连接数要加1，如果这个表项还不存在，要在表中添加一条记录，
	// 并且将ip对应的连接数置1。

	unsigned int count;
	unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash,
		ip, sizeof(unsigned int));
	//表明该ip是第一次连接
	if (p_count == NULL) {
		count = 1;
		//插入一个表项
		hash_add_entry(s_ip_count_hash, ip, sizeof(unsigned int),
			&count, sizeof(unsigned int));
	}
	//表项已经存在，更新对应的连接数
	else {
		count = *p_count;
		++count;
		*p_count = count;
	}

	return count;
}


//减1操作
void drop_ip_count(void *ip)
{
	// 得到了ip进而我们就可以在s_ip_count_hash表中找到对应的连接数，进而进行减1操作。

	unsigned int count;
	unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash,
		ip, sizeof(unsigned int));
	if (p_count == NULL) {
		return;
	}

	count = *p_count;
	if (count <= 0) {
		return;
	}
	--count;
	*p_count = count;

	if (count == 0) {
		//可以删除表项了
		hash_free_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	}
}

