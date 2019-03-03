#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"
#include "ftpcodes.h"
#include "tunable.h"
#include "privsock.h"

//这个模块是ftp协议相关的一些细节

void ftp_lreply(session_t *sess, int status, const char *text);

void handle_alarm_timeout(int sig);
void handle_sigalrm(int sig);
void handle_sigurg(int sig);
void start_cmdio_alarm(void);
void start_data_alarm(void);

void check_abor(session_t *sess);

//列出当前目录
int list_common(session_t *sess, int detail);
void limit_rate(session_t *sess, int bytes_transfered, int is_upload);
void upload_common(session_t *sess, int is_append);

int get_port_fd(session_t *sess);
int get_pasv_fd(session_t *sess);
int get_transfer_fd(session_t *sess);
int port_active(session_t *sess);
int pasv_active(session_t *sess);

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
//static void do_stru(session_t *sess);
//static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);


static void do_site_chmod(session_t *sess, char *chmod_arg);
static void do_site_umask(session_t *sess, char *umask_arg);

//ftp命令及其对应的处理函数
typedef struct ftpcmd {
	const char *cmd;
	void (*cmd_handler)(session_t *sess);
} ftpcmd_t;

//收到“USER命令”，则执行do_user方法，以此类推
//不在这个表格中的命令，就是非法命令
//采用的是命令映射的方式，比if..else好很多
//下面都是服务器所支持的一些特性
static ftpcmd_t ctrl_cmds[] = {
	/*访问控制命令*/
	{"USER",	do_user	},
	{"PASS",	do_pass	},
	{"CWD",		do_cwd	},
	{"XCWD",	do_cwd	},
	{"CDUP",	do_cdup	},
	{"XCUP",	do_cdup	},
	{"QUIT",	do_quit	},
	{"ACCT",	NULL	},//能够识别命令，但是没有响应函数
	{"SMNT",	NULL	},
	{"REIN",	NULL	},
	/* 传输参数命令 */
	{"PORT",	do_port	},
	{"PASV",	do_pasv	},
	{"TYPE",	do_type	},
	{"STRU",	/*do_stru*/NULL	},
	{"MODE",	/*do_mode*/NULL	},

	/* 服务命令 */
	{"RETR",	do_retr	},
	{"STOR",	do_stor	},
	{"APPE",	do_appe	},
	{"LIST",	do_list	},
	{"NLST",	do_nlst	},
	{"REST",	do_rest	},
	{"ABOR",	do_abor	},
	{"\377\364\377\362ABOR", do_abor},
	{"PWD",		do_pwd	},
	{"XPWD",	do_pwd	},
	{"MKD",		do_mkd	},
	{"XMKD",	do_mkd	},
	{"RMD",		do_rmd	},
	{"XRMD",	do_rmd	},
	{"DELE",	do_dele	},
	{"RNFR",	do_rnfr	},
	{"RNTO",	do_rnto	},
	{"SITE",	do_site	},
	{"SYST",	do_syst	},
	{"FEAT",	do_feat },
	{"SIZE",	do_size	},
	{"STAT",	do_stat	},
	{"NOOP",	do_noop	},
	{"HELP",	do_help	},
	{"STOU",	NULL	},
	{"ALLO",	NULL	}
};

session_t *p_sess;
void handle_alarm_timeout(int sig)
{
	//关闭读的一半
	shutdown(p_sess->ctrl_fd, SHUT_RD);
	//给客户端应答
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");
	//关闭写的这一半
	shutdown(p_sess->ctrl_fd, SHUT_WR);
	exit(EXIT_FAILURE);
}

//数据连接通道超时对应的函数
//重新安装信号的处理函数
void handle_sigalrm(int sig)
{
	//数据连接通道超时了，并且当前未处于数据传输的状态
	if (!p_sess->data_process) {
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout. Reconnect. Sorry.");
		exit(EXIT_FAILURE);
	}

	//否则，当前处于数据传输的状态收到了超时信号
	p_sess->data_process = 0;
	//重新启动数据超时闹钟
	start_data_alarm();
}

//这个函数仅仅只是登记abor命令
//一旦产生一个SRGURG信号，意味着发送了一个带外数据（紧急数据）
//也就是abor命令可能发送过来了
void handle_sigurg(int sig)
{
	//判断当前是否处于数据传输的状态
	//如果不是处于数据传输的状态，则不用处理
	if (p_sess->data_fd == -1) {
		return;
	}

	//如果是带外数据传送的，就不会执行do_abor函数了
	char cmdline[MAX_COMMAND_LINE] = {0};
	//接收一行数据，也就是abor命令
	int ret = readline(p_sess->ctrl_fd, cmdline, MAX_COMMAND_LINE);
	if (ret <= 0) {
		ERR_EXIT("readline");
	}

	//去除\r\n
	str_trim_crlf(cmdline);
	//判断收到的是否是abor命令（abor命令没有参数，直接比较就行）
	if (strcmp(cmdline, "ABOR") == 0 
		|| strcmp(cmdline, "\377\364\377\362ABOR") == 0) {
		//收到了abor命令
		p_sess->abor_received = 1;
		//即使处于数据连接，也要断开数据连接通道
		shutdown(p_sess->data_fd, SHUT_RDWR);
	} else {
		ftp_reply(p_sess, FTP_BADCMD, "Unknown command.");
	}
}

//检查是否有chenk_abor命令
void check_abor(session_t *sess)
{
	if (sess->abor_received) {
		sess->abor_received = 0;
		ftp_reply(p_sess, FTP_ABOROK, "ABOR successful.");
	}
}

//启动一个闹钟
void start_cmdio_alarm(void)
{
	if (tunable_idle_session_timeout > 0) {
		// 安装信号
		signal(SIGALRM, handle_alarm_timeout);
		// 启动闹钟
		alarm(tunable_idle_session_timeout);
	}
}

//重新安装SIGALRM信号，并启动闹钟
void start_data_alarm(void)
{
	if (tunable_data_connection_timeout > 0) {
		//安装信号
		signal(SIGALRM, handle_sigalrm);
		// 启动闹钟，取代了先前的那个闹钟
		alarm(tunable_data_connection_timeout);
	}
	//如果数据连接通道没有开启超时，应该将控制连接通道设置的闹钟关闭掉
	else if (tunable_idle_session_timeout > 0) {
		// 关闭先前安装的闹钟	
		alarm(0);
	}
}

//从客户端一行一行接受数据，也就是接收客户端的命令
void handle_child(session_t *sess)
{
    //发送信息给客户端
	ftp_reply(sess, FTP_GREET, "(iceftpd 0.1)");
	int ret;
	//不停接受数据
	while (1) {
		memset(sess->cmdline, 0, sizeof(sess->cmdline));
		memset(sess->cmd, 0, sizeof(sess->cmd));
		memset(sess->arg, 0, sizeof(sess->arg));

		//启动一个闹钟
		//如果你在10s之内有readline，那么就会进行下一次循环，从而再一次执行start_cmdio_alarm();
		//那么又会重启闹钟，原来那个失效
		start_cmdio_alarm();
		//读取到s->cmdline
		//如果规定时间内未超时，则调用readline函数
		ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
		if (ret == -1)
			ERR_EXIT("readline");
		//客户端断开连接
		else if (ret == 0)
			exit(EXIT_SUCCESS);

		//客户端发送过来的命令包含\r\n 去除r\n
		str_trim_crlf(sess->cmdline);
		//接受到的这一行打印出来
		printf("cmdline=[%s]\n", sess->cmdline);
		// 解析FTP命令与参数
		//将cmdline进行分割，命令保存自cmd，参数保存自arg,分割的字符是空格
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
		//分割之后进行打印
		printf("cmd=[%s] arg=[%s]\n", sess->cmd, sess->arg);
		//将命令转换为大写
		str_upper(sess->cmd);


		//处理不同的命令
		int i;
		//数组的长度
		int size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);
		for (i=0; i<size; i++) {
			//如果命令匹配，调用相对应的函数
			if (strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0) {
				if (ctrl_cmds[i].cmd_handler != NULL) {
					ctrl_cmds[i].cmd_handler(sess);
				} else {
					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
				}
				
				break;
			}
		}

		if (i == size) {
			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
		}
	}
}

//当连接建立的时候，发送信息给客户端
//参数是状态和文本
void ftp_reply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	//将信息格式化到buf中
	sprintf(buf, "%d %s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

//发送信息给客户端时，格式是"%d-%s
void ftp_lreply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d-%s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

//目录列表的实现，将当前目录列出来
int list_common(session_t *sess, int detail)
{
	//打开当前目录
	DIR *dir = opendir(".");
	if (dir == NULL) {
		return 0;
	}

	//遍历目录中的文件
	struct dirent *dt;
	struct stat sbuf;
	//利用readdir函数进行遍历，d_name是遍历到的名称 
	while ((dt = readdir(dir)) != NULL) {
		//显示文件的状态，保存到sbuf中
		if (lstat(dt->d_name, &sbuf) < 0) {
			continue;
		}
        if (dt->d_name[0] == '.') {
			continue;
        }

		//将获取到的权限、连接数和uid等格式化到buf中
		char buf[1024] = {0};
		//如果是详细的清单
		if (detail) {
			//先获取文件类型和权限
			const char *perms = statbuf_get_perms(&sbuf);

			//off是格式化到buf中的长度
			int off = 0;
			off += sprintf(buf, "%s ", perms);
			//uid、gid和连接数
			off += sprintf(buf + off, " %3d %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
			off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);

			//获取时间
			const char *datebuf = statbuf_get_date(&sbuf);
			off += sprintf(buf + off, "%s ", datebuf);
			//判断是否是符号文件
			if (S_ISLNK(sbuf.st_mode)) {
				char tmp[1024] = {0};
				//获取符号链接文件所指向的文件，保存到tmp中
				readlink(dt->d_name, tmp, sizeof(tmp));
				off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
			} else {
				off += sprintf(buf + off, "%s\r\n", dt->d_name);
			}
		}
		//短的清单，只需要一个文件名称即可
		else {
			sprintf(buf, "%s\r\n", dt->d_name);
		}
		
		//printf("%s", buf);
		writen(sess->data_fd, buf, strlen(buf));
	}
	//循环结束，关闭目录
	closedir(dir);

	return 1;
}

//限速，计算睡眠时间，第二个参数是当前传输的字节数
void limit_rate(session_t *sess, int bytes_transfered, int is_upload)
{
 	//表明处于数据传输的状态
	sess->data_process = 1;

	// 睡眠时间=（当前传输速度/最大传输速度-1）*当前传输时间;
	long curr_sec = get_time_sec();
	long curr_usec = get_time_usec();

	//流过的时间，当前所用的传输时间
	double elapsed;
	elapsed = (double)(curr_sec - sess->bw_transfer_start_sec);
	//秒+微秒
	elapsed += (double)(curr_usec - sess->bw_transfer_start_usec) / (double)1000000;
	if (elapsed <= (double)0) {//等于0的情况有可能，因为传的太快了
		elapsed = (double)0.01;
	}


	// 计算当前传输速度，传输的量除以传输时间,忽略了传输速度的小数部分
	unsigned int bw_rate = (unsigned int)((double)bytes_transfered / elapsed);

	double rate_ratio;
	//上传
	if (is_upload) {
		//当前速度小于上传速度
		if (bw_rate <= sess->bw_upload_rate_max) {
			// 不需要限速，也需要更新时间
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			return;
		}

		//根据公式进行计算
		rate_ratio = bw_rate / sess->bw_upload_rate_max;
	}
	//下载
	else {
		if (bw_rate <= sess->bw_download_rate_max) {
			//不需要限速 
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			return;
		}

		rate_ratio = bw_rate / sess->bw_download_rate_max;
	}

	//计算睡眠时间
	//睡眠时间=（当前传输速度/最大传输速度-1）*当前传输时间��;
	double pause_time;
	//需要睡眠的时间
	pause_time = (rate_ratio - (double)1) * elapsed;

	//进行睡眠
	nano_sleep(pause_time);

	//更新时间，下一次要开始传输的时间更新为当前时间
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

}

//上传文件内部实现
void upload_common(session_t *sess, int is_append)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0) {
		return;
	}

	//保存断点
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;

	// 打开一个文件，接收上传的内容，0表示8进制
	int fd = open(sess->arg, O_CREAT | O_WRONLY, 0666);
	if (fd == -1) {
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	int ret;
	// 加写锁，不允许其他进程读写
	ret = lock_file_write(fd);
	if (ret == -1) {
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	// STOR   普通上传
	// REST+STOR   断点续传
	// APPE    断点续传
	if (!is_append && offset == 0) {   // STOR模式上传
		//将文件清0
		ftruncate(fd, 0);
		//定位到文件头的位置
		if (lseek(fd, 0, SEEK_SET) < 0) {
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}
	else if (!is_append && offset != 0) { // REST+STOR
		//偏移到offset位置
		if (lseek(fd, offset, SEEK_SET) < 0) {
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}
	else if (is_append) {   // APPE（追加）
		//偏移到文件的末尾
		if (lseek(fd, 0, SEEK_END) < 0) {
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if (!S_ISREG(sbuf.st_mode)) {
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	// 150
	char text[1024] = {0};
	if (sess->is_ascii) {
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	} else {
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	}

	ftp_reply(sess, FTP_DATACONN, text);

	int flag = 0;
	// 上传文件

	char buf[1024];

    //开始传输之前的时间
    //获取当前时间的秒数和微秒数
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

	//这是一个循环，所以能实现上传大文件
	while (1) {
		//从数据套接字接收数据
		ret = read(sess->data_fd, buf, sizeof(buf));
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				flag = 2;
				break;
			}
		}
		else if (ret == 0) {
			flag = 0;
			break;
		}

		//读取了一定数据之后需要判断是否限速
		limit_rate(sess, ret, 1);
		//睡醒之后判断是否收到了abor，如果是直接break,其实没有也可以，返回去
		//的时候read会返回-1，因为已经关闭了数据连接套接字了
		if (sess->abor_received) {
			flag = 2;
			break;
		}

		//写入文件中
		if (writen(fd, buf, ret) != ret) {
			flag = 1;
			break;
		}
	}


	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;

	//关闭文件
	close(fd);

	if (flag == 0 && !sess->abor_received) {
		// 226
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	//写入到本地文件失败 
	else if (flag == 1) {
		// 451
		ftp_reply(sess, FTP_BADSENDFILE, "Failure writting to local file.");
	}
	else if (flag == 2) {
		// 426 网络发送失败
		ftp_reply(sess, FTP_BADSENDNET, "Failure reading from network stream.");
	}

	//上传文件完毕，检测是否有abor命令过来
	check_abor(sess);
	// 重新开启控制连接通道
	start_cmdio_alarm();
}

//判断主动模式是否处于激活状态
int port_active(session_t *sess)
{
	if (sess->port_addr) {
		if (pasv_active(sess)) {
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}

	return 0;
}

//判断被动模式是否处于激活状态
int pasv_active(session_t *sess)
{
	//实际是由nobody进程进行判断的，因为监听套接字是由nobbody进程创建的
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
	int active = priv_sock_get_int(sess->child_fd);
	if (active) {
		if (port_active(sess)) {
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;
}

//获取PORT模式下的数据套接字
int get_port_fd(session_t *sess)
{
	/*
	向nobody发送PRIV_SOCK_GET_DATA_SOCK命令
	向nobbody发送一个整数port
	向nobody发送一个字符串ip         不定长
	*/

	//获得数据连接套接字
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);
	unsigned short port = ntohs(sess->port_addr->sin_port);
	char *ip = inet_ntoa(sess->port_addr->sin_addr);
	//发送端口号和IP地址
	priv_sock_send_int(sess->child_fd, (int)port);
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

	//接受应答
	char res = priv_sock_get_result(sess->child_fd);
	//失败的应答
	if (res == PRIV_SOCK_RESULT_BAD) {
		return 0;
	}
	//成功的应答
	else if (res == PRIV_SOCK_RESULT_OK) {
		//获取到主动模式数据套接字
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}

	return 1;
}

//获取被动模式的数据套接字
int get_pasv_fd(session_t *sess)
{
	//发送一个PRIV_SOCK_PASV_ACCEPT给nobody进程
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
	char res = priv_sock_get_result(sess->child_fd);
	if (res == PRIV_SOCK_RESULT_BAD) {
		return 0;
	}
	else if (res == PRIV_SOCK_RESULT_OK) {
		//接收回传回来的数据套接字
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}

	return 1;
}

//数据连接通道的创建
//创建数据连接，获取数据连接所对应的套接字，有可能是主动模式也可能是被动模式
int get_transfer_fd(session_t *sess)
{
	// 检测是否收到PORT或者PASV命令，也就是检测是主动模式还是被动模式
	if (!port_active(sess) && !pasv_active(sess)) {
		//若上述两者命令都未收到，给客户端一个应答
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
		return 0;
	}

	int ret = 1;
	// 如果是主动模式PORT，则服务器端创建数据套接字（bind20端口），调用conect
	//主动连接客户端IP和端口，从而建立数据连接
	if (port_active(sess)) {
		//获得了数据套接字
		if (get_port_fd(sess) == 0) {
			ret = 0;
		}
	}

	//被动模式 
	if (pasv_active(sess)) {
		//获取被动模式的数据套接字
		if (get_pasv_fd(sess) == 0) {
			ret = 0;
		}

	}

	if (sess->port_addr) {
		free(sess->port_addr);
		sess->port_addr = NULL;
	}

	if (ret) {
		// 不管是哪种方式创建数据通道，一旦创建完毕，就启动数据连接闹钟
		start_data_alarm();
	}

	return ret;
}

//用户名
//static表示只能用于当前模块
static void do_user(session_t *sess)
{
	//USER jjl
	//getpwnam获取用户登录相关信息
	struct passwd *pw = getpwnam(sess->arg);
	//说明是不存在的用户
	if (pw == NULL) {
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//用户id
	sess->uid = pw->pw_uid;
	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");
	
}

//密码
//登录成功
static void do_pass(session_t *sess)
{
	// PASS 123456
	//根据uid得到passwd结构体
	struct passwd *pw = getpwuid(sess->uid);
	//用户不存在
	if (pw == NULL) {
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	printf("name=[%s]\n", pw->pw_name);
	//普通用户无法访问密码文件，所以等到验证结束之后，才切换为用户
	struct spwd *sp = getspnam(pw->pw_name);
	if (sp == NULL) {
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//将明文进行加密，将加密的结果跟已知文件中已经加密的密码进行比较
	//crypt是加密函数，第一个参数是明文，第二个参数是加密的密钥
	//返回一个加密的密码
	char *encrypted_pass = crypt(sess->arg, sp->sp_pwdp);
	// 验证失败
	if (strcmp(encrypted_pass, sp->sp_pwdp) != 0) {
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//接收到SIGURG信号，处理函数是handle_sigurg
	signal(SIGURG, handle_sigurg);
	//开启能够处理SIGURG信号的能力
	activate_sigurg(sess->ctrl_fd);

	umask(tunable_local_umask);
	//将当前进程的有效ID设置为uid
	//也就是从root用户变成了wangkai用户
	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);
	chdir(pw->pw_dir);
	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

//改变当前路径，比如进入到一个子目录中
static void do_cwd(session_t *sess)
{
	//更改路径失败
	if (chdir(sess->arg) < 0) {
		ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");
		return;
	}
	//更改到arg目录下面
	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

//进入上一层目录
static void do_cdup(session_t *sess)
{
	if (chdir("..") < 0) {
		ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");
		return;
	}

	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

//从服务器断开连接
static void do_quit(session_t *sess)
{
	ftp_reply(sess, FTP_GOODBYE, "Goodbye.");
	exit(EXIT_SUCCESS);
}

//主动模式的实现
//FTP服务进程接收到PORT h1,h2,h3,h4,p1,p2
static void do_port(session_t *sess)
{
	unsigned int v[6];

	//arg中保存的是IP和端口，解析出来
	//sscanf从字符串获取输入按照一定的格式 格式化到相应的变量中
	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
	sess->port_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memset(sess->port_addr, 0, sizeof(struct sockaddr_in));
	sess->port_addr->sin_family = AF_INET;
	unsigned char *p = (unsigned char *)&sess->port_addr->sin_port;
	p[0] = v[0];
	p[1] = v[1];

	p = (unsigned char *)&sess->port_addr->sin_addr;
	p[0] = v[2];
	p[1] = v[3];
	p[2] = v[4];
	p[3] = v[5];

	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}

//被动模式的实现
//首先是客户端向ftp发送pasv的命令，FTP服务进程收到pasv命令之后，
//执行do_pasv函数
static void do_pasv(session_t *sess)
{
	//Entering Passive Mode (192,168,244,100,101,46).

	char ip[16] = {0};
	//获取本地的IP地址
	getlocalip(ip);

	//监听的操作由nobody来完成
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
	//nobody监听完成之后，将实际绑定的端口号发送过来
	unsigned short port = (int)priv_sock_get_int(sess->child_fd);


	//将端口号格式化，然后发送给客户端
	unsigned int v[4];
	sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
	char text[1024] = {0};
	sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", 
		v[0], v[1], v[2], v[3], port>>8, port&0xFF);//高8位低8位的获取

	//给客户端响应，包括IP地址和端口号
	ftp_reply(sess, FTP_PASVOK, text);
}

//转到ASII模式
static void do_type(session_t *sess)
{
	if (strcmp(sess->arg, "A") == 0) {
		sess->is_ascii = 1;//表示是ASII模式
		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	}
	else if (strcmp(sess->arg, "I") == 0) {
		sess->is_ascii = 0;
		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	} else {
		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
	}

}
/*
static void do_stru(session_t *sess)
{
}

static void do_mode(session_t *sess)
{
}
*/

static void do_retr(session_t *sess)
{
   //下载文件
	//断点需载
	
	//创建数据连接
	if (get_transfer_fd(sess) == 0) {
		return;
	}

	//保存断点位置
	long long offset = sess->restart_pos;
	//然后将断点位置清零
	sess->restart_pos = 0;

	// 只读方式打开文件
	//将文件里面的内容读取出来，然后写入数据套接字即可
	int fd = open(sess->arg, O_RDONLY);
	if (fd == -1) {
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	int ret;
	// 加读锁，希望在下载的时候其他进程不能更改该文件
	ret = lock_file_read(fd);
	if (ret == -1) {
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	// 判断是否是普通文件
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	//不是普通文件，S_ISREG是否是一个常规文件
	if (!S_ISREG(sbuf.st_mode)) {
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	//说明有断点
	if (offset != 0) {
		//lseek函数的作用是用来重新定位文件读写的位移
		//SEEK_SET，从文件头部开始偏移offset个字节
		ret = lseek(fd, offset, SEEK_SET);
		if (ret == -1) {
			ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
			return;
		}
	}

//150 Opening BINARY mode data connection 

	// 150
	char text[1024] = {0};
	//未实现以ascii模式传输的功能
	//ascii模式传送
	if (sess->is_ascii) {
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	}
	//二进制模式，区别是对\r\n的处理
	else {
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	}

	ftp_reply(sess, FTP_DATACONN, text);

	int flag = 0;
	// 从in_fd读取数据发送到out_fd，并且是在内核空间完成的，效率高，不涉及用户空间到内核空间切换
	// ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

	//计算传送的文件大小  
	long long bytes_to_send = sbuf.st_size;
	if (offset > bytes_to_send) {
		bytes_to_send = 0;  
	}
	else {
		//断点到文件结尾的大小，如果不是断点续传，那么offset=0
		bytes_to_send -= offset;
	}

	//先登记一下时间
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();
	while (bytes_to_send) {
		//发送的字节数
		int num_this_time = bytes_to_send > 4096 ? 4096 : bytes_to_send;
		//当前的传输量，返回值ret是发送的字节数
		ret = sendfile(sess->data_fd, fd, NULL, num_this_time);
		if (ret == -1) {
			flag = 2;
			break;
		}

		limit_rate(sess, ret, 0);
		//如果处于限速状态，恰好接收到abor命令，此刻无法返回，所以需要下面的判断
		if (sess->abor_received) {
			flag = 2;
			break;
		}

		bytes_to_send -= ret;
	}

	//说明已经发送完毕了
	if (bytes_to_send == 0) {
		flag = 0;
	}

	//下载完之后，关闭数据连接
	close(sess->data_fd);
	sess->data_fd = -1;

	close(fd);

	
	//成功的应答
	if (flag == 0 && !sess->abor_received) {
		// 226
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	//读取数据失败
	else if (flag == 1) {
		// 451
		ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
	}
	//写入到数据套接字时失败
	else if (flag == 2) {
		// 426
		ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
	}

	check_abor(sess);
	// 重新开启控制连接通道闹钟，因为有可能在数据连接的时候关闭了
	start_cmdio_alarm();
	
}

//上传文件
static void do_stor(session_t *sess)
{
	//非appe模式
	upload_common(sess, 0);
}

//上传文件
static void do_appe(session_t *sess)
{
	upload_common(sess, 1);
}

//list命令进行数据传输
static void do_list(session_t *sess)
{
	// 创建数据连接，有可能的两种形式
	if (get_transfer_fd(sess) == 0) {
		return;
	}
	// 如果数据连接成功（也就意味着有了数据连接套接字），给客户端150响应
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	// 传输列表
	list_common(sess, 1);
	// 关闭数据套接字，传输完毕之后一定要关闭数据连接套接字，要不然客户端怎么知道传完没有
	close(sess->data_fd);
	sess->data_fd = -1;
	// 226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}

//实现目录的短清单
static void do_nlst(session_t *sess)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0) {
		return;
	}
	// 150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	// �����б�
	list_common(sess, 0);
	// �ر������׽���
	close(sess->data_fd);
	sess->data_fd = -1;
	// 226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}

//断点续传，包括断点上传和断点下载
static void do_rest(session_t *sess)
{
	//将断点信息保存下来
	//这个信息客户端软件知道，也就是客户端知道你传了多少，然后告诉你下次从哪里开始传
	sess->restart_pos = str_to_longlong(sess->arg);
	char text[1024] = {0};
	sprintf(text, "Restart position accepted (%lld).", sess->restart_pos);
	ftp_reply(sess, FTP_RESTOK, text);
}

static void do_abor(session_t *sess)
{
	ftp_reply(sess, FTP_ABOR_NOCONN, "No transfer to ABOR");
	
}

//显式路径
static void do_pwd(session_t *sess)
{
	char text[1024] = {0};
	char dir[1024+1] = {0};
	//得到路径
	getcwd(dir, 1024);
	//转义双引号\"
	sprintf(text, "\"%s\"", dir);

	ftp_reply(sess, FTP_PWDOK, text);
}

//创建一个目录
static void do_mkd(session_t *sess)
{
	// 0777 & umask
	if (mkdir(sess->arg, 0777) < 0) {
		ftp_reply(sess, FTP_FILEFAIL, "Create directory operation failed.");
		return;
	}
	
	char text[4096] = {0};
	//第一个是'/'，说明是绝对路径
	if (sess->arg[0] == '/') {
		sprintf(text, "%s created", sess->arg);
	}
	//相对路径
	else {
		char dir[4096+1] = {0};
		//获取当前路径
		getcwd(dir, 4096);
		//判断当前路径的结尾是不是有'/'
		if (dir[strlen(dir)-1] == '/') {
			sprintf(text, "%s%s created", dir, sess->arg);
		} else {
			sprintf(text, "%s/%s created", dir, sess->arg);
		}
	}

	//响应给客户端
	ftp_reply(sess, FTP_MKDIROK, text);
}

//删除一个文件夹

static void do_rmd(session_t *sess)
{
	if (rmdir(sess->arg) < 0) {
		ftp_reply(sess, FTP_FILEFAIL, "Remove directory operation failed.");
	}

	ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful.");

}

//删除文件
static void do_dele(session_t *sess)
{
	//从文件系统中删除一个名称。如果名称是文件的最后一个连接，
	//并且没有其它进程将文件打开，名称对应的文件会实际被删除
	if (unlink(sess->arg) < 0) {
		ftp_reply(sess, FTP_FILEFAIL, "Delete operation failed.");
		return;
	}

	ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}

//要重命名的文件名，把要更改的文件名保存到sess->rnfr_name中
static void do_rnfr(session_t *sess)
{
	sess->rnfr_name = (char *)malloc(strlen(sess->arg) + 1);
	memset(sess->rnfr_name, 0, strlen(sess->arg) + 1);
	strcpy(sess->rnfr_name, sess->arg);
	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}

//重命名后的文件名称
static void do_rnto(session_t *sess)
{
	if (sess->rnfr_name == NULL) {
		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
		return;
	}

	//第一个参数是旧文件名，后一个参数是更改后的文件名
	rename(sess->rnfr_name, sess->arg);

	ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");

	free(sess->rnfr_name);
	sess->rnfr_name = NULL;
}


static void do_site(session_t *sess)
{
	// SITE CHMOD <perm> <file>
	// SITE UMASK [umask]
	// SITE HELP

	char cmd[100] = {0};
	char arg[100] = {0};

	//先按照空格进行分割
	str_split(sess->arg , cmd, arg, ' ');
	if (strcmp(cmd, "CHMOD") == 0) {
		do_site_chmod(sess, arg);
	}
	else if (strcmp(cmd, "UMASK") == 0) {
		do_site_umask(sess, arg);
	}
	//提示SITE有哪些参数
	else if (strcmp(cmd, "HELP") == 0) {
		ftp_reply(sess, FTP_SITEHELP, "CHMOD UMASK HELP");
	} else {
		 ftp_reply(sess, FTP_BADCMD, "Unknown SITE command.");
	}

}

//当前系统类型
static void do_syst(session_t *sess)
{
	ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}

//请求服务器端的特征，服务器端所支持的一些特性
static void do_feat(session_t *sess)
{
	ftp_lreply(sess, FTP_FEAT, "Features:");
	writen(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"));
	writen(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"));
	writen(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"));
	writen(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"));
	writen(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
	writen(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"));
	writen(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"));
	writen(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"));
	ftp_reply(sess, FTP_FEAT, "End");
}

//文件大小
static void do_size(session_t *sess)
{
	//550 Could not get file size.

	struct stat buf;
	if (stat(sess->arg, &buf) < 0) {
		ftp_reply(sess, FTP_FILEFAIL, "SIZE operation failed.");
		return;
	}

	//判断是否是普通文件，如果是文件夹就返回下面语句
	if (!S_ISREG(buf.st_mode)) {
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}

	char text[1024] = {0};
	sprintf(text, "%lld", (long long)buf.st_size);
	ftp_reply(sess, FTP_SIZEOK, text);
}

//查看服务器的状态
static void do_stat(session_t *sess)
{
	ftp_lreply(sess, FTP_STATOK, "FTP server status:");
	//上传的带宽限制
	if (sess->bw_upload_rate_max == 0) {
		char text[1024];
		sprintf(text,
			"     No session upload bandwidth limit\r\n");
		writen(sess->ctrl_fd, text, strlen(text));
	}
	else if (sess->bw_upload_rate_max > 0) {
		char text[1024];
		sprintf(text,
			"     Session upload bandwidth limit in byte/s is %u\r\n",
			sess->bw_upload_rate_max);
		writen(sess->ctrl_fd, text, strlen(text));
	}

	//下载的带宽限制
	if (sess->bw_download_rate_max == 0) {
		char text[1024];
		sprintf(text,
			"     No session download bandwidth limit\r\n");
		writen(sess->ctrl_fd, text, strlen(text));
	}
	else if (sess->bw_download_rate_max > 0) {
		char text[1024];
		sprintf(text,
			"     Session download bandwidth limit in byte/s is %u\r\n",
			sess->bw_download_rate_max);
		writen(sess->ctrl_fd, text, strlen(text));
	}

	char text[1024] = {0};
	//连接数的限制
	sprintf(text,
		"     At session startup, client count was %u\r\n",
		sess->num_clients);
	writen(sess->ctrl_fd, text, strlen(text));
	
	ftp_reply(sess, FTP_STATOK, "End of status");
}

//防止空闲断开，一旦客户端发送noop命令，空闲时间就重新开始计算
static void do_noop(session_t *sess)
{
	ftp_reply(sess, FTP_NOOPOK, "NOOP ok.");

}

static void do_help(session_t *sess)
{
	ftp_lreply(sess, FTP_HELP, "The following commands are recognized.");
	writen(sess->ctrl_fd,
		" ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n",
		strlen(" ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n"));
	writen(sess->ctrl_fd,
		" MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n",
		strlen(" MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n"));
	writen(sess->ctrl_fd,
		" RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n",
		strlen(" RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n"));
	writen(sess->ctrl_fd,
		" XPWD XRMD\r\n",
		strlen(" XPWD XRMD\r\n"));
	ftp_reply(sess, FTP_HELP, "Help OK.");
}

static void do_site_chmod(session_t *sess, char *chmod_arg)
{
	// SITE CHMOD <perm> <file>
	//说明没有参数
	if (strlen(chmod_arg) == 0) {
		ftp_reply(sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
		return;
	}

	char perm[100] = {0};
	char file[100] = {0};
	//拆分字符串，权限+文件名称
	str_split(chmod_arg , perm, file, ' ');
	if (strlen(file) == 0) {
		ftp_reply(sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
		return;
	}

	//字符串转换8进制整数
	unsigned int mode = str_octal_to_uint(perm);
	//更改文件的权限
	if (chmod(file, mode) < 0) {
		ftp_reply(sess, FTP_CHMODOK, "SITE CHMOD command failed.");
	} else {
		ftp_reply(sess, FTP_CHMODOK, "SITE CHMOD command ok.");
	}
}

static void do_site_umask(session_t *sess, char *umask_arg)
{
	// SITE UMASK [umask]
	if (strlen(umask_arg) == 0) {
		char text[1024] = {0};
		sprintf(text, "Your current UMASK is 0%o", tunable_local_umask);
		ftp_reply(sess, FTP_UMASKOK, text);
	} else {
		unsigned int um = str_octal_to_uint(umask_arg);
		umask(um);
		char text[1024] = {0};
		sprintf(text, "UMASK set to 0%o", um);
		ftp_reply(sess, FTP_UMASKOK, text);
	}
}


