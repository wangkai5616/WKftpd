#ifndef _COMMON_H_
#define _COMMON_H_

//头文件模块

#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>

#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/time.h>


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define ERR_EXIT(m) \
    do { \
        perror(m); \
        exit(EXIT_FAILURE); \
    } while (0)

//每行每个命令的最大值
#define MAX_COMMAND_LINE 1024
//命令的最大值
#define MAX_COMMAND 32
//参数的最大值
#define MAX_ARG 1024
//配置文件的路径
#define ICEFTP_CONF "iceftpd.conf"

#endif /* _COMMON_H_ */

