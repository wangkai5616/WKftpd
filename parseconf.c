#include "parseconf.h"
#include "common.h"
#include "tunable.h"
#include "str.h"

//配置项的解析模块

static struct parseconf_bool_setting {
  const char *p_setting_name;
  int *p_variable;
}

//遍历bool类型的表格
//这个是别名，结构体类型的数组，直接跟在结构体后面进行的定义
parseconf_bool_array[] = {
	{ "pasv_enable", &tunable_pasv_enable },
	{ "port_enable", &tunable_port_enable },
	{ NULL, NULL }
};

static struct parseconf_uint_setting {
	const char *p_setting_name;
	unsigned int *p_variable;
}

//遍历无符号整型的表格
parseconf_uint_array[] = {
	{ "listen_port", &tunable_listen_port },//如果p_setting_name为listen_port，将配置信息保存到tunable_listen_port
	{ "max_clients", &tunable_max_clients },
	{ "max_per_ip", &tunable_max_per_ip },
	{ "accept_timeout", &tunable_accept_timeout },
	{ "connect_timeout", &tunable_connect_timeout },
	{ "idle_session_timeout", &tunable_idle_session_timeout },
	{ "data_connection_timeout", &tunable_data_connection_timeout },
	{ "local_umask", &tunable_local_umask },
	{ "upload_max_rate", &tunable_upload_max_rate },
	{ "download_max_rate", &tunable_download_max_rate },
	{ NULL, NULL }
};


static struct parseconf_str_setting {
	const char *p_setting_name;
	const char **p_variable;
}

//我们得到一个配置项，先从字符串数组中进行配置
//若配置项等于listen_address，将配置项的值保存到tunable_listen_address
parseconf_str_array[] = {
	{ "listen_address", &tunable_listen_address },
	{ NULL, NULL }
};


//加载配置文件
//一行一行读取配置信息，保存到相应的变量中
void parseconf_load_file(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (fp == NULL)
		ERR_EXIT("fopen");

	char setting_line[1024] = {0};
	//一行一行读取配置信息，保存到setting_line中
	while (fgets(setting_line, sizeof(setting_line), fp) != NULL) {
		//每当读取到一行，判断是否合法
		if (strlen(setting_line) == 0
			|| setting_line[0] == '#'
			|| str_all_space(setting_line))
			continue;

		//去除\r\n,因为fets会把回车换行符也带回来
		str_trim_crlf(setting_line);
		//解析配置行
		parseconf_load_setting(setting_line);
		//准备继续获取下一行
		memset(setting_line, 0, sizeof(setting_line));
	}

	fclose(fp);
}


//将配置项加载到相应的变量
//现在得到一行数据，一个配置行，需要将它存放至相对应的配置项变量中，这需要在三张表
//格中进行遍历，如果在表格中找到一个相对应的配置名称，那么就将配置信息保存到
//相对应的配置变量中
void parseconf_load_setting(const char *setting)
{
	// 去除左空格
	while (isspace(*setting))
		setting++;

	char key[128] ={0};
	char value[128] = {0};
	str_split(setting, key, value, '=');
	if (strlen(value) == 0) {
		fprintf(stderr, "mising value in config file for: %s\n", key);
		exit(EXIT_FAILURE);
	}
	//现在就将配置项的key保存到了key变量，配置项的值保存在了value变量中
	//下面根据key在三张表格中进行搜索 

		//定义一个指针指向结构体 parseconf_str_array数组
		const struct parseconf_str_setting *p_str_setting = parseconf_str_array;
	    //在数组变量中进行遍历
		while (p_str_setting->p_setting_name != NULL) {
			//一行一行搜索配置项表格
			if (strcmp(key, p_str_setting->p_setting_name) == 0) {
				//定义一个指针指向变量的地址，注意p_variable的类型是const char**
				const char **p_cur_setting = p_str_setting->p_variable;
				//取出变量的内容，进行判定
				//若不为空，说明之前已经有数据了，将它free掉
				if (*p_cur_setting)
					free((char*)*p_cur_setting);

				//strdup内部申请内存，值是value
				//strdup调用的是malloc和memcpy
				*p_cur_setting = strdup(value);
				return;
			}

			p_str_setting++;
		}

		const struct parseconf_bool_setting *p_bool_setting = parseconf_bool_array;
		while (p_bool_setting->p_setting_name != NULL) {
			if (strcmp(key, p_bool_setting->p_setting_name) == 0) {
				str_upper(value);
				if (strcmp(value, "YES") == 0
					|| strcmp(value, "TRUE") == 0
					|| strcmp(value, "1") == 0) {
					*(p_bool_setting->p_variable) = 1;
                }
				else if (strcmp(value, "NO") == 0
					|| strcmp(value, "FALSE") == 0
					|| strcmp(value, "0") == 0) {
					*(p_bool_setting->p_variable) = 0;
                } else {
					fprintf(stderr, "bad bool value in config file for: %s\n", key);
					exit(EXIT_FAILURE);
				}

				return;
			}

			p_bool_setting++;
		}

		const struct parseconf_uint_setting *p_uint_setting = parseconf_uint_array;
		while (p_uint_setting->p_setting_name != NULL) {
			if (strcmp(key, p_uint_setting->p_setting_name) == 0) {
				//以0开头的八进制
				if (value[0] == '0')
					*(p_uint_setting->p_variable) = str_octal_to_uint(value);
				else
					//atoi将字符串str转换成一个整数并返回结果
					*(p_uint_setting->p_variable) = atoi(value);

				return;
			}

			p_uint_setting++;
		}
}

