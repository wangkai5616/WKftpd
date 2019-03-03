#include "parseconf.h"
#include "common.h"
#include "tunable.h"
#include "str.h"

//������Ľ���ģ��

static struct parseconf_bool_setting {
  const char *p_setting_name;
  int *p_variable;
}

//����bool���͵ı��
//����Ǳ������ṹ�����͵����飬ֱ�Ӹ��ڽṹ�������еĶ���
parseconf_bool_array[] = {
	{ "pasv_enable", &tunable_pasv_enable },
	{ "port_enable", &tunable_port_enable },
	{ NULL, NULL }
};

static struct parseconf_uint_setting {
	const char *p_setting_name;
	unsigned int *p_variable;
}

//�����޷������͵ı��
parseconf_uint_array[] = {
	{ "listen_port", &tunable_listen_port },//���p_setting_nameΪlisten_port����������Ϣ���浽tunable_listen_port
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

//���ǵõ�һ��������ȴ��ַ��������н�������
//�����������listen_address�����������ֵ���浽tunable_listen_address
parseconf_str_array[] = {
	{ "listen_address", &tunable_listen_address },
	{ NULL, NULL }
};


//���������ļ�
//һ��һ�ж�ȡ������Ϣ�����浽��Ӧ�ı�����
void parseconf_load_file(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (fp == NULL)
		ERR_EXIT("fopen");

	char setting_line[1024] = {0};
	//һ��һ�ж�ȡ������Ϣ�����浽setting_line��
	while (fgets(setting_line, sizeof(setting_line), fp) != NULL) {
		//ÿ����ȡ��һ�У��ж��Ƿ�Ϸ�
		if (strlen(setting_line) == 0
			|| setting_line[0] == '#'
			|| str_all_space(setting_line))
			continue;

		//ȥ��\r\n,��Ϊfets��ѻس����з�Ҳ������
		str_trim_crlf(setting_line);
		//����������
		parseconf_load_setting(setting_line);
		//׼��������ȡ��һ��
		memset(setting_line, 0, sizeof(setting_line));
	}

	fclose(fp);
}


//����������ص���Ӧ�ı���
//���ڵõ�һ�����ݣ�һ�������У���Ҫ������������Ӧ������������У�����Ҫ�����ű�
//���н��б���������ڱ�����ҵ�һ�����Ӧ���������ƣ���ô�ͽ�������Ϣ���浽
//���Ӧ�����ñ�����
void parseconf_load_setting(const char *setting)
{
	// ȥ����ո�
	while (isspace(*setting))
		setting++;

	char key[128] ={0};
	char value[128] = {0};
	str_split(setting, key, value, '=');
	if (strlen(value) == 0) {
		fprintf(stderr, "mising value in config file for: %s\n", key);
		exit(EXIT_FAILURE);
	}
	//���ھͽ��������key���浽��key�������������ֵ��������value������
	//�������key�����ű���н������� 

		//����һ��ָ��ָ��ṹ�� parseconf_str_array����
		const struct parseconf_str_setting *p_str_setting = parseconf_str_array;
	    //����������н��б���
		while (p_str_setting->p_setting_name != NULL) {
			//һ��һ��������������
			if (strcmp(key, p_str_setting->p_setting_name) == 0) {
				//����һ��ָ��ָ������ĵ�ַ��ע��p_variable��������const char**
				const char **p_cur_setting = p_str_setting->p_variable;
				//ȡ�����������ݣ������ж�
				//����Ϊ�գ�˵��֮ǰ�Ѿ��������ˣ�����free��
				if (*p_cur_setting)
					free((char*)*p_cur_setting);

				//strdup�ڲ������ڴ棬ֵ��value
				//strdup���õ���malloc��memcpy
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
				//��0��ͷ�İ˽���
				if (value[0] == '0')
					*(p_uint_setting->p_variable) = str_octal_to_uint(value);
				else
					//atoi���ַ���strת����һ�����������ؽ��
					*(p_uint_setting->p_variable) = atoi(value);

				return;
			}

			p_uint_setting++;
		}
}

