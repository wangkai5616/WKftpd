#include "hash.h"
#include "common.h"
#include <assert.h>

//����ṹ
typedef struct hash_node {
	void *key;
	void *value;
	struct hash_node *prev;
	struct hash_node *next;
} hash_node_t;


struct hash {
	unsigned int buckets;//Ͱ�ĸ���
	hashfunc_t hash_func;//��ϣ����
	hash_node_t **nodes;//��ϣ���д�ŵ������ַ
};

hash_node_t** hash_get_bucket(hash_t *hash, void *key);
hash_node_t* hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size);


///����һ����ϣ��
hash_t *hash_alloc(unsigned int buckets, hashfunc_t hash_func)
{
	hash_t *hash = (hash_t *)malloc(sizeof(hash_t));
	//assert(hash != NULL);
	hash->buckets = buckets;
	hash->hash_func = hash_func;
	//��Ҫsize��С��ָ��
	int size = buckets * sizeof(hash_node_t *);
	//ָ��ָ��ĵ�ַ
	hash->nodes = (hash_node_t **)malloc(size);
	memset(hash->nodes, 0, size);
	return hash;
}

//����
void* hash_lookup_entry(hash_t *hash, void* key, unsigned int key_size)
{
	hash_node_t *node = hash_get_node_by_key(hash, key, key_size);
	if (node == NULL) {
		return NULL;
	}

	return node->value;
}

//���һ��������Ƚ��в����Ƿ����
void hash_add_entry(hash_t *hash, void *key, unsigned int key_size,
	void *value, unsigned int value_size)
{
	//�Ѿ�����
	if (hash_lookup_entry(hash, key, key_size)) {
		fprintf(stderr, "duplicate hash key\n");
		return;
	}

	hash_node_t *node = malloc(sizeof(hash_node_t));
	node->prev = NULL;
	node->next = NULL;

	node->key = malloc(key_size);
	memcpy(node->key, key, key_size);

	node->value = malloc(value_size);
	memcpy(node->value, value, value_size);

	hash_node_t **bucket = hash_get_bucket(hash, key);
	if (*bucket == NULL) {
		*bucket = node;
	} else {
		// ���½����뵽����ͷ��
		node->next = *bucket;
		(*bucket)->prev = node;
		*bucket = node;
	}

}

//�ͷ�һ���ڵ�
void hash_free_entry(hash_t *hash, void *key, unsigned int key_size)
{
	hash_node_t *node = hash_get_node_by_key(hash, key, key_size);
	if (node == NULL) {
		return;
	}

	free(node->key);
	free(node->value);

    if (node->prev) {
		node->prev->next = node->next;
    } else {
		hash_node_t **bucket = hash_get_bucket(hash, key);
		*bucket = node->next;
	}

	if (node->next)
		node->next->prev = node->prev;

	free(node);

}

//���Ͱ��ַ
hash_node_t** hash_get_bucket(hash_t *hash, void *key)
{
	//���ݹ�ϣ�������
	unsigned int bucket = hash->hash_func(hash->buckets, key);
	if (bucket >= hash->buckets) {
		fprintf(stderr, "bad bucket lookup\n");
		exit(EXIT_FAILURE);
	}

	return &(hash->nodes[bucket]);
}

//����key��ù�ϣ���е�һ���ڵ�
//��ϣ���ؼ��롢�ؼ���Ĵ�С
hash_node_t* hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size)
{
	//���ҵ�Ͱ��
	hash_node_t **bucket = hash_get_bucket(hash, key);
	//��ӦͰ������ͷָ��
	hash_node_t *node = *bucket;
	if (node == NULL) {
		return NULL;
	}

	while (node != NULL && memcmp(node->key, key, key_size) != 0) {
		node = node->next;
	}

	return node;
}

