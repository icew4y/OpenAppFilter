
#include <linux/init.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/etherdevice.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include "cJSON.h"
#include "app_filter.h"
#include "af_utils.h"
#include "af_log.h"
#define AF_MAX_APP_TYPE_NUM 16
#define AF_MAX_APP_NUM 256
#define AF_DEV_NAME "appfilter"

DEFINE_RWLOCK(af_rule_lock);

#define af_rule_read_lock() 		read_lock_bh(&af_rule_lock);
#define af_rule_read_unlock() 		read_unlock_bh(&af_rule_lock);
#define af_rule_write_lock() 		write_lock_bh(&af_rule_lock);
#define af_rule_write_unlock()		write_unlock_bh(&af_rule_lock);

DEFINE_RWLOCK(louis_af_custom_lock);

#define louis_af_custom_read_lock() 		read_lock_bh(&louis_af_custom_lock);
#define louis_af_custom_read_unlock() 		read_unlock_bh(&louis_af_custom_lock);
#define louis_af_custom_write_lock() 		write_lock_bh(&louis_af_custom_lock);
#define louis_af_custom_write_unlock()		write_unlock_bh(&louis_af_custom_lock);

struct list_head louis_domains_head = LIST_HEAD_INIT(louis_domains_head);


static struct mutex af_cdev_mutex;
struct af_config_dev {
    dev_t id;
    struct cdev char_dev;
    struct class *c;
};
struct af_config_dev g_af_dev;

struct af_cdev_file {
    size_t size;
    char buf[256 << 10];
};
	
enum AF_CONFIG_CMD{
	AF_CMD_ADD_APPID = 1,
	AF_CMD_DEL_APPID,
	AF_CMD_CLEAN_APPID,
	AF_CMD_SET_MAC_LIST,
	AF_CMD_SET_CUSTOM_SETTINGS,
};

char g_app_id_array[AF_MAX_APP_TYPE_NUM][AF_MAX_APP_NUM] = {0};


void af_show_app_status(void)
{
	int i, j;
	AF_DEBUG("#########show app status##########\n");
	for (i = 0; i < AF_MAX_APP_TYPE_NUM; i++) {
		for (j = 0; j < AF_MAX_APP_NUM; j++) {
			
			af_rule_read_lock();
			if (g_app_id_array[i][j] == AF_TRUE) {
				AF_DEBUG("%d, %d\n", i, j);
			}
			af_rule_read_unlock();
		}
	}
	
	AF_DEBUG("\n\n\n");
}

int af_change_app_status(cJSON * data_obj, int status)
{
	int i;
	int id;
	int type;
	if (!data_obj) {
		AF_ERROR("data obj is null\n");
		return -1;
	}
	cJSON *appid_arr = cJSON_GetObjectItem(data_obj, "apps");
	if (!appid_arr){
		AF_ERROR("apps obj is null\n");
		return -1;
	}
	for (i = 0; i < cJSON_GetArraySize(appid_arr); i++) {
		cJSON *appid_obj = cJSON_GetArrayItem(appid_arr, i);
		if (!appid_obj){
			AF_ERROR("appid obj is null\n");
			return -1;
		}
		id = AF_APP_ID(appid_obj->valueint);
		type = AF_APP_TYPE(appid_obj->valueint);
		AF_DEBUG("appid:%d, type = %d, id = %d\n", appid_obj->valueint, type, id);
		
		af_rule_write_lock();
		g_app_id_array[type][id] = status;
		af_rule_write_unlock();
	}
	
	return 0;
}
DEFINE_RWLOCK(af_mac_lock);            
#define MAX_AF_MAC_HASH_SIZE 64
#define AF_MAC_LOCK_R() 		read_lock_bh(&af_mac_lock);
#define AF_MAC_UNLOCK_R() 	read_unlock_bh(&af_mac_lock);
#define AF_MAC_LOCK_W() 		write_lock_bh(&af_mac_lock);
#define AF_MAC_UNLOCK_W()	write_unlock_bh(&af_mac_lock);

u32 total_mac = 0;
struct list_head af_mac_list_table[MAX_AF_MAC_HASH_SIZE];

void 
af_mac_list_init(void)
{
	int i;
	AF_MAC_LOCK_W();
	for(i = 0; i < MAX_AF_MAC_HASH_SIZE; i ++){
        INIT_LIST_HEAD(&af_mac_list_table[i]);
    }
	AF_MAC_UNLOCK_W();
	AF_INFO("client list init......ok\n");
}

void 
af_mac_list_clear(void)
{
	int i;
	af_mac_info_t * p = NULL;
	char mac_str[32] = {0};
	
	AF_DEBUG("clean list\n");
	AF_MAC_LOCK_W();
	for (i = 0; i < MAX_AF_MAC_HASH_SIZE;i++){
		while(!list_empty(&af_mac_list_table[i])){
			p = list_first_entry(&af_mac_list_table[i], af_mac_info_t, hlist);
			memset(mac_str, 0x0, sizeof(mac_str));
			sprintf(mac_str, MAC_FMT, MAC_ARRAY(p->mac));
			AF_DEBUG("clean mac:%s\n", mac_str);
			list_del(&(p->hlist));
			kfree(p);
		}
	}
	total_mac = 0;
	AF_MAC_UNLOCK_W();
}


int hash_mac(unsigned char *mac)
{
	if (!mac)
		return 0;
	else
		return mac[5] & (MAX_AF_MAC_HASH_SIZE - 1);
}

af_mac_info_t * find_af_mac(unsigned char *mac)
{
    af_mac_info_t *node;
    unsigned int index;

    index = hash_mac(mac);
    list_for_each_entry(node, &af_mac_list_table[index], hlist){
    	if (0 == memcmp(node->mac, mac, 6)){
			AF_DEBUG("match mac:"MAC_FMT"\n", MAC_ARRAY(node->mac));
			return node;
    	}
    }
    return NULL;
}

static af_mac_info_t *
af_mac_add(unsigned char *mac)
{
    af_mac_info_t *node;
	int index = 0;
	
	node = (af_mac_info_t *)kmalloc(sizeof(af_mac_info_t), GFP_ATOMIC);
    if (node == NULL) {
        AF_ERROR("kmalloc failed\n");
        return NULL;
    }

	memset(node, 0, sizeof(af_mac_info_t));
	memcpy(node->mac, mac, MAC_ADDR_LEN);
	
    index = hash_mac(mac);
	
	AF_LMT_INFO("new client mac="MAC_FMT"\n", MAC_ARRAY(node->mac));
	total_mac++;
	list_add(&(node->hlist), &af_mac_list_table[index]);
    return node;
}

int is_user_match_enable(void){
	return total_mac > 0;
}
int mac_to_hex(u8 *mac, u8 *mac_hex){
	u32 mac_tmp[MAC_ADDR_LEN];
	int ret = 0, i = 0;
	ret = sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
		(unsigned int *)&mac_tmp[0],
		(unsigned int *)&mac_tmp[1],
		(unsigned int *)&mac_tmp[2],
		(unsigned int *)&mac_tmp[3],
		(unsigned int *)&mac_tmp[4],
		(unsigned int *)&mac_tmp[5]);
	if (MAC_ADDR_LEN != ret)
		return -1;
	for (i = 0; i < MAC_ADDR_LEN; i++)
	{
		mac_hex[i] = mac_tmp[i];
	}
	return 0;
}
int af_set_mac_list(cJSON * data_obj)
{
	int i;
	int id;
	int type;
	u8 mac_hex[MAC_ADDR_LEN] = {0};
	if (!data_obj) {
		AF_ERROR("data obj is null\n");
		return -1;
	}
	cJSON *mac_arr = cJSON_GetObjectItem(data_obj, "mac_list");
	if (!mac_arr){
		AF_ERROR("apps obj is null\n");
		return -1;
	}
	af_mac_list_clear();
	for (i = 0; i < cJSON_GetArraySize(mac_arr); i++) {
		cJSON *mac_obj = cJSON_GetArrayItem(mac_arr, i);
		if (!mac_obj){
			AF_ERROR("appid obj is null\n");
			return -1;
		}
		if (-1 == mac_to_hex(mac_obj->valuestring, mac_hex)){
			AF_ERROR("mac format error: %s\n", mac_obj->valuestring);
			continue;
		}
		af_mac_add(mac_hex);
	}
	AF_DEBUG("## mac num = %d\n", total_mac);
	return 0;
}

void af_init_app_status(void)
{
	int i, j;
	
	for (i = 0; i < AF_MAX_APP_TYPE_NUM; i++) {
		for (j = 0; j < AF_MAX_APP_NUM; j++) {
			af_rule_write_lock();
			g_app_id_array[i][j] = AF_FALSE;
			af_rule_write_unlock();
		}
	}
}
int af_get_app_status(int appid)
{
	int status = 0;
	int id = AF_APP_ID(appid);
	int type = AF_APP_TYPE(appid);
	af_rule_read_lock();
	status = g_app_id_array[type][id];
	af_rule_read_unlock();
	return status;
}



////////////////////////////////////////////////////////



int louis_hex2string(unsigned char *in, int inlen, char *out, int *outlen)
{
    int i = 0;
    char *pos = out;

    if(outlen == NULL || *outlen < 2*inlen + 1)
        return -1;

    for(i = 0; i < inlen; i += 1)
        pos += sprintf(pos, "%02hhx", in[i]);

    *outlen = pos - out + 1;
    return 0;
}

int louis_string2hex(const char *in, unsigned char *out, int *outlen)
{
    int i = 0;
    int j = 0;
    int inlen = strlen(in);
    unsigned char hex[2] = {0};

    if(outlen == NULL || *outlen < inlen/2)
        return -1;

    for(*outlen = 0, i = 0; i < inlen; *outlen += 1, i += 2)
    {
        for(j = 0; j < 2; j += 1)
        {
            if(in[i+j] >= '0' && in[i+j] <= '9')        hex[j] = in[i+j] - '0';
            else if(in[i+j] >= 'a' && in[i+j] <= 'f')   hex[j] = in[i+j] - 'a' + 10;
            else if(in[i+j] >= 'A' && in[i+j] <= 'F')   hex[j] = in[i+j] - 'A' + 10;
            else return -1;
        }
        out[*outlen] = hex[0] << 4 | hex[1];
    }

    return 0;
}
void louis_remove_chars(char *str, char garbage) {

    char *src, *dst;
    for (src = dst = str; *src != '\0'; src++) {
        *dst = *src;
        if (*dst != garbage) dst++;
    }
    *dst = '\0';
}
//xx:xx:xx:xx:xx:xx
struct domain_feature *louis_new_domain_feature(char *mac_str){
	unsigned char machex[MAC_ADDR_LEN] = {0};
	int outbuff_len = MAC_ADDR_LEN;
	struct domain_feature *vt = NULL;
	char *newmac_str = kmalloc(strlen(mac_str) + 1, GFP_ATOMIC);
	memset(newmac_str, 0, strlen(mac_str) + 1);
	memcpy(newmac_str, mac_str, strlen(mac_str));
	louis_remove_chars(newmac_str, ':');
	louis_string2hex(newmac_str, machex, &outbuff_len);
	vt = kmalloc(sizeof(struct domain_feature), GFP_ATOMIC);
	memcpy(vt->mac, machex, MAC_ADDR_LEN);
	vt->domain_size = 0;
	if (newmac_str)
		kfree(newmac_str);
	return vt;
}

void louis_add_domain_to_feature(struct domain_feature *vt, char *domain){
	char *domain1 = (char *)kmalloc(strlen(domain) + 1, GFP_ATOMIC);
	strcpy(domain1, domain);
	vt->domains[vt->domain_size] = domain1;
	vt->domain_size += 1;
}

void louis_init_domain_feature(void){
	struct domain_feature *vt_oppo = louis_new_domain_feature("e4:33:ae:e7:ac:73");
	struct domain_feature *vt_pixel = louis_new_domain_feature("e2:44:5b:54:37:81");

	louis_add_domain_to_feature(vt_oppo, "www.baidu.com");
	list_add(&vt_oppo->hlist, &louis_domains_head);

	louis_add_domain_to_feature(vt_pixel, "www.baidu.com");
	list_add(&vt_pixel->hlist, &louis_domains_head);
}


void louis_clear_domains(void){
	af_feature_node_t node;
	struct domain_feature *node_vt, *n;

	printk("louis_clear_domains\n");

	louis_af_custom_write_lock();
	if(!list_empty(&louis_domains_head)) {
		list_for_each_entry_safe(node_vt, n, &louis_domains_head, hlist) {
			list_del(&node_vt->hlist);
			kfree(node_vt);
		}
	}
	louis_af_custom_write_unlock();
}



void louis_load_domains(char *json_buf){
	cJSON *json_object = NULL;
	cJSON *blocklist_array = NULL;
	cJSON *blocklist = NULL;

	cJSON *mac = NULL;
	cJSON *urlarray = NULL;
	cJSON *url_object = NULL;
	int array_size = 0;
	size_t i = 0;
	char *url_value = NULL;
	struct domain_feature *df_node = NULL;

	printk("louis_load_domains\n");
	if (!json_buf){
		printk("domains buf is empty!\n");
		goto Exit;
	}

	json_object = cJSON_Parse(json_buf);
	if (!json_object){
		printk("json_object is NULL\n");
		goto Exit;
	}

	

	/*
	{
		"blocklist":[
			{
				"mac":"1",
				"urls":[
					"www.baidu.com",
					"www.qq.com"
				]
			},
			{
				"mac":"2",
				"urls":[
					"www.baidu.com",
					"www.qq.com"
				]
			}
		]
	}
	*/

	blocklist_array = cJSON_GetObjectItem(json_object, "blocklist");
	if (!blocklist_array){
		printk("blocklist_array is NULL\n");
		goto Exit;
	}
	louis_clear_domains();
	louis_af_custom_write_lock();
	blocklist = blocklist_array->child;
	while (blocklist != NULL){
		mac = cJSON_GetObjectItem(blocklist, "mac");
		if (0 != strcmp(mac->valuestring, "")){
			urlarray = cJSON_GetObjectItem(blocklist, "urls");
			array_size = cJSON_GetArraySize(urlarray);

			df_node = louis_new_domain_feature(mac->valuestring);
			
			for (i = 0; i < array_size; i++){
				url_object = cJSON_GetArrayItem(urlarray, i);
				if (!url_object)
					continue;
				url_value = url_object->valuestring;
				louis_add_domain_to_feature(df_node, url_value);
				printk("adding url:%s to mac:%s\n", url_value, mac->valuestring);
			}
			list_add(&df_node->hlist, &louis_domains_head);
		}
		blocklist = blocklist->next;
	}
	louis_af_custom_write_unlock();

Exit:
	if (json_object){
		kfree(json_object);
		json_object = NULL;
	}
	return;
}

int louis_is_match_rule(char *reg_url_buf, char *mac){
	af_feature_node_t node;
	struct domain_feature *node_vt, *n;
	int isMatch = 0;
	size_t i = 0;

	louis_af_custom_read_lock();
	if (strlen(reg_url_buf) > 0){
		//printk("mac:"MAC_FMT", url:%s\n", MAC_ARRAY(mac), reg_url_buf);
		if(!list_empty(&louis_domains_head)) { 
			list_for_each_entry_safe(node_vt, n, &louis_domains_head, hlist) {
				if (0 == memcmp(node_vt->mac, mac, MAC_ADDR_LEN)){
					
					for (i = 0; i < node_vt->domain_size; i++)
					{
						if (strstr(reg_url_buf, node_vt->domains[i])){
							printk("mac:"MAC_FMT", block url:%s\n", MAC_ARRAY(node_vt->mac), node_vt->domains[i]);
							isMatch = 1;
							louis_af_custom_read_unlock();
							return isMatch;
						}
					}
					
				}
			}
		}
	}
	louis_af_custom_read_unlock();
	return isMatch;
}


int louis_af_set_custom_settings(cJSON * data_obj)
{
	int i;
	int id;
	int type;
	u8 mac_hex[MAC_ADDR_LEN] = {0};

	printk("louis_af_set_custom_settings\n");


	if (!data_obj) {
		AF_ERROR("data obj is null\n");
		return -1;
	}
	cJSON *customsettings = cJSON_GetObjectItem(data_obj, "customsettings");
	if (!customsettings){
		AF_ERROR("customsettings obj is null\n");
		return -1;
	}
	louis_load_domains(customsettings->valuestring);
	return 0;
}


////////////////////////////////////////////////////////


/*
add:
{
	"op":1,
	"data"{
		"apps":[]
	}
}
clean
{
	"op":3,
}

*/
int af_config_handle(char *config, unsigned int len)
{
	cJSON * config_obj = NULL;
	cJSON * cmd_obj = NULL;
	cJSON * data_obj = NULL;
	if (!config || len == 0) {
		AF_ERROR("config or len is invalid\n");
		return -1;
	}
	config_obj = cJSON_Parse(config);
	if (!config_obj){
		AF_ERROR("config_obj is NULL\n");
		return -1;
	}
	cmd_obj = cJSON_GetObjectItem(config_obj, "op");
	if (!cmd_obj){
		AF_ERROR("not find op object\n");
		return -1;
	}
	data_obj = cJSON_GetObjectItem(config_obj, "data");

	switch(cmd_obj->valueint) {
	case AF_CMD_ADD_APPID:
		if (!data_obj)
			break;
		af_change_app_status(data_obj, AF_TRUE);
		break;
	case AF_CMD_DEL_APPID:
		if (!data_obj)
			break;
		af_change_app_status(data_obj, AF_FALSE);
		break;
	case AF_CMD_CLEAN_APPID:
		af_init_app_status();
		break;
	case AF_CMD_SET_MAC_LIST:
		af_set_mac_list(data_obj);
		break;
	case AF_CMD_SET_CUSTOM_SETTINGS:
		louis_af_set_custom_settings(data_obj);
		break;
	default:
		AF_ERROR("invalid cmd %d\n", cmd_obj->valueint);
		return -1;
	}
	af_show_app_status();
	return 0;
	
}


static int af_cdev_open(struct inode *inode, struct file *filp)
{
    struct af_cdev_file *file;
    file = vzalloc(sizeof(*file));
    if (!file)
        return -EINVAL;

    mutex_lock(&af_cdev_mutex);
    filp->private_data = file;
    return 0;
}

static ssize_t af_cdev_read(struct file *filp, char *buf, size_t count, loff_t *off)
{
    return 0;
}

static int af_cdev_release(struct inode *inode, struct file *filp)
{
    struct af_cdev_file *file = filp->private_data;
    AF_DEBUG("config size: %d,data = %s\n", (int)file->size, file->buf);
	af_config_handle(file->buf, file->size);
    filp->private_data = NULL;
    mutex_unlock(&af_cdev_mutex);
    vfree(file);
    return 0;
}

static ssize_t af_cdev_write(struct file *filp, const char *buffer, size_t count, loff_t *off)
{
    struct af_cdev_file *file = filp->private_data;
    int ret;
    if (file->size + count > sizeof(file->buf)) {
        AF_ERROR("config overflow, cur_size: %d, block_size: %d, max_size: %d",
            (int)file->size, (int)count, (int)sizeof(file->buf));
        return -EINVAL;
    }

    ret = copy_from_user(file->buf + file->size, buffer, count);
    if (ret != 0)
        return -EINVAL;

    file->size += count;
    return count;
}

static struct file_operations af_cdev_ops = {
	owner:   THIS_MODULE,
	release: af_cdev_release,
	open:    af_cdev_open,
	write:   af_cdev_write,
	read:    af_cdev_read,
};

int af_register_dev(void)
{
    struct device *dev;
    int res;
    mutex_init(&af_cdev_mutex);

    res = alloc_chrdev_region(&g_af_dev.id, 0, 1, AF_DEV_NAME);
    if (res != 0) {
        return -EINVAL;
    }

    cdev_init(&g_af_dev.char_dev, &af_cdev_ops);
    res = cdev_add(&g_af_dev.char_dev, g_af_dev.id, 1);
    if (res < 0) {
        goto REGION_OUT;
    }

    g_af_dev.c= class_create(THIS_MODULE, AF_DEV_NAME);
    if (IS_ERR_OR_NULL(g_af_dev.c)) {
        goto CDEV_OUT;
    }

    dev = device_create(g_af_dev.c, NULL, g_af_dev.id, NULL, AF_DEV_NAME);
    if (IS_ERR_OR_NULL(dev)) {
        goto CLASS_OUT;
    }
	AF_INFO("register char dev....ok\n");

    return 0;

CLASS_OUT:
    class_destroy(g_af_dev.c);
CDEV_OUT:
    cdev_del(&g_af_dev.char_dev);
REGION_OUT:
    unregister_chrdev_region(g_af_dev.id, 1);
	
	AF_ERROR("register char dev....fail\n");
    return -EINVAL;
}


void af_unregister_dev(void)
{
	device_destroy(g_af_dev.c, g_af_dev.id);
    class_destroy(g_af_dev.c);
    cdev_del(&g_af_dev.char_dev);
    unregister_chrdev_region(g_af_dev.id, 1);
	AF_INFO("unregister char dev....ok\n");
}

