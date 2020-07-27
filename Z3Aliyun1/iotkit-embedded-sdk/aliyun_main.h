#ifndef __ALIYUN_MAIN_H__
#define __ALIYUN_MAIN_H__


#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

typedef enum
{
    DEMO_Z3DIMMERLIGHT    = 0x0102,
    DEMO_Z3CURTAIN        = 0x0200,
}SUPPORT_DEVICEID_E;

int aliyun_wifi_provision();
int aliyun_connect_cloud();
bool aliyun_is_cloud_connected();
int aliyun_add_subdev(EmberEUI64 eui64, uint8_t endpoint, uint16_t deviceid, int *pdevid);
int aliyun_del_subdev(int devid);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif /* __ALIYUN_MAIN_H__ */
