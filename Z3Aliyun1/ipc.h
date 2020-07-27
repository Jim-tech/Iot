/*
 * ipc.h
 *
 *  Created on: Jul 20, 2020
 *      Author: root
 */

#ifndef IPC_H_
#define IPC_H_

#include "app/framework/include/af.h"
#include "msgQue.h"

extern OS_Q    ZBMsgQueue;
extern OS_Q    AliyunMsgQueue;

typedef enum
{
	IPC_ZB_ON_OFF_CMD,
	IPC_ZB_LEVEL_CMD,
	IPC_ZB_COLOR_TMP_CMD,
	IPC_ZB_CURTAIN_CMD,
	IPC_ZB_CLOUD_CONNECTED_EVT,
}IPCZigbeeCmd;

typedef struct
{
	uint8_t  Eui64[8];
	uint8_t  endpoint;
	bool     on;
}ZigbeeOnOffCmdPara;

typedef struct
{
	uint8_t  Eui64[8];
	uint8_t  endpoint;
	uint8_t  level;
}ZigbeeLevelCmdPara;

typedef struct
{
	uint8_t  Eui64[8];
	uint8_t  endpoint;
	uint16_t colorTemp;
}ZigbeeColorTempCmdPara;

typedef struct
{
	uint8_t  Eui64[8];
	uint8_t  endpoint;
	bool     setByLevel;
	uint8_t  level;
	bool     open;
	bool     close;
	bool     pause;
}ZigbeeCurtainCmdPara;

typedef struct
{
	bool     connected;
}ZigbeeCloudConnectEventPara;

typedef enum
{
	IPC_ALIYUN_WIFI_PROVISION_CMD,
	IPC_ALIYUN_START_CMD,
	IPC_ALIYUN_ADD_SUBDEV_CMD,
}IPCAliyunCmd;

typedef struct
{
	char     ssid[64];
	char     passwd[64];
}AliyunStartCmdPara;

typedef struct
{
	uint8_t  Eui64[8];
	uint8_t  endPoint;
	uint16_t DeviceID;
}AliyunAddSubDevCmdPara;

int ipc_SendZigbeeCmdCommon(uint8_t cmd, void *pPara, uint8_t paraSize);
int ipc_SendAliyunCmdCommon(uint8_t cmd, void *pPara, uint8_t paraSize);

#endif /* IPC_H_ */
