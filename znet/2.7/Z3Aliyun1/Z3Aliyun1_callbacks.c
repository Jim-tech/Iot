/***************************************************************************//**
 * @file
 * @brief Callback implementation for ZigbeeMinimal sample application.
 *******************************************************************************
 * # License
 * <b>Copyright 2019 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

// This callback file is created for your convenience. You may add application
// code to this file. If you regenerate this file over a previous version, the
// previous version will be overwritten and any code you have added will be
// lost.

#include "app/framework/include/af.h"
#include "app/framework/plugin/device-table/device-table.h"
#include "platform/emdrv/nvm3/inc/nvm3.h"
#include "platform/emdrv/nvm3/inc/nvm3_default.h"
#include "em_rmu.h"

#include <kernel/include/os.h>
#include "dbgprint.h"
#include "msgQue.h"
#include "ipc.h"
#include "wgm110.h"
#include "aliyun_main.h"

extern int HAL_Timer_Task_Init();

#define SOFT_WDOG_TIMEOUT_LEN  90000
#define WIFI_CHECK_INTERVAL    2000
#define WIFI_CHECK_MAX_MISSED  32

//add heap
static uint8_t custom_heap[0xC000]   __attribute__ ((aligned(8), used, section(".heap")));

OS_Q    ZBMsgQueue;
OS_Q    AliyunMsgQueue;

size_t _write(int file, const char *ptr, int len)
{
	  // A little white lie.  We don't know how many bytes were actually written,
	  // so we pretend it was 0.  I don't know of code that handles anything
	  // other than expectedSize != actualSize, in other words to handle recovery
	  // of partial writes.
//	  return (EMBER_SUCCESS == emberSerialWriteData(APP_SERIAL, (uint8_t*)ptr, len) ? len : 0);
	  return (EMBER_SUCCESS == COM_ForceWriteData(APP_SERIAL, (uint8_t*)ptr, len) ? len : 0);
}

void OSIdleContextHook()
{
	while (1) {
		extern void emAfPluginMicriumRtosWakeUpZigbeeStackTask(void);
		emAfPluginMicriumRtosWakeUpZigbeeStackTask();
	}
}

extern uint8_t *emAfZclBuffer;
extern uint16_t emAfZclBufferLen;
extern uint16_t *emAfResponseLengthPtr;
extern EmberApsFrame *emAfCommandApsFrame;

static uint8_t    g_button1_pressed = 0;
static bool       g_cloud_connected = false;
static uint32_t   g_cloud_heartbeat_cnt = 0;
static uint8_t    g_wifi_hello_missed = 0;

EmberEventControl pollAttrEventControl;
EmberEventControl clearWiFiEventControl;
EmberEventControl commissionEventControl;
EmberEventControl softWdgEventControl;
EmberEventControl wifiCheckEventControl;

void emberAfPollAttrByDeviceTable()
{
    uint8_t     attributeIdBuffer[2];

    attributeIdBuffer[0] = LOW_BYTE(ZCL_VERSION_ATTRIBUTE_ID);
    attributeIdBuffer[1] = HIGH_BYTE(ZCL_VERSION_ATTRIBUTE_ID);
    emberAfFillCommandGlobalClientToServerReadAttributes(ZCL_BASIC_CLUSTER_ID, attributeIdBuffer, sizeof(attributeIdBuffer));

    emAfCommandApsFrame->profileId = HA_PROFILE_ID;
    emAfCommandApsFrame->sourceEndpoint = 1;
    emAfCommandApsFrame->destinationEndpoint = 255;


    EmberMessageBuffer payload = emberFillLinkedBuffers(emAfZclBuffer, *emAfResponseLengthPtr);
    if (payload == EMBER_NULL_MESSAGE_BUFFER) {
        emberAfCorePrintln("[%d] no enough buffer", __LINE__);
        return;
    }

    emberSendBroadcast(EMBER_RX_ON_WHEN_IDLE_BROADCAST_ADDRESS,
                       emAfCommandApsFrame,
                       0,
                       payload);
    emberReleaseMessageBuffer(payload);
}

void pollAttrEventHandler()
{
    emberEventControlSetInactive(pollAttrEventControl);

    if (g_cloud_connected) {
        emberAfPollAttrByDeviceTable();
        emberEventControlSetDelayMS(pollAttrEventControl, 30000);
    } else {
        emberEventControlSetDelayMS(pollAttrEventControl, 1000);
    }
}
void clearWiFiEventHandler()
{
    emberEventControlSetInactive(clearWiFiEventControl);

    tokTypeWiFiInfo data;
    memset(&data, 0, sizeof(data));
    halCommonSetToken(TOKEN_WIFI_INFO, &data);
    halReboot();
}

void commissionEventHandler()
{
    EmberStatus status;

    emberEventControlSetInactive(commissionEventControl);
    if (emberAfNetworkState() == EMBER_JOINED_NETWORK) {
        if (1 == g_button1_pressed) {
            nvm3_eraseAll(nvm3_defaultHandle);
            halReboot();
        }
    } else {
        status = emberAfPluginNetworkSteeringStart();
        emberAfCorePrintln("start to steering, status=%X...", status);
    }
}

void softWdgEventHandler()
{
    dbg_error("!!Software WDog reset!!");
    halReboot();
}

void wifiCheckEventHandler()
{
    emberEventControlSetInactive(wifiCheckEventControl);

    wifi_hello();
    g_wifi_hello_missed++;
    
    if (g_wifi_hello_missed >= WIFI_CHECK_MAX_MISSED) {
        dbg_error("!!WiFi Check reset!!");
        halReboot();
    } else {
        emberEventControlSetDelayMS(wifiCheckEventControl, WIFI_CHECK_INTERVAL);
    }
}

/*
    button0:
        long press (6s) -- clear wifi

    button1:
        long press (6s) -- clear Zigbee network
        short press     -- poll device
*/
void emberAfHalButtonIsrCallback(int8u button, int8u state)
{
    if (BUTTON0 == button) {
        if (state == BUTTON_PRESSED) {
            emberEventControlSetDelayMS(clearWiFiEventControl, 6000);
        } else {
            emberEventControlSetInactive(clearWiFiEventControl);
        }
    }

    if (BUTTON1 == button) {
        if (state == BUTTON_PRESSED) {
            emberEventControlSetDelayMS(commissionEventControl, 6000);
            g_button1_pressed = 1;
        } else {
            g_button1_pressed = 0;
            emberEventControlSetInactive(commissionEventControl);

            /*press button1 to scan again  */
            emberEventControlSetActive(pollAttrEventControl);
        }
    }
}

void emberAfMainInitCallback(void)
{
    RMU_ResetControl(rmuResetSys, rmuResetModeFull);
    
	msgq_InitBuffer();

	assert(0 == msgq_CreateMsgQ(&ZBMsgQueue, "ZBMsgQueue", 64));

    emberEventControlSetActive(commissionEventControl);
}

int ember_HandleZigbeeOnOffCmd(void *pPara)
{
	ZigbeeOnOffCmdPara *pCmd = (ZigbeeOnOffCmdPara *)pPara;

	if (pCmd->on) {
		emberAfFillCommandOnOffClusterOn();
	} else {
		emberAfFillCommandOnOffClusterOff();
	}

	emberAfDeviceTableCommandSendWithEndpoint(pCmd->Eui64, pCmd->endpoint);
	return 0;
}

int ember_HandleZigbeeLevelCmd(void *pPara)
{
	ZigbeeLevelCmdPara *pCmd = (ZigbeeLevelCmdPara *)pPara;

	emberAfFillCommandLevelControlClusterMoveToLevelWithOnOff(pCmd->level, 0);
	emberAfDeviceTableCommandSendWithEndpoint(pCmd->Eui64, pCmd->endpoint);
	return 0;
}

int ember_HandleZigbeeColorTempCmd(void *pPara)
{
	ZigbeeColorTempCmdPara *pCmd = (ZigbeeColorTempCmdPara *)pPara;

	emberAfFillCommandColorControlClusterMoveToColorTemperature(pCmd->colorTemp, 0, 0, 0);
	emberAfDeviceTableCommandSendWithEndpoint(pCmd->Eui64, pCmd->endpoint);
	return 0;
}

int ember_HandleZigbeeCurtainCmd(void *pPara)
{
	ZigbeeCurtainCmdPara *pCmd = (ZigbeeCurtainCmdPara *)pPara;

	if (pCmd->setByLevel) {
		emberAfFillCommandLevelControlClusterMoveToLevelWithOnOff(pCmd->level, 0);
	} else if (pCmd->open) {
		emberAfFillCommandLevelControlClusterMoveWithOnOff(0, 0);
	} else if (pCmd->close) {
		emberAfFillCommandLevelControlClusterMoveWithOnOff(1, 0);
	} else if (pCmd->pause) {
		emberAfFillCommandLevelControlClusterStopWithOnOff();
	} else {
		dbg_error("Unexpected branch!");
		return -1;
	}

	emberAfDeviceTableCommandSendWithEndpoint(pCmd->Eui64, pCmd->endpoint);
	return 0;
}

int ember_CloudConnectedNotify(void *pPara)
{
	ZigbeeCloudConnectEventPara *pEvt = (ZigbeeCloudConnectEventPara *)pPara;

	if (pEvt->connected) {
		halSetLed(BOARDLED0);
        g_cloud_connected = true;
        emberEventControlSetDelayMS(softWdgEventControl, SOFT_WDOG_TIMEOUT_LEN);

#if 1
        //add sub dev
        for (int i = 0; i < EMBER_AF_PLUGIN_DEVICE_TABLE_DEVICE_TABLE_SIZE; i++) {
            EmberAfPluginDeviceTableEntry *pentry = emberAfDeviceTableFindDeviceTableEntry(i);
            if ((pentry->nodeId == EMBER_AF_PLUGIN_DEVICE_TABLE_NULL_NODE_ID)
                || (pentry->state != EMBER_AF_PLUGIN_DEVICE_TABLE_STATE_JOINED)
                || (pentry->deviceId != DEMO_Z3DIMMERLIGHT && pentry->deviceId != DEMO_Z3CURTAIN)){
                continue;
            }

            AliyunAddSubDevCmdPara cmdPara = {0};
            memcpy(cmdPara.Eui64, pentry->eui64, sizeof(cmdPara.Eui64));
            cmdPara.endPoint = pentry->endpoint;
            cmdPara.DeviceID = pentry->deviceId;
            dbg_error("Add dev %02X%02X%02X%02X%02X%02X%02X%02X ep%d deviceID=0x%x",
                cmdPara.Eui64[7],cmdPara.Eui64[6],cmdPara.Eui64[5],cmdPara.Eui64[4],
                cmdPara.Eui64[3],cmdPara.Eui64[2],cmdPara.Eui64[1],cmdPara.Eui64[0],
                cmdPara.endPoint,cmdPara.DeviceID);
            ipc_SendAliyunCmdCommon(IPC_ALIYUN_ADD_SUBDEV_CMD, &cmdPara, sizeof(cmdPara));
    	  }

#elif 0
        	char *subdev_strlist[] = {"00137A0000021BA3_1",
									  "00137A0000021BA3_2",
									  "00137A00000298B1_1",
									  "00137A00000298B1_2",
									  "000D6F000AA9D53C_1",
									  "000D6F000AA8579F_1",
									  "000D6F0005A0CC9A_1",
									  "000D6F000AAB20D2_1",
									  "000D6F000AA9D575_1",
									  "000D6F00057AA966_1",
									  "000D6F00056AE60A_1",
									  "000D6F000AA9A4EE_1",
									  "000D6F000AA806C9_1"};
        	int eui64[8], ep;

        	for (int i = 0; i < sizeof(subdev_strlist)/sizeof(char *); i++) {
        		sscanf(subdev_strlist[i], "%02X%02X%02X%02X%02X%02X%02X%02X_%d", &eui64[7], &eui64[6], &eui64[5], &eui64[4],
        				&eui64[3], &eui64[2], &eui64[1], &eui64[0], &ep);

        		AliyunAddSubDevCmdPara cmdPara = {0};
        		for (int j = 0; j < 8; j++) {
        			cmdPara.Eui64[j] = eui64[j] & 0xFF;
        		}

        		cmdPara.endPoint = ep & 0xFF;

        		if (i < 4) {
        			cmdPara.DeviceID = DEMO_Z3CURTAIN;
        		} else {
        			cmdPara.DeviceID = DEMO_Z3DIMMERLIGHT;
        		}

        		ipc_SendAliyunCmdCommon(IPC_ALIYUN_ADD_SUBDEV_CMD, &cmdPara, sizeof(cmdPara));
        	}
#elif 1
        	char *subdev_strlist[] = {"1122334455667788_1",
									  "0000000011223344_1"};
        	int eui64[8], ep;

        	for (int i = 0; i < sizeof(subdev_strlist)/sizeof(char *); i++) {
        		sscanf(subdev_strlist[i], "%02X%02X%02X%02X%02X%02X%02X%02X_%d", &eui64[7], &eui64[6], &eui64[5], &eui64[4],
        				&eui64[3], &eui64[2], &eui64[1], &eui64[0], &ep);

        		AliyunAddSubDevCmdPara cmdPara = {0};
        		for (int j = 0; j < 8; j++) {
        			cmdPara.Eui64[j] = eui64[j] & 0xFF;
        		}

        		cmdPara.endPoint = ep & 0xFF;

        		if (i < 1) {
        			cmdPara.DeviceID = DEMO_Z3CURTAIN;
        		} else {
        			cmdPara.DeviceID = DEMO_Z3DIMMERLIGHT;
        		}

        		ipc_SendAliyunCmdCommon(IPC_ALIYUN_ADD_SUBDEV_CMD, &cmdPara, sizeof(cmdPara));
        	}
#endif
	} else {
		halClearLed(BOARDLED0);
        g_cloud_connected = false;
	}

	return 0;
}

int ember_CloudHeartBeatCmd()
{
    emberEventControlSetInactive(softWdgEventControl);
    emberEventControlSetDelayMS(softWdgEventControl, SOFT_WDOG_TIMEOUT_LEN);

    g_cloud_heartbeat_cnt++;
    return 0;
}

/** @brief Stack Status
 *
 * This function is called by the application framework from the stack status
 * handler.  This callbacks provides applications an opportunity to be notified
 * of changes to the stack status and take appropriate action.  The return code
 * from this callback is ignored by the framework.  The framework will always
 * process the stack status after the callback returns.
 *
 * @param status   Ver.: always
 */
bool emberAfStackStatusCallback(EmberStatus status)
{
    tokTypeWiFiInfo     wifi_data;
    AliyunStartCmdPara  cmdPara = {0};
    
    if (status == EMBER_NETWORK_DOWN) {
        halClearLed(BOARDLED1);
        emberEventControlSetInactive(pollAttrEventControl);
    } else if (status == EMBER_NETWORK_UP) {
        halSetLed(BOARDLED1);
        emberEventControlSetDelayMS(pollAttrEventControl, 3000);
    }

    memset(&wifi_data, 0, sizeof(wifi_data));
    halCommonGetToken(&wifi_data, TOKEN_WIFI_INFO);
    memcpy(cmdPara.ssid, wifi_data.ssid, strlen(wifi_data.ssid) + 1);
    memcpy(cmdPara.passwd, wifi_data.passwd, strlen(wifi_data.passwd) + 1);
    ipc_SendAliyunCmdCommon(IPC_ALIYUN_START_CMD, &cmdPara, sizeof(cmdPara));

	// This value is ignored by the framework.
	return false;
}
void emberAfMainTickCallback(void)
{
	AppMsgHdr 	   *pMsg = NULL;

	pMsg = msgq_DeQueue(&ZBMsgQueue);
	if (NULL == pMsg) {
		return;
	}

	switch (pMsg->msgCmd)
	{
	case IPC_ZB_ON_OFF_CMD:
		ember_HandleZigbeeOnOffCmd(pMsg->data);
		break;

	case IPC_ZB_LEVEL_CMD:
		ember_HandleZigbeeLevelCmd(pMsg->data);
		break;

	case IPC_ZB_COLOR_TMP_CMD:
		ember_HandleZigbeeColorTempCmd(pMsg->data);
		break;

	case IPC_ZB_CURTAIN_CMD:
		ember_HandleZigbeeCurtainCmd(pMsg->data);
		break;

	case IPC_ZB_CLOUD_CONNECTED_EVT:
		ember_CloudConnectedNotify(pMsg->data);
		break;

    case IPC_ZB_CLOUD_HEARTBEAT_CMD:
        ember_CloudHeartBeatCmd();
        break;

    case IPC_ZB_START_WIFI_CHECK_CMD:
        emberEventControlSetDelayMS(wifiCheckEventControl, WIFI_CHECK_INTERVAL);
        break;

    case IPC_ZB_WIFI_HELLO_CMD:
        g_wifi_hello_missed = 0;
        break;

	default:
		dbg_trace("TBD:msgCmd=%X len=%d", pMsg->msgCmd, pMsg->dataLen);
		break;
	}

	msgq_FreeBuffer(pMsg);
}

void emberWifiHelloCmdNotify()
{
    ipc_SendZigbeeCmdCommon(IPC_ZB_WIFI_HELLO_CMD, NULL, 0);
}

void emberAfPluginMicriumRtosAppTask1InitCallback(void)
{
	if (0 != msgq_CreateMsgQ(&AliyunMsgQueue, "AliyunMsgQueue", 16)) {
		dbg_error("Init MsgQ failed");
		return;
	}
}

void emberAfPluginMicriumRtosAppTask1MainLoopCallback(void *p_arg)
{
    int             retrycnt = 0;
	RTOS_ERR        err;
	AppMsgHdr 	   *pMsg = NULL;

	assert(0 == HAL_Timer_Task_Init());

	while (NULL == (pMsg = msgq_DeQueue(&AliyunMsgQueue))) {
		OSTimeDly(100, OS_OPT_TIME_DLY, &err);
	}

    if (IPC_ALIYUN_START_CMD != pMsg->msgCmd) {
        dbg_error("unsupported msgCmd=%X len=%d", pMsg->msgCmd, pMsg->dataLen);
        return;
    }

    AliyunStartCmdPara *pdata = (AliyunStartCmdPara *)(pMsg->data);
    if (0 != wifi_init(pdata->ssid, pdata->passwd, emberWifiHelloCmdNotify)) {
        dbg_error("init wifi failed");
        halReboot();
    } else {
        ipc_SendZigbeeCmdCommon(IPC_ZB_START_WIFI_CHECK_CMD, NULL, 0);
    }

    if (0 == strlen(pdata->ssid)) {
        msgq_FreeBuffer(pMsg);
        
        if (0 != aliyun_wifi_provision()) {
            dbg_error("Start wifi provisioning failed");
            halReboot();
        }

        
    } else {
        msgq_FreeBuffer(pMsg);
        
        while (!wifi_is_connected()) {
            OSTimeDly(5000, OS_OPT_TIME_DLY, &err);

            if (retrycnt++ > 3) {
                dbg_error("Connect to wifi failed");
                halReboot();
            }
        }

        if (0 != aliyun_connect_cloud()) {
            dbg_error("Connect to Aliyun failed");
            halReboot();
        }
    }
}

void emberAfPluginDeviceTableNewEndPointCallback(EmberEUI64 eui64, uint8_t endpoint, uint16_t deviceID)
{
    if (DEMO_Z3DIMMERLIGHT != deviceID && DEMO_Z3CURTAIN != deviceID) {
        return;
    }

    if (true == aliyun_is_cloud_connected()) {
        AliyunAddSubDevCmdPara cmdPara = {0};
        memcpy(cmdPara.Eui64, eui64, sizeof(cmdPara.Eui64));
        cmdPara.endPoint = endpoint;
        cmdPara.DeviceID = deviceID;
        dbg_error("Add dev %02X%02X%02X%02X%02X%02X%02X%02X ep%d deviceID=0x%x", 
            cmdPara.Eui64[7],cmdPara.Eui64[6],cmdPara.Eui64[5],cmdPara.Eui64[4],
            cmdPara.Eui64[3],cmdPara.Eui64[2],cmdPara.Eui64[1],cmdPara.Eui64[0],
            cmdPara.endPoint,cmdPara.DeviceID);
        ipc_SendAliyunCmdCommon(IPC_ALIYUN_ADD_SUBDEV_CMD, &cmdPara, sizeof(cmdPara));
    }
}

void emAfIEEEDiscoveryCallback(const EmberAfServiceDiscoveryResult* result)
{
    if (!emberAfHaveDiscoveryResponseStatus(result->status)) {
        return;
    }

    if ((result->matchAddress == emberGetNodeId()) || (0 == result->matchAddress)){
        return;
    }

    uint8_t* eui64ptr = (uint8_t*)(result->responseData);
    emberAfDeviceTableNewDeviceJoinHandler(result->matchAddress, eui64ptr);
}

boolean emberAfReadAttributesResponseCallback(EmberAfClusterId clusterId, int8u *buffer, int16u bufLen)
{
    EmberNodeId nodeID;
    uint16_t    index;

    nodeID = emberGetSender();
    if ((nodeID == emberGetNodeId()) || (0 == emberGetNodeId())) {
        return false;
    }

    index = emberAfDeviceTableGetEndpointFromNodeIdAndEndpoint(nodeID, emberAfCurrentCommand()->apsFrame->sourceEndpoint);
    if (EMBER_AF_PLUGIN_DEVICE_TABLE_NULL_INDEX == index) {
        emberAfFindIeeeAddress(nodeID, emAfIEEEDiscoveryCallback);
        return false;
    }

    return false;
}

static void kv_show(void)
{
	uint8_t i;
	tokTypeKvs data;

	printf("read:\r\n");
	for (i = 0; i < MAX_KV_NUMBER; i++) {
		memset(&data, 0, sizeof(data));
		halCommonGetIndexedToken(&data, TOKEN_KV_PAIRS, i);
		if ('\0' != data.kv_key[0]) {
			printf("i=%d key=%s len=%d \r\n", i, data.kv_key, data.value_len);
		}
	}
}

static void kv_add(void)
{
	int       ret;
    uint8_t   vallen;
    uint8_t  *value = NULL;
    char      key[64] = {0};
    char      val[64] = {0};

    //DYNAMIC_REG_
    value = emberStringCommandArgument(0, &vallen);
    if (vallen >= sizeof(key)) {
        printf("input key too long\r\n");
        return;
    }
    MEMCOPY(key, value, vallen);

    value = emberStringCommandArgument(1, &vallen);
    if (vallen >= sizeof(key)) {
        printf("input value too long\r\n");
        return;
    }
    MEMCOPY(val, value, vallen);

    extern int HAL_Kv_Set(const char *key, const void *val, int len, int sync);
	ret = HAL_Kv_Set(key, val, strlen(val) + 1, 0);

	printf("add ret:%d\r\n", ret);
}

static void dev_show(void)
{
	uint8_t i;
	tokTypeDevTable data;

	printf("read:\r\n");
	for (i = 0; i < MAX_DEV_TABLE_NUMBER; i++) {
		memset(&data, 0xFF, sizeof(data));
		halCommonGetIndexedToken(&data, TOKEN_DEV_TABLE, i);
		if (0xFFFF != data.nodeId) {
			printf("i=%d nodeId=0x%04X ep=%d \r\n", i, data.nodeId, data.endpoint);
		}
	}
}

static void wifi_clear(void)
{
    int ret = 0;
    
    //ret = wifi_erase_alldata();

    tokTypeWiFiInfo data;

    memset(&data, 0, sizeof(data));
    halCommonSetToken(TOKEN_WIFI_INFO, &data);

    printf("erase all wifi data ret=%d\r\n", ret);
}

static void wifi_show(void)
{
    tokTypeWiFiInfo data;

    memset(&data, 0, sizeof(data));
    halCommonGetToken(&data, TOKEN_WIFI_INFO);

    printf("wifi ssid=[%s] passwd=[%s]\r\n", data.ssid, data.passwd);
}

static void wifi_set(void)
{
    tokTypeWiFiInfo data;

    memset(&data, 0, sizeof(data));
    emberCopyStringArgument(0, (uint8_t *)data.ssid, 63, false);
    emberCopyStringArgument(1, (uint8_t *)data.passwd, 63, false);
    
    halCommonSetToken(TOKEN_WIFI_INFO, &data);

    printf("set wifi ssid=[%s] passwd=[%s]\r\n", data.ssid, data.passwd);
}

static void em_showtxpwr(void)
{
    tokTypeStackNodeData data;

    memset(&data, 0xFF, sizeof(data));
    halCommonGetToken(&data, TOKEN_STACK_NODE_DATA);
    printf("txpwr:%d\r\n", data.radioTxPower);
}

static void em_settxpower(void)
{
    tokTypeStackNodeData data;

    uint8_t pwr = (uint8_t)emberUnsignedCommandArgument(0);

    memset(&data, 0xFF, sizeof(data));
    halCommonGetToken(&data, TOKEN_STACK_NODE_DATA);
    data.radioTxPower = pwr;
    halCommonSetToken(TOKEN_STACK_NODE_DATA, &data);
}


void custom_cmd_show_crash()
{
	emberAfCorePrintln("Last crash record:%d", emberGetLastCrashRecordIndex());

	for (uint8_t i = 0; i < emberGetMaxCrashRecordNum(); i++) {
		halInternalResetWatchDog();
		emberAfCorePrintln("***********************");
		emberAfCorePrintln("Crash Record %d", i);
		emberCrashRecordDump(APP_SERIAL, i);
		emberAfCorePrintln("***********************");
	}
}

void custom_cmd_crash()
{
	uint8_t type = (uint8_t)emberUnsignedCommandArgument(0);

	if (0 == type) {
		*(uint32_t *)(0xFFFFFFF0) = 0;
	} else if (1 == type) {
		while (1) {
			;
		}
	}
}

void custom_cmd_showstatus()
{
	extern unsigned int g_heap_used;
    extern uint32_t g_heap_alloc_failure;
    extern uint32_t g_heap_free_failure;
    extern uint32_t g_kv_full;
    extern uint32_t g_kv_too_long;
    
	emberAfCorePrintln("g_heap_used=0x%4X", g_heap_used);
	emberAfCorePrintln("g_heap_alloc_failure=0x%4X", g_heap_alloc_failure);
	emberAfCorePrintln("g_heap_free_failure=0x%4X", g_heap_free_failure);
	emberAfCorePrintln("g_kv_full=0x%4X", g_kv_full);
	emberAfCorePrintln("g_kv_too_long=0x%4X", g_kv_too_long);

	emberAfCorePrintln("wifi rx counter=0x%4X", wifi_get_rx_counter());
	emberAfCorePrintln("wifi tx counter=0x%4X", wifi_get_tx_counter());
	emberAfCorePrintln("g_cloud_heartbeat_cnt=0x%4X", g_cloud_heartbeat_cnt);


}

//typedef enum _IOT_LogLevel {
//    IOT_LOG_NONE = 0,
//    IOT_LOG_CRIT,
//    IOT_LOG_ERROR,
//    IOT_LOG_WARNING,
//    IOT_LOG_INFO,
//    IOT_LOG_DEBUG,
//	  IOT_LOG_FLOW
//} IOT_LogLevel;

char *p_switch_desc[] = {
	"IOT_LOG_NONE",
	"IOT_LOG_CRIT",
	"IOT_LOG_ERROR",
	"IOT_LOG_WARNING",
	"IOT_LOG_INFO",
	"IOT_LOG_DEBUG",
	"IOT_LOG_FLOW"
};

extern void LITE_set_loglevel(int pri);

void custom_cmd_dbgprint()
{
	uint8_t vswitch = (uint8_t)emberUnsignedCommandArgument(0);

	if (vswitch > 6) {
		vswitch = 6;
	}
	LITE_set_loglevel(vswitch);
	printf("set debug level to %s", p_switch_desc[vswitch]);
}

EmberCommandEntry emberAfCustomCommands[] = {
  emberCommandEntryAction("kvshow", kv_show, "", ""),
  emberCommandEntryAction("kvadd",  kv_add, "bb", ""),
  emberCommandEntryAction("devshow", dev_show, "", ""),
  emberCommandEntryAction("wificlear", wifi_clear, "", ""),
  emberCommandEntryAction("wifishow", wifi_show, "", ""),
  emberCommandEntryAction("wifiset", wifi_set, "bb", ""),
  emberCommandEntryAction("showtxpwr", em_showtxpwr, "", ""),
  emberCommandEntryAction("settxpwr", em_settxpower, "u", ""),
  emberCommandEntryAction("showcrash", custom_cmd_show_crash, "", ""),
  emberCommandEntryAction("crash", custom_cmd_crash, "u", ""),
  emberCommandEntryAction("showstatus", custom_cmd_showstatus, "", ""),
  emberCommandEntryAction("dbgprint", custom_cmd_dbgprint, "u", ""),
  emberCommandEntryTerminator()
};
