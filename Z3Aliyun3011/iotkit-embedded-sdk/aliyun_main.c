#include "infra_config.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

#include "sdk_include.h"
#include "app/framework/include/af.h"
#include "app/framework/plugin/device-table/device-table.h"
#include "aliyun_main.h"

extern void emberAfCloudConnectedHandler();
extern void emberAfDeviceTableCommandIndexSendByDeviceID(uint16_t deviceid, uint8_t sendtimes);

#define ALIYUN_TRACE(...) \
    do { \
        HAL_Printf("\033[1;32;40m%s.%d: ", __func__, __LINE__); \
        HAL_Printf(__VA_ARGS__); \
        HAL_Printf("\033[0m\r\n"); \
    } while (0)
#define ALIYUN_ERROR(...) \
    do { \
        HAL_Printf("\033[31m%s.%d: ", __func__, __LINE__); \
        HAL_Printf(__VA_ARGS__); \
        HAL_Printf("\033[0m\r\n"); \
    } while (0)

typedef struct {
    int     master_devid;
    int     wifi_provisioning;
    int     cloud_connected;
    int     master_initialized;
    int     permit_join;
    void   *g_dispatch_thread;
    int     g_dispatch_thread_running;
}aliyun_ctx_t;

typedef struct {
    uint16_t    deviceid;
    char       *product_key;
}aliyun_support_list;

static aliyun_ctx_t g_aliyun_ctx;
const static aliyun_support_list g_aliyun_supportlist[] = 
{
    {DEMO_Z3DIMMERLIGHT,    "a1WEfJue80z"},    /*Z3DimmerLight  */
    {DEMO_Z3CURTAIN,        "a1FyNtzNxCq"},    /*Z3Curtain  */
};

typedef enum
{
    CURTAIN_OPER_OPEN,
    CURTAIN_OPER_CLOSE,
    CURTAIN_OPER_PAUSE,
}CURTAIN_OPER_E;


static void *g_led_timer = NULL;
static void aliyun_led_flashing(void *arg)
{
    halToggleLed(BOARDLED0);
    HAL_Timer_Start(g_led_timer, 250);
    return;
}
static aliyun_ctx_t *aliyun_get_ctx(void)
{
    return &g_aliyun_ctx;
}

static int aliyun_connected_event_handler(void)
{
    aliyun_ctx_t *aliyun_ctx = aliyun_get_ctx();

    ALIYUN_TRACE("Cloud Connected");

    aliyun_ctx->cloud_connected = 1;

    emberAfCloudConnectedHandler();
    return 0;
}

static int aliyun_disconnected_event_handler(void)
{
    aliyun_ctx_t *aliyun_ctx = aliyun_get_ctx();

    ALIYUN_TRACE("Cloud Disconnected");

    aliyun_ctx->cloud_connected = 0;
    halClearLed(BOARDLED0);
    
    while (1) {
        HAL_Reboot();
    }
    return 0;
}

static int aliyun_get_zigbee_address_from_device(int devid, EmberEUI64 eui64, uint8_t *pendpoint)
{
    int        res = 0;    
    char       product_key[IOTX_PRODUCT_KEY_LEN + 1] = {0};
    char       device_name[IOTX_DEVICE_NAME_LEN + 1] = {0};
    char       device_secret[IOTX_DEVICE_SECRET_LEN + 1] = {0};
    uint32_t   val[EUI64_SIZE + 1];

    res = dm_mgr_search_device_by_devid(devid, product_key, device_name, device_secret);
    if (res < SUCCESS_RETURN) {
        return res;
    }

    if (EUI64_SIZE + 1 != sscanf(device_name, "%02X%02X%02X%02X%02X%02X%02X%02X_%d", &val[0], &val[1], &val[2], &val[3],
                                                                                     &val[4], &val[5], &val[6], &val[7],
                                                                                     &val[8])) {
        ALIYUN_ERROR("invalid devicename=[%s]", device_name);
        return -1;
    }

    eui64[0] = (uint8_t)val[7];
    eui64[1] = (uint8_t)val[6];
    eui64[2] = (uint8_t)val[5];
    eui64[3] = (uint8_t)val[4];
    eui64[4] = (uint8_t)val[3];
    eui64[5] = (uint8_t)val[2];
    eui64[6] = (uint8_t)val[1];
    eui64[7] = (uint8_t)val[0];
    *pendpoint = (uint8_t)val[8];

    return 0;
}

int aliyun_get_productkey(uint16_t deviceid, char product_key[IOTX_PRODUCT_KEY_LEN + 1])
{
    uint8_t i;

    for (i = 0; i < sizeof(g_aliyun_supportlist)/sizeof(aliyun_support_list); i++) {
        if (deviceid == g_aliyun_supportlist[i].deviceid) {
            break;
        }
    }

    if (i >= sizeof(g_aliyun_supportlist)/sizeof(aliyun_support_list)) {
        return -1;
    }

    snprintf(product_key, IOTX_PRODUCT_KEY_LEN, "%s", g_aliyun_supportlist[i].product_key);
    return 0;
}

int aliyun_form_devicename(uint16_t deviceid, EmberEUI64 eui64, uint8_t endpoint, char device_name[IOTX_DEVICE_NAME_LEN + 1])
{
    snprintf(device_name, IOTX_DEVICE_NAME_LEN, "%02X%02X%02X%02X%02X%02X%02X%02X_%d", eui64[7], eui64[6],
                                                                                                 eui64[5], eui64[4],
                                                                                                 eui64[3], eui64[2],
                                                                                                 eui64[1], eui64[0],
                                                                                                 endpoint);
    return 0;
}

static int aliyun_lightswitch_property_set(int devid, cJSON *json_item)
{
    int        res = 0;
    int        switchval = 0;
    EmberEUI64 eui64;
    uint8_t    endpoint;

    res = aliyun_get_zigbee_address_from_device(devid, eui64, &endpoint);
    if (0 != res) {
        ALIYUN_ERROR("get zigbee address fail");
        return res;
    }

    switchval = json_item->valueint;
    if (0 == switchval) {
        emberAfFillCommandOnOffClusterOff();
    } else {
        emberAfFillCommandOnOffClusterOn();
    }

    
    emberAfDeviceTableCommandSendWithEndpoint(eui64, endpoint);
    return 0;
}

static int aliyun_brightness_property_set(int devid, cJSON *json_item)
{
    int        res = 0;
    int        val = 0;
    uint8_t    brightness;
    EmberEUI64 eui64;
    uint8_t    endpoint;

    res = aliyun_get_zigbee_address_from_device(devid, eui64, &endpoint);
    if (0 != res) {
        ALIYUN_ERROR("get zigbee address fail");
        return res;
    }

    val = json_item->valueint;
    brightness = (uint8_t)(val * 255.0 / 100);
    emberAfFillCommandLevelControlClusterMoveToLevelWithOnOff(brightness, 0);
    emberAfDeviceTableCommandSendWithEndpoint(eui64, endpoint);
    return 0;
}

static int aliyun_colorTemperature_property_set(int devid, cJSON *json_item)
{
    int        res = 0;
    int        val = 0;
    int16_t    colortemps;
    EmberEUI64 eui64;
    uint8_t    endpoint;

    res = aliyun_get_zigbee_address_from_device(devid, eui64, &endpoint);
    if (0 != res) {
        ALIYUN_ERROR("get zigbee address fail");
        return res;
    }

    val = json_item->valueint;
    if (val == 0) {
        ALIYUN_ERROR("invalid value");
        return -1;
    }
    
    colortemps = (int16_t)(1000000/val);
    emberAfFillCommandColorControlClusterMoveToColorTemperature(colortemps, 0, 0, 0);
    emberAfDeviceTableCommandSendWithEndpoint(eui64, endpoint);
    return 0;
}

static int aliyun_curtain_property_set(int devid, cJSON *json_item)
{
    int        res = 0;
    int        val = 0;
    uint8_t    level;
    EmberEUI64 eui64;
    uint8_t    endpoint;

    res = aliyun_get_zigbee_address_from_device(devid, eui64, &endpoint);
    if (0 != res) {
        ALIYUN_ERROR("get zigbee address fail");
        return res;
    }

    val = json_item->valueint;
    if (0 == strcmp(json_item->string, "CurtainPosition")) {
        level = (uint8_t)(val * 255.0 / 100);
        emberAfFillCommandLevelControlClusterMoveToLevelWithOnOff(level, 0);
    } else if (0 == strcmp(json_item->string, "CurtainOperation")) {
        switch (val)
        {
            case CURTAIN_OPER_CLOSE:
                emberAfFillCommandLevelControlClusterMoveWithOnOff(1, 0);
                break;
            case CURTAIN_OPER_OPEN:
                emberAfFillCommandLevelControlClusterMoveWithOnOff(0, 0);
                break;
            case CURTAIN_OPER_PAUSE:
                emberAfFillCommandLevelControlClusterStopWithOnOff();
                break;
            default:
                ALIYUN_ERROR("Invalid operation %d", val);
                break;
        }
    }

    emberAfDeviceTableCommandSendWithEndpoint(eui64, endpoint);
    return 0;
}

static int aliyun_property_set_event_handler(const int devid, const char *request, const int request_len)
{
    int        res = 0;
    cJSON     *json_root = NULL;
    cJSON     *json_item = NULL;
    aliyun_ctx_t *aliyun_ctx = aliyun_get_ctx();
    
    ALIYUN_TRACE("Property Set Received, Devid: %d, Request: %s", devid, request);

    json_root = cJSON_Parse(request);
    if (json_root) {

        /*light switch  */
        json_item = cJSON_GetObjectItem(json_root, "LightSwitch");
        if (json_item && cJSON_IsNumber(json_item)) {
            aliyun_lightswitch_property_set(devid, json_item);
        }

        /*Brightness  */
        json_item = cJSON_GetObjectItem(json_root, "Brightness");
        if (json_item && cJSON_IsNumber(json_item)) {
            aliyun_brightness_property_set(devid, json_item);
        }

        /*ColorTemperature  */
        json_item = cJSON_GetObjectItem(json_root, "ColorTemperature");
        if (json_item && cJSON_IsNumber(json_item)) {
            aliyun_colorTemperature_property_set(devid, json_item);
        }

        /*CurtainPosition  */
        json_item = cJSON_GetObjectItem(json_root, "CurtainPosition");
        if (json_item && cJSON_IsNumber(json_item)) {
            aliyun_curtain_property_set(devid, json_item);
        }

        /*CurtainOperation  */
        json_item = cJSON_GetObjectItem(json_root, "CurtainOperation");
        if (json_item && cJSON_IsNumber(json_item)) {
            aliyun_curtain_property_set(devid, json_item);
        }
        
        cJSON_Delete(json_root);
    }
        
    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (unsigned char *)request, request_len);
    ALIYUN_TRACE("Post Property Message ID: %d", res);

    return 0;
}

static int aliyun_report_reply_event_handler(const int devid, const int msgid, const int code, const char *reply,
        const int reply_len)
{
    #if  0
    const char *reply_value = (reply == NULL) ? ("NULL") : (reply);
    const int reply_value_len = (reply_len == 0) ? (strlen("NULL")) : (reply_len);

    ALIYUN_TRACE("Message Post Reply Received, Devid: %d, Message ID: %d, Code: %d, Reply: %.*s", devid, msgid, code,
                  reply_value_len,
                  reply_value);
    #endif /* #if 0 */
    return 0;
}

static int aliyun_timestamp_reply_event_handler(const char *timestamp)
{
    //ALIYUN_TRACE("Current Timestamp: %s", timestamp);

    return 0;
}

int aliyun_permit_join_event_handler(const char *product_key, const int time)
{
    aliyun_ctx_t *aliyun_ctx = aliyun_get_ctx();

    ALIYUN_TRACE("Product Key: %s, Time: %d", product_key, time);

    //aliyun_ctx->permit_join = 1;

    //emberAfPluginNetworkCreatorSecurityOpenNetwork();
    //emberAfPluginFindAndBindTargetStart(1);
    return 0;
}

void aliyun_post_property(int devid, char *property_payload)
{
    int   res = 0;

    if (devid < 0) {
        ALIYUN_ERROR("invalid parameter devid=%d", devid);
        return;
    }

    if (!aliyun_is_cloud_connected()) {
        return;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (unsigned char *)property_payload, strlen(property_payload));
    //ALIYUN_TRACE("Post Property Message ID: %d", res);
}

static int aliyun_initialized(const int devid)
{
    aliyun_ctx_t *aliyun_ctx = aliyun_get_ctx();
    ALIYUN_TRACE("Device Initialized, Devid: %d", devid);

    if (aliyun_ctx->master_devid == devid) {
        aliyun_ctx->master_initialized = 1;
    }

    return 0;
}

void *aliyun_dispatch_yield(void *args)
{
    aliyun_ctx_t *aliyun_ctx = aliyun_get_ctx();

    while (aliyun_ctx->g_dispatch_thread_running) {
        IOT_Linkkit_Yield(100);
    }

    return NULL;
}

int aliyun_connect_cloud()
{
    int res = 0;
    aliyun_ctx_t *aliyun_ctx = aliyun_get_ctx();
    iotx_linkkit_dev_meta_info_t master_meta_info;
    int domain_type = 0;
    int dynamic_register = 0;
    int post_event_reply = 0;

    memset(aliyun_ctx, 0, sizeof(aliyun_ctx_t));

    IOT_SetLogLevel(IOT_LOG_DEBUG);

    /* Register Callback */
    IOT_RegisterCallback(ITE_CONNECT_SUCC, aliyun_connected_event_handler);
    IOT_RegisterCallback(ITE_DISCONNECTED, aliyun_disconnected_event_handler);
    IOT_RegisterCallback(ITE_PROPERTY_SET, aliyun_property_set_event_handler);
    IOT_RegisterCallback(ITE_REPORT_REPLY, aliyun_report_reply_event_handler);
    IOT_RegisterCallback(ITE_TIMESTAMP_REPLY, aliyun_timestamp_reply_event_handler);
    IOT_RegisterCallback(ITE_INITIALIZE_COMPLETED, aliyun_initialized);
    IOT_RegisterCallback(ITE_PERMIT_JOIN, aliyun_permit_join_event_handler);

    memset(&master_meta_info, 0, sizeof(iotx_linkkit_dev_meta_info_t));
    HAL_GetProductKey(master_meta_info.product_key);
    HAL_GetProductSecret(master_meta_info.product_secret);
    HAL_GetDeviceName(master_meta_info.device_name);
    HAL_GetDeviceSecret(master_meta_info.device_secret);

    /* Create Master Device Resources */
    aliyun_ctx->master_devid = IOT_Linkkit_Open(IOTX_LINKKIT_DEV_TYPE_MASTER, &master_meta_info);
    if (aliyun_ctx->master_devid < 0) {
        ALIYUN_ERROR("IOT_Linkkit_Open Failed");
        return -1;
    }

    /* Choose Login Server */
    domain_type = IOTX_CLOUD_REGION_SHANGHAI;
    IOT_Ioctl(IOTX_IOCTL_SET_DOMAIN, (void *)&domain_type);

    /* Choose Login Method */
    dynamic_register = 1;
    IOT_Ioctl(IOTX_IOCTL_SET_DYNAMIC_REGISTER, (void *)&dynamic_register);

    /* Choose Whether You Need Post Property/Event Reply */
    post_event_reply = 0;
    IOT_Ioctl(IOTX_IOCTL_RECV_EVENT_REPLY, (void *)&post_event_reply);

    /* Start Connect Aliyun Server */
    res = IOT_Linkkit_Connect(aliyun_ctx->master_devid);
    if (res < 0) {
        ALIYUN_ERROR("IOT_Linkkit_Connect Failed\n");
        return -1;
    }

    aliyun_ctx->g_dispatch_thread_running = 1;
    res = HAL_ThreadCreate(&aliyun_ctx->g_dispatch_thread, aliyun_dispatch_yield, NULL, NULL, NULL);
    if (res < 0) {
    	ALIYUN_ERROR("HAL_ThreadCreate Failed\n");
        IOT_Linkkit_Close(aliyun_ctx->master_devid);
        return -1;
    }
    
    while (aliyun_ctx->g_dispatch_thread_running) {
        HAL_SleepMs(100);
    }

    aliyun_ctx->g_dispatch_thread_running = 0;
    IOT_Linkkit_Close(aliyun_ctx->master_devid);
    IOT_DumpMemoryStats(IOT_LOG_DEBUG);
    IOT_SetLogLevel(IOT_LOG_NONE);
    return 0;
}

int aliyun_main(bool wifi_connected)
{
    int ret = 0;
    aliyun_ctx_t *aliyun_ctx = aliyun_get_ctx();

    if (!wifi_connected) {
        ALIYUN_TRACE("wifi not connected, start wifi provisioning...");

        g_led_timer = HAL_Timer_Create("ledtimer", (void (*)(void *))aliyun_led_flashing, NULL);
        if (NULL != g_led_timer) {
            HAL_Timer_Start(g_led_timer, 250);
        } else {
            ALIYUN_ERROR("Start led timer fail\n");
        }

        aliyun_ctx->wifi_provisioning = 1;
        
        ret = awss_dev_ap_start();
        if (0 != ret) {
            ALIYUN_ERROR("Start WiFi provisioning fail\n");
            return ret;
        }

        HAL_Reboot();
    }

    ret = aliyun_connect_cloud();
    if (0 != ret) {
        ALIYUN_ERROR("Connect to cloud fail\n");
        return ret;
    }

    return ret;
}

bool aliyun_is_cloud_connected()
{
    aliyun_ctx_t *aliyun_ctx = aliyun_get_ctx();
    
    return (1 == aliyun_ctx->cloud_connected && 1 != aliyun_ctx->wifi_provisioning) ? true : false;
}

int aliyun_add_subdev(EmberEUI64 eui64, uint8_t endpoint, uint16_t deviceid, int *pdevid)
{
    int     res = 0;
    int     devid = -1;
    iotx_linkkit_dev_meta_info_t meta_info;

    memset(&meta_info, 0, sizeof(meta_info));
    if (0 != aliyun_get_productkey(deviceid, meta_info.product_key)) {
        ALIYUN_ERROR("unsupported deviceid=0x%04x\n", deviceid);
        return -1;
    }

    if (0 != aliyun_form_devicename(deviceid, eui64, endpoint, meta_info.device_name)) {
        ALIYUN_ERROR("form device name failed, deviceid=0x%04x\n", deviceid);
        return -1;
    }

    if (0 != iotx_dm_subdev_query(meta_info.product_key, meta_info.device_name, &devid)) {
        ALIYUN_TRACE("query deviceid=0x%04x product_key[%s] device_name[%s] fail\n", deviceid, meta_info.product_key, meta_info.device_name);
        devid = IOT_Linkkit_Open(IOTX_LINKKIT_DEV_TYPE_SLAVE, &meta_info);
        if (devid == FAIL_RETURN) {
        	ALIYUN_ERROR("subdev open Failed\n");
            return FAIL_RETURN;
        }
        ALIYUN_TRACE("subdev open susseed, devid = %d\n", devid);
    } else {
        ALIYUN_TRACE("subdev query success: devid = %d\n", devid);
    }

    res = IOT_Linkkit_Connect(devid);
    if (res == FAIL_RETURN) {
    	ALIYUN_ERROR("subdev connect Failed\n");
        //return res;
    } else {
        ALIYUN_TRACE("subdev connect success: devid = %d\n", devid);
    }
        
    res = IOT_Linkkit_Report(devid, ITM_MSG_LOGIN, NULL, 0);
    if (res == FAIL_RETURN) {
    	ALIYUN_TRACE("subdev login Failed\n");
        return res;
    } else {
        ALIYUN_TRACE("subdev login success: devid = %d\n", devid);
    }

    *pdevid = devid;
    return res;
}

int aliyun_del_subdev(int devid)
{
    if (devid <= 0) {
        ALIYUN_ERROR("invalid parameter devid=%d", devid);
        return -1;
    }

    (void)IOT_Linkkit_Report(devid, ITM_MSG_LOGOUT, NULL, 0);   
    //(void)IOT_Linkkit_Report(devid, ITM_MSG_DELETE_TOPO, NULL, 0);
    
    ALIYUN_TRACE("subdev logout success: devid = %d\n", devid);
    return 0;    
}
