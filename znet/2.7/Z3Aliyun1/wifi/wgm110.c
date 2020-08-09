#include "app/framework/include/af.h"
#include <kernel/include/os.h>
#include <common/include/rtos_prio.h>
#include "dbgprint.h"

#include "api/wifi_bglib.h"
#include "wgm110.h"

//#define USE_UDP_DATA_QUQUE   1
#define WIFI_DEFAULT_TIMEOUT 30000
#define WIFI_MINIMAL_TIMEOUT 5000

#define DESC(x) #x

typedef enum
{
    TLS_AUTH_NONE,
    TLS_AUTH_OPTIONAL,
    TLS_AUTH_MANDATORY,
}TLS_AUTH_MODE;

typedef enum
{
    WLAN_OPER_MODE_STA = 1,
    WLAN_OPER_MODE_AP  = 2,
}WLAN_OPER_MODE;

typedef enum
{
    WLAN_AP_SECURITY_NONE = 0,
    WLAN_AP_SECURITY_WPA  = 1,
    WLAN_AP_SECURITY_WPA2 = 2,
    WLAN_AP_SECURITY_WEP  = 3,
}WLAN_AP_SECURITY;

#define WLAN_AP_DEFAULT_CHANNEL 6

typedef enum
{
    WLAN_STATE_IDLE,
    WLAN_STATE_INIT,
    WLAN_STATE_ON,
    WLAN_STATE_PASSWD_SET,
    WLAN_STATE_CONNECTED,
}WLAN_STATE;

typedef enum
{
    WLAN_OPER_INVALID,
    WLAN_OPER_DNS_RESOLVE,
    WLAN_OPER_TCP_CONNECT,
    WLAN_OPER_TCP_DISCONNECT,
    WLAN_OPER_TCP_WRITE,
    WLAN_OPER_UDP_LISTEN,
    WLAN_OPER_UDP_CONNECT,
    WLAN_OPER_UDP_BIND,
    WLAN_OPER_UDP_TRANSFER_SIZE,
    WLAN_OPER_MULTICAST_JOIN,
    WLAN_OPER_TLS_SET_CERT,
    WLAN_OPER_TLS_SET_AUTHMODE,
    WLAN_OPER_TLS_CONNECT,
    WLAN_OPER_SET_MODE,
    WLAN_OPER_SET_ON,
    WLAN_OPER_SET_AP_PASSWD,
    WLAN_OPER_SET_AP_HIDDEN,
    WLAN_OPER_SET_AP_SRV,
    WLAN_OPER_START_AP,
    WLAN_OPER_STOP_AP,
    WLAN_OPER_HELLO,
}WLAN_REQ_TYPE;


typedef struct
{
    uint8_t   type;    
    uint8_t   done;    
    uint8_t   input[64];    
    uint8_t   output[64];    
    uint16_t  error;    
}wifi_operation;

typedef enum 
{
    WIFI_EP_TCP,
    WIFI_EP_UDP,
}wifi_ep_type;

#define MAX_EP_SIMULTANEOUS_NUM 5
typedef struct
{
    uint8_t   used;    
    uint8_t   endpoint;
    uint16_t  rx_len;
    uint8     ep_type;
    uint8     resv;
    uint16_t  src_udp_port;
    uint8_t   rxdata[3072];
}wifi_ep_state;


/**
 * Define BGLIB library
 */
BGLIB_DEFINE();

static OS_MUTEX          g_wifi_mutex;
static OS_MUTEX          g_recv_mutex;
static OS_TCB            g_wifi_tcb;
static CPU_STK           g_wifi_task_stack[512];

static WLAN_STATE        g_wifi_state = WLAN_STATE_IDLE;
static uint8_t           g_uartrx_buffer[BGLIB_MSG_MAXLEN];
static uint8_t           g_local_mac[6] = {0xFF};
static uint32_t          g_local_ipaddr = 0;
//static uint16_t          g_local_udpport = 0;

static wifi_operation    wifi_oper_ctrl;
static wifi_ep_state     g_wifi_ep_state[MAX_EP_SIMULTANEOUS_NUM];
static char              g_wifi_ssid[32] = {0};
static char              g_wifi_passwd[32] = {0};
static uint32_t          g_wifi_uart_rxcnt = 0;
static uint32_t          g_wifi_uart_txcnt = 0;

uint32_t wifi_get_rx_counter()
{
    return g_wifi_uart_rxcnt;
}
uint32_t wifi_get_tx_counter()
{
    return g_wifi_uart_txcnt;
}

static int uart_rx(int data_length, unsigned char* data)
{
    uint16_t    bytes_available = 0;
    uint16_t    bytes_read = 0;
    int         cnt = 0;
    RTOS_ERR    err;

    if (data_length > sizeof(g_uartrx_buffer)) {
        dbg_error("Invalid rx len(%d) > max(%d)", data_length, sizeof(g_uartrx_buffer));
        return -1;
    }

	while (cnt < data_length) {
        bytes_available = emberSerialReadAvailable(comPortUsart3);
        while (bytes_available <= 0) {
            halResetWatchdog();
            OSTimeDly(10, OS_OPT_TIME_DLY, &err);
            bytes_available = emberSerialReadAvailable(comPortUsart3);
        }

        if (bytes_available > data_length - cnt) {
            bytes_available = data_length - cnt;
        }
        
		emberSerialReadData(comPortUsart3, &data[cnt], bytes_available, &bytes_read);
        cnt += bytes_read;
	}

    dbg_trace("rx %d bytes", cnt);
    g_wifi_uart_rxcnt += cnt;
    return cnt;
}

static int uart_tx(int data_length, const unsigned char* data)
{
    RTOS_ERR  err;
    
    if (data_length > sizeof(bglib_temp_msg)) {
        dbg_error("Invalid tx len(%d) > max(%d)", data_length, sizeof(bglib_temp_msg));
        return -1;
    }

    while (EMBER_SUCCESS != emberSerialWriteData(comPortUsart3, (uint8_t *)data, (uint16_t)data_length)) {
        halResetWatchdog();
        OSTimeDly(10, OS_OPT_TIME_DLY, &err);
        dbg_error("trace data_length=%d", data_length);
    }
    
    dbg_trace("tx %d bytes", data_length);
    g_wifi_uart_txcnt += data_length;
    return data_length;
}

static void wifi_on_message_send(uint8 msg_len, uint8* msg_data, uint16 data_len, uint8* data)
{
    uart_tx(msg_len, msg_data);
    if(data_len && data)
    {
        uart_tx(data_len, data);
    }
}

static int wifi_uart_init()
{
    return 0;
}

void wifi_init_ep_state()
{
    RTOS_ERR  err;

    OSMutexPend(&g_recv_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    for (int i = 0; i < MAX_EP_SIMULTANEOUS_NUM; i++) {
        g_wifi_ep_state[i].endpoint = 0xFF;
        g_wifi_ep_state[i].ep_type = (uint16_t)0xFFFF;
        g_wifi_ep_state[i].src_udp_port = 0;
        g_wifi_ep_state[i].used = 0;
        g_wifi_ep_state[i].rx_len = 0;
        memset(g_wifi_ep_state[i].rxdata, 0, sizeof(g_wifi_ep_state[i].rxdata));
    }

    OSMutexPost(&g_recv_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
}

static void wifi_endpoint_status_change(uint32_t ep_type, uint8_t endpoint, bool up)
{
    uint8_t i;
    RTOS_ERR  err;

    OSMutexPend(&g_recv_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    if (up) {
        for (i = 0; i < MAX_EP_SIMULTANEOUS_NUM; i++) {
            if (true == g_wifi_ep_state[i].used && 
                ep_type == g_wifi_ep_state[i].ep_type &&
                endpoint == g_wifi_ep_state[i].endpoint) {
                break;
            }
        }

        if (i >= MAX_EP_SIMULTANEOUS_NUM) {
            for (i = 0; i < MAX_EP_SIMULTANEOUS_NUM; i++) {
                if (true != g_wifi_ep_state[i].used) {
                    g_wifi_ep_state[i].endpoint = endpoint;
                    g_wifi_ep_state[i].ep_type = ep_type;
                    g_wifi_ep_state[i].src_udp_port = 0;
                    g_wifi_ep_state[i].rx_len = 0;
                    g_wifi_ep_state[i].used = true;
                    break;
                }
            }
        }
    } else {
        for (i = 0; i < MAX_EP_SIMULTANEOUS_NUM; i++) {
            if (true == g_wifi_ep_state[i].used && 
				ep_type == g_wifi_ep_state[i].ep_type &&
                endpoint == g_wifi_ep_state[i].endpoint) {
                g_wifi_ep_state[i].endpoint = 0xFF;
                g_wifi_ep_state[i].ep_type = (uint16_t)0xFFFF;
                g_wifi_ep_state[i].src_udp_port = 0;
                g_wifi_ep_state[i].rx_len = 0;
                g_wifi_ep_state[i].used = false;
                break;
            }
        }
    }
    OSMutexPost(&g_recv_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    
    dbg_trace("ep(%d) %s", endpoint, up ? "up" : "down");
    for (i = 0; i < MAX_EP_SIMULTANEOUS_NUM; i++) {
        if (true == g_wifi_ep_state[i].used) {
            dbg_trace("index(%d) ep(%d) type(%d)", i, g_wifi_ep_state[i].endpoint, g_wifi_ep_state[i].ep_type);
        }
    }
    return;
}

static int wifi_endpoint_datalen_in_queue(uint32_t ep_type, uint8_t endpoint)
{
    uint8_t   i;
    RTOS_ERR  err;
    int       len = 0;

    OSMutexPend(&g_recv_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    for (i = 0; i < MAX_EP_SIMULTANEOUS_NUM; i++) {
        if (true == g_wifi_ep_state[i].used && 
            ep_type == g_wifi_ep_state[i].ep_type &&
            endpoint == g_wifi_ep_state[i].endpoint) {
            
            len = g_wifi_ep_state[i].rx_len;
            break;
        }
    }
    
    OSMutexPost(&g_recv_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return len;
}

static int wifi_endpoint_data_enqueue(uint32_t ep_type, uint8_t endpoint, uint8_t *pdata, int len)
{
    uint8_t   i;
    RTOS_ERR  err;
    int       copylen = 0;

    OSMutexPend(&g_recv_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    for (i = 0; i < MAX_EP_SIMULTANEOUS_NUM; i++) {
        if (true == g_wifi_ep_state[i].used && 
            ep_type == g_wifi_ep_state[i].ep_type &&
            endpoint == g_wifi_ep_state[i].endpoint) {
            //dbg_trace("ep(%d) %d bytes", endpoint, g_wifi_ep_state[i].rx_len);
            if (g_wifi_ep_state[i].rx_len >= sizeof(g_wifi_ep_state[i].rxdata)) {
                dbg_error("endpoint %d buf full", endpoint);
            } else {
                copylen = len;
                if (copylen + g_wifi_ep_state[i].rx_len >= sizeof(g_wifi_ep_state[i].rxdata)) {
                    copylen = sizeof(g_wifi_ep_state[i].rxdata) - g_wifi_ep_state[i].rx_len;
                }
                memcpy(&g_wifi_ep_state[i].rxdata[g_wifi_ep_state[i].rx_len],
                       pdata,
                       copylen);
                g_wifi_ep_state[i].rx_len += copylen;
                dbg_trace("ep(%d) enqueue %d bytes", endpoint, copylen);
            }

            break;
        }
    }
    
    OSMutexPost(&g_recv_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return copylen;
}

static int wifi_endpoint_data_dequeue(uint32_t ep_type, uint8_t endpoint, uint8_t *pdata, int len)
{
    uint8_t   i;
    RTOS_ERR  err;
    int       copylen = 0;

    OSMutexPend(&g_recv_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    for (i = 0; i < MAX_EP_SIMULTANEOUS_NUM; i++) {
        if (true == g_wifi_ep_state[i].used && 
            ep_type == g_wifi_ep_state[i].ep_type &&
            endpoint == g_wifi_ep_state[i].endpoint) {
            //dbg_trace("ep(%d) %d bytes", endpoint, g_wifi_ep_state[i].rx_len);
            if (g_wifi_ep_state[i].rx_len > 0) {
                if (g_wifi_ep_state[i].rx_len <= len) {
                    copylen = g_wifi_ep_state[i].rx_len;
                    memcpy(pdata, &g_wifi_ep_state[i].rxdata[0], copylen);
                    g_wifi_ep_state[i].rx_len = 0;
                } else {
                    memcpy(pdata, &g_wifi_ep_state[i].rxdata[0], len);
                    memcpy(&g_wifi_ep_state[i].rxdata[0], &g_wifi_ep_state[i].rxdata[len], g_wifi_ep_state[i].rx_len - len);
                    g_wifi_ep_state[i].rx_len -= len;
                    copylen = len;
                }
                
                dbg_trace("ep(%d) dequeue %d bytes", endpoint, copylen);
            }

            break;
        }
    }
    OSMutexPost(&g_recv_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return copylen;
}

static void wifi_endpoint_bind_udp(uint32_t ep_type, uint8_t endpoint, uint16 port)
{
    uint8_t   i;
    RTOS_ERR  err;

    OSMutexPend(&g_recv_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    for (i = 0; i < MAX_EP_SIMULTANEOUS_NUM; i++) {
        if (true == g_wifi_ep_state[i].used && 
            ep_type == g_wifi_ep_state[i].ep_type &&
            endpoint == g_wifi_ep_state[i].endpoint) {
            g_wifi_ep_state[i].src_udp_port = port;
            break;
        }
    }
    
    OSMutexPost(&g_recv_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return;
}

static int wifi_endpoint_get_udp_port(uint32_t ep_type, uint8_t endpoint, uint16 *p_port)
{
    int       ret = -1;
    uint8_t   i;
    RTOS_ERR  err;

    OSMutexPend(&g_recv_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    for (i = 0; i < MAX_EP_SIMULTANEOUS_NUM; i++) {
        if (true == g_wifi_ep_state[i].used && 
            ep_type == g_wifi_ep_state[i].ep_type &&
            endpoint == g_wifi_ep_state[i].endpoint) {
            *p_port = g_wifi_ep_state[i].src_udp_port;
            ret = 0;
            break;
        }
    }
    
    OSMutexPost(&g_recv_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret; 
}

void wifi_ip2str(int ipaddr, char *pstr)
{
    sprintf(pstr, "%d.%d.%d.%d", ipaddr & 0xFF, (ipaddr >> 8) & 0xFF,
                                 (ipaddr >> 16) & 0xFF, (ipaddr >> 24) & 0xFF);
}

bool wifi_is_running()
{
    return (WLAN_STATE_INIT <= g_wifi_state) ? true : false;
}

bool wifi_is_ssid_valid()
{
    return (0 == strlen(g_wifi_ssid)) ? false : true;
}

bool wifi_is_connected()
{
    return (WLAN_STATE_CONNECTED <= g_wifi_state) ? true : false;
}

void wifi_task(void *para)
{
    uint16_t                msg_length;
    char                    ipstring[32] = {0};
    struct wifi_cmd_packet *pck;

    dbg_trace("wifi task run");

    //halResetWatchdog();
    wifi_cmd_system_reset(0);

    while (1) {
        uart_rx(BGLIB_MSG_HEADER_LEN, g_uartrx_buffer);
        msg_length = BGLIB_MSG_LEN(g_uartrx_buffer);
        if(msg_length)
        {
            uart_rx(msg_length, &g_uartrx_buffer[BGLIB_MSG_HEADER_LEN]);
        }

        pck = BGLIB_MSG(g_uartrx_buffer);
        switch(BGLIB_MSG_ID(g_uartrx_buffer)) {
            case wifi_rsp_system_hello_id:
                dbg_trace("recv %s", DESC(wifi_rsp_system_hello_id));
                if (WLAN_OPER_HELLO == wifi_oper_ctrl.type) {
                    wifi_oper_ctrl.error = WLAN_ERR_NONE;
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_evt_system_boot_id:
                dbg_trace("WiFi reset");
                dbg_trace("recv %s", DESC(wifi_evt_system_boot_id));
                g_wifi_state = WLAN_STATE_IDLE;
                wifi_cmd_config_get_mac(0);
                break;
            case wifi_rsp_config_get_mac_id:
                dbg_trace("recv %s result %d", DESC(wifi_rsp_config_get_mac_id), pck->rsp_config_get_mac.result);
                if (wifi_err_success != pck->rsp_config_get_mac.result){
                    wifi_cmd_system_reset(0);
                }
                if (WLAN_STATE_IDLE == g_wifi_state){
                    dbg_print("wifi init...");
                    g_wifi_state = WLAN_STATE_INIT;

                    if (wifi_is_ssid_valid()) {
                        wifi_cmd_sme_wifi_on();
                    }
                }
                break;
            case wifi_evt_config_mac_address_id:
                dbg_trace("recv %s", DESC(wifi_evt_config_mac_address_id));
                memcpy(g_local_mac, (uint8_t *)pck->evt_config_mac_address.mac.addr, 6);
                break;  
            case wifi_evt_system_power_saving_state_id:
                dbg_trace("recv %s state=%d", DESC(wifi_evt_system_power_saving_state_id), pck->evt_system_power_saving_state.state);
                if (system_power_saving_state_0 != pck->evt_system_power_saving_state.state) {
                    wifi_cmd_system_set_max_power_saving_state(system_power_saving_state_0);
                }
                break;
            case wifi_rsp_system_set_max_power_saving_state_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_system_set_max_power_saving_state_id), pck->rsp_system_set_max_power_saving_state.result);
                if (0 != pck->rsp_system_set_max_power_saving_state.result) {
                    wifi_cmd_system_reset(0);
                }
                break;
            case wifi_rsp_sme_set_operating_mode_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_sme_set_operating_mode_id), pck->rsp_sme_set_operating_mode.result);
                if (WLAN_OPER_SET_MODE == wifi_oper_ctrl.type) {
                    wifi_oper_ctrl.error = pck->rsp_sme_set_operating_mode.result;
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_rsp_sme_wifi_on_id:
                dbg_trace("WiFi on");
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_sme_wifi_on_id), pck->rsp_sme_wifi_on.result);
                if (wifi_err_success != pck->rsp_sme_wifi_on.result) {
                    if (WLAN_OPER_SET_ON == wifi_oper_ctrl.type) {
                        wifi_oper_ctrl.error = pck->rsp_sme_wifi_on.result;
                        wifi_oper_ctrl.done = true;
                    } else {
                        wifi_cmd_system_reset(0);
                    }
                }
                break;
            case wifi_evt_sme_wifi_is_on_id:
                dbg_trace("WiFi on...ok");
                dbg_trace("recv %s %d", DESC(wifi_evt_sme_wifi_is_on_id), pck->evt_sme_wifi_is_on.result);
                if (WLAN_OPER_SET_ON == wifi_oper_ctrl.type) {
                    wifi_oper_ctrl.error = pck->evt_sme_wifi_is_on.result;
                    wifi_oper_ctrl.done = true;
                }
                
                if (wifi_err_success == pck->evt_sme_wifi_is_on.result) {
                    if (WLAN_STATE_INIT == g_wifi_state){
                        dbg_print("wifi on...");
                        g_wifi_state = WLAN_STATE_ON;
                    }

                    if (wifi_is_ssid_valid()) {
                        wifi_cmd_sme_set_password(strlen(g_wifi_passwd), g_wifi_passwd);
                    }
                } else {
                    if (wifi_is_ssid_valid()) {
                        wifi_cmd_system_reset(0);
                    }
                }
                break;
            case wifi_rsp_sme_set_ap_password_id:
                dbg_trace("recv %s status=%d", DESC(wifi_rsp_sme_set_ap_password_id), pck->rsp_sme_set_ap_password.status);
                if (WLAN_OPER_SET_AP_PASSWD == wifi_oper_ctrl.type) {
                    wifi_oper_ctrl.error = pck->rsp_sme_set_ap_password.status;
                    wifi_oper_ctrl.done = true;
                }                
                break;
            case wifi_rsp_sme_start_ap_mode_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_sme_start_ap_mode_id), pck->rsp_sme_start_ap_mode.result);
                if (wifi_err_success != pck->rsp_sme_start_ap_mode.result) {
                    if (WLAN_OPER_START_AP == wifi_oper_ctrl.type) {
                        wifi_oper_ctrl.error = pck->rsp_sme_start_ap_mode.result;
                        wifi_oper_ctrl.done = true;
                    }
                }
                break;
            case wifi_evt_sme_ap_mode_failed_id:
                dbg_trace("recv %s reason=%d", DESC(wifi_evt_sme_ap_mode_failed_id), pck->evt_sme_ap_mode_failed.reason);
                if (WLAN_OPER_START_AP == wifi_oper_ctrl.type) {
                    wifi_oper_ctrl.error = pck->evt_sme_ap_mode_failed.reason;
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_rsp_sme_set_ap_hidden_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_sme_set_ap_hidden_id), pck->rsp_sme_set_ap_hidden.result);
                if (WLAN_OPER_SET_AP_HIDDEN == wifi_oper_ctrl.type) {
                    wifi_oper_ctrl.error = pck->rsp_sme_set_ap_hidden.result;
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_rsp_https_enable_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_https_enable_id), pck->rsp_https_enable.result);
                if (WLAN_OPER_SET_AP_SRV == wifi_oper_ctrl.type) {
                    wifi_oper_ctrl.error = pck->rsp_https_enable.result;
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_rsp_sme_stop_ap_mode_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_sme_stop_ap_mode_id), pck->rsp_sme_stop_ap_mode.result);
                if (wifi_err_success != pck->rsp_sme_stop_ap_mode.result) {
                    if (WLAN_OPER_STOP_AP == wifi_oper_ctrl.type) {
                        wifi_oper_ctrl.error = pck->rsp_sme_stop_ap_mode.result;
                        wifi_oper_ctrl.done = true;
                    }
                }
                break;
            case wifi_evt_sme_ap_mode_started_id:
                dbg_trace("recv %s", DESC(wifi_evt_sme_ap_mode_started_id));
                if (WLAN_OPER_START_AP == wifi_oper_ctrl.type) {
                    wifi_oper_ctrl.error = 0;
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_evt_sme_ap_mode_stopped_id:
                dbg_trace("recv %s", DESC(wifi_evt_sme_ap_mode_stopped_id));
                if (WLAN_OPER_STOP_AP == wifi_oper_ctrl.type) {
                    wifi_oper_ctrl.error = 0;
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_rsp_sme_set_password_id:
                dbg_trace("WiFi set password...ok");
                dbg_trace("recv %s status=%d", DESC(wifi_rsp_sme_set_password_id), pck->rsp_sme_set_password.status);
                if (wifi_err_success == pck->rsp_sme_set_password.status) {
                    if (WLAN_STATE_ON == g_wifi_state){
                        dbg_print("wifi set passwd...");
                        g_wifi_state = WLAN_STATE_PASSWD_SET;
                    }

                    if (wifi_is_ssid_valid()) {
                        wifi_cmd_sme_connect_ssid(strlen(g_wifi_ssid), g_wifi_ssid);
                    }
                } else {
                    if (wifi_is_ssid_valid()) {
                        wifi_cmd_system_reset(0);
                    }
                }
                
                break;
            case wifi_rsp_sme_connect_ssid_id:
                dbg_print("WiFi connect...");
                dbg_trace("recv %s %d", DESC(wifi_rsp_sme_connect_ssid_id), pck->rsp_sme_connect_ssid.result);
                if (wifi_err_success != pck->rsp_sme_connect_ssid.result) {
                    if (wifi_is_ssid_valid()) {
                        wifi_cmd_system_reset(0);
                    }
                }
                break;
            case wifi_evt_sme_connected_id:
                dbg_print("WiFi connected");
                dbg_trace("recv %s %d", DESC(wifi_evt_sme_connected_id), pck->evt_sme_connected.status);
                if (wifi_is_ssid_valid()) {
                    if (WLAN_STATE_PASSWD_SET == g_wifi_state){
                        g_wifi_state = WLAN_STATE_CONNECTED;
                        wifi_cmd_tcpip_tls_set_authmode(TLS_AUTH_OPTIONAL);
                    }
                }
                break;
            case wifi_evt_sme_connect_failed_id:
                dbg_print("WiFi connect fail");
                dbg_trace("recv %s %d", DESC(wifi_evt_sme_connect_failed_id), pck->evt_sme_connect_failed.reason);
                if (wifi_is_ssid_valid()) {
                    wifi_cmd_system_reset(0);
                }
                break;
            case wifi_evt_tcpip_configuration_id:
                wifi_ip2str(pck->evt_tcpip_configuration.address.u, ipstring);
                dbg_trace("recv %s ip=%s", DESC(wifi_evt_tcpip_configuration_id), ipstring);
                g_local_ipaddr = pck->evt_tcpip_configuration.address.u;
                break;
            case wifi_evt_sme_interface_status_id:
                dbg_print("WiFi set interface up");
                dbg_trace("recv %s status %d", DESC(wifi_evt_sme_interface_status_id), pck->evt_sme_interface_status.status);
                if (1 == pck->evt_sme_interface_status.status) {
                    g_wifi_state = WLAN_STATE_CONNECTED;
                    wifi_cmd_tcpip_tls_set_authmode(TLS_AUTH_OPTIONAL);
                } else {
                    g_wifi_state = WLAN_STATE_IDLE;
                    wifi_cmd_system_reset(0);
                }
                break;
            case wifi_rsp_tcpip_dns_gethostbyname_id:
                dbg_trace("recv %s", DESC(wifi_rsp_tcpip_dns_gethostbyname_id));
                if (WLAN_OPER_DNS_RESOLVE == wifi_oper_ctrl.type) {
                    if (wifi_err_success != pck->rsp_tcpip_dns_gethostbyname.result){
                        wifi_oper_ctrl.error = pck->rsp_tcpip_dns_gethostbyname.result;
                        wifi_oper_ctrl.done = true;
                    }
                }                
                break;
            case wifi_evt_tcpip_dns_gethostbyname_result_id:
                dbg_trace("recv %s result=%d", DESC(wifi_evt_tcpip_dns_gethostbyname_result_id), pck->evt_tcpip_dns_gethostbyname_result.result);
                if (WLAN_OPER_DNS_RESOLVE == wifi_oper_ctrl.type) {
                    if (wifi_err_success != pck->evt_tcpip_dns_gethostbyname_result.result){
                        wifi_oper_ctrl.error = pck->evt_tcpip_dns_gethostbyname_result.result;
                    } else {
                        wifi_oper_ctrl.error = 0;
                        *(uint32_t *)wifi_oper_ctrl.output = pck->evt_tcpip_dns_gethostbyname_result.address.u;
                    }

                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_rsp_tcpip_tcp_connect_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_tcpip_tcp_connect_id), pck->rsp_tcpip_tcp_connect.result);
                if (WLAN_OPER_TCP_CONNECT == wifi_oper_ctrl.type) {
                    if (wifi_err_success != pck->rsp_tcpip_tcp_connect.result){
                        wifi_oper_ctrl.error = pck->rsp_tcpip_tcp_connect.result;
                        wifi_oper_ctrl.done = true;
                    }
                }
                break;
            case wifi_rsp_tcpip_tls_connect_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_tcpip_tls_connect_id), pck->rsp_tcpip_tls_connect.result);
                if (WLAN_OPER_TLS_CONNECT == wifi_oper_ctrl.type) {
                    if (wifi_err_success != pck->rsp_tcpip_tls_connect.result){
                        wifi_oper_ctrl.error = pck->rsp_tcpip_tls_connect.result;
                        wifi_oper_ctrl.done = true;
                    }
                }
                break;
            case wifi_evt_endpoint_status_id:
                dbg_trace("recv %s ep%d type=%d active=%d", DESC(wifi_evt_endpoint_status_id), 
                                                    pck->evt_endpoint_status.endpoint,
                                                    pck->evt_endpoint_status.type,
                                                    pck->evt_endpoint_status.active);
                uint32_t ep_type = 0xFFFFFFFF;
                
                if (2048 == pck->evt_endpoint_status.type) {
                    ep_type = WIFI_EP_TCP;
                } else if (16 == pck->evt_endpoint_status.type || 32 == pck->evt_endpoint_status.type) {
                    ep_type = WIFI_EP_UDP;
                }

                if (WIFI_EP_TCP == ep_type || WIFI_EP_UDP == ep_type) {
                    wifi_endpoint_status_change(ep_type, pck->evt_endpoint_status.endpoint, pck->evt_endpoint_status.active);
                }
                if (WLAN_OPER_TCP_DISCONNECT == wifi_oper_ctrl.type && 0 == pck->evt_endpoint_status.active) {
                    if (pck->evt_endpoint_status.endpoint == *(uint8_t *)wifi_oper_ctrl.input) {
                        wifi_oper_ctrl.done = true;
                    }
                } else if (( (WLAN_OPER_TCP_CONNECT == wifi_oper_ctrl.type) ||
                             (WLAN_OPER_UDP_LISTEN == wifi_oper_ctrl.type) ||
                             (WLAN_OPER_UDP_CONNECT == wifi_oper_ctrl.type) ||
                             (WLAN_OPER_TLS_CONNECT == wifi_oper_ctrl.type))
                      && 1 == pck->evt_endpoint_status.active) {
                    wifi_oper_ctrl.error = 0;
                    *(uint8_t *)wifi_oper_ctrl.output = pck->evt_endpoint_status.endpoint;
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_rsp_endpoint_close_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_endpoint_close_id), pck->rsp_endpoint_close.result);
                if (WLAN_OPER_TCP_DISCONNECT == wifi_oper_ctrl.type) {
                    if (wifi_err_success != pck->rsp_endpoint_close.result 
                        && pck->rsp_endpoint_close.endpoint == *(uint8_t *)wifi_oper_ctrl.input){
                        wifi_oper_ctrl.error = pck->rsp_endpoint_close.result;
                        wifi_oper_ctrl.done = true;
                    }
                }
                break;
            case wifi_rsp_endpoint_send_id:
                dbg_trace("recv %s ep=%d result=%d", DESC(wifi_rsp_endpoint_send_id), pck->rsp_endpoint_send.endpoint, pck->rsp_endpoint_send.result);
                if (WLAN_OPER_TCP_WRITE == wifi_oper_ctrl.type) {
                    if (*(uint8_t *)wifi_oper_ctrl.input == pck->rsp_endpoint_send.endpoint) {
                        if (wifi_err_success != pck->rsp_endpoint_send.result){
                            wifi_oper_ctrl.error = pck->rsp_endpoint_send.result;
                        } else {
                            wifi_oper_ctrl.error = 0;
                        }
                        wifi_oper_ctrl.done = true;
                    }
                }
                break;
            case wifi_evt_endpoint_closing_id:
                dbg_trace("recv %s endpoint=%d", DESC(wifi_evt_endpoint_closing_id), pck->evt_endpoint_closing.endpoint);
                wifi_cmd_endpoint_close(pck->evt_endpoint_closing.endpoint);
                break;
            case wifi_evt_endpoint_data_id:
                dbg_trace("recv %s endpoint=%d len=%d", DESC(wifi_evt_endpoint_data_id), 
                                                              pck->evt_endpoint_data.endpoint,
                                                              pck->evt_endpoint_data.data.len);
                wifi_endpoint_data_enqueue(WIFI_EP_TCP, pck->evt_endpoint_data.endpoint, pck->evt_endpoint_data.data.data, pck->evt_endpoint_data.data.len);
                break;
            case wifi_evt_tcpip_udp_data_id:
                dbg_trace("recv %s endpoint=%d len=%d", DESC(wifi_evt_tcpip_udp_data_id), 
                                                              pck->evt_tcpip_udp_data.endpoint,
                                                              pck->evt_tcpip_udp_data.data.len);

                //enqueue sender info for the first time
                if (wifi_endpoint_datalen_in_queue(WIFI_EP_UDP, pck->evt_tcpip_udp_data.endpoint) <= 0) {
                    UDP_Addr src_addr;
                    src_addr.ipaddr = pck->evt_tcpip_udp_data.source_address.u;
                    src_addr.port = pck->evt_tcpip_udp_data.source_port;
                    wifi_endpoint_data_enqueue(WIFI_EP_UDP,
                                               pck->evt_tcpip_udp_data.endpoint, 
                                               (uint8_t *)&src_addr,
                                               sizeof(src_addr));
                }
                
                wifi_endpoint_data_enqueue(WIFI_EP_UDP,
                                           pck->evt_tcpip_udp_data.endpoint, 
                                           pck->evt_tcpip_udp_data.data.data, 
                                           pck->evt_tcpip_udp_data.data.len);
                
                break;
            case wifi_rsp_tcpip_start_udp_server_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_tcpip_start_udp_server_id), pck->rsp_tcpip_start_udp_server.result);
                if (WLAN_OPER_UDP_LISTEN == wifi_oper_ctrl.type) {
                    if (wifi_err_success != pck->rsp_tcpip_start_udp_server.result){
                        wifi_oper_ctrl.error = pck->rsp_tcpip_start_udp_server.result;
                        wifi_oper_ctrl.done = true;
                    }
                }
                break; 
            case wifi_rsp_tcpip_udp_connect_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_tcpip_udp_connect_id), pck->rsp_tcpip_udp_connect.result);
                if (WLAN_OPER_UDP_CONNECT == wifi_oper_ctrl.type) {
                    if (wifi_err_success != pck->rsp_tcpip_udp_connect.result){
                        wifi_oper_ctrl.error = pck->rsp_tcpip_udp_connect.result;
                        wifi_oper_ctrl.done = true;
                    }
                }
                break;
            case wifi_rsp_tcpip_udp_bind_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_tcpip_udp_bind_id), pck->rsp_tcpip_udp_bind.result);
                if (WLAN_OPER_UDP_BIND == wifi_oper_ctrl.type) {
                    if (wifi_err_success != pck->rsp_tcpip_udp_bind.result){
                        wifi_oper_ctrl.error = pck->rsp_tcpip_udp_bind.result;
                    }
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_rsp_tcpip_multicast_join_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_tcpip_multicast_join_id), pck->rsp_tcpip_multicast_join.result);
                if (WLAN_OPER_MULTICAST_JOIN == wifi_oper_ctrl.type) {
                    if (wifi_err_success != pck->rsp_tcpip_multicast_join.result){
                        wifi_oper_ctrl.error = pck->rsp_tcpip_multicast_join.result;
                    }
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_rsp_endpoint_set_transmit_size_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_endpoint_set_transmit_size_id), pck->rsp_endpoint_set_transmit_size.result);
                if (WLAN_OPER_UDP_TRANSFER_SIZE == wifi_oper_ctrl.type) {
                    if (wifi_err_success != pck->rsp_endpoint_set_transmit_size.result){
                        wifi_oper_ctrl.error = pck->rsp_endpoint_set_transmit_size.result;
                    }
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_rsp_tcpip_tls_set_user_certificate_id:
                dbg_trace("recv %s result=%d", DESC(wifi_rsp_tcpip_tls_set_user_certificate_id), pck->rsp_tcpip_tls_set_user_certificate.result);
                if (WLAN_OPER_TLS_SET_CERT == wifi_oper_ctrl.type) {
                    if (wifi_err_success != pck->rsp_tcpip_tls_set_user_certificate.result){
                        wifi_oper_ctrl.error = pck->rsp_tcpip_tls_set_user_certificate.result;
                    }
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_rsp_tcpip_tls_set_authmode_id:
                dbg_trace("recv %s", DESC(wifi_rsp_tcpip_tls_set_authmode_id));
                if (WLAN_OPER_TLS_SET_AUTHMODE == wifi_oper_ctrl.type) {
                    wifi_oper_ctrl.done = true;
                }
                break;
            case wifi_evt_tcpip_tls_verify_result_id:
                dbg_trace("recv %s flags=%d", DESC(wifi_evt_tcpip_tls_verify_result_id), pck->evt_tcpip_tls_verify_result.flags);
                break;
            case wifi_evt_flash_ps_key_changed_id:
            case wifi_evt_tcpip_endpoint_status_id:
            case wifi_evt_sme_connect_retry_id:
            case wifi_evt_tcpip_dns_configuration_id:
                break;
            case wifi_evt_sme_disconnected_id:
                dbg_error("recv %s", DESC(wifi_evt_sme_disconnected_id));
                wifi_cmd_system_reset(0);
                g_wifi_state = WLAN_STATE_IDLE;
                wifi_init_ep_state();
                break;
            default:
                dbg_trace("recv unknown msg %lx", BGLIB_MSG_ID(g_uartrx_buffer));
                break;
        }
    }
}

int wifi_init(char *pssid, char *ppasswd)
{
    uint32_t  ms = 0;
    RTOS_ERR  err;

    if (0 != wifi_uart_init()) {
        dbg_error("Init wifi uart fail.");
        return -1;
    }

    /*prevent wifi API from being called by multitask  */
    OSMutexCreate(&g_wifi_mutex, "wifi_mutex", &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    /*protect the data queue*/
    OSMutexCreate(&g_recv_mutex, "ip_data_mutex", &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_init_ep_state();

    //set ssid and passwd
    dbg_print("pssid=[%s] ppasswd=[%s]", pssid, ppasswd);
    snprintf(g_wifi_ssid, sizeof(g_wifi_ssid)-1, pssid);
    snprintf(g_wifi_passwd, sizeof(g_wifi_passwd)-1, ppasswd);
    
    g_wifi_state = WLAN_STATE_IDLE;
    BGLIB_INITIALIZE(wifi_on_message_send);
    OSTaskCreate(&g_wifi_tcb,
                 "wifi_task",
                 wifi_task,
                 NULL,
                 6,
                 &g_wifi_task_stack[0],
                 64,
                 512,
                 0,       /* Not receiving messages  */
                 0,       /* Default time quanta  */
                 NULL,    /* No TCB extensions  */
                 OS_OPT_TASK_STK_CLR | OS_OPT_TASK_STK_CHK,
                 &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    while (true != wifi_is_running()) {
        halResetWatchdog();
        OSTimeDly(100, OS_OPT_TIME_DLY, &err);

        ms += 100;
        if (ms >= 5000) {
            wifi_cmd_system_reset(0);
            dbg_error("wifi init timeout");
            return -1;
        }
    }

    dbg_print("wifi is running");
    return 0;
}

uint32_t wifi_get_local_ipaddr()
{
    return g_local_ipaddr;
}

int wifi_get_local_mac(uint8_t mac[6])
{
    memcpy(mac, g_local_mac, 6);
    return 0;
}

int wifi_sync_wait_done(int timeout_ms)
{
    int      ret = WLAN_ERR_NONE;
    uint64_t start;
    RTOS_ERR err;

    start = halCommonGetInt64uMillisecondTick();
    while (!wifi_oper_ctrl.done) {
        if (halCommonGetInt64uMillisecondTick() - start > timeout_ms) {
            ret = WLAN_ERR_TIMEOUT;
            dbg_error("Wifi timeout, oper=%d", wifi_oper_ctrl.type);
            break;
        }

        halResetWatchdog();
        OSTimeDly(10, OS_OPT_TIME_DLY, &err);
    }

    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    wifi_oper_ctrl.type = WLAN_OPER_INVALID;
    wifi_oper_ctrl.done = true;
    return ret;
}

int wifi_set_operation_mode(WLAN_OPER_MODE mode)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_running()) {
        dbg_error("Wifi not running");
        return WLAN_ERR_HW;
    }

    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_oper_ctrl.type = WLAN_OPER_SET_MODE;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_sme_set_operating_mode(mode);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_set_wifi_on()
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_running()) {
        dbg_error("Wifi not running");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_oper_ctrl.type = WLAN_OPER_SET_ON;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_sme_wifi_on();

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_set_ap_passwd(char *passwd)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_running()) {
        dbg_error("Wifi not running");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_oper_ctrl.type = WLAN_OPER_SET_AP_PASSWD;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_sme_set_ap_password(strlen(passwd), passwd);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_start_ap_mode(uint8_t channel, WLAN_AP_SECURITY security, char *ssid)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_running()) {
        dbg_error("Wifi not running");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_oper_ctrl.type = WLAN_OPER_START_AP;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_sme_start_ap_mode(channel, security, strlen(ssid), ssid);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_stop_ap_mode()
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_running()) {
        dbg_error("Wifi not running");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_oper_ctrl.type = WLAN_OPER_STOP_AP;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_sme_stop_ap_mode();

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_set_ap_hidden(uint8_t hidden)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_running()) {
        dbg_error("Wifi not running");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_oper_ctrl.type = WLAN_OPER_SET_AP_HIDDEN;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_sme_set_ap_hidden(hidden);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_set_ap_server(uint8_t http, uint8_t dhcp, uint8_t dns)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_running()) {
        dbg_error("Wifi not running");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    wifi_oper_ctrl.type = WLAN_OPER_SET_AP_SRV;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_https_enable(http, dhcp, dns);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_start_ap(char *ssid, char *passwd, uint8_t hide)
{
    int      ret = WLAN_ERR_NONE;

    dbg_trace("ssid[%s] passwd[%s] hide[%d]", ssid, passwd, hide);

    ret = wifi_set_operation_mode(WLAN_OPER_MODE_AP);
    if (WLAN_ERR_NONE != ret) {
        dbg_error("set operation mode fail");
        return ret;
    }

    ret = wifi_set_wifi_on();
    if (WLAN_ERR_NONE != ret) {
        dbg_error("set wifi on fail");
        return ret;
    }

    if (1 == hide) {
        ret = wifi_set_ap_hidden(hide);
        if (WLAN_ERR_NONE != ret) {
            dbg_error("set ap hidden fail");
            return ret;
        }
    }

    ret = wifi_set_ap_passwd(passwd);
    if (WLAN_ERR_NONE != ret) {
        dbg_error("set ap password fail");
        return ret;
    }

    ret = wifi_set_ap_server(0, 1, 0);
    if (WLAN_ERR_NONE != ret) {
        dbg_error("set ap dhcp fail");
        return ret;
    }

    ret = wifi_start_ap_mode(WLAN_AP_DEFAULT_CHANNEL, WLAN_AP_SECURITY_NONE, ssid);
    if (WLAN_ERR_NONE != ret) {
        dbg_error("start ap mode fail");
        return ret;
    }

    return WLAN_ERR_NONE;
}

int wifi_stop_ap()
{
    RTOS_ERR err;

    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_cmd_system_reset(0);
    g_wifi_state = WLAN_STATE_IDLE;
    wifi_init_ep_state();

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    return WLAN_ERR_NONE;
}

int wifi_connect(char *pssid, char *ppasswd)
{
    RTOS_ERR err;

    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    //set ssid and passwd
    snprintf(g_wifi_ssid, sizeof(g_wifi_ssid)-1, pssid);
    snprintf(g_wifi_passwd, sizeof(g_wifi_passwd)-1, ppasswd);
    wifi_cmd_system_reset(0);
    g_wifi_state = WLAN_STATE_IDLE;
    wifi_init_ep_state();

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    return WLAN_ERR_NONE;
}

int wifi_hostname_resolve(const char *hostname, uint32_t *p_ipaddr)
{
    int      ret = WLAN_ERR_NONE;
    char     ipstring[32] = {0};
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    wifi_oper_ctrl.type = WLAN_OPER_DNS_RESOLVE;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_tcpip_dns_gethostbyname(strlen(hostname), hostname);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    if (WLAN_ERR_NONE == ret) {
        *p_ipaddr = *(uint32_t *)wifi_oper_ctrl.output;
        wifi_ip2str(*p_ipaddr, ipstring);
        dbg_trace("host[%s]-->%s", hostname, ipstring);
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_tcpip_tcp_connect_byip(uint32_t ipaddr, uint16_t port, uint8_t *pendpoint)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    wifi_oper_ctrl.type = WLAN_OPER_TCP_CONNECT;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_tcpip_tcp_connect(ipaddr, port, -1);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    if (WLAN_ERR_NONE == ret) {
        *pendpoint = *(uint8_t *)wifi_oper_ctrl.output;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_tcpip_tcp_connect_byhostname(const char *phostname, uint16_t port, uint8_t *pendpoint)
{
    int      ret;
    uint32_t ipaddr;

    ret = wifi_hostname_resolve(phostname, &ipaddr);
    if (0 != ret) {
        return ret;
    }

    ret = wifi_tcpip_tcp_connect_byip(ipaddr, port, pendpoint);
    if (0 != ret) {
        return ret;
    }

    return 0;
}

int wifi_close_ep(uint32_t ep_type, uint8_t endpoint)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    wifi_oper_ctrl.type = WLAN_OPER_TCP_DISCONNECT;
    *(uint8_t *)wifi_oper_ctrl.input = endpoint;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_endpoint_close(endpoint);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    wifi_endpoint_status_change(ep_type, endpoint, false);
    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;    
}

int wifi_tcpip_write_onemtu(uint8_t endpoint, uint8_t *pdata, int len, int timeout_ms)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    wifi_oper_ctrl.type = WLAN_OPER_TCP_WRITE;
    *(uint8_t *)wifi_oper_ctrl.input = endpoint;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_endpoint_send(endpoint, len, pdata);

    ret = wifi_sync_wait_done(timeout_ms);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;      
}

int wifi_tcpip_write(uint8_t endpoint, uint8_t *pdata, int len, int timeout_ms)
{
    int      offset = 0;
    int      send_size = 0;
    int      retry = 0;
    bool     done = false;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }

    dbg_trace("write %d bytes ep=%d timeout_ms=%d", len, endpoint, timeout_ms);
    if (0 == timeout_ms) {
        timeout_ms = WIFI_DEFAULT_TIMEOUT;
    } else if (timeout_ms < WIFI_MINIMAL_TIMEOUT) {
        timeout_ms = WIFI_MINIMAL_TIMEOUT;
    }

    while (offset < len) {
        send_size = len - offset;
        if (128 < send_size) {
            send_size = 128;
        }

        retry = 0;
        done = false;
        while (retry++ < 3 && true != done) {
            if (0 == wifi_tcpip_write_onemtu(endpoint, pdata + offset, send_size, timeout_ms)) {
                offset += send_size;
                retry = 0;
                done = true;
                break;
            }

            //wifi_cmd_system_hello();
        }

        if (true != done) {
            break;
        }
    }
    
    return offset;        
}

int wifi_tcpip_read(uint8_t endpoint, uint8_t *pdata, int len, int timeout_ms)
{
    int      cnt = 0;
    int      size = 0;
    uint64_t start;
    RTOS_ERR err;

    if (0 == timeout_ms) {
        timeout_ms = WIFI_DEFAULT_TIMEOUT;
    }

    start = halCommonGetInt64uMillisecondTick();
    while (cnt < len) {
        if (halCommonGetInt64uMillisecondTick() - start > timeout_ms) {
            //dbg_error("Wifi timeout");
            break;
        }

        size= wifi_endpoint_data_dequeue(WIFI_EP_TCP, endpoint, pdata + cnt, len - cnt);
        if (size <= 0) {
            halResetWatchdog();
            OSTimeDly(10, OS_OPT_TIME_DLY, &err);
            continue;
        } else {
            cnt += size;
        }
    }

    #if  0
    dbg_trace("read %d bytes len=%d ep=%d timeout_ms=%d", cnt, len, endpoint, timeout_ms);
    int i;
    dbg_error("TCP Read:");
    for (i = 0; i < cnt; i++) {
        dbg_error("%02X ", pdata[i]);
    }
    dbg_error("\r\n");
    #endif /* #if 0 */ 
    return cnt;
}

int wifi_tls_set_user_cert(const char *pcert)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    wifi_oper_ctrl.type = WLAN_OPER_TLS_SET_CERT;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_tcpip_tls_set_user_certificate(strlen(pcert), pcert);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }
    
    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_tls_set_auth_mode(uint8_t mode)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    wifi_oper_ctrl.type = WLAN_OPER_TLS_SET_AUTHMODE;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_tcpip_tls_set_authmode(mode);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }
    
    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_tcpip_tls_connect_byip(uint32_t ipaddr, uint16_t port, uint8_t *pendpoint)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    wifi_oper_ctrl.type = WLAN_OPER_TLS_CONNECT;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_tcpip_tls_connect(ipaddr, port, -1);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    if (WLAN_ERR_NONE == ret) {
        *pendpoint = *(uint8_t *)wifi_oper_ctrl.output;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_tcpip_tls_connect_byhostname(const char *phostname, uint16_t port, uint8_t *pendpoint)
{
    int      ret;
    uint32_t ipaddr;

    ret = wifi_hostname_resolve(phostname, &ipaddr);
    if (0 != ret) {
        return ret;
    }

    ret = wifi_tcpip_tls_connect_byip(ipaddr, port, pendpoint);
    if (0 != ret) {
        return ret;
    }

    return 0;
}

int wifi_tcpip_tcp_close(uint8_t endpoint)
{
    if (0 != wifi_close_ep(WIFI_EP_TCP, endpoint)) {
        dbg_error("disconnect fail");
    }

    return 0;
}

int wifi_udp_listen(uint16_t port, uint8_t *p_endpoint)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    wifi_oper_ctrl.type = WLAN_OPER_UDP_LISTEN;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_tcpip_start_udp_server(port, -1);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    if (WLAN_ERR_NONE == ret) {
        *p_endpoint = *(uint8_t *)wifi_oper_ctrl.output;
    }

    //g_local_udpport = port;
    wifi_endpoint_bind_udp(WIFI_EP_UDP, *p_endpoint, port);
    
    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    return ret;
}

int wifi_udp_read(uint8_t endpoint, uint8_t *pdata, int len, int timeout_ms, UDP_Addr *psrc)
{
    uint64_t start;
    RTOS_ERR err;

    start = halCommonGetInt64uMillisecondTick();
    while (sizeof(UDP_Addr) != wifi_endpoint_data_dequeue(WIFI_EP_UDP, endpoint, (uint8_t *)psrc, sizeof(UDP_Addr))) {
        halResetWatchdog();
        OSTimeDly(100, OS_OPT_TIME_DLY, &err);

        if (halCommonGetInt64uMillisecondTick() - start > timeout_ms) {
            return -1;
        }
    }

    return wifi_endpoint_data_dequeue(WIFI_EP_UDP, endpoint, pdata, len);
}

int wifi_udp_connect(uint32_t ipaddr, uint16_t port, uint8_t *p_endpoint, int timeout_ms)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }
    
    if (0 == timeout_ms) {
        timeout_ms = WIFI_DEFAULT_TIMEOUT;
    } else if (timeout_ms < WIFI_MINIMAL_TIMEOUT) {
        timeout_ms = WIFI_MINIMAL_TIMEOUT;
    }
     
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    
    wifi_oper_ctrl.type = WLAN_OPER_UDP_CONNECT;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_tcpip_udp_connect(ipaddr, port, -1);

    ret = wifi_sync_wait_done(timeout_ms);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    if (WLAN_ERR_NONE == ret) {
        *p_endpoint = *(uint8_t *)wifi_oper_ctrl.output;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_udp_bind(uint16_t port, uint8_t endpoint, int timeout_ms)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }

    if (0 == timeout_ms) {
        timeout_ms = WIFI_DEFAULT_TIMEOUT;
    } else if (timeout_ms < WIFI_MINIMAL_TIMEOUT) {
        timeout_ms = WIFI_MINIMAL_TIMEOUT;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_oper_ctrl.type = WLAN_OPER_UDP_BIND;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_tcpip_udp_bind(endpoint, port);

    ret = wifi_sync_wait_done(timeout_ms);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_udp_set_transfersize(uint8_t endpoint, int size, int timeout_ms)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }

    if (0 == timeout_ms) {
        timeout_ms = WIFI_DEFAULT_TIMEOUT;
    } else if (timeout_ms < WIFI_MINIMAL_TIMEOUT) {
        timeout_ms = WIFI_MINIMAL_TIMEOUT;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_oper_ctrl.type = WLAN_OPER_UDP_TRANSFER_SIZE;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_endpoint_set_transmit_size(endpoint, size);

    ret = wifi_sync_wait_done(timeout_ms);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    wifi_oper_ctrl.type = WLAN_OPER_INVALID;
    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_udp_write(uint8_t endpoint, uint8_t *pdata, int len, int timeout_ms, UDP_Addr *premote)
{
    int      ret = WLAN_ERR_NONE;
    uint8_t  endpoint_new = 255;
    uint16_t udp_port;

    (void)endpoint;

    dbg_trace("wifi_udp_connect to port %d", premote->port);
    ret = wifi_udp_connect(premote->ipaddr, premote->port, &endpoint_new, timeout_ms);
    if (WLAN_ERR_NONE != ret) {
        dbg_error("wifi_udp_connect fail");
        return -1;
    }

    if (0 != wifi_endpoint_get_udp_port(WIFI_EP_UDP, endpoint, &udp_port)) {
        dbg_error("get src udp port fail");
        return -1;
    }
    
    dbg_trace("wifi_udp_bind ep%d to port %d", endpoint_new,  udp_port);
    ret = wifi_udp_bind(udp_port, endpoint_new, timeout_ms);
    if (WLAN_ERR_NONE != ret) {
        dbg_error("wifi_udp_bind fail");
        return -1;
    }

    dbg_trace("wifi_udp_set_transfersize ep%d to len %d", endpoint_new, len);
    ret = wifi_udp_set_transfersize(endpoint_new, len, timeout_ms);
    if (WLAN_ERR_NONE != ret) {
        dbg_error("wifi_udp_set_transfersize fail");
        return -1;
    }

    dbg_trace("wifi_tcpip_udp_write %d bytes to ep%d", len, endpoint_new);
    ret = wifi_tcpip_write(endpoint_new, pdata, len, timeout_ms);
    if (ret <= 0) {
        dbg_error("wifi_tcpip_write fail");
        return -1;
    }

    RTOS_ERR err;
    OSTimeDly(100, OS_OPT_TIME_DLY, &err);
    wifi_close_ep(WIFI_EP_UDP, endpoint_new);
    
    /*dbg_trace("write %d bytes ep=%d", len, endpoint);  */
    return ret;
}

int wifi_tcpip_udp_close(uint8_t endpoint)
{
    if (0 != wifi_close_ep(WIFI_EP_UDP, endpoint)) {
        dbg_error("disconnect fail");
    }

    return 0;
}

int wifi_tcpip_multicast_join(uint32_t ipaddr)
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    if (!wifi_is_connected()) {
        dbg_error("Wifi not connected");
        return WLAN_ERR_HW;
    }
    
    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_oper_ctrl.type = WLAN_OPER_MULTICAST_JOIN;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_tcpip_multicast_join(ipaddr);

    ret = wifi_sync_wait_done(WIFI_DEFAULT_TIMEOUT);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}

int wifi_hello()
{
    int      ret = WLAN_ERR_NONE;
    RTOS_ERR err;

    OSMutexPend(&g_wifi_mutex, 0u, OS_OPT_PEND_BLOCKING, DEF_NULL, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);

    wifi_oper_ctrl.type = WLAN_OPER_HELLO;
    wifi_oper_ctrl.error = WLAN_ERR_NONE;
    wifi_oper_ctrl.done = false;
    wifi_cmd_system_hello();

    ret = wifi_sync_wait_done(2000);
    if (WLAN_ERR_TIMEOUT != ret) {
        ret = wifi_oper_ctrl.error;
    }

    OSMutexPost(&g_wifi_mutex, OS_OPT_POST_NONE, &err);
    APP_RTOS_ASSERT_DBG((RTOS_ERR_CODE_GET(err) == RTOS_ERR_NONE), 1);
    return ret;
}