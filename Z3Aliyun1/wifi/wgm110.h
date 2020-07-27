/*
 * wgm110.h
 *
 *  Created on: Mar 24, 2019
 *      Author: jilin1
 */

#ifndef WIFI_WGM110_H_
#define WIFI_WGM110_H_

typedef enum
{
    WLAN_ERR_NONE = 0,
    WLAN_ERR_TIMEOUT = -1,
    WLAN_ERR_OS = -2,
    WLAN_ERR_RES = -3,
    WLAN_ERR_HW = -4,
    WLAN_ERR_GEN = -5,
    WLAN_ERR_PARA = -6,
}WLAN_ERRCODE;

#define MAX_WIFI_SSID_LEN   32
#define MAX_WIFI_PASSWD_LEN 32

typedef struct
{
    uint32_t ipaddr;
    uint16_t port;
}UDP_Addr;

int wifi_init();
int wifi_connect(const char *pssid, const char *ppasswd, int timeout_ms);
int wifi_connect_withsaveddata(int timeout_ms);
int wifi_tcpip_tcp_connect_byhostname(const char *phostname, uint16_t port, uint8_t *pendpoint);
int wifi_tcpip_tls_connect_byhostname(const char *phostname, uint16_t port, uint8_t *pendpoint);
int wifi_tcpip_write(uint8_t endpoint, uint8_t *pdata, int len, int timeout_ms);
int wifi_tcpip_read(uint8_t endpoint, uint8_t *pdata, int len, int timeout_ms);
int wifi_tcpip_disconnect(uint8_t endpoint);
uint32_t wifi_get_local_ipaddr();
int wifi_get_local_mac(uint8_t mac[6]);
int wifi_tcpip_multicast_join(uint32_t ipaddr);
int wifi_udp_listen(uint16_t port, uint8_t *p_endpoint);
int wifi_udp_read(uint8_t endpoint, uint8_t *pdata, int len, int timeout_ms, UDP_Addr *psrc);
int wifi_udp_write(uint8_t endpoint, uint8_t *pdata, int len, int timeout_ms, UDP_Addr *premote);
int wifi_tcpip_udp_close(uint8_t endpoint);
int wifi_tls_set_user_cert(const char *pcert);
int wifi_tls_set_auth_mode(uint8_t mode);
int wifi_start_ap(char *ssid, char *passwd, uint8_t hide);
int wifi_stop_ap();
bool wifi_is_ssid_valid();
int wifi_erase_alldata();
bool wifi_is_connected();


#endif /* WIFI_WGM110_H_ */
