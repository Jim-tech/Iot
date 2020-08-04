#ifndef wifi_bglib_h
#define wifi_bglib_h
#define VERSION 

/*****************************************************************************
 *
 *
 *  Header only interface for BGLIB
 *
 *
 ****************************************************************************/

/*****************************************************************************
 *
 *  BGLIB usage:
 *      Define library, it should be defined globally to allow usage 
 *      from every function:
 *          BGLIB_DEFINE();
 *
 *      Declare and define output function, prototype is:
 *          void my_output(uint8 len1,uint8* data1,uint16 len2,uint8* data2);
 *
 *          function sends len1 amount of data from pointer data1 to device, and then sends
 *          len2 amount of data from pointer data2 to device
 *
 *      Initialize library,and provide output function:
 *          BGLIB_INITIALIZE(my_output);
 *
 *      Receiving messages:
 *          Allocate buffer of size BGLIB_MSG_MAXLEN for message, can be less but reader shall then drop too long packets from module
 *          Read BGLIB_MSG_HEADER_LEN amount of bytes from device to buffer
 *          Read BGLIB_MSG_LEN(buffer) amount of bytes from device to buffer after the header
 *          Get message ID by BGLIB_MSG_ID(buffer), use switch or if to compare to message_ids:
 *                  if(BGLIB_MSG_ID(buffer)==wifi_rsp_sme_wifi_on_id)
 *              Cast buffer to msg_packet structure by BGLIB_MSG(buffer) and use it to access message structure:
 *                  if(BGLIB_MSG(buffer)->rsp_sme_wifi_on.result != wifi_err_success)
 *
 *      Sending messages:
 *          Call macros which build message to temporary buffer and calls my_output to send message.
 *              wifi_cmd_sme_connect_bssid(&selected_bssid[0]);
 *          
 *
 ****************************************************************************/

/*****************************************************************************
 *
 *      Notes about SPI interface:
 *          Byte zero is sent by module when there is no valid data to send.
 *          Host shall drop bytes from module until first nonzero byte is received.
 *          Host shall send zero bytes to module when it is reading data from module
 *          and there is no valid data to send.
 *
 ****************************************************************************/

/*****************************************************************************
 *
 *      Support for compilers other than GCC and MSVC:
 *      
 *      To support specific compiler add compiler's structure packing directives to following macro:
 *          PACKSTRUCT( decl )
 *          
 *      BGLIB uses PACKSTRUCT macro to add packing information for structures:
 *      PACKSTRUCT(struct wifi_msg_dfu_reset_cmd_t
 *      {
 *          uint8	dfu;
 *      });
 *
 *
 ****************************************************************************/

/*lint -save --e{528,572,778,845,835,849}*/
#include "apitypes.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Compability */
#ifndef PACKSTRUCT
/*Default packed configuration*/
#ifdef __GNUC__
#ifdef _WIN32
#define PACKSTRUCT( decl ) decl __attribute__((__packed__,gcc_struct))
#else
#define PACKSTRUCT( decl ) decl __attribute__((__packed__))
#endif
#define ALIGNED __attribute__((aligned(0x4)))
#elif __IAR_SYSTEMS_ICC__

#define PACKSTRUCT( decl ) __packed decl

#define ALIGNED
#elif _MSC_VER  //msvc

#define PACKSTRUCT( decl ) __pragma( pack(push, 1) ) decl __pragma( pack(pop) )
#define ALIGNED
#else 
#define PACKSTRUCT(a) a PACKED 
#endif
#endif


struct wifi_header
{
    uint8  type_hilen;
    uint8  lolen;
    uint8  cls;
    uint8  command;
};

#define BGLIB_DEFINE() struct wifi_cmd_packet bglib_temp_msg;\
void (*bglib_output)(uint8 len1,uint8* data1,uint16 len2,uint8* data2);
#define BGLIB_INITIALIZE(X) bglib_output=X;
#define BGLIB_MSG_ID(BUF) ((*((uint32*)BUF))&0xffff00f8)
#define BGLIB_MSG(X) ((struct wifi_cmd_packet*)X)
#define BGLIB_MSG_HEADER_LEN (4)
#define BGLIB_MSG_LEN(BUF) ((((*((uint32*)BUF))&0x7)<<8)|(((*((uint32*)BUF))&0xff00)>>8))
#define BGLIB_MSG_MAXLEN 2052
extern void (*bglib_output)(uint8 len1,uint8* data1,uint16 len2,uint8* data2);

enum system_main_state
{
	system_idle       = 1,
	system_powered    = 2,
	system_connecting = 4,
	system_connected  = 8,
	system_wps        = 16,
	system_ap         = 32,
	system_p2p        = 64,
	system_p2p_go     = 128,
	system_main_state_max= 129
};

enum system_power_saving_state
{
	system_power_saving_state_0 = 0,
	system_power_saving_state_1 = 1,
	system_power_saving_state_2 = 2,
	system_power_saving_state_3 = 3,
	system_power_saving_state_4 = 4,
	system_power_saving_state_max= 5
};

enum sme_eap_type
{
	sme_eap_type_none     = 0x0,
	sme_eap_type_tls      = 0x1,
	sme_eap_type_peap     = 0x2,
	sme_eap_type_mschapv2 = 0x3,
	sme_eap_type_max      = 4
};

enum endpoint_type
{
	endpoint_type_free       = 0x0,
	endpoint_type_uart       = 0x1,
	endpoint_type_usb        = 0x2,
	endpoint_type_tcp        = 0x4,
	endpoint_type_tcp_server = 0x8,
	endpoint_type_udp        = 0x10,
	endpoint_type_udp_server = 0x20,
	endpoint_type_script     = 0x40,
	endpoint_type_wait_close = 0x80,
	endpoint_type_spi        = 0x100,
	endpoint_type_drop       = 0x400,
	endpoint_type_tls        = 0x800,
	endpoint_type_max        = 2049
};

enum hardware_gpio_port
{
	hardware_gpio_porta = 0x0,
	hardware_gpio_portb = 0x1,
	hardware_gpio_portc = 0x2,
	hardware_gpio_portd = 0x3,
	hardware_gpio_porte = 0x4,
	hardware_gpio_portf = 0x5,
	hardware_gpio_port_max= 6
};

enum hardware_gpio_mode
{
	hardware_gpio_mode_disabled          = 0x0,
	hardware_gpio_mode_input             = 0x1,
	hardware_gpio_mode_input_pull        = 0x2,
	hardware_gpio_mode_input_pull_filter = 0x3,
	hardware_gpio_mode_push_pull         = 0x4,
	hardware_gpio_mode_max               = 5
};

enum hardware_gpio_trigger
{
	hardware_gpio_trigger_disabled = 0x0,
	hardware_gpio_trigger_rising   = 0x1,
	hardware_gpio_trigger_falling  = 0x2,
	hardware_gpio_trigger_both     = 0x3,
	hardware_gpio_trigger_max      = 4
};

enum hardware_adc_input
{
	hardware_adc_input_ch0     = 0x0,
	hardware_adc_input_ch1     = 0x1,
	hardware_adc_input_ch2     = 0x2,
	hardware_adc_input_ch3     = 0x3,
	hardware_adc_input_ch4     = 0x4,
	hardware_adc_input_ch5     = 0x5,
	hardware_adc_input_ch6     = 0x6,
	hardware_adc_input_ch7     = 0x7,
	hardware_adc_input_vdddiv3 = 0x9,
	hardware_adc_input_max     = 10
};

enum hardware_uart_config
{
	hardware_uart_conf_parity_none      = 0,
	hardware_uart_conf_parity_odd       = 1,
	hardware_uart_conf_parity_even      = 2,
	hardware_uart_conf_flow_ctrl_none   = 0,
	hardware_uart_conf_flow_ctrl_rtscts = 1,
	hardware_uart_conf_flow_ctrl_rts    = 2,
	hardware_uart_config_max            = 3
};

#define FLASH_PS_KEY_MAC                   1
#define FLASH_PS_KEY_IPV4_SETTINGS         2
#define FLASH_PS_KEY_DNS0_SETTINGS         3
#define FLASH_PS_KEY_DNS1_SETTINGS         4
#define FLASH_PS_KEY_MODULE_SERVICE        5
#define FLASH_PS_KEY_AP_SSID               20
#define FLASH_PS_KEY_AP_CHANNEL            21
#define FLASH_PS_KEY_AP_PW                 22
#define FLASH_PS_KEY_AP_WIFI_N             23
#define FLASH_PS_KEY_AP_SECURITY           24
#define FLASH_PS_KEY_CLIENT_SSID           25
#define FLASH_PS_KEY_CLIENT_PW             26
#define FLASH_PS_KEY_DHCPS_ENABLE          30
#define FLASH_PS_KEY_DHCPS_SPACE           31
#define FLASH_PS_KEY_DHCPS_DISABLE_ROUTING 32
#define FLASH_PS_KEY_DHCPS_MASK            33
#define FLASH_PS_KEY_DHCPS_LEASETIME       34
#define FLASH_PS_KEY_DNSS_ENABLE           35
#define FLASH_PS_KEY_DNSS_URL              36
#define FLASH_PS_KEY_DNSS_ANY_URL          37
#define FLASH_PS_KEY_EOF                   65535

enum https_errors
{
	https_timeout = 1,
	https_unknown = 254,
	https_errors_max= 255
};

enum x509_store
{
	x509_store_flash = 0x0,
	x509_store_ram   = 0x1,
	x509_store_max   = 2
};

enum x509_type
{
	x509_type_ca   = 0x0,
	x509_type_user = 0x1,
	x509_type_max  = 2
};


enum wifi_parameter_types
{
    wifi_msg_parameter_uint8=2,
    wifi_msg_parameter_int8=3,
    wifi_msg_parameter_uint16=4,
    wifi_msg_parameter_int16=5,
    wifi_msg_parameter_uint32=6,
    wifi_msg_parameter_int32=7,
    wifi_msg_parameter_uint8array=8,
    wifi_msg_parameter_string=9,
    wifi_msg_parameter_hwaddr=10,
    wifi_msg_parameter_uint16array=11
};

enum wifi_msg_types
{
    wifi_msg_type_cmd=0x00,
    wifi_msg_type_rsp=0x00,
    wifi_msg_type_evt=0x80
};
enum wifi_dev_types
{
    wifi_dev_type_ble    =0x00,
    wifi_dev_type_wifi   =0x08,
    wifi_dev_type_iwrap  =0x10,
    wifi_dev_type_dumo   =0x20,
    wifi_dev_type_test   =0x20,
    wifi_dev_type_gecko  =0x20
};

#define	wifi_cmd_dfu_reset_id                          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x00000000)
#define	wifi_cmd_dfu_flash_set_address_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x01000000)
#define	wifi_cmd_dfu_flash_upload_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x02000000)
#define	wifi_cmd_dfu_flash_upload_finish_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x03000000)
#define	wifi_cmd_system_sync_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x00010000)
#define	wifi_cmd_system_reset_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x01010000)
#define	wifi_cmd_system_hello_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x02010000)
#define	wifi_cmd_system_set_max_power_saving_state_id  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x03010000)
#define	wifi_cmd_config_get_mac_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x00020000)
#define	wifi_cmd_config_set_mac_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x01020000)
#define	wifi_cmd_sme_wifi_on_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x00030000)
#define	wifi_cmd_sme_wifi_off_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x01030000)
#define	wifi_cmd_sme_power_on_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x02030000)
#define	wifi_cmd_sme_start_scan_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x03030000)
#define	wifi_cmd_sme_stop_scan_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x04030000)
#define	wifi_cmd_sme_set_password_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x05030000)
#define	wifi_cmd_sme_connect_bssid_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x06030000)
#define	wifi_cmd_sme_connect_ssid_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x07030000)
#define	wifi_cmd_sme_disconnect_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x08030000)
#define	wifi_cmd_sme_set_scan_channels_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x09030000)
#define	wifi_cmd_sme_set_operating_mode_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0A030000)
#define	wifi_cmd_sme_start_ap_mode_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0B030000)
#define	wifi_cmd_sme_stop_ap_mode_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0C030000)
#define	wifi_cmd_sme_scan_results_sort_rssi_id         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0D030000)
#define	wifi_cmd_sme_ap_client_disconnect_id           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0E030000)
#define	wifi_cmd_sme_set_ap_password_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0F030000)
#define	wifi_cmd_sme_set_ap_max_clients_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x10030000)
#define	wifi_cmd_sme_start_wps_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x11030000)
#define	wifi_cmd_sme_stop_wps_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x12030000)
#define	wifi_cmd_sme_get_signal_quality_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x13030000)
#define	wifi_cmd_sme_start_ssid_scan_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x14030000)
#define	wifi_cmd_sme_set_ap_hidden_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x15030000)
#define	wifi_cmd_sme_set_11n_mode_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x16030000)
#define	wifi_cmd_sme_set_eap_configuration_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x17030000)
#define	wifi_cmd_sme_set_eap_type_username_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x18030000)
#define	wifi_cmd_sme_set_eap_type_password_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x19030000)
#define	wifi_cmd_sme_set_eap_type_ca_certificate_id    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x1A030000)
#define	wifi_cmd_sme_set_eap_type_server_common_name_id	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x1B030000)
#define	wifi_cmd_sme_set_eap_type_user_certificate_id  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x1C030000)
#define	wifi_cmd_sme_start_p2p_group_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x1D030000)
#define	wifi_cmd_sme_stop_p2p_group_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x1E030000)
#define	wifi_cmd_sme_p2p_accept_client_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x1F030000)
#define	wifi_cmd_sme_ap_client_config_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x20030000)
#define	wifi_cmd_sme_set_ap_client_isolation_id        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x21030000)
#define	wifi_cmd_tcpip_start_tcp_server_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x00040000)
#define	wifi_cmd_tcpip_tcp_connect_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x01040000)
#define	wifi_cmd_tcpip_start_udp_server_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x02040000)
#define	wifi_cmd_tcpip_udp_connect_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x03040000)
#define	wifi_cmd_tcpip_configure_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x04040000)
#define	wifi_cmd_tcpip_dns_configure_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x05040000)
#define	wifi_cmd_tcpip_dns_gethostbyname_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x06040000)
#define	wifi_cmd_tcpip_udp_bind_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x07040000)
#define	wifi_cmd_tcpip_dhcp_set_hostname_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x08040000)
#define	wifi_cmd_tcpip_tls_connect_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x09040000)
#define	wifi_cmd_tcpip_tls_set_authmode_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0A040000)
#define	wifi_cmd_tcpip_dhcp_enable_routing_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0B040000)
#define	wifi_cmd_tcpip_mdns_set_hostname_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0C040000)
#define	wifi_cmd_tcpip_mdns_start_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0D040000)
#define	wifi_cmd_tcpip_mdns_stop_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0E040000)
#define	wifi_cmd_tcpip_dnssd_add_service_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0F040000)
#define	wifi_cmd_tcpip_dnssd_add_service_instance_id   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x10040000)
#define	wifi_cmd_tcpip_dnssd_add_service_attribute_id  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x11040000)
#define	wifi_cmd_tcpip_dnssd_remove_service_id         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x12040000)
#define	wifi_cmd_tcpip_dnssd_start_service_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x13040000)
#define	wifi_cmd_tcpip_dnssd_stop_service_id           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x14040000)
#define	wifi_cmd_tcpip_multicast_join_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x15040000)
#define	wifi_cmd_tcpip_multicast_leave_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x16040000)
#define	wifi_cmd_tcpip_tls_set_user_certificate_id     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x17040000)
#define	wifi_cmd_tcpip_dhcp_configure_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x18040000)
#define	wifi_cmd_tcpip_mdns_gethostbyname_id           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x19040000)
#define	wifi_cmd_tcpip_dhcp_clients_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x1A040000)
#define	wifi_cmd_endpoint_send_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x00050000)
#define	wifi_cmd_endpoint_set_streaming_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x01050000)
#define	wifi_cmd_endpoint_set_active_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x02050000)
#define	wifi_cmd_endpoint_set_streaming_destination_id 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x03050000)
#define	wifi_cmd_endpoint_close_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x04050000)
#define	wifi_cmd_endpoint_set_transmit_size_id         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x05050000)
#define	wifi_cmd_endpoint_disable_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x06050000)
#define	wifi_cmd_hardware_set_soft_timer_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x00060000)
#define	wifi_cmd_hardware_configure_gpio_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x01060000)
#define	wifi_cmd_hardware_configure_gpio_interrupt_id  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x02060000)
#define	wifi_cmd_hardware_write_gpio_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x03060000)
#define	wifi_cmd_hardware_read_gpio_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x04060000)
#define	wifi_cmd_hardware_timer_init_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x05060000)
#define	wifi_cmd_hardware_timer_initcc_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x06060000)
#define	wifi_cmd_hardware_adc_read_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x07060000)
#define	wifi_cmd_hardware_rtc_init_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x08060000)
#define	wifi_cmd_hardware_rtc_set_time_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x09060000)
#define	wifi_cmd_hardware_rtc_get_time_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0A060000)
#define	wifi_cmd_hardware_rtc_set_alarm_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0B060000)
#define	wifi_cmd_hardware_uart_conf_set_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0C060000)
#define	wifi_cmd_hardware_uart_conf_get_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0D060000)
#define	wifi_cmd_hardware_spi_transfer_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x0E060000)
#define	wifi_cmd_flash_ps_defrag_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x00070000)
#define	wifi_cmd_flash_ps_dump_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x01070000)
#define	wifi_cmd_flash_ps_erase_all_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x02070000)
#define	wifi_cmd_flash_ps_save_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x03070000)
#define	wifi_cmd_flash_ps_load_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x04070000)
#define	wifi_cmd_flash_ps_erase_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x05070000)
#define	wifi_cmd_i2c_start_read_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x00080000)
#define	wifi_cmd_i2c_start_write_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x01080000)
#define	wifi_cmd_i2c_stop_id                           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x02080000)
#define	wifi_cmd_https_enable_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x00090000)
#define	wifi_cmd_https_add_path_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x01090000)
#define	wifi_cmd_https_api_response_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x02090000)
#define	wifi_cmd_https_api_response_finish_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x03090000)
#define	wifi_cmd_ethernet_set_dataroute_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x000A0000)
#define	wifi_cmd_ethernet_close_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x010A0000)
#define	wifi_cmd_ethernet_connected_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x020A0000)
#define	wifi_cmd_x509_reset_store_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x000B0000)
#define	wifi_cmd_x509_add_certificate_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x010B0000)
#define	wifi_cmd_x509_add_certificate_data_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x020B0000)
#define	wifi_cmd_x509_add_certificate_finish_id        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x030B0000)
#define	wifi_cmd_x509_add_private_key_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x040B0000)
#define	wifi_cmd_x509_add_private_key_data_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x050B0000)
#define	wifi_cmd_x509_add_private_key_finish_id        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x060B0000)
#define	wifi_cmd_x509_delete_certificate_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x070B0000)
#define	wifi_cmd_x509_list_certificates_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x080B0000)
#define	wifi_cmd_sdhc_fopen_id                         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x000C0000)
#define	wifi_cmd_sdhc_fclose_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x010C0000)
#define	wifi_cmd_sdhc_fdir_id                          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x020C0000)
#define	wifi_cmd_sdhc_fread_id                         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x030C0000)
#define	wifi_cmd_sdhc_fwrite_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x040C0000)
#define	wifi_cmd_sdhc_fdelete_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x050C0000)
#define	wifi_cmd_sdhc_fmkdir_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x060C0000)
#define	wifi_cmd_sdhc_fchdir_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x070C0000)
#define	wifi_cmd_sdhc_frename_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x080C0000)
#define	wifi_cmd_sdhc_fchmode_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x090C0000)
#define	wifi_cmd_util_atoi_id                          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x000D0000)
#define	wifi_cmd_util_itoa_id                          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_cmd|0x010D0000)
#define	wifi_rsp_dfu_reset_id                          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x00000000)
#define	wifi_rsp_dfu_flash_set_address_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x01000000)
#define	wifi_rsp_dfu_flash_upload_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x02000000)
#define	wifi_rsp_dfu_flash_upload_finish_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x03000000)
#define	wifi_rsp_system_sync_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x00010000)
#define	wifi_rsp_system_reset_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x01010000)
#define	wifi_rsp_system_hello_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x02010000)
#define	wifi_rsp_system_set_max_power_saving_state_id  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x03010000)
#define	wifi_rsp_config_get_mac_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x00020000)
#define	wifi_rsp_config_set_mac_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x01020000)
#define	wifi_rsp_sme_wifi_on_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x00030000)
#define	wifi_rsp_sme_wifi_off_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x01030000)
#define	wifi_rsp_sme_power_on_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x02030000)
#define	wifi_rsp_sme_start_scan_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x03030000)
#define	wifi_rsp_sme_stop_scan_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x04030000)
#define	wifi_rsp_sme_set_password_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x05030000)
#define	wifi_rsp_sme_connect_bssid_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x06030000)
#define	wifi_rsp_sme_connect_ssid_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x07030000)
#define	wifi_rsp_sme_disconnect_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x08030000)
#define	wifi_rsp_sme_set_scan_channels_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x09030000)
#define	wifi_rsp_sme_set_operating_mode_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0A030000)
#define	wifi_rsp_sme_start_ap_mode_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0B030000)
#define	wifi_rsp_sme_stop_ap_mode_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0C030000)
#define	wifi_rsp_sme_scan_results_sort_rssi_id         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0D030000)
#define	wifi_rsp_sme_ap_client_disconnect_id           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0E030000)
#define	wifi_rsp_sme_set_ap_password_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0F030000)
#define	wifi_rsp_sme_set_ap_max_clients_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x10030000)
#define	wifi_rsp_sme_start_wps_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x11030000)
#define	wifi_rsp_sme_stop_wps_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x12030000)
#define	wifi_rsp_sme_get_signal_quality_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x13030000)
#define	wifi_rsp_sme_start_ssid_scan_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x14030000)
#define	wifi_rsp_sme_set_ap_hidden_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x15030000)
#define	wifi_rsp_sme_set_11n_mode_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x16030000)
#define	wifi_rsp_sme_set_eap_configuration_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x17030000)
#define	wifi_rsp_sme_set_eap_type_username_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x18030000)
#define	wifi_rsp_sme_set_eap_type_password_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x19030000)
#define	wifi_rsp_sme_set_eap_type_ca_certificate_id    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x1A030000)
#define	wifi_rsp_sme_set_eap_type_server_common_name_id	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x1B030000)
#define	wifi_rsp_sme_set_eap_type_user_certificate_id  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x1C030000)
#define	wifi_rsp_sme_start_p2p_group_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x1D030000)
#define	wifi_rsp_sme_stop_p2p_group_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x1E030000)
#define	wifi_rsp_sme_p2p_accept_client_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x1F030000)
#define	wifi_rsp_sme_ap_client_config_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x20030000)
#define	wifi_rsp_sme_set_ap_client_isolation_id        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x21030000)
#define	wifi_rsp_tcpip_start_tcp_server_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x00040000)
#define	wifi_rsp_tcpip_tcp_connect_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x01040000)
#define	wifi_rsp_tcpip_start_udp_server_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x02040000)
#define	wifi_rsp_tcpip_udp_connect_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x03040000)
#define	wifi_rsp_tcpip_configure_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x04040000)
#define	wifi_rsp_tcpip_dns_configure_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x05040000)
#define	wifi_rsp_tcpip_dns_gethostbyname_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x06040000)
#define	wifi_rsp_tcpip_udp_bind_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x07040000)
#define	wifi_rsp_tcpip_dhcp_set_hostname_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x08040000)
#define	wifi_rsp_tcpip_tls_connect_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x09040000)
#define	wifi_rsp_tcpip_tls_set_authmode_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0A040000)
#define	wifi_rsp_tcpip_dhcp_enable_routing_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0B040000)
#define	wifi_rsp_tcpip_mdns_set_hostname_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0C040000)
#define	wifi_rsp_tcpip_mdns_start_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0D040000)
#define	wifi_rsp_tcpip_mdns_stop_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0E040000)
#define	wifi_rsp_tcpip_dnssd_add_service_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0F040000)
#define	wifi_rsp_tcpip_dnssd_add_service_instance_id   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x10040000)
#define	wifi_rsp_tcpip_dnssd_add_service_attribute_id  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x11040000)
#define	wifi_rsp_tcpip_dnssd_remove_service_id         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x12040000)
#define	wifi_rsp_tcpip_dnssd_start_service_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x13040000)
#define	wifi_rsp_tcpip_dnssd_stop_service_id           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x14040000)
#define	wifi_rsp_tcpip_multicast_join_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x15040000)
#define	wifi_rsp_tcpip_multicast_leave_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x16040000)
#define	wifi_rsp_tcpip_tls_set_user_certificate_id     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x17040000)
#define	wifi_rsp_tcpip_dhcp_configure_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x18040000)
#define	wifi_rsp_tcpip_mdns_gethostbyname_id           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x19040000)
#define	wifi_rsp_tcpip_dhcp_clients_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x1A040000)
#define	wifi_rsp_endpoint_send_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x00050000)
#define	wifi_rsp_endpoint_set_streaming_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x01050000)
#define	wifi_rsp_endpoint_set_active_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x02050000)
#define	wifi_rsp_endpoint_set_streaming_destination_id 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x03050000)
#define	wifi_rsp_endpoint_close_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x04050000)
#define	wifi_rsp_endpoint_set_transmit_size_id         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x05050000)
#define	wifi_rsp_endpoint_disable_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x06050000)
#define	wifi_rsp_hardware_set_soft_timer_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x00060000)
#define	wifi_rsp_hardware_configure_gpio_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x01060000)
#define	wifi_rsp_hardware_configure_gpio_interrupt_id  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x02060000)
#define	wifi_rsp_hardware_write_gpio_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x03060000)
#define	wifi_rsp_hardware_read_gpio_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x04060000)
#define	wifi_rsp_hardware_timer_init_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x05060000)
#define	wifi_rsp_hardware_timer_initcc_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x06060000)
#define	wifi_rsp_hardware_adc_read_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x07060000)
#define	wifi_rsp_hardware_rtc_init_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x08060000)
#define	wifi_rsp_hardware_rtc_set_time_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x09060000)
#define	wifi_rsp_hardware_rtc_get_time_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0A060000)
#define	wifi_rsp_hardware_rtc_set_alarm_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0B060000)
#define	wifi_rsp_hardware_uart_conf_set_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0C060000)
#define	wifi_rsp_hardware_uart_conf_get_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0D060000)
#define	wifi_rsp_hardware_spi_transfer_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x0E060000)
#define	wifi_rsp_flash_ps_defrag_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x00070000)
#define	wifi_rsp_flash_ps_dump_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x01070000)
#define	wifi_rsp_flash_ps_erase_all_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x02070000)
#define	wifi_rsp_flash_ps_save_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x03070000)
#define	wifi_rsp_flash_ps_load_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x04070000)
#define	wifi_rsp_flash_ps_erase_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x05070000)
#define	wifi_rsp_i2c_start_read_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x00080000)
#define	wifi_rsp_i2c_start_write_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x01080000)
#define	wifi_rsp_i2c_stop_id                           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x02080000)
#define	wifi_rsp_https_enable_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x00090000)
#define	wifi_rsp_https_add_path_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x01090000)
#define	wifi_rsp_https_api_response_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x02090000)
#define	wifi_rsp_https_api_response_finish_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x03090000)
#define	wifi_rsp_ethernet_set_dataroute_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x000A0000)
#define	wifi_rsp_ethernet_close_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x010A0000)
#define	wifi_rsp_ethernet_connected_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x020A0000)
#define	wifi_rsp_x509_reset_store_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x000B0000)
#define	wifi_rsp_x509_add_certificate_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x010B0000)
#define	wifi_rsp_x509_add_certificate_data_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x020B0000)
#define	wifi_rsp_x509_add_certificate_finish_id        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x030B0000)
#define	wifi_rsp_x509_add_private_key_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x040B0000)
#define	wifi_rsp_x509_add_private_key_data_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x050B0000)
#define	wifi_rsp_x509_add_private_key_finish_id        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x060B0000)
#define	wifi_rsp_x509_delete_certificate_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x070B0000)
#define	wifi_rsp_x509_list_certificates_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x080B0000)
#define	wifi_rsp_sdhc_fopen_id                         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x000C0000)
#define	wifi_rsp_sdhc_fclose_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x010C0000)
#define	wifi_rsp_sdhc_fdir_id                          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x020C0000)
#define	wifi_rsp_sdhc_fread_id                         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x030C0000)
#define	wifi_rsp_sdhc_fwrite_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x040C0000)
#define	wifi_rsp_sdhc_fdelete_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x050C0000)
#define	wifi_rsp_sdhc_fmkdir_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x060C0000)
#define	wifi_rsp_sdhc_fchdir_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x070C0000)
#define	wifi_rsp_sdhc_frename_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x080C0000)
#define	wifi_rsp_sdhc_fchmode_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x090C0000)
#define	wifi_rsp_util_atoi_id                          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x000D0000)
#define	wifi_rsp_util_itoa_id                          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_rsp|0x010D0000)
#define	wifi_evt_dfu_boot_id                           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x00000000)
#define	wifi_evt_system_boot_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x00010000)
#define	wifi_evt_system_state_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x01010000)
#define	wifi_evt_system_sw_exception_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x02010000)
#define	wifi_evt_system_power_saving_state_id          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x03010000)
#define	wifi_evt_config_mac_address_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x00020000)
#define	wifi_evt_sme_wifi_is_on_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x00030000)
#define	wifi_evt_sme_wifi_is_off_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x01030000)
#define	wifi_evt_sme_scan_result_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x02030000)
#define	wifi_evt_sme_scan_result_drop_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x03030000)
#define	wifi_evt_sme_scanned_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x04030000)
#define	wifi_evt_sme_connected_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x05030000)
#define	wifi_evt_sme_disconnected_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x06030000)
#define	wifi_evt_sme_interface_status_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x07030000)
#define	wifi_evt_sme_connect_failed_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x08030000)
#define	wifi_evt_sme_connect_retry_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x09030000)
#define	wifi_evt_sme_ap_mode_started_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x0A030000)
#define	wifi_evt_sme_ap_mode_stopped_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x0B030000)
#define	wifi_evt_sme_ap_mode_failed_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x0C030000)
#define	wifi_evt_sme_ap_client_joined_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x0D030000)
#define	wifi_evt_sme_ap_client_left_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x0E030000)
#define	wifi_evt_sme_scan_sort_result_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x0F030000)
#define	wifi_evt_sme_scan_sort_finished_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x10030000)
#define	wifi_evt_sme_wps_stopped_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x11030000)
#define	wifi_evt_sme_wps_completed_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x12030000)
#define	wifi_evt_sme_wps_failed_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x13030000)
#define	wifi_evt_sme_wps_credential_ssid_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x14030000)
#define	wifi_evt_sme_wps_credential_password_id        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x15030000)
#define	wifi_evt_sme_signal_quality_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x16030000)
#define	wifi_evt_sme_p2p_group_started_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x17030000)
#define	wifi_evt_sme_p2p_group_stopped_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x18030000)
#define	wifi_evt_sme_p2p_group_failed_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x19030000)
#define	wifi_evt_sme_p2p_client_wants_to_join_id       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x1A030000)
#define	wifi_evt_tcpip_configuration_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x00040000)
#define	wifi_evt_tcpip_dns_configuration_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x01040000)
#define	wifi_evt_tcpip_endpoint_status_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x02040000)
#define	wifi_evt_tcpip_dns_gethostbyname_result_id     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x03040000)
#define	wifi_evt_tcpip_udp_data_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x04040000)
#define	wifi_evt_tcpip_tls_verify_result_id            	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x05040000)
#define	wifi_evt_tcpip_mdns_started_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x06040000)
#define	wifi_evt_tcpip_mdns_failed_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x07040000)
#define	wifi_evt_tcpip_mdns_stopped_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x08040000)
#define	wifi_evt_tcpip_dnssd_service_started_id        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x09040000)
#define	wifi_evt_tcpip_dnssd_service_failed_id         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x0A040000)
#define	wifi_evt_tcpip_dnssd_service_stopped_id        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x0B040000)
#define	wifi_evt_tcpip_dhcp_configuration_id           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x0C040000)
#define	wifi_evt_tcpip_mdns_gethostbyname_result_id    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x0D040000)
#define	wifi_evt_tcpip_dhcp_client_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x0E040000)
#define	wifi_evt_endpoint_syntax_error_id              	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x00050000)
#define	wifi_evt_endpoint_data_id                      	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x01050000)
#define	wifi_evt_endpoint_status_id                    	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x02050000)
#define	wifi_evt_endpoint_closing_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x03050000)
#define	wifi_evt_endpoint_error_id                     	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x04050000)
#define	wifi_evt_hardware_soft_timer_id                	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x00060000)
#define	wifi_evt_hardware_interrupt_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x01060000)
#define	wifi_evt_hardware_rtc_alarm_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x02060000)
#define	wifi_evt_hardware_uart_conf_id                 	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x03060000)
#define	wifi_evt_flash_ps_key_id                       	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x00070000)
#define	wifi_evt_flash_ps_key_changed_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x01070000)
#define	wifi_evt_flash_low_voltage_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x02070000)
#define	wifi_evt_https_api_request_id                  	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x00090000)
#define	wifi_evt_https_api_request_header_id           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x01090000)
#define	wifi_evt_https_api_request_data_id             	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x02090000)
#define	wifi_evt_https_api_request_finished_id         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x03090000)
#define	wifi_evt_https_error_id                        	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x04090000)
#define	wifi_evt_ethernet_link_status_id               	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x000A0000)
#define	wifi_evt_x509_certificate_id                   	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x000B0000)
#define	wifi_evt_x509_certificate_subject_id           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x010B0000)
#define	wifi_evt_x509_certificates_listed_id           	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x020B0000)
#define	wifi_evt_sdhc_ready_id                         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x000C0000)
#define	wifi_evt_sdhc_fdata_id                         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x010C0000)
#define	wifi_evt_sdhc_ffile_id                         	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x020C0000)
#define	wifi_evt_sdhc_fpwd_id                          	(((uint32)wifi_dev_type_wifi)|wifi_msg_type_evt|0x030C0000)
#ifndef BG_ERRORCODES
#define BG_ERRORCODES
enum wifi_error_spaces
{
	wifi_errspc_hardware=768,
	wifi_errspc_bg=256,
	wifi_errspc_tcpip=512,
};
typedef enum wifi_error
{
	wifi_err_hardware_ps_store_full            =wifi_errspc_hardware+1,//Flash reserved for Persistent Store is full
	wifi_err_hardware_ps_key_not_found         =wifi_errspc_hardware+2,//Persistent Store key not found
	wifi_err_hardware_i2c_write_already_started=wifi_errspc_hardware+3,//Tried to start an I2C write transaction, but it is already in progress
	wifi_err_hardware_i2c_ack_missing          =wifi_errspc_hardware+4,//Acknowledge for an I2C operation was not received due to bus fail or operation timeout
	wifi_err_hardware_flash_failed             =wifi_errspc_hardware+8,//Writing to flash failed
	wifi_err_hardware_sdhc_not_opened          =wifi_errspc_hardware+5,//Tried to access an unopened file
	wifi_err_hardware_sdhc_not_found           =wifi_errspc_hardware+6,//File not in SD card
	wifi_err_hardware_sdhc_disk_error          =wifi_errspc_hardware+7,//Disk error or disk full
	wifi_err_success                           =0,                     //No error
	wifi_err_invalid_param                     =wifi_errspc_bg+128,    //Command contained an invalid parameter
	wifi_err_wrong_state                       =wifi_errspc_bg+129,    //Device is in wrong state to accept command
	wifi_err_out_of_memory                     =wifi_errspc_bg+130,    //Device has run out of memory
	wifi_err_not_implemented                   =wifi_errspc_bg+131,    //Feature is not implemented
	wifi_err_invalid_command                   =wifi_errspc_bg+132,    //Command was not recognized
	wifi_err_timeout                           =wifi_errspc_bg+133,    //Command or procedure failed due to timeout
	wifi_err_unspecified                       =wifi_errspc_bg+134,    //Unspecified error
	wifi_err_hardware                          =wifi_errspc_bg+135,    //Hardware failure
	wifi_err_buffers_full                      =wifi_errspc_bg+136,    //Command not accepted, because internal buffers are full
	wifi_err_disconnected                      =wifi_errspc_bg+137,    //Command or procedure failed due to disconnection
	wifi_err_too_many_requests                 =wifi_errspc_bg+138,    //Too many simultaneous requests
	wifi_err_ap_not_in_scanlist                =wifi_errspc_bg+139,    //Access Point not found from scanlist
	wifi_err_invalid_password                  =wifi_errspc_bg+140,    //Password is invalid or missing
	wifi_err_authentication_failure            =wifi_errspc_bg+141,    //WPA/WPA2 authentication has failed
	wifi_err_overflow                          =wifi_errspc_bg+142,    //Overflow detected
	wifi_err_multiple_pbc_sessions             =wifi_errspc_bg+143,    //Multiple PBC sessions detected
	wifi_err_eth_not_connected                 =wifi_errspc_bg+144,    //Ethernet cable not connected
	wifi_err_eth_route_not_set                 =wifi_errspc_bg+145,    //Ethernet route not set
	wifi_err_wrong_operating_mode              =wifi_errspc_bg+146,    //Wrong operating mode for this command
	wifi_err_not_found                         =wifi_errspc_bg+147,    //Requested resource not found
	wifi_err_already_exists                    =wifi_errspc_bg+148,    //Requested resource already exists
	wifi_err_invalid_configuration             =wifi_errspc_bg+149,    //Current configuration is invalid
	wifi_err_ap_lost                           =wifi_errspc_bg+150,    //Connection to Access Point lost
	wifi_err_tcpip_success                     =wifi_errspc_tcpip+0,   //No error
	wifi_err_tcpip_out_of_memory               =wifi_errspc_tcpip+1,   //Out of memory
	wifi_err_tcpip_buffer                      =wifi_errspc_tcpip+2,   //Buffer handling failed
	wifi_err_tcpip_timeout                     =wifi_errspc_tcpip+3,   //Timeout
	wifi_err_tcpip_routing                     =wifi_errspc_tcpip+4,   //Could not find route
	wifi_err_tcpip_in_progress                 =wifi_errspc_tcpip+5,   //Operation in progress
	wifi_err_tcpip_illegal_value               =wifi_errspc_tcpip+6,   //Illegal value
	wifi_err_tcpip_would_block                 =wifi_errspc_tcpip+7,   //Operation would block
	wifi_err_tcpip_in_use                      =wifi_errspc_tcpip+8,   //Address in use
	wifi_err_tcpip_already_connected           =wifi_errspc_tcpip+9,   //Already connected
	wifi_err_tcpip_abort                       =wifi_errspc_tcpip+10,  //Connection aborted
	wifi_err_tcpip_reset                       =wifi_errspc_tcpip+11,  //Connection reset
	wifi_err_tcpip_closed                      =wifi_errspc_tcpip+12,  //Connection closed
	wifi_err_tcpip_not_connected               =wifi_errspc_tcpip+13,  //Not connected
	wifi_err_tcpip_illegal_argument            =wifi_errspc_tcpip+14,  //Illegal argument
	wifi_err_tcpip_interface                   =wifi_errspc_tcpip+15,  //Interface error
	wifi_err_tcpip_service_not_running         =wifi_errspc_tcpip+16,  //Service not running
	wifi_err_tcpip_service_running             =wifi_errspc_tcpip+17,  //Service already running
	wifi_err_tcpip_hostname_not_set            =wifi_errspc_tcpip+18,  //Hostname not set
	wifi_err_tcpip_hostname_conflict           =wifi_errspc_tcpip+19,  //Hostname conflict detected
	wifi_err_tcpip_unknown_host                =wifi_errspc_tcpip+128, //Unknown host
	wifi_err_last
}errorcode_t;
#endif
PACKSTRUCT(struct wifi_msg_dfu_reset_cmd_t
{
	uint8	dfu;
});

PACKSTRUCT(struct wifi_msg_dfu_flash_set_address_cmd_t
{
	uint32	address;
});

PACKSTRUCT(struct wifi_msg_dfu_flash_set_address_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_dfu_flash_upload_cmd_t
{
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_dfu_flash_upload_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_dfu_flash_upload_finish_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_dfu_boot_evt_t
{
	uint32	version;
});

PACKSTRUCT(struct wifi_msg_system_reset_cmd_t
{
	uint8	dfu;
});

PACKSTRUCT(struct wifi_msg_system_set_max_power_saving_state_cmd_t
{
	uint8	state;
});

PACKSTRUCT(struct wifi_msg_system_set_max_power_saving_state_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_system_boot_evt_t
{
	uint16	hw;
	uint16	bootloader_version;
	uint16	major;
	uint16	minor;
	uint16	build;
	uint8array	revision;
});

PACKSTRUCT(struct wifi_msg_system_state_evt_t
{
	uint16	state;
});

PACKSTRUCT(struct wifi_msg_system_sw_exception_evt_t
{
	uint32	address;
	uint8	type;
});

PACKSTRUCT(struct wifi_msg_system_power_saving_state_evt_t
{
	uint8	state;
});

PACKSTRUCT(struct wifi_msg_config_get_mac_cmd_t
{
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_config_get_mac_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_config_set_mac_cmd_t
{
	uint8	hw_interface;
	hw_addr	mac;
});

PACKSTRUCT(struct wifi_msg_config_set_mac_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_config_mac_address_evt_t
{
	uint8	hw_interface;
	hw_addr	mac;
});

PACKSTRUCT(struct wifi_msg_sme_wifi_on_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_wifi_off_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_power_on_cmd_t
{
	uint8	enable;
});

PACKSTRUCT(struct wifi_msg_sme_power_on_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_start_scan_cmd_t
{
	uint8	hw_interface;
	uint8array	chList;
});

PACKSTRUCT(struct wifi_msg_sme_start_scan_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_stop_scan_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_set_password_cmd_t
{
	uint8array	password;
});

PACKSTRUCT(struct wifi_msg_sme_set_password_rsp_t
{
	uint8	status;
});

PACKSTRUCT(struct wifi_msg_sme_connect_bssid_cmd_t
{
	hw_addr	bssid;
});

PACKSTRUCT(struct wifi_msg_sme_connect_bssid_rsp_t
{
	uint16	result;
	uint8	hw_interface;
	hw_addr	bssid;
});

PACKSTRUCT(struct wifi_msg_sme_connect_ssid_cmd_t
{
	uint8array	ssid;
});

PACKSTRUCT(struct wifi_msg_sme_connect_ssid_rsp_t
{
	uint16	result;
	uint8	hw_interface;
	hw_addr	bssid;
});

PACKSTRUCT(struct wifi_msg_sme_disconnect_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_set_scan_channels_cmd_t
{
	uint8	hw_interface;
	uint8array	chList;
});

PACKSTRUCT(struct wifi_msg_sme_set_scan_channels_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_set_operating_mode_cmd_t
{
	uint8	mode;
});

PACKSTRUCT(struct wifi_msg_sme_set_operating_mode_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_start_ap_mode_cmd_t
{
	uint8	channel;
	uint8	security;
	uint8array	ssid;
});

PACKSTRUCT(struct wifi_msg_sme_start_ap_mode_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_stop_ap_mode_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_scan_results_sort_rssi_cmd_t
{
	uint8	amount;
});

PACKSTRUCT(struct wifi_msg_sme_scan_results_sort_rssi_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_ap_client_disconnect_cmd_t
{
	hw_addr	mac_address;
});

PACKSTRUCT(struct wifi_msg_sme_ap_client_disconnect_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_set_ap_password_cmd_t
{
	uint8array	password;
});

PACKSTRUCT(struct wifi_msg_sme_set_ap_password_rsp_t
{
	uint8	status;
});

PACKSTRUCT(struct wifi_msg_sme_set_ap_max_clients_cmd_t
{
	uint8	max_clients;
});

PACKSTRUCT(struct wifi_msg_sme_set_ap_max_clients_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_start_wps_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_stop_wps_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_get_signal_quality_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_start_ssid_scan_cmd_t
{
	uint8array	ssid;
});

PACKSTRUCT(struct wifi_msg_sme_start_ssid_scan_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_set_ap_hidden_cmd_t
{
	uint8	hidden;
});

PACKSTRUCT(struct wifi_msg_sme_set_ap_hidden_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_set_11n_mode_cmd_t
{
	uint8	mode;
});

PACKSTRUCT(struct wifi_msg_sme_set_11n_mode_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_configuration_cmd_t
{
	uint8	outer_type;
	uint8	inner_type;
	uint8array	identity;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_configuration_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_type_username_cmd_t
{
	uint8	type;
	uint8array	username;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_type_username_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_type_password_cmd_t
{
	uint8	type;
	uint8array	password;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_type_password_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_type_ca_certificate_cmd_t
{
	uint8	type;
	uint8array	fingerprint;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_type_ca_certificate_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_type_server_common_name_cmd_t
{
	uint8	type;
	uint8array	common_name;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_type_server_common_name_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_type_user_certificate_cmd_t
{
	uint8	type;
	uint8array	fingerprint;
});

PACKSTRUCT(struct wifi_msg_sme_set_eap_type_user_certificate_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_start_p2p_group_cmd_t
{
	uint8	channel;
	uint8array	ssid;
});

PACKSTRUCT(struct wifi_msg_sme_start_p2p_group_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_stop_p2p_group_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_p2p_accept_client_cmd_t
{
	hw_addr	mac_address;
});

PACKSTRUCT(struct wifi_msg_sme_p2p_accept_client_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_ap_client_config_cmd_t
{
	uint8	max_clients;
	uint16	cleanup_period;
	uint16	keepalive_interval;
});

PACKSTRUCT(struct wifi_msg_sme_ap_client_config_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_set_ap_client_isolation_cmd_t
{
	uint8	isolation;
});

PACKSTRUCT(struct wifi_msg_sme_set_ap_client_isolation_rsp_t
{
	uint16	result;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_wifi_is_on_evt_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_wifi_is_off_evt_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sme_scan_result_evt_t
{
	hw_addr	bssid;
	int8	channel;
	int16	rssi;
	int8	snr;
	uint8	secure;
	uint8array	ssid;
});

PACKSTRUCT(struct wifi_msg_sme_scan_result_drop_evt_t
{
	hw_addr	bssid;
});

PACKSTRUCT(struct wifi_msg_sme_scanned_evt_t
{
	int8	status;
});

PACKSTRUCT(struct wifi_msg_sme_connected_evt_t
{
	int8	status;
	uint8	hw_interface;
	hw_addr	bssid;
});

PACKSTRUCT(struct wifi_msg_sme_disconnected_evt_t
{
	uint16	reason;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_interface_status_evt_t
{
	uint8	hw_interface;
	uint8	status;
});

PACKSTRUCT(struct wifi_msg_sme_connect_failed_evt_t
{
	uint16	reason;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_connect_retry_evt_t
{
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_ap_mode_started_evt_t
{
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_ap_mode_stopped_evt_t
{
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_ap_mode_failed_evt_t
{
	uint16	reason;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_ap_client_joined_evt_t
{
	hw_addr	mac_address;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_ap_client_left_evt_t
{
	hw_addr	mac_address;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_scan_sort_result_evt_t
{
	hw_addr	bssid;
	int8	channel;
	int16	rssi;
	int8	snr;
	uint8	secure;
	uint8array	ssid;
});

PACKSTRUCT(struct wifi_msg_sme_wps_stopped_evt_t
{
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_wps_completed_evt_t
{
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_wps_failed_evt_t
{
	uint16	reason;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_wps_credential_ssid_evt_t
{
	uint8	hw_interface;
	uint8array	ssid;
});

PACKSTRUCT(struct wifi_msg_sme_wps_credential_password_evt_t
{
	uint8	hw_interface;
	uint8array	password;
});

PACKSTRUCT(struct wifi_msg_sme_signal_quality_evt_t
{
	int8	rssi;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_p2p_group_started_evt_t
{
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_p2p_group_stopped_evt_t
{
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_p2p_group_failed_evt_t
{
	uint16	reason;
	uint8	hw_interface;
});

PACKSTRUCT(struct wifi_msg_sme_p2p_client_wants_to_join_evt_t
{
	hw_addr	mac_address;
});

PACKSTRUCT(struct wifi_msg_tcpip_start_tcp_server_cmd_t
{
	uint16	port;
	int8	default_destination;
});

PACKSTRUCT(struct wifi_msg_tcpip_start_tcp_server_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_tcpip_tcp_connect_cmd_t
{
	ipv4	address;
	uint16	port;
	int8	routing;
});

PACKSTRUCT(struct wifi_msg_tcpip_tcp_connect_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_tcpip_start_udp_server_cmd_t
{
	uint16	port;
	int8	default_destination;
});

PACKSTRUCT(struct wifi_msg_tcpip_start_udp_server_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_tcpip_udp_connect_cmd_t
{
	ipv4	address;
	uint16	port;
	int8	routing;
});

PACKSTRUCT(struct wifi_msg_tcpip_udp_connect_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_tcpip_configure_cmd_t
{
	ipv4	address;
	ipv4	netmask;
	ipv4	gateway;
	uint8	use_dhcp;
});

PACKSTRUCT(struct wifi_msg_tcpip_configure_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_dns_configure_cmd_t
{
	uint8	index;
	ipv4	address;
});

PACKSTRUCT(struct wifi_msg_tcpip_dns_configure_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_dns_gethostbyname_cmd_t
{
	uint8array	name;
});

PACKSTRUCT(struct wifi_msg_tcpip_dns_gethostbyname_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_udp_bind_cmd_t
{
	uint8	endpoint;
	uint16	port;
});

PACKSTRUCT(struct wifi_msg_tcpip_udp_bind_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_dhcp_set_hostname_cmd_t
{
	uint8array	hostname;
});

PACKSTRUCT(struct wifi_msg_tcpip_dhcp_set_hostname_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_tls_connect_cmd_t
{
	ipv4	address;
	uint16	port;
	int8	routing;
});

PACKSTRUCT(struct wifi_msg_tcpip_tls_connect_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_tcpip_tls_set_authmode_cmd_t
{
	uint8	auth_mode;
});

PACKSTRUCT(struct wifi_msg_tcpip_dhcp_enable_routing_cmd_t
{
	uint8	enable;
});

PACKSTRUCT(struct wifi_msg_tcpip_dhcp_enable_routing_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_mdns_set_hostname_cmd_t
{
	uint8array	hostname;
});

PACKSTRUCT(struct wifi_msg_tcpip_mdns_set_hostname_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_mdns_start_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_mdns_stop_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_add_service_cmd_t
{
	uint16	port;
	uint8	protocol;
	uint8array	service;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_add_service_rsp_t
{
	uint16	result;
	uint8	index;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_add_service_instance_cmd_t
{
	uint8	index;
	uint8array	instance;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_add_service_instance_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_add_service_attribute_cmd_t
{
	uint8	index;
	uint8array	attribute;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_add_service_attribute_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_remove_service_cmd_t
{
	uint8	index;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_remove_service_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_start_service_cmd_t
{
	uint8	index;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_start_service_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_stop_service_cmd_t
{
	uint8	index;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_stop_service_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_multicast_join_cmd_t
{
	ipv4	address;
});

PACKSTRUCT(struct wifi_msg_tcpip_multicast_join_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_multicast_leave_cmd_t
{
	ipv4	address;
});

PACKSTRUCT(struct wifi_msg_tcpip_multicast_leave_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_tls_set_user_certificate_cmd_t
{
	uint8array	fingerprint;
});

PACKSTRUCT(struct wifi_msg_tcpip_tls_set_user_certificate_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_dhcp_configure_cmd_t
{
	ipv4	address;
	ipv4	subnet_mask;
	uint32	lease_time;
});

PACKSTRUCT(struct wifi_msg_tcpip_dhcp_configure_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_mdns_gethostbyname_cmd_t
{
	uint8array	name;
});

PACKSTRUCT(struct wifi_msg_tcpip_mdns_gethostbyname_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_tcpip_dhcp_clients_rsp_t
{
	uint16	result;
	uint8	client_cnt;
});

PACKSTRUCT(struct wifi_msg_tcpip_configuration_evt_t
{
	ipv4	address;
	ipv4	netmask;
	ipv4	gateway;
	uint8	use_dhcp;
});

PACKSTRUCT(struct wifi_msg_tcpip_dns_configuration_evt_t
{
	uint8	index;
	ipv4	address;
});

PACKSTRUCT(struct wifi_msg_tcpip_endpoint_status_evt_t
{
	uint8	endpoint;
	ipv4	local_ip;
	uint16	local_port;
	ipv4	remote_ip;
	uint16	remote_port;
});

PACKSTRUCT(struct wifi_msg_tcpip_dns_gethostbyname_result_evt_t
{
	uint16	result;
	ipv4	address;
	uint8array	name;
});

PACKSTRUCT(struct wifi_msg_tcpip_udp_data_evt_t
{
	uint8	endpoint;
	ipv4	source_address;
	uint16	source_port;
	uint16array	data;
});

PACKSTRUCT(struct wifi_msg_tcpip_tls_verify_result_evt_t
{
	uint8	depth;
	uint16	flags;
});

PACKSTRUCT(struct wifi_msg_tcpip_mdns_failed_evt_t
{
	uint16	reason;
});

PACKSTRUCT(struct wifi_msg_tcpip_mdns_stopped_evt_t
{
	uint16	reason;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_service_started_evt_t
{
	uint8	index;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_service_failed_evt_t
{
	uint16	reason;
	uint8	index;
});

PACKSTRUCT(struct wifi_msg_tcpip_dnssd_service_stopped_evt_t
{
	uint16	reason;
	uint8	index;
});

PACKSTRUCT(struct wifi_msg_tcpip_dhcp_configuration_evt_t
{
	uint8	routing_enabled;
	ipv4	address;
	ipv4	subnet_mask;
	uint32	lease_time;
});

PACKSTRUCT(struct wifi_msg_tcpip_mdns_gethostbyname_result_evt_t
{
	uint16	result;
	ipv4	address;
	uint8array	name;
});

PACKSTRUCT(struct wifi_msg_tcpip_dhcp_client_evt_t
{
	ipv4	ip_address;
	hw_addr	mac_address;
});

PACKSTRUCT(struct wifi_msg_endpoint_send_cmd_t
{
	uint8	endpoint;
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_endpoint_send_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_set_streaming_cmd_t
{
	uint8	endpoint;
	uint8	streaming;
});

PACKSTRUCT(struct wifi_msg_endpoint_set_streaming_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_set_active_cmd_t
{
	uint8	endpoint;
	uint8	active;
});

PACKSTRUCT(struct wifi_msg_endpoint_set_active_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_set_streaming_destination_cmd_t
{
	uint8	endpoint;
	int8	destination_endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_set_streaming_destination_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_close_cmd_t
{
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_close_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_set_transmit_size_cmd_t
{
	uint8	endpoint;
	uint16	size;
});

PACKSTRUCT(struct wifi_msg_endpoint_set_transmit_size_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_disable_cmd_t
{
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_disable_rsp_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_syntax_error_evt_t
{
	uint16	result;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_data_evt_t
{
	uint8	endpoint;
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_endpoint_status_evt_t
{
	uint8	endpoint;
	uint32	type;
	uint8	streaming;
	int8	destination;
	uint8	active;
});

PACKSTRUCT(struct wifi_msg_endpoint_closing_evt_t
{
	uint16	reason;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_endpoint_error_evt_t
{
	uint16	reason;
	uint8	endpoint;
});

PACKSTRUCT(struct wifi_msg_hardware_set_soft_timer_cmd_t
{
	uint32	time;
	uint8	handle;
	uint8	single_shot;
});

PACKSTRUCT(struct wifi_msg_hardware_set_soft_timer_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_hardware_configure_gpio_cmd_t
{
	uint8	port;
	uint8	pin;
	uint8	mode;
	uint8	output;
});

PACKSTRUCT(struct wifi_msg_hardware_configure_gpio_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_hardware_configure_gpio_interrupt_cmd_t
{
	uint8	port;
	uint8	pin;
	uint8	trigger;
});

PACKSTRUCT(struct wifi_msg_hardware_configure_gpio_interrupt_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_hardware_write_gpio_cmd_t
{
	uint8	port;
	uint16	mask;
	uint16	data;
});

PACKSTRUCT(struct wifi_msg_hardware_write_gpio_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_hardware_read_gpio_cmd_t
{
	uint8	port;
	uint16	mask;
});

PACKSTRUCT(struct wifi_msg_hardware_read_gpio_rsp_t
{
	uint16	result;
	uint16	data;
});

PACKSTRUCT(struct wifi_msg_hardware_timer_init_cmd_t
{
	uint8	index;
	uint8	location;
	uint16	prescale;
	uint16	top_value;
});

PACKSTRUCT(struct wifi_msg_hardware_timer_init_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_hardware_timer_initcc_cmd_t
{
	uint8	index;
	uint8	channel;
	uint8	mode;
	uint16	compare_value;
});

PACKSTRUCT(struct wifi_msg_hardware_timer_initcc_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_hardware_adc_read_cmd_t
{
	uint8	input;
});

PACKSTRUCT(struct wifi_msg_hardware_adc_read_rsp_t
{
	uint16	result;
	uint8	input;
	uint16	value;
});

PACKSTRUCT(struct wifi_msg_hardware_rtc_init_cmd_t
{
	uint8	enable;
});

PACKSTRUCT(struct wifi_msg_hardware_rtc_init_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_hardware_rtc_set_time_cmd_t
{
	int16	year;
	int8	month;
	int8	day;
	int8	hour;
	int8	minute;
	int8	second;
});

PACKSTRUCT(struct wifi_msg_hardware_rtc_set_time_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_hardware_rtc_get_time_rsp_t
{
	uint16	result;
	int16	year;
	int8	month;
	int8	day;
	int8	weekday;
	int8	hour;
	int8	minute;
	int8	second;
});

PACKSTRUCT(struct wifi_msg_hardware_rtc_set_alarm_cmd_t
{
	int16	year;
	int8	month;
	int8	day;
	int8	hour;
	int8	minute;
	int8	second;
});

PACKSTRUCT(struct wifi_msg_hardware_rtc_set_alarm_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_hardware_uart_conf_set_cmd_t
{
	uint8	id;
	uint32	rate;
	uint8	data_bits;
	uint8	stop_bits;
	uint8	parity;
	uint8	flow_ctrl;
});

PACKSTRUCT(struct wifi_msg_hardware_uart_conf_set_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_hardware_uart_conf_get_cmd_t
{
	uint8	id;
});

PACKSTRUCT(struct wifi_msg_hardware_uart_conf_get_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_hardware_spi_transfer_cmd_t
{
	uint8	channel;
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_hardware_spi_transfer_rsp_t
{
	uint16	result;
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_hardware_soft_timer_evt_t
{
	uint8	handle;
});

PACKSTRUCT(struct wifi_msg_hardware_interrupt_evt_t
{
	uint32	interrupts;
	uint32	timestamp;
});

PACKSTRUCT(struct wifi_msg_hardware_uart_conf_evt_t
{
	uint8	id;
	uint32	rate;
	uint8	data_bits;
	uint8	stop_bits;
	uint8	parity;
	uint8	flow_ctrl;
});

PACKSTRUCT(struct wifi_msg_flash_ps_defrag_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_flash_ps_dump_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_flash_ps_erase_all_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_flash_ps_save_cmd_t
{
	uint16	key;
	uint8array	value;
});

PACKSTRUCT(struct wifi_msg_flash_ps_save_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_flash_ps_load_cmd_t
{
	uint16	key;
});

PACKSTRUCT(struct wifi_msg_flash_ps_load_rsp_t
{
	uint16	result;
	uint8array	value;
});

PACKSTRUCT(struct wifi_msg_flash_ps_erase_cmd_t
{
	uint16	key;
});

PACKSTRUCT(struct wifi_msg_flash_ps_erase_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_flash_ps_key_evt_t
{
	uint16	key;
	uint8array	value;
});

PACKSTRUCT(struct wifi_msg_flash_ps_key_changed_evt_t
{
	uint16	key;
});

PACKSTRUCT(struct wifi_msg_i2c_start_read_cmd_t
{
	uint8	channel;
	uint8	slave_address;
	uint8	length;
});

PACKSTRUCT(struct wifi_msg_i2c_start_read_rsp_t
{
	uint16	result;
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_i2c_start_write_cmd_t
{
	uint8	channel;
	uint8	slave_address;
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_i2c_start_write_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_i2c_stop_cmd_t
{
	uint8	channel;
});

PACKSTRUCT(struct wifi_msg_i2c_stop_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_https_enable_cmd_t
{
	uint8	https;
	uint8	dhcps;
	uint8	dnss;
});

PACKSTRUCT(struct wifi_msg_https_enable_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_https_add_path_cmd_t
{
	uint8	resource;
	uint8array	path;
});

PACKSTRUCT(struct wifi_msg_https_add_path_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_https_api_response_cmd_t
{
	uint32	request;
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_https_api_response_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_https_api_response_finish_cmd_t
{
	uint32	request;
});

PACKSTRUCT(struct wifi_msg_https_api_response_finish_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_https_api_request_evt_t
{
	uint32	request;
	uint8	method;
	uint8array	resource;
});

PACKSTRUCT(struct wifi_msg_https_api_request_header_evt_t
{
	uint32	request;
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_https_api_request_data_evt_t
{
	uint32	request;
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_https_api_request_finished_evt_t
{
	uint32	request;
});

PACKSTRUCT(struct wifi_msg_https_error_evt_t
{
	uint8	reason;
});

PACKSTRUCT(struct wifi_msg_ethernet_set_dataroute_cmd_t
{
	uint8	route;
});

PACKSTRUCT(struct wifi_msg_ethernet_set_dataroute_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_ethernet_connected_rsp_t
{
	uint8	state;
});

PACKSTRUCT(struct wifi_msg_ethernet_link_status_evt_t
{
	uint8	state;
});

PACKSTRUCT(struct wifi_msg_x509_reset_store_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_x509_add_certificate_cmd_t
{
	uint8	store;
	uint16	size;
});

PACKSTRUCT(struct wifi_msg_x509_add_certificate_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_x509_add_certificate_data_cmd_t
{
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_x509_add_certificate_data_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_x509_add_certificate_finish_rsp_t
{
	uint16	result;
	uint8array	fingerprint;
});

PACKSTRUCT(struct wifi_msg_x509_add_private_key_cmd_t
{
	uint16	size;
	uint8array	fingerprint;
});

PACKSTRUCT(struct wifi_msg_x509_add_private_key_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_x509_add_private_key_data_cmd_t
{
	uint8array	data;
});

PACKSTRUCT(struct wifi_msg_x509_add_private_key_data_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_x509_add_private_key_finish_cmd_t
{
	uint8array	password;
});

PACKSTRUCT(struct wifi_msg_x509_add_private_key_finish_rsp_t
{
	uint16	result;
	uint8array	fingerprint;
});

PACKSTRUCT(struct wifi_msg_x509_delete_certificate_cmd_t
{
	uint8array	fingerprint;
});

PACKSTRUCT(struct wifi_msg_x509_delete_certificate_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_x509_list_certificates_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_x509_certificate_evt_t
{
	uint8	index;
	uint8	type;
	uint8	store;
	uint8array	fingerprint;
});

PACKSTRUCT(struct wifi_msg_x509_certificate_subject_evt_t
{
	uint8	index;
	uint8array	subject;
});

PACKSTRUCT(struct wifi_msg_sdhc_fopen_cmd_t
{
	uint8	mode;
	uint8array	fname;
});

PACKSTRUCT(struct wifi_msg_sdhc_fopen_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sdhc_fclose_cmd_t
{
	uint8	fhandle;
});

PACKSTRUCT(struct wifi_msg_sdhc_fclose_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sdhc_fdir_cmd_t
{
	uint8	mode;
	uint8array	path;
});

PACKSTRUCT(struct wifi_msg_sdhc_fdir_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sdhc_fread_cmd_t
{
	uint8	fhandle;
	uint32	fsize;
});

PACKSTRUCT(struct wifi_msg_sdhc_fread_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sdhc_fwrite_cmd_t
{
	uint8	fhandle;
	uint16array	fdata;
});

PACKSTRUCT(struct wifi_msg_sdhc_fwrite_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sdhc_fdelete_cmd_t
{
	uint8array	fname;
});

PACKSTRUCT(struct wifi_msg_sdhc_fdelete_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sdhc_fmkdir_cmd_t
{
	uint8array	dir_name;
});

PACKSTRUCT(struct wifi_msg_sdhc_fmkdir_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sdhc_fchdir_cmd_t
{
	uint8array	dir_name;
});

PACKSTRUCT(struct wifi_msg_sdhc_fchdir_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sdhc_frename_cmd_t
{
	uint8	fhandle;
	uint8array	new_name;
});

PACKSTRUCT(struct wifi_msg_sdhc_frename_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sdhc_fchmode_cmd_t
{
	uint8	value;
	uint8array	fname;
});

PACKSTRUCT(struct wifi_msg_sdhc_fchmode_rsp_t
{
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sdhc_ready_evt_t
{
	uint8	fhandle;
	uint8	operation;
	uint16	result;
});

PACKSTRUCT(struct wifi_msg_sdhc_fdata_evt_t
{
	uint8	fhandle;
	uint16array	data;
});

PACKSTRUCT(struct wifi_msg_sdhc_ffile_evt_t
{
	uint8	fhandle;
	uint32	fsize;
	uint8	fattrib;
	uint8array	fname;
});

PACKSTRUCT(struct wifi_msg_sdhc_fpwd_evt_t
{
	uint8array	fdir;
});

PACKSTRUCT(struct wifi_msg_util_atoi_cmd_t
{
	uint8array	string;
});

PACKSTRUCT(struct wifi_msg_util_atoi_rsp_t
{
	int32	value;
});

PACKSTRUCT(struct wifi_msg_util_itoa_cmd_t
{
	int32	value;
});

PACKSTRUCT(struct wifi_msg_util_itoa_rsp_t
{
	uint8array	string;
});

PACKSTRUCT(
struct wifi_cmd_packet
{
	uint32   header;

union{
	uint8 handle;

	struct wifi_msg_dfu_reset_cmd_t                           cmd_dfu_reset;
	struct wifi_msg_dfu_flash_set_address_cmd_t               cmd_dfu_flash_set_address;
	struct wifi_msg_dfu_flash_upload_cmd_t                    cmd_dfu_flash_upload;
	struct wifi_msg_dfu_boot_evt_t                            evt_dfu_boot;
	struct wifi_msg_dfu_flash_set_address_rsp_t               rsp_dfu_flash_set_address;
	struct wifi_msg_dfu_flash_upload_rsp_t                    rsp_dfu_flash_upload;
	struct wifi_msg_dfu_flash_upload_finish_rsp_t             rsp_dfu_flash_upload_finish;
	struct wifi_msg_system_reset_cmd_t                        cmd_system_reset;
	struct wifi_msg_system_set_max_power_saving_state_cmd_t   cmd_system_set_max_power_saving_state;
	struct wifi_msg_system_boot_evt_t                         evt_system_boot;
	struct wifi_msg_system_state_evt_t                        evt_system_state;
	struct wifi_msg_system_sw_exception_evt_t                 evt_system_sw_exception;
	struct wifi_msg_system_power_saving_state_evt_t           evt_system_power_saving_state;
	struct wifi_msg_system_set_max_power_saving_state_rsp_t   rsp_system_set_max_power_saving_state;
	struct wifi_msg_config_get_mac_cmd_t                      cmd_config_get_mac;
	struct wifi_msg_config_set_mac_cmd_t                      cmd_config_set_mac;
	struct wifi_msg_config_mac_address_evt_t                  evt_config_mac_address;
	struct wifi_msg_config_get_mac_rsp_t                      rsp_config_get_mac;
	struct wifi_msg_config_set_mac_rsp_t                      rsp_config_set_mac;
	struct wifi_msg_sme_power_on_cmd_t                        cmd_sme_power_on;
	struct wifi_msg_sme_start_scan_cmd_t                      cmd_sme_start_scan;
	struct wifi_msg_sme_set_password_cmd_t                    cmd_sme_set_password;
	struct wifi_msg_sme_connect_bssid_cmd_t                   cmd_sme_connect_bssid;
	struct wifi_msg_sme_connect_ssid_cmd_t                    cmd_sme_connect_ssid;
	struct wifi_msg_sme_set_scan_channels_cmd_t               cmd_sme_set_scan_channels;
	struct wifi_msg_sme_set_operating_mode_cmd_t              cmd_sme_set_operating_mode;
	struct wifi_msg_sme_start_ap_mode_cmd_t                   cmd_sme_start_ap_mode;
	struct wifi_msg_sme_scan_results_sort_rssi_cmd_t          cmd_sme_scan_results_sort_rssi;
	struct wifi_msg_sme_ap_client_disconnect_cmd_t            cmd_sme_ap_client_disconnect;
	struct wifi_msg_sme_set_ap_password_cmd_t                 cmd_sme_set_ap_password;
	struct wifi_msg_sme_set_ap_max_clients_cmd_t              cmd_sme_set_ap_max_clients;
	struct wifi_msg_sme_start_ssid_scan_cmd_t                 cmd_sme_start_ssid_scan;
	struct wifi_msg_sme_set_ap_hidden_cmd_t                   cmd_sme_set_ap_hidden;
	struct wifi_msg_sme_set_11n_mode_cmd_t                    cmd_sme_set_11n_mode;
	struct wifi_msg_sme_set_eap_configuration_cmd_t           cmd_sme_set_eap_configuration;
	struct wifi_msg_sme_set_eap_type_username_cmd_t           cmd_sme_set_eap_type_username;
	struct wifi_msg_sme_set_eap_type_password_cmd_t           cmd_sme_set_eap_type_password;
	struct wifi_msg_sme_set_eap_type_ca_certificate_cmd_t     cmd_sme_set_eap_type_ca_certificate;
	struct wifi_msg_sme_set_eap_type_server_common_name_cmd_t cmd_sme_set_eap_type_server_common_name;
	struct wifi_msg_sme_set_eap_type_user_certificate_cmd_t   cmd_sme_set_eap_type_user_certificate;
	struct wifi_msg_sme_start_p2p_group_cmd_t                 cmd_sme_start_p2p_group;
	struct wifi_msg_sme_p2p_accept_client_cmd_t               cmd_sme_p2p_accept_client;
	struct wifi_msg_sme_ap_client_config_cmd_t                cmd_sme_ap_client_config;
	struct wifi_msg_sme_set_ap_client_isolation_cmd_t         cmd_sme_set_ap_client_isolation;
	struct wifi_msg_sme_wifi_is_on_evt_t                      evt_sme_wifi_is_on;
	struct wifi_msg_sme_wifi_is_off_evt_t                     evt_sme_wifi_is_off;
	struct wifi_msg_sme_scan_result_evt_t                     evt_sme_scan_result;
	struct wifi_msg_sme_scan_result_drop_evt_t                evt_sme_scan_result_drop;
	struct wifi_msg_sme_scanned_evt_t                         evt_sme_scanned;
	struct wifi_msg_sme_connected_evt_t                       evt_sme_connected;
	struct wifi_msg_sme_disconnected_evt_t                    evt_sme_disconnected;
	struct wifi_msg_sme_interface_status_evt_t                evt_sme_interface_status;
	struct wifi_msg_sme_connect_failed_evt_t                  evt_sme_connect_failed;
	struct wifi_msg_sme_connect_retry_evt_t                   evt_sme_connect_retry;
	struct wifi_msg_sme_ap_mode_started_evt_t                 evt_sme_ap_mode_started;
	struct wifi_msg_sme_ap_mode_stopped_evt_t                 evt_sme_ap_mode_stopped;
	struct wifi_msg_sme_ap_mode_failed_evt_t                  evt_sme_ap_mode_failed;
	struct wifi_msg_sme_ap_client_joined_evt_t                evt_sme_ap_client_joined;
	struct wifi_msg_sme_ap_client_left_evt_t                  evt_sme_ap_client_left;
	struct wifi_msg_sme_scan_sort_result_evt_t                evt_sme_scan_sort_result;
	struct wifi_msg_sme_wps_stopped_evt_t                     evt_sme_wps_stopped;
	struct wifi_msg_sme_wps_completed_evt_t                   evt_sme_wps_completed;
	struct wifi_msg_sme_wps_failed_evt_t                      evt_sme_wps_failed;
	struct wifi_msg_sme_wps_credential_ssid_evt_t             evt_sme_wps_credential_ssid;
	struct wifi_msg_sme_wps_credential_password_evt_t         evt_sme_wps_credential_password;
	struct wifi_msg_sme_signal_quality_evt_t                  evt_sme_signal_quality;
	struct wifi_msg_sme_p2p_group_started_evt_t               evt_sme_p2p_group_started;
	struct wifi_msg_sme_p2p_group_stopped_evt_t               evt_sme_p2p_group_stopped;
	struct wifi_msg_sme_p2p_group_failed_evt_t                evt_sme_p2p_group_failed;
	struct wifi_msg_sme_p2p_client_wants_to_join_evt_t        evt_sme_p2p_client_wants_to_join;
	struct wifi_msg_sme_wifi_on_rsp_t                         rsp_sme_wifi_on;
	struct wifi_msg_sme_wifi_off_rsp_t                        rsp_sme_wifi_off;
	struct wifi_msg_sme_power_on_rsp_t                        rsp_sme_power_on;
	struct wifi_msg_sme_start_scan_rsp_t                      rsp_sme_start_scan;
	struct wifi_msg_sme_stop_scan_rsp_t                       rsp_sme_stop_scan;
	struct wifi_msg_sme_set_password_rsp_t                    rsp_sme_set_password;
	struct wifi_msg_sme_connect_bssid_rsp_t                   rsp_sme_connect_bssid;
	struct wifi_msg_sme_connect_ssid_rsp_t                    rsp_sme_connect_ssid;
	struct wifi_msg_sme_disconnect_rsp_t                      rsp_sme_disconnect;
	struct wifi_msg_sme_set_scan_channels_rsp_t               rsp_sme_set_scan_channels;
	struct wifi_msg_sme_set_operating_mode_rsp_t              rsp_sme_set_operating_mode;
	struct wifi_msg_sme_start_ap_mode_rsp_t                   rsp_sme_start_ap_mode;
	struct wifi_msg_sme_stop_ap_mode_rsp_t                    rsp_sme_stop_ap_mode;
	struct wifi_msg_sme_scan_results_sort_rssi_rsp_t          rsp_sme_scan_results_sort_rssi;
	struct wifi_msg_sme_ap_client_disconnect_rsp_t            rsp_sme_ap_client_disconnect;
	struct wifi_msg_sme_set_ap_password_rsp_t                 rsp_sme_set_ap_password;
	struct wifi_msg_sme_set_ap_max_clients_rsp_t              rsp_sme_set_ap_max_clients;
	struct wifi_msg_sme_start_wps_rsp_t                       rsp_sme_start_wps;
	struct wifi_msg_sme_stop_wps_rsp_t                        rsp_sme_stop_wps;
	struct wifi_msg_sme_get_signal_quality_rsp_t              rsp_sme_get_signal_quality;
	struct wifi_msg_sme_start_ssid_scan_rsp_t                 rsp_sme_start_ssid_scan;
	struct wifi_msg_sme_set_ap_hidden_rsp_t                   rsp_sme_set_ap_hidden;
	struct wifi_msg_sme_set_11n_mode_rsp_t                    rsp_sme_set_11n_mode;
	struct wifi_msg_sme_set_eap_configuration_rsp_t           rsp_sme_set_eap_configuration;
	struct wifi_msg_sme_set_eap_type_username_rsp_t           rsp_sme_set_eap_type_username;
	struct wifi_msg_sme_set_eap_type_password_rsp_t           rsp_sme_set_eap_type_password;
	struct wifi_msg_sme_set_eap_type_ca_certificate_rsp_t     rsp_sme_set_eap_type_ca_certificate;
	struct wifi_msg_sme_set_eap_type_server_common_name_rsp_t rsp_sme_set_eap_type_server_common_name;
	struct wifi_msg_sme_set_eap_type_user_certificate_rsp_t   rsp_sme_set_eap_type_user_certificate;
	struct wifi_msg_sme_start_p2p_group_rsp_t                 rsp_sme_start_p2p_group;
	struct wifi_msg_sme_stop_p2p_group_rsp_t                  rsp_sme_stop_p2p_group;
	struct wifi_msg_sme_p2p_accept_client_rsp_t               rsp_sme_p2p_accept_client;
	struct wifi_msg_sme_ap_client_config_rsp_t                rsp_sme_ap_client_config;
	struct wifi_msg_sme_set_ap_client_isolation_rsp_t         rsp_sme_set_ap_client_isolation;
	struct wifi_msg_tcpip_start_tcp_server_cmd_t              cmd_tcpip_start_tcp_server;
	struct wifi_msg_tcpip_tcp_connect_cmd_t                   cmd_tcpip_tcp_connect;
	struct wifi_msg_tcpip_start_udp_server_cmd_t              cmd_tcpip_start_udp_server;
	struct wifi_msg_tcpip_udp_connect_cmd_t                   cmd_tcpip_udp_connect;
	struct wifi_msg_tcpip_configure_cmd_t                     cmd_tcpip_configure;
	struct wifi_msg_tcpip_dns_configure_cmd_t                 cmd_tcpip_dns_configure;
	struct wifi_msg_tcpip_dns_gethostbyname_cmd_t             cmd_tcpip_dns_gethostbyname;
	struct wifi_msg_tcpip_udp_bind_cmd_t                      cmd_tcpip_udp_bind;
	struct wifi_msg_tcpip_dhcp_set_hostname_cmd_t             cmd_tcpip_dhcp_set_hostname;
	struct wifi_msg_tcpip_tls_connect_cmd_t                   cmd_tcpip_tls_connect;
	struct wifi_msg_tcpip_tls_set_authmode_cmd_t              cmd_tcpip_tls_set_authmode;
	struct wifi_msg_tcpip_dhcp_enable_routing_cmd_t           cmd_tcpip_dhcp_enable_routing;
	struct wifi_msg_tcpip_mdns_set_hostname_cmd_t             cmd_tcpip_mdns_set_hostname;
	struct wifi_msg_tcpip_dnssd_add_service_cmd_t             cmd_tcpip_dnssd_add_service;
	struct wifi_msg_tcpip_dnssd_add_service_instance_cmd_t    cmd_tcpip_dnssd_add_service_instance;
	struct wifi_msg_tcpip_dnssd_add_service_attribute_cmd_t   cmd_tcpip_dnssd_add_service_attribute;
	struct wifi_msg_tcpip_dnssd_remove_service_cmd_t          cmd_tcpip_dnssd_remove_service;
	struct wifi_msg_tcpip_dnssd_start_service_cmd_t           cmd_tcpip_dnssd_start_service;
	struct wifi_msg_tcpip_dnssd_stop_service_cmd_t            cmd_tcpip_dnssd_stop_service;
	struct wifi_msg_tcpip_multicast_join_cmd_t                cmd_tcpip_multicast_join;
	struct wifi_msg_tcpip_multicast_leave_cmd_t               cmd_tcpip_multicast_leave;
	struct wifi_msg_tcpip_tls_set_user_certificate_cmd_t      cmd_tcpip_tls_set_user_certificate;
	struct wifi_msg_tcpip_dhcp_configure_cmd_t                cmd_tcpip_dhcp_configure;
	struct wifi_msg_tcpip_mdns_gethostbyname_cmd_t            cmd_tcpip_mdns_gethostbyname;
	struct wifi_msg_tcpip_configuration_evt_t                 evt_tcpip_configuration;
	struct wifi_msg_tcpip_dns_configuration_evt_t             evt_tcpip_dns_configuration;
	struct wifi_msg_tcpip_endpoint_status_evt_t               evt_tcpip_endpoint_status;
	struct wifi_msg_tcpip_dns_gethostbyname_result_evt_t      evt_tcpip_dns_gethostbyname_result;
	struct wifi_msg_tcpip_udp_data_evt_t                      evt_tcpip_udp_data;
	struct wifi_msg_tcpip_tls_verify_result_evt_t             evt_tcpip_tls_verify_result;
	struct wifi_msg_tcpip_mdns_failed_evt_t                   evt_tcpip_mdns_failed;
	struct wifi_msg_tcpip_mdns_stopped_evt_t                  evt_tcpip_mdns_stopped;
	struct wifi_msg_tcpip_dnssd_service_started_evt_t         evt_tcpip_dnssd_service_started;
	struct wifi_msg_tcpip_dnssd_service_failed_evt_t          evt_tcpip_dnssd_service_failed;
	struct wifi_msg_tcpip_dnssd_service_stopped_evt_t         evt_tcpip_dnssd_service_stopped;
	struct wifi_msg_tcpip_dhcp_configuration_evt_t            evt_tcpip_dhcp_configuration;
	struct wifi_msg_tcpip_mdns_gethostbyname_result_evt_t     evt_tcpip_mdns_gethostbyname_result;
	struct wifi_msg_tcpip_dhcp_client_evt_t                   evt_tcpip_dhcp_client;
	struct wifi_msg_tcpip_start_tcp_server_rsp_t              rsp_tcpip_start_tcp_server;
	struct wifi_msg_tcpip_tcp_connect_rsp_t                   rsp_tcpip_tcp_connect;
	struct wifi_msg_tcpip_start_udp_server_rsp_t              rsp_tcpip_start_udp_server;
	struct wifi_msg_tcpip_udp_connect_rsp_t                   rsp_tcpip_udp_connect;
	struct wifi_msg_tcpip_configure_rsp_t                     rsp_tcpip_configure;
	struct wifi_msg_tcpip_dns_configure_rsp_t                 rsp_tcpip_dns_configure;
	struct wifi_msg_tcpip_dns_gethostbyname_rsp_t             rsp_tcpip_dns_gethostbyname;
	struct wifi_msg_tcpip_udp_bind_rsp_t                      rsp_tcpip_udp_bind;
	struct wifi_msg_tcpip_dhcp_set_hostname_rsp_t             rsp_tcpip_dhcp_set_hostname;
	struct wifi_msg_tcpip_tls_connect_rsp_t                   rsp_tcpip_tls_connect;
	struct wifi_msg_tcpip_dhcp_enable_routing_rsp_t           rsp_tcpip_dhcp_enable_routing;
	struct wifi_msg_tcpip_mdns_set_hostname_rsp_t             rsp_tcpip_mdns_set_hostname;
	struct wifi_msg_tcpip_mdns_start_rsp_t                    rsp_tcpip_mdns_start;
	struct wifi_msg_tcpip_mdns_stop_rsp_t                     rsp_tcpip_mdns_stop;
	struct wifi_msg_tcpip_dnssd_add_service_rsp_t             rsp_tcpip_dnssd_add_service;
	struct wifi_msg_tcpip_dnssd_add_service_instance_rsp_t    rsp_tcpip_dnssd_add_service_instance;
	struct wifi_msg_tcpip_dnssd_add_service_attribute_rsp_t   rsp_tcpip_dnssd_add_service_attribute;
	struct wifi_msg_tcpip_dnssd_remove_service_rsp_t          rsp_tcpip_dnssd_remove_service;
	struct wifi_msg_tcpip_dnssd_start_service_rsp_t           rsp_tcpip_dnssd_start_service;
	struct wifi_msg_tcpip_dnssd_stop_service_rsp_t            rsp_tcpip_dnssd_stop_service;
	struct wifi_msg_tcpip_multicast_join_rsp_t                rsp_tcpip_multicast_join;
	struct wifi_msg_tcpip_multicast_leave_rsp_t               rsp_tcpip_multicast_leave;
	struct wifi_msg_tcpip_tls_set_user_certificate_rsp_t      rsp_tcpip_tls_set_user_certificate;
	struct wifi_msg_tcpip_dhcp_configure_rsp_t                rsp_tcpip_dhcp_configure;
	struct wifi_msg_tcpip_mdns_gethostbyname_rsp_t            rsp_tcpip_mdns_gethostbyname;
	struct wifi_msg_tcpip_dhcp_clients_rsp_t                  rsp_tcpip_dhcp_clients;
	struct wifi_msg_endpoint_send_cmd_t                       cmd_endpoint_send;
	struct wifi_msg_endpoint_set_streaming_cmd_t              cmd_endpoint_set_streaming;
	struct wifi_msg_endpoint_set_active_cmd_t                 cmd_endpoint_set_active;
	struct wifi_msg_endpoint_set_streaming_destination_cmd_t  cmd_endpoint_set_streaming_destination;
	struct wifi_msg_endpoint_close_cmd_t                      cmd_endpoint_close;
	struct wifi_msg_endpoint_set_transmit_size_cmd_t          cmd_endpoint_set_transmit_size;
	struct wifi_msg_endpoint_disable_cmd_t                    cmd_endpoint_disable;
	struct wifi_msg_endpoint_syntax_error_evt_t               evt_endpoint_syntax_error;
	struct wifi_msg_endpoint_data_evt_t                       evt_endpoint_data;
	struct wifi_msg_endpoint_status_evt_t                     evt_endpoint_status;
	struct wifi_msg_endpoint_closing_evt_t                    evt_endpoint_closing;
	struct wifi_msg_endpoint_error_evt_t                      evt_endpoint_error;
	struct wifi_msg_endpoint_send_rsp_t                       rsp_endpoint_send;
	struct wifi_msg_endpoint_set_streaming_rsp_t              rsp_endpoint_set_streaming;
	struct wifi_msg_endpoint_set_active_rsp_t                 rsp_endpoint_set_active;
	struct wifi_msg_endpoint_set_streaming_destination_rsp_t  rsp_endpoint_set_streaming_destination;
	struct wifi_msg_endpoint_close_rsp_t                      rsp_endpoint_close;
	struct wifi_msg_endpoint_set_transmit_size_rsp_t          rsp_endpoint_set_transmit_size;
	struct wifi_msg_endpoint_disable_rsp_t                    rsp_endpoint_disable;
	struct wifi_msg_hardware_set_soft_timer_cmd_t             cmd_hardware_set_soft_timer;
	struct wifi_msg_hardware_configure_gpio_cmd_t             cmd_hardware_configure_gpio;
	struct wifi_msg_hardware_configure_gpio_interrupt_cmd_t   cmd_hardware_configure_gpio_interrupt;
	struct wifi_msg_hardware_write_gpio_cmd_t                 cmd_hardware_write_gpio;
	struct wifi_msg_hardware_read_gpio_cmd_t                  cmd_hardware_read_gpio;
	struct wifi_msg_hardware_timer_init_cmd_t                 cmd_hardware_timer_init;
	struct wifi_msg_hardware_timer_initcc_cmd_t               cmd_hardware_timer_initcc;
	struct wifi_msg_hardware_adc_read_cmd_t                   cmd_hardware_adc_read;
	struct wifi_msg_hardware_rtc_init_cmd_t                   cmd_hardware_rtc_init;
	struct wifi_msg_hardware_rtc_set_time_cmd_t               cmd_hardware_rtc_set_time;
	struct wifi_msg_hardware_rtc_set_alarm_cmd_t              cmd_hardware_rtc_set_alarm;
	struct wifi_msg_hardware_uart_conf_set_cmd_t              cmd_hardware_uart_conf_set;
	struct wifi_msg_hardware_uart_conf_get_cmd_t              cmd_hardware_uart_conf_get;
	struct wifi_msg_hardware_spi_transfer_cmd_t               cmd_hardware_spi_transfer;
	struct wifi_msg_hardware_soft_timer_evt_t                 evt_hardware_soft_timer;
	struct wifi_msg_hardware_interrupt_evt_t                  evt_hardware_interrupt;
	struct wifi_msg_hardware_uart_conf_evt_t                  evt_hardware_uart_conf;
	struct wifi_msg_hardware_set_soft_timer_rsp_t             rsp_hardware_set_soft_timer;
	struct wifi_msg_hardware_configure_gpio_rsp_t             rsp_hardware_configure_gpio;
	struct wifi_msg_hardware_configure_gpio_interrupt_rsp_t   rsp_hardware_configure_gpio_interrupt;
	struct wifi_msg_hardware_write_gpio_rsp_t                 rsp_hardware_write_gpio;
	struct wifi_msg_hardware_read_gpio_rsp_t                  rsp_hardware_read_gpio;
	struct wifi_msg_hardware_timer_init_rsp_t                 rsp_hardware_timer_init;
	struct wifi_msg_hardware_timer_initcc_rsp_t               rsp_hardware_timer_initcc;
	struct wifi_msg_hardware_adc_read_rsp_t                   rsp_hardware_adc_read;
	struct wifi_msg_hardware_rtc_init_rsp_t                   rsp_hardware_rtc_init;
	struct wifi_msg_hardware_rtc_set_time_rsp_t               rsp_hardware_rtc_set_time;
	struct wifi_msg_hardware_rtc_get_time_rsp_t               rsp_hardware_rtc_get_time;
	struct wifi_msg_hardware_rtc_set_alarm_rsp_t              rsp_hardware_rtc_set_alarm;
	struct wifi_msg_hardware_uart_conf_set_rsp_t              rsp_hardware_uart_conf_set;
	struct wifi_msg_hardware_uart_conf_get_rsp_t              rsp_hardware_uart_conf_get;
	struct wifi_msg_hardware_spi_transfer_rsp_t               rsp_hardware_spi_transfer;
	struct wifi_msg_flash_ps_save_cmd_t                       cmd_flash_ps_save;
	struct wifi_msg_flash_ps_load_cmd_t                       cmd_flash_ps_load;
	struct wifi_msg_flash_ps_erase_cmd_t                      cmd_flash_ps_erase;
	struct wifi_msg_flash_ps_key_evt_t                        evt_flash_ps_key;
	struct wifi_msg_flash_ps_key_changed_evt_t                evt_flash_ps_key_changed;
	struct wifi_msg_flash_ps_defrag_rsp_t                     rsp_flash_ps_defrag;
	struct wifi_msg_flash_ps_dump_rsp_t                       rsp_flash_ps_dump;
	struct wifi_msg_flash_ps_erase_all_rsp_t                  rsp_flash_ps_erase_all;
	struct wifi_msg_flash_ps_save_rsp_t                       rsp_flash_ps_save;
	struct wifi_msg_flash_ps_load_rsp_t                       rsp_flash_ps_load;
	struct wifi_msg_flash_ps_erase_rsp_t                      rsp_flash_ps_erase;
	struct wifi_msg_i2c_start_read_cmd_t                      cmd_i2c_start_read;
	struct wifi_msg_i2c_start_write_cmd_t                     cmd_i2c_start_write;
	struct wifi_msg_i2c_stop_cmd_t                            cmd_i2c_stop;
	struct wifi_msg_i2c_start_read_rsp_t                      rsp_i2c_start_read;
	struct wifi_msg_i2c_start_write_rsp_t                     rsp_i2c_start_write;
	struct wifi_msg_i2c_stop_rsp_t                            rsp_i2c_stop;
	struct wifi_msg_https_enable_cmd_t                        cmd_https_enable;
	struct wifi_msg_https_add_path_cmd_t                      cmd_https_add_path;
	struct wifi_msg_https_api_response_cmd_t                  cmd_https_api_response;
	struct wifi_msg_https_api_response_finish_cmd_t           cmd_https_api_response_finish;
	struct wifi_msg_https_api_request_evt_t                   evt_https_api_request;
	struct wifi_msg_https_api_request_header_evt_t            evt_https_api_request_header;
	struct wifi_msg_https_api_request_data_evt_t              evt_https_api_request_data;
	struct wifi_msg_https_api_request_finished_evt_t          evt_https_api_request_finished;
	struct wifi_msg_https_error_evt_t                         evt_https_error;
	struct wifi_msg_https_enable_rsp_t                        rsp_https_enable;
	struct wifi_msg_https_add_path_rsp_t                      rsp_https_add_path;
	struct wifi_msg_https_api_response_rsp_t                  rsp_https_api_response;
	struct wifi_msg_https_api_response_finish_rsp_t           rsp_https_api_response_finish;
	struct wifi_msg_ethernet_set_dataroute_cmd_t              cmd_ethernet_set_dataroute;
	struct wifi_msg_ethernet_link_status_evt_t                evt_ethernet_link_status;
	struct wifi_msg_ethernet_set_dataroute_rsp_t              rsp_ethernet_set_dataroute;
	struct wifi_msg_ethernet_connected_rsp_t                  rsp_ethernet_connected;
	struct wifi_msg_x509_add_certificate_cmd_t                cmd_x509_add_certificate;
	struct wifi_msg_x509_add_certificate_data_cmd_t           cmd_x509_add_certificate_data;
	struct wifi_msg_x509_add_private_key_cmd_t                cmd_x509_add_private_key;
	struct wifi_msg_x509_add_private_key_data_cmd_t           cmd_x509_add_private_key_data;
	struct wifi_msg_x509_add_private_key_finish_cmd_t         cmd_x509_add_private_key_finish;
	struct wifi_msg_x509_delete_certificate_cmd_t             cmd_x509_delete_certificate;
	struct wifi_msg_x509_certificate_evt_t                    evt_x509_certificate;
	struct wifi_msg_x509_certificate_subject_evt_t            evt_x509_certificate_subject;
	struct wifi_msg_x509_reset_store_rsp_t                    rsp_x509_reset_store;
	struct wifi_msg_x509_add_certificate_rsp_t                rsp_x509_add_certificate;
	struct wifi_msg_x509_add_certificate_data_rsp_t           rsp_x509_add_certificate_data;
	struct wifi_msg_x509_add_certificate_finish_rsp_t         rsp_x509_add_certificate_finish;
	struct wifi_msg_x509_add_private_key_rsp_t                rsp_x509_add_private_key;
	struct wifi_msg_x509_add_private_key_data_rsp_t           rsp_x509_add_private_key_data;
	struct wifi_msg_x509_add_private_key_finish_rsp_t         rsp_x509_add_private_key_finish;
	struct wifi_msg_x509_delete_certificate_rsp_t             rsp_x509_delete_certificate;
	struct wifi_msg_x509_list_certificates_rsp_t              rsp_x509_list_certificates;
	struct wifi_msg_sdhc_fopen_cmd_t                          cmd_sdhc_fopen;
	struct wifi_msg_sdhc_fclose_cmd_t                         cmd_sdhc_fclose;
	struct wifi_msg_sdhc_fdir_cmd_t                           cmd_sdhc_fdir;
	struct wifi_msg_sdhc_fread_cmd_t                          cmd_sdhc_fread;
	struct wifi_msg_sdhc_fwrite_cmd_t                         cmd_sdhc_fwrite;
	struct wifi_msg_sdhc_fdelete_cmd_t                        cmd_sdhc_fdelete;
	struct wifi_msg_sdhc_fmkdir_cmd_t                         cmd_sdhc_fmkdir;
	struct wifi_msg_sdhc_fchdir_cmd_t                         cmd_sdhc_fchdir;
	struct wifi_msg_sdhc_frename_cmd_t                        cmd_sdhc_frename;
	struct wifi_msg_sdhc_fchmode_cmd_t                        cmd_sdhc_fchmode;
	struct wifi_msg_sdhc_ready_evt_t                          evt_sdhc_ready;
	struct wifi_msg_sdhc_fdata_evt_t                          evt_sdhc_fdata;
	struct wifi_msg_sdhc_ffile_evt_t                          evt_sdhc_ffile;
	struct wifi_msg_sdhc_fpwd_evt_t                           evt_sdhc_fpwd;
	struct wifi_msg_sdhc_fopen_rsp_t                          rsp_sdhc_fopen;
	struct wifi_msg_sdhc_fclose_rsp_t                         rsp_sdhc_fclose;
	struct wifi_msg_sdhc_fdir_rsp_t                           rsp_sdhc_fdir;
	struct wifi_msg_sdhc_fread_rsp_t                          rsp_sdhc_fread;
	struct wifi_msg_sdhc_fwrite_rsp_t                         rsp_sdhc_fwrite;
	struct wifi_msg_sdhc_fdelete_rsp_t                        rsp_sdhc_fdelete;
	struct wifi_msg_sdhc_fmkdir_rsp_t                         rsp_sdhc_fmkdir;
	struct wifi_msg_sdhc_fchdir_rsp_t                         rsp_sdhc_fchdir;
	struct wifi_msg_sdhc_frename_rsp_t                        rsp_sdhc_frename;
	struct wifi_msg_sdhc_fchmode_rsp_t                        rsp_sdhc_fchmode;
	struct wifi_msg_util_atoi_cmd_t                           cmd_util_atoi;
	struct wifi_msg_util_itoa_cmd_t                           cmd_util_itoa;
	struct wifi_msg_util_atoi_rsp_t                           rsp_util_atoi;
	struct wifi_msg_util_itoa_rsp_t                           rsp_util_itoa;

	uint8 payload[128];/*TODO: fix this for getting command size larger*/
};

}ALIGNED);

extern struct wifi_cmd_packet bglib_temp_msg;

/**This command is used to reset the device.{p}The command does not have a response, but it triggers a boot event.{/p}**/
#define wifi_cmd_dfu_reset(DFU) \
{\
bglib_temp_msg.cmd_dfu_reset.dfu=(DFU);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x0<<16)|((uint32)0x0<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the flash address offset for the DFU upgrade.**/
#define wifi_cmd_dfu_flash_set_address(ADDRESS) \
{\
bglib_temp_msg.cmd_dfu_flash_set_address.address=(ADDRESS);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)4+0)>>8)))|((((uint32)4+0)&0xff)<<8)|((uint32)0x0<<16)|((uint32)0x1<<24);\
bglib_output(4+4,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to upload a block of firmware data.**/
#define wifi_cmd_dfu_flash_upload(DATA_LEN,DATA_DATA) \
{\
bglib_temp_msg.cmd_dfu_flash_upload.data.len=(DATA_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_dfu_flash_upload.data.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_dfu_flash_upload.data.len)&0xff)<<8)|((uint32)0x0<<16)|((uint32)0x2<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_dfu_flash_upload.data.len,(uint8*)DATA_DATA);\
}
/**This command is used to finish the DFU upgrade.{p}The command must be called once all firmware data has been uploaded.{/p}**/
#define wifi_cmd_dfu_flash_upload_finish() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x0<<16)|((uint32)0x3<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to retrieve the device status.{p}When the sync command is sent, multiple events are output representing the device status.{/p}**/
#define wifi_cmd_system_sync() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x1<<16)|((uint32)0x0<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to reset the device.{p}The command does not have a response, but it triggers a boot event.{/p}**/
#define wifi_cmd_system_reset(DFU) \
{\
bglib_temp_msg.cmd_system_reset.dfu=(DFU);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x1<<16)|((uint32)0x1<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to verify that communication works between the external host and the device.{p}The device sends a response without doing anything else.{/p}**/
#define wifi_cmd_system_hello() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x1<<16)|((uint32)0x2<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the maximum power saving state allowed for the device.{p}Initial state is power_saving_state_0{/p}**/
#define wifi_cmd_system_set_max_power_saving_state(STATE) \
{\
bglib_temp_msg.cmd_system_set_max_power_saving_state.state=(STATE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x1<<16)|((uint32)0x3<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to read the MAC address of the device.**/
#define wifi_cmd_config_get_mac(HW_INTERFACE) \
{\
bglib_temp_msg.cmd_config_get_mac.hw_interface=(HW_INTERFACE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x2<<16)|((uint32)0x0<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to write the device MAC address.{p}The MAC address will be taken into use when the Wi-Fi radio is switched on using the {a href="#cmd_sme_wifi_on"}sme_wifi_on{/a} command.{/p}**/
#define wifi_cmd_config_set_mac(HW_INTERFACE,MAC) \
{\
bglib_temp_msg.cmd_config_set_mac.hw_interface=(HW_INTERFACE);\
memcpy(&bglib_temp_msg.cmd_config_set_mac.mac,(MAC),sizeof(hw_addr));\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)7+0)>>8)))|((((uint32)7+0)&0xff)<<8)|((uint32)0x2<<16)|((uint32)0x1<<24);\
bglib_output(4+7,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to switch on the Wi-Fi radio.**/
#define wifi_cmd_sme_wifi_on() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x0<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to turn off the Wi-Fi radio.**/
#define wifi_cmd_sme_wifi_off() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x1<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to control the Wi-Fi radio supply voltage directly.**/
#define wifi_cmd_sme_power_on(ENABLE) \
{\
bglib_temp_msg.cmd_sme_power_on.enable=(ENABLE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x2<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command initiates a scan for Access Points.{p}Scanning is not possible once connected or once Access Point mode has been started.{/p}{p}The internal scan list is cleared before the scan is initiated.{/p}**/
#define wifi_cmd_sme_start_scan(HW_INTERFACE,CHLIST_LEN,CHLIST_DATA) \
{\
bglib_temp_msg.cmd_sme_start_scan.hw_interface=(HW_INTERFACE);\
bglib_temp_msg.cmd_sme_start_scan.chList.len=(CHLIST_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sme_start_scan.chList.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sme_start_scan.chList.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x3<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_start_scan.chList.len,(uint8*)CHLIST_DATA);\
}
/**This command is used to terminate the active scanning procedure.**/
#define wifi_cmd_sme_stop_scan() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x4<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the password used when authenticating with a secure Access Point.{p}There is no password set by default.{/p}**/
#define wifi_cmd_sme_set_password(PASSWORD_LEN,PASSWORD_DATA) \
{\
bglib_temp_msg.cmd_sme_set_password.password.len=(PASSWORD_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_sme_set_password.password.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_sme_set_password.password.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x5<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_set_password.password.len,(uint8*)PASSWORD_DATA);\
}
/**This command is used to try to connect to a specific Access Point using its unique BSSID.{p}The command requires a preceding {a href="#cmd_sme_start_scan"}sme_start_scan{/a} or {a href="#cmd_sme_start_ssid_scan"}sme_start_ssid_scan{/a} command and that the desired Access Point was found during that scan. When connecting to an Access Point on channel 12 or 13, at least one of the Access Points discovered in the scan must advertise the use of channels up to 13.{/p}{p}An ongoing connection attempt can be canceled using the {a href="#cmd_sme_disconnect"}sme_disconnect{/a} command.{/p}**/
#define wifi_cmd_sme_connect_bssid(BSSID) \
{\
memcpy(&bglib_temp_msg.cmd_sme_connect_bssid.bssid,(BSSID),sizeof(hw_addr));\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)6+0)>>8)))|((((uint32)6+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x6<<24);\
bglib_output(4+6,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to start a connection establishment procedure with an Access Point with the given SSID.{p}Executing this command launches an internal scan procedure in order to discover the Access Points in range. The results of the scan are NOT exposed via BGAPI nor stored in the internal scan list. The channels used in the scan procedure can be defined with the {a href="#cmd_sme_set_scan_channels"}sme_set_scan_channels{/a} command. If the command has not been executed, all channels will be scanned. When connecting to an Access Point on channel 12 or 13, at least one of the Access Points discovered in the scan must advertise the use of channels up to 13.{/p}{p}An ongoing connection attempt can be canceled using the {a href="#cmd_sme_disconnect"}sme_disconnect{/a} command.{/p}**/
#define wifi_cmd_sme_connect_ssid(SSID_LEN,SSID_DATA) \
{\
bglib_temp_msg.cmd_sme_connect_ssid.ssid.len=(SSID_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_sme_connect_ssid.ssid.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_sme_connect_ssid.ssid.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x7<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_connect_ssid.ssid.len,(uint8*)SSID_DATA);\
}
/**This command is used to cancel an ongoing connection attempt or disconnect from the currently connected Access Point.**/
#define wifi_cmd_sme_disconnect() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x8<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the default scan channel list.**/
#define wifi_cmd_sme_set_scan_channels(HW_INTERFACE,CHLIST_LEN,CHLIST_DATA) \
{\
bglib_temp_msg.cmd_sme_set_scan_channels.hw_interface=(HW_INTERFACE);\
bglib_temp_msg.cmd_sme_set_scan_channels.chList.len=(CHLIST_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sme_set_scan_channels.chList.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sme_set_scan_channels.chList.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x9<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_set_scan_channels.chList.len,(uint8*)CHLIST_DATA);\
}
/**This command is used to set the Wi-Fi operating mode, either to Wi-Fi client or Wi-Fi Access Point.{p}The selected operating mode will become effective the next time the Wi-Fi radio is switched on using the {a href="#cmd_sme_wifi_on"}sme_wifi_on{/a} command.{/p}**/
#define wifi_cmd_sme_set_operating_mode(MODE) \
{\
bglib_temp_msg.cmd_sme_set_operating_mode.mode=(MODE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0xa<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to start the Access Point mode.{p}In order to start the Access Point on channel 12 or 13, at least one Access Point discovered in a scan must advertise the use of channels up to 13.{/p}**/
#define wifi_cmd_sme_start_ap_mode(CHANNEL,SECURITY,SSID_LEN,SSID_DATA) \
{\
bglib_temp_msg.cmd_sme_start_ap_mode.channel=(CHANNEL);\
bglib_temp_msg.cmd_sme_start_ap_mode.security=(SECURITY);\
bglib_temp_msg.cmd_sme_start_ap_mode.ssid.len=(SSID_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+bglib_temp_msg.cmd_sme_start_ap_mode.ssid.len)>>8)))|((((uint32)3+bglib_temp_msg.cmd_sme_start_ap_mode.ssid.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0xb<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_start_ap_mode.ssid.len,(uint8*)SSID_DATA);\
}
/**This command is used to stop the Access Point mode.**/
#define wifi_cmd_sme_stop_ap_mode() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0xc<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to retrieve results from the internal scan list, sorted according to RSSI value.{p}The command can be run only after the {a href="#cmd_sme_start_scan"}sme_start_scan{/a} command or the {a href="#cmd_sme_start_ssid_scan"}sme_start_ssid_scan{/a} command has been issued at least once during the current session.{/p}**/
#define wifi_cmd_sme_scan_results_sort_rssi(AMOUNT) \
{\
bglib_temp_msg.cmd_sme_scan_results_sort_rssi.amount=(AMOUNT);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0xd<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to disconnect a client from the Access Point.**/
#define wifi_cmd_sme_ap_client_disconnect(MAC_ADDRESS) \
{\
memcpy(&bglib_temp_msg.cmd_sme_ap_client_disconnect.mac_address,(MAC_ADDRESS),sizeof(hw_addr));\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)6+0)>>8)))|((((uint32)6+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0xe<<24);\
bglib_output(4+6,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the Wi-Fi password for the Access Point mode.**/
#define wifi_cmd_sme_set_ap_password(PASSWORD_LEN,PASSWORD_DATA) \
{\
bglib_temp_msg.cmd_sme_set_ap_password.password.len=(PASSWORD_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_sme_set_ap_password.password.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_sme_set_ap_password.password.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0xf<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_set_ap_password.password.len,(uint8*)PASSWORD_DATA);\
}
/**This command is used to set the maximum amount of clients that can be associated to the Access Point simultaneously.{p}The command does not affect currently connected clients.{/p}**/
#define wifi_cmd_sme_set_ap_max_clients(MAX_CLIENTS) \
{\
bglib_temp_msg.cmd_sme_set_ap_max_clients.max_clients=(MAX_CLIENTS);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x10<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to start the Wi-Fi Protected Setup (WPS) session.{p}Only WPS push-button mode (PBC) is supported. The session will timeout in 120 seconds if no Access Point in WPS mode is discovered.{/p}{p}This command can only be used in client mode.{/p}**/
#define wifi_cmd_sme_start_wps() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x11<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to stop the Wi-Fi Protected Setup (WPS) session.**/
#define wifi_cmd_sme_stop_wps() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x12<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to get a value indicating the signal quality of the connection.{p}The command is applicable only in client mode{/p}**/
#define wifi_cmd_sme_get_signal_quality() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x13<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to initiate an active scan for Access Points.{p}Scanning is not possible once connected or once Access Point mode has been started.{/p}{p}The internal scan list is cleared before the scan is initiated.{/p}**/
#define wifi_cmd_sme_start_ssid_scan(SSID_LEN,SSID_DATA) \
{\
bglib_temp_msg.cmd_sme_start_ssid_scan.ssid.len=(SSID_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_sme_start_ssid_scan.ssid.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_sme_start_ssid_scan.ssid.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x14<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_start_ssid_scan.ssid.len,(uint8*)SSID_DATA);\
}
/**This command is used to set whether the Access Point is hidden or visible.{p}The Access Point is set visible by default.{/p}**/
#define wifi_cmd_sme_set_ap_hidden(HIDDEN) \
{\
bglib_temp_msg.cmd_sme_set_ap_hidden.hidden=(HIDDEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x15<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to select whether 802.11n mode is enabled or disabled.{p}The mode is enabled by default.{/p}**/
#define wifi_cmd_sme_set_11n_mode(MODE) \
{\
bglib_temp_msg.cmd_sme_set_11n_mode.mode=(MODE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x16<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the EAP configuration, which is used when authenticating with a secure Access Point.**/
#define wifi_cmd_sme_set_eap_configuration(OUTER_TYPE,INNER_TYPE,IDENTITY_LEN,IDENTITY_DATA) \
{\
bglib_temp_msg.cmd_sme_set_eap_configuration.outer_type=(OUTER_TYPE);\
bglib_temp_msg.cmd_sme_set_eap_configuration.inner_type=(INNER_TYPE);\
bglib_temp_msg.cmd_sme_set_eap_configuration.identity.len=(IDENTITY_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+bglib_temp_msg.cmd_sme_set_eap_configuration.identity.len)>>8)))|((((uint32)3+bglib_temp_msg.cmd_sme_set_eap_configuration.identity.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x17<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_set_eap_configuration.identity.len,(uint8*)IDENTITY_DATA);\
}
/**This command is used to set the user name of an EAP type.**/
#define wifi_cmd_sme_set_eap_type_username(TYPE,USERNAME_LEN,USERNAME_DATA) \
{\
bglib_temp_msg.cmd_sme_set_eap_type_username.type=(TYPE);\
bglib_temp_msg.cmd_sme_set_eap_type_username.username.len=(USERNAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sme_set_eap_type_username.username.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sme_set_eap_type_username.username.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x18<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_set_eap_type_username.username.len,(uint8*)USERNAME_DATA);\
}
/**This command is used to set the password of an EAP type.**/
#define wifi_cmd_sme_set_eap_type_password(TYPE,PASSWORD_LEN,PASSWORD_DATA) \
{\
bglib_temp_msg.cmd_sme_set_eap_type_password.type=(TYPE);\
bglib_temp_msg.cmd_sme_set_eap_type_password.password.len=(PASSWORD_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sme_set_eap_type_password.password.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sme_set_eap_type_password.password.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x19<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_set_eap_type_password.password.len,(uint8*)PASSWORD_DATA);\
}
/**This command is used to set the required CA certificate of an EAP type.{p}Connection attempt will fail if the certificate chain given by the authentication server cannot be verified using the provided CA certificate. If no CA certificate has been set, the internal certificate store is checked for a suitable certificate.{/p}**/
#define wifi_cmd_sme_set_eap_type_ca_certificate(TYPE,FINGERPRINT_LEN,FINGERPRINT_DATA) \
{\
bglib_temp_msg.cmd_sme_set_eap_type_ca_certificate.type=(TYPE);\
bglib_temp_msg.cmd_sme_set_eap_type_ca_certificate.fingerprint.len=(FINGERPRINT_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sme_set_eap_type_ca_certificate.fingerprint.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sme_set_eap_type_ca_certificate.fingerprint.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x1a<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_set_eap_type_ca_certificate.fingerprint.len,(uint8*)FINGERPRINT_DATA);\
}
/**This command is used to set the required Common Name of an EAP type.{p}Connection attempt will fail if the Common Name in the server certificate given by the authentication server does not match the set value. If not set, Common Name value is ignored.{/p}**/
#define wifi_cmd_sme_set_eap_type_server_common_name(TYPE,COMMON_NAME_LEN,COMMON_NAME_DATA) \
{\
bglib_temp_msg.cmd_sme_set_eap_type_server_common_name.type=(TYPE);\
bglib_temp_msg.cmd_sme_set_eap_type_server_common_name.common_name.len=(COMMON_NAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sme_set_eap_type_server_common_name.common_name.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sme_set_eap_type_server_common_name.common_name.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x1b<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_set_eap_type_server_common_name.common_name.len,(uint8*)COMMON_NAME_DATA);\
}
/**This command is used to set the client certificate of an EAP type.{p}If set, the certificate will be sent to the authentication server if requested by the server during authentication.{/p}**/
#define wifi_cmd_sme_set_eap_type_user_certificate(TYPE,FINGERPRINT_LEN,FINGERPRINT_DATA) \
{\
bglib_temp_msg.cmd_sme_set_eap_type_user_certificate.type=(TYPE);\
bglib_temp_msg.cmd_sme_set_eap_type_user_certificate.fingerprint.len=(FINGERPRINT_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sme_set_eap_type_user_certificate.fingerprint.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sme_set_eap_type_user_certificate.fingerprint.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x1c<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_set_eap_type_user_certificate.fingerprint.len,(uint8*)FINGERPRINT_DATA);\
}
/**This command is used to start Wi-Fi Direct Group. Before using the command, set the operating mode of the module to 4 by using sme_set_operating_mode.**/
#define wifi_cmd_sme_start_p2p_group(CHANNEL,SSID_LEN,SSID_DATA) \
{\
bglib_temp_msg.cmd_sme_start_p2p_group.channel=(CHANNEL);\
bglib_temp_msg.cmd_sme_start_p2p_group.ssid.len=(SSID_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sme_start_p2p_group.ssid.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sme_start_p2p_group.ssid.len)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x1d<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sme_start_p2p_group.ssid.len,(uint8*)SSID_DATA);\
}
/**This command is used to stop Wi-Fi Direct Group**/
#define wifi_cmd_sme_stop_p2p_group() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x1e<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to accept the pending connection attempt**/
#define wifi_cmd_sme_p2p_accept_client(MAC_ADDRESS) \
{\
memcpy(&bglib_temp_msg.cmd_sme_p2p_accept_client.mac_address,(MAC_ADDRESS),sizeof(hw_addr));\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)6+0)>>8)))|((((uint32)6+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x1f<<24);\
bglib_output(4+6,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to configure clients connected in access point mode**/
#define wifi_cmd_sme_ap_client_config(MAX_CLIENTS,CLEANUP_PERIOD,KEEPALIVE_INTERVAL) \
{\
bglib_temp_msg.cmd_sme_ap_client_config.max_clients=(MAX_CLIENTS);\
bglib_temp_msg.cmd_sme_ap_client_config.cleanup_period=(CLEANUP_PERIOD);\
bglib_temp_msg.cmd_sme_ap_client_config.keepalive_interval=(KEEPALIVE_INTERVAL);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)5+0)>>8)))|((((uint32)5+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x20<<24);\
bglib_output(4+5,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**Set whether Access Points clients are isolated from each other.**/
#define wifi_cmd_sme_set_ap_client_isolation(ISOLATION) \
{\
bglib_temp_msg.cmd_sme_set_ap_client_isolation.isolation=(ISOLATION);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x3<<16)|((uint32)0x21<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to start a TCP server.**/
#define wifi_cmd_tcpip_start_tcp_server(PORT,DEFAULT_DESTINATION) \
{\
bglib_temp_msg.cmd_tcpip_start_tcp_server.port=(PORT);\
bglib_temp_msg.cmd_tcpip_start_tcp_server.default_destination=(DEFAULT_DESTINATION);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+0)>>8)))|((((uint32)3+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x0<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to create a new TCP connection to a TCP server.**/
#define wifi_cmd_tcpip_tcp_connect(ADDRESS,PORT,ROUTING) \
{\
bglib_temp_msg.cmd_tcpip_tcp_connect.address.u=(ADDRESS);\
bglib_temp_msg.cmd_tcpip_tcp_connect.port=(PORT);\
bglib_temp_msg.cmd_tcpip_tcp_connect.routing=(ROUTING);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)7+0)>>8)))|((((uint32)7+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x1<<24);\
bglib_output(4+7,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to start an UDP server.**/
#define wifi_cmd_tcpip_start_udp_server(PORT,DEFAULT_DESTINATION) \
{\
bglib_temp_msg.cmd_tcpip_start_udp_server.port=(PORT);\
bglib_temp_msg.cmd_tcpip_start_udp_server.default_destination=(DEFAULT_DESTINATION);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+0)>>8)))|((((uint32)3+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x2<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to create a new UDP connection.**/
#define wifi_cmd_tcpip_udp_connect(ADDRESS,PORT,ROUTING) \
{\
bglib_temp_msg.cmd_tcpip_udp_connect.address.u=(ADDRESS);\
bglib_temp_msg.cmd_tcpip_udp_connect.port=(PORT);\
bglib_temp_msg.cmd_tcpip_udp_connect.routing=(ROUTING);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)7+0)>>8)))|((((uint32)7+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x3<<24);\
bglib_output(4+7,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to configure IP settings of the device.{p}When enabling DHCP, the IP settings will be stored, but they will be overridden as soon as IP configuration is received from the remote DHCP server.{/p}**/
#define wifi_cmd_tcpip_configure(ADDRESS,NETMASK,GATEWAY,USE_DHCP) \
{\
bglib_temp_msg.cmd_tcpip_configure.address.u=(ADDRESS);\
bglib_temp_msg.cmd_tcpip_configure.netmask.u=(NETMASK);\
bglib_temp_msg.cmd_tcpip_configure.gateway.u=(GATEWAY);\
bglib_temp_msg.cmd_tcpip_configure.use_dhcp=(USE_DHCP);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)13+0)>>8)))|((((uint32)13+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x4<<24);\
bglib_output(4+13,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to configure DNS settings of the device.{p}The primary DNS server is set to 208.67.222.222 (resolver1.opendns.com) by default, the secondary DNS server is zero.{/p}**/
#define wifi_cmd_tcpip_dns_configure(INDEX,ADDRESS) \
{\
bglib_temp_msg.cmd_tcpip_dns_configure.index=(INDEX);\
bglib_temp_msg.cmd_tcpip_dns_configure.address.u=(ADDRESS);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)5+0)>>8)))|((((uint32)5+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x5<<24);\
bglib_output(4+5,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to resolve the IP address of a domain name using the configured DNS servers.**/
#define wifi_cmd_tcpip_dns_gethostbyname(NAME_LEN,NAME_DATA) \
{\
bglib_temp_msg.cmd_tcpip_dns_gethostbyname.name.len=(NAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_tcpip_dns_gethostbyname.name.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_tcpip_dns_gethostbyname.name.len)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x6<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_tcpip_dns_gethostbyname.name.len,(uint8*)NAME_DATA);\
}
/**This command is used to change the source port of an existing UDP endpoint.**/
#define wifi_cmd_tcpip_udp_bind(ENDPOINT,PORT) \
{\
bglib_temp_msg.cmd_tcpip_udp_bind.endpoint=(ENDPOINT);\
bglib_temp_msg.cmd_tcpip_udp_bind.port=(PORT);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+0)>>8)))|((((uint32)3+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x7<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the DHCP host name parameter (option 12) used in client DHCPDISCOVER and DHCPREQUEST messages.**/
#define wifi_cmd_tcpip_dhcp_set_hostname(HOSTNAME_LEN,HOSTNAME_DATA) \
{\
bglib_temp_msg.cmd_tcpip_dhcp_set_hostname.hostname.len=(HOSTNAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_tcpip_dhcp_set_hostname.hostname.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_tcpip_dhcp_set_hostname.hostname.len)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x8<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_tcpip_dhcp_set_hostname.hostname.len,(uint8*)HOSTNAME_DATA);\
}
/**This command is used to create a new TLS connection to a TLS server. {p}Only one TLS connection at a time is feasible{/p} **/
#define wifi_cmd_tcpip_tls_connect(ADDRESS,PORT,ROUTING) \
{\
bglib_temp_msg.cmd_tcpip_tls_connect.address.u=(ADDRESS);\
bglib_temp_msg.cmd_tcpip_tls_connect.port=(PORT);\
bglib_temp_msg.cmd_tcpip_tls_connect.routing=(ROUTING);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)7+0)>>8)))|((((uint32)7+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x9<<24);\
bglib_output(4+7,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the TLS certificate verification mode.{p}The mode must be set before calling the {a href="#cmd_tcpip_tls_connect"}tcpip_tls_connect{/a} command. If the verification mode has been set to optional or mandatory, the server certificate is verified against a root certificate from the built-in certificate store during TLS connection setup. The verification result is indicated with the {a href="#evt_tcpip_tls_verify_result"}evt_tcpip_tls_verify_result{/a} event.{/p}{p}The verification mode is set to mandatory by default.{/p}**/
#define wifi_cmd_tcpip_tls_set_authmode(AUTH_MODE) \
{\
bglib_temp_msg.cmd_tcpip_tls_set_authmode.auth_mode=(AUTH_MODE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0xa<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set whether the built-in DHCP server responses include gateway and DNS server information.{p}Gateway and DNS information is included by default.{/p}**/
#define wifi_cmd_tcpip_dhcp_enable_routing(ENABLE) \
{\
bglib_temp_msg.cmd_tcpip_dhcp_enable_routing.enable=(ENABLE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0xb<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the mDNS host name.**/
#define wifi_cmd_tcpip_mdns_set_hostname(HOSTNAME_LEN,HOSTNAME_DATA) \
{\
bglib_temp_msg.cmd_tcpip_mdns_set_hostname.hostname.len=(HOSTNAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_tcpip_mdns_set_hostname.hostname.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_tcpip_mdns_set_hostname.hostname.len)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0xc<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_tcpip_mdns_set_hostname.hostname.len,(uint8*)HOSTNAME_DATA);\
}
/**This command is used to start the mDNS service.{p}The mDNS service cannot be started until the host name has been set using the {a href="#cmd_tcpip_mdns_set_hostname"}tcpip_mdns_set_hostname{/a} command.{/p}**/
#define wifi_cmd_tcpip_mdns_start() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0xd<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to stop the mDNS service.**/
#define wifi_cmd_tcpip_mdns_stop() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0xe<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to add a new DNS-SD service.{p}The maximum amount of DNS-SD services is 3.{/p}**/
#define wifi_cmd_tcpip_dnssd_add_service(PORT,PROTOCOL,SERVICE_LEN,SERVICE_DATA) \
{\
bglib_temp_msg.cmd_tcpip_dnssd_add_service.port=(PORT);\
bglib_temp_msg.cmd_tcpip_dnssd_add_service.protocol=(PROTOCOL);\
bglib_temp_msg.cmd_tcpip_dnssd_add_service.service.len=(SERVICE_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)4+bglib_temp_msg.cmd_tcpip_dnssd_add_service.service.len)>>8)))|((((uint32)4+bglib_temp_msg.cmd_tcpip_dnssd_add_service.service.len)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0xf<<24);\
bglib_output(4+4,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_tcpip_dnssd_add_service.service.len,(uint8*)SERVICE_DATA);\
}
/**This command is used to set the instance name of a DNS-SD service.**/
#define wifi_cmd_tcpip_dnssd_add_service_instance(INDEX,INSTANCE_LEN,INSTANCE_DATA) \
{\
bglib_temp_msg.cmd_tcpip_dnssd_add_service_instance.index=(INDEX);\
bglib_temp_msg.cmd_tcpip_dnssd_add_service_instance.instance.len=(INSTANCE_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_tcpip_dnssd_add_service_instance.instance.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_tcpip_dnssd_add_service_instance.instance.len)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x10<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_tcpip_dnssd_add_service_instance.instance.len,(uint8*)INSTANCE_DATA);\
}
/**This command is used to add a service attribute to a DNS-SD service.{p}One DNS-SD service can contain multiple service attributes. The maximum combined length of service attributes is 64 bytes.{/p}**/
#define wifi_cmd_tcpip_dnssd_add_service_attribute(INDEX,ATTRIBUTE_LEN,ATTRIBUTE_DATA) \
{\
bglib_temp_msg.cmd_tcpip_dnssd_add_service_attribute.index=(INDEX);\
bglib_temp_msg.cmd_tcpip_dnssd_add_service_attribute.attribute.len=(ATTRIBUTE_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_tcpip_dnssd_add_service_attribute.attribute.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_tcpip_dnssd_add_service_attribute.attribute.len)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x11<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_tcpip_dnssd_add_service_attribute.attribute.len,(uint8*)ATTRIBUTE_DATA);\
}
/**This command is used to remove a DNS-SD service.**/
#define wifi_cmd_tcpip_dnssd_remove_service(INDEX) \
{\
bglib_temp_msg.cmd_tcpip_dnssd_remove_service.index=(INDEX);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x12<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to start a DNS-SD service.{p}The DNS-SD service cannot be started until the instance name has been set using the {a href="#cmd_tcpip_dnssd_add_service_instance"}tcpip_dnssd_add_service_instance{/a} command.{/p}**/
#define wifi_cmd_tcpip_dnssd_start_service(INDEX) \
{\
bglib_temp_msg.cmd_tcpip_dnssd_start_service.index=(INDEX);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x13<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to stop a DNS-SD service.**/
#define wifi_cmd_tcpip_dnssd_stop_service(INDEX) \
{\
bglib_temp_msg.cmd_tcpip_dnssd_stop_service.index=(INDEX);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x14<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to join a multicast group. {p}Maximum number of multicast groups that can be joined is 4. Use 224.0.0.2 - 224.0.0.254 as address range. Note that 224.0.0.1 is automatically joined.{/p}**/
#define wifi_cmd_tcpip_multicast_join(ADDRESS) \
{\
bglib_temp_msg.cmd_tcpip_multicast_join.address.u=(ADDRESS);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)4+0)>>8)))|((((uint32)4+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x15<<24);\
bglib_output(4+4,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to leave a multicast group.**/
#define wifi_cmd_tcpip_multicast_leave(ADDRESS) \
{\
bglib_temp_msg.cmd_tcpip_multicast_leave.address.u=(ADDRESS);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)4+0)>>8)))|((((uint32)4+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x16<<24);\
bglib_output(4+4,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the client certificate for a TLS connection.{p}If set, the certificate will be sent to the TLS server if requested by the server during authentication.{/p}**/
#define wifi_cmd_tcpip_tls_set_user_certificate(FINGERPRINT_LEN,FINGERPRINT_DATA) \
{\
bglib_temp_msg.cmd_tcpip_tls_set_user_certificate.fingerprint.len=(FINGERPRINT_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_tcpip_tls_set_user_certificate.fingerprint.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_tcpip_tls_set_user_certificate.fingerprint.len)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x17<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_tcpip_tls_set_user_certificate.fingerprint.len,(uint8*)FINGERPRINT_DATA);\
}
/**This command is used to configure the DHCP Server**/
#define wifi_cmd_tcpip_dhcp_configure(ADDRESS,SUBNET_MASK,LEASE_TIME) \
{\
bglib_temp_msg.cmd_tcpip_dhcp_configure.address.u=(ADDRESS);\
bglib_temp_msg.cmd_tcpip_dhcp_configure.subnet_mask.u=(SUBNET_MASK);\
bglib_temp_msg.cmd_tcpip_dhcp_configure.lease_time=(LEASE_TIME);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)12+0)>>8)))|((((uint32)12+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x18<<24);\
bglib_output(4+12,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to resolve the IP address of a domain name using Multicast DNS (MDNS).**/
#define wifi_cmd_tcpip_mdns_gethostbyname(NAME_LEN,NAME_DATA) \
{\
bglib_temp_msg.cmd_tcpip_mdns_gethostbyname.name.len=(NAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_tcpip_mdns_gethostbyname.name.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_tcpip_mdns_gethostbyname.name.len)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x19<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_tcpip_mdns_gethostbyname.name.len,(uint8*)NAME_DATA);\
}
/**This command is used to read mac and ip addresses of connected clients in Access Point mode**/
#define wifi_cmd_tcpip_dhcp_clients() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x4<<16)|((uint32)0x1a<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to send data to a given endpoint.**/
#define wifi_cmd_endpoint_send(ENDPOINT,DATA_LEN,DATA_DATA) \
{\
bglib_temp_msg.cmd_endpoint_send.endpoint=(ENDPOINT);\
bglib_temp_msg.cmd_endpoint_send.data.len=(DATA_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_endpoint_send.data.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_endpoint_send.data.len)&0xff)<<8)|((uint32)0x5<<16)|((uint32)0x0<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_endpoint_send.data.len,(uint8*)DATA_DATA);\
}
/**This command is used to switch an endpoint between streaming or BGAPI modes.{p}When an endpoint is in streaming mode, received data is passed unmodified to another endpoint such as TCP and sent data written as-is to a peripheral interface. In BGAPI mode, received data is handled as BGAPI protocol messages and sent data is encapsulated in {a href="#evt_endpoint_data"}evt_endpoint_data{/a} events.{/p}{p}This command can currently be used only with UART endpoints. If the switch from streaming to BGAPI mode is made while there is incoming or outgoing UART data, data loss may occur.{/p}**/
#define wifi_cmd_endpoint_set_streaming(ENDPOINT,STREAMING) \
{\
bglib_temp_msg.cmd_endpoint_set_streaming.endpoint=(ENDPOINT);\
bglib_temp_msg.cmd_endpoint_set_streaming.streaming=(STREAMING);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+0)>>8)))|((((uint32)2+0)&0xff)<<8)|((uint32)0x5<<16)|((uint32)0x1<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to activate or deactivate endpoints.{p}Configured endpoints are active by default, i.e., you can send data to them, and data can be received from them. This command allows you to temporarily halt the outgoing data from an endpoint by deactivating it. For example, deactivating a BGAPI UART endpoint will prevent BGAPI events and responses from being sent out of the UART interface. Similarly, deactivating the BGScript endpoint will prevent events from being passed to the script, thus preventing the calls from being executed.{/p}**/
#define wifi_cmd_endpoint_set_active(ENDPOINT,ACTIVE) \
{\
bglib_temp_msg.cmd_endpoint_set_active.endpoint=(ENDPOINT);\
bglib_temp_msg.cmd_endpoint_set_active.active=(ACTIVE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+0)>>8)))|((((uint32)2+0)&0xff)<<8)|((uint32)0x5<<16)|((uint32)0x2<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the destination endpoint to which the received data from an endpoint will be routed to.{p}The command is only applicable for endpoints that can be configured in streaming mode.{/p}**/
#define wifi_cmd_endpoint_set_streaming_destination(ENDPOINT,DESTINATION_ENDPOINT) \
{\
bglib_temp_msg.cmd_endpoint_set_streaming_destination.endpoint=(ENDPOINT);\
bglib_temp_msg.cmd_endpoint_set_streaming_destination.destination_endpoint=(DESTINATION_ENDPOINT);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+0)>>8)))|((((uint32)2+0)&0xff)<<8)|((uint32)0x5<<16)|((uint32)0x3<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to close a protocol endpoint.{p}The command must only be used for protocol endpoints such as TCP, UDP and TLS endpoints.{/p}{p}TCP server endpoint close is denied when one or more clients are connected to the server{/p}**/
#define wifi_cmd_endpoint_close(ENDPOINT) \
{\
bglib_temp_msg.cmd_endpoint_close.endpoint=(ENDPOINT);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x5<<16)|((uint32)0x4<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the desired transmit size of a protocol endpoint.{p}If defined, the endpoint will buffer outgoing data until transmit size is reached and send the data to remote end. This is meant for UDP endpoints and must not be used with any other type of endpoint, including TCP. Transmit size is not set by default.{/p}**/
#define wifi_cmd_endpoint_set_transmit_size(ENDPOINT,SIZE) \
{\
bglib_temp_msg.cmd_endpoint_set_transmit_size.endpoint=(ENDPOINT);\
bglib_temp_msg.cmd_endpoint_set_transmit_size.size=(SIZE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+0)>>8)))|((((uint32)3+0)&0xff)<<8)|((uint32)0x5<<16)|((uint32)0x5<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to disable an UART endpoint.{p}The command effectively switches off an UART interface until the device is reset or power-cycled. When an UART interface is disabled its pins go to high-impedance state.{/p}**/
#define wifi_cmd_endpoint_disable(ENDPOINT) \
{\
bglib_temp_msg.cmd_endpoint_disable.endpoint=(ENDPOINT);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x5<<16)|((uint32)0x6<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to enable a software timer.{p}Multiple concurrent timers can be running simultaneously as long as an unique handle is used for each.{/p}**/
#define wifi_cmd_hardware_set_soft_timer(TIME,HANDLE,SINGLE_SHOT) \
{\
bglib_temp_msg.cmd_hardware_set_soft_timer.time=(TIME);\
bglib_temp_msg.cmd_hardware_set_soft_timer.handle=(HANDLE);\
bglib_temp_msg.cmd_hardware_set_soft_timer.single_shot=(SINGLE_SHOT);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)6+0)>>8)))|((((uint32)6+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0x0<<24);\
bglib_output(4+6,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to configure the mode of a specified I/O pin.**/
#define wifi_cmd_hardware_configure_gpio(PORT,PIN,MODE,OUTPUT) \
{\
bglib_temp_msg.cmd_hardware_configure_gpio.port=(PORT);\
bglib_temp_msg.cmd_hardware_configure_gpio.pin=(PIN);\
bglib_temp_msg.cmd_hardware_configure_gpio.mode=(MODE);\
bglib_temp_msg.cmd_hardware_configure_gpio.output=(OUTPUT);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)4+0)>>8)))|((((uint32)4+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0x1<<24);\
bglib_output(4+4,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to configure an interrupt on a specified I/O pin.**/
#define wifi_cmd_hardware_configure_gpio_interrupt(PORT,PIN,TRIGGER) \
{\
bglib_temp_msg.cmd_hardware_configure_gpio_interrupt.port=(PORT);\
bglib_temp_msg.cmd_hardware_configure_gpio_interrupt.pin=(PIN);\
bglib_temp_msg.cmd_hardware_configure_gpio_interrupt.trigger=(TRIGGER);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+0)>>8)))|((((uint32)3+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0x2<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the logic state of pins on a specified I/O-port.**/
#define wifi_cmd_hardware_write_gpio(PORT,MASK,DATA) \
{\
bglib_temp_msg.cmd_hardware_write_gpio.port=(PORT);\
bglib_temp_msg.cmd_hardware_write_gpio.mask=(MASK);\
bglib_temp_msg.cmd_hardware_write_gpio.data=(DATA);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)5+0)>>8)))|((((uint32)5+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0x3<<24);\
bglib_output(4+5,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to read the logic state of pins of a specified I/O-port.**/
#define wifi_cmd_hardware_read_gpio(PORT,MASK) \
{\
bglib_temp_msg.cmd_hardware_read_gpio.port=(PORT);\
bglib_temp_msg.cmd_hardware_read_gpio.mask=(MASK);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+0)>>8)))|((((uint32)3+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0x4<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to configure a hardware timer.{p}The timer clock signal is derived from the peripheral clock signal using the prescale factor. The timer counter is increased by one at every clock cycle. When the timer reaches the configured maximum value, it wraps around to zero and continues counting.{/p}**/
#define wifi_cmd_hardware_timer_init(INDEX,LOCATION,PRESCALE,TOP_VALUE) \
{\
bglib_temp_msg.cmd_hardware_timer_init.index=(INDEX);\
bglib_temp_msg.cmd_hardware_timer_init.location=(LOCATION);\
bglib_temp_msg.cmd_hardware_timer_init.prescale=(PRESCALE);\
bglib_temp_msg.cmd_hardware_timer_init.top_value=(TOP_VALUE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)6+0)>>8)))|((((uint32)6+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0x5<<24);\
bglib_output(4+6,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to configure a hardware timer compare channel.{p}In PWM mode, the compare channel pin will be held high until the timer reaches the configured compare value, at which point the pin will be set low until the timer reaches the configured maximum value. After reaching the maximum value, the timer wraps around to zero and the cycle restarts.{/p}**/
#define wifi_cmd_hardware_timer_initcc(INDEX,CHANNEL,MODE,COMPARE_VALUE) \
{\
bglib_temp_msg.cmd_hardware_timer_initcc.index=(INDEX);\
bglib_temp_msg.cmd_hardware_timer_initcc.channel=(CHANNEL);\
bglib_temp_msg.cmd_hardware_timer_initcc.mode=(MODE);\
bglib_temp_msg.cmd_hardware_timer_initcc.compare_value=(COMPARE_VALUE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)5+0)>>8)))|((((uint32)5+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0x6<<24);\
bglib_output(4+5,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to trigger a single ADC sample conversion.{p}Conversion parameters are 12-bit resolution and 32 clock cycle conversion time.{/p}**/
#define wifi_cmd_hardware_adc_read(INPUT) \
{\
bglib_temp_msg.cmd_hardware_adc_read.input=(INPUT);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0x7<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to enable or disable the Real Time Clock.{p}The clock must be initialized using the {a href="#cmd_hardware_rtc_set_time"}hardware_rtc_set_time{/a} command before it can be used.{/p}**/
#define wifi_cmd_hardware_rtc_init(ENABLE) \
{\
bglib_temp_msg.cmd_hardware_rtc_init.enable=(ENABLE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0x8<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set the current Real Time Clock time.**/
#define wifi_cmd_hardware_rtc_set_time(YEAR,MONTH,DAY,HOUR,MINUTE,SECOND) \
{\
bglib_temp_msg.cmd_hardware_rtc_set_time.year=(YEAR);\
bglib_temp_msg.cmd_hardware_rtc_set_time.month=(MONTH);\
bglib_temp_msg.cmd_hardware_rtc_set_time.day=(DAY);\
bglib_temp_msg.cmd_hardware_rtc_set_time.hour=(HOUR);\
bglib_temp_msg.cmd_hardware_rtc_set_time.minute=(MINUTE);\
bglib_temp_msg.cmd_hardware_rtc_set_time.second=(SECOND);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)7+0)>>8)))|((((uint32)7+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0x9<<24);\
bglib_output(4+7,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to read the current Real Time Clock (RTC) time.**/
#define wifi_cmd_hardware_rtc_get_time() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0xa<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to set an alarm for the Real Time Clock.{p}Only one alarm can be active at one time. The alarm can be disabled by disabling the Real Time Clock using the {a href="#cmd_hardware_rtc_init"}hardware_rtc_init{/a} command.{/p}**/
#define wifi_cmd_hardware_rtc_set_alarm(YEAR,MONTH,DAY,HOUR,MINUTE,SECOND) \
{\
bglib_temp_msg.cmd_hardware_rtc_set_alarm.year=(YEAR);\
bglib_temp_msg.cmd_hardware_rtc_set_alarm.month=(MONTH);\
bglib_temp_msg.cmd_hardware_rtc_set_alarm.day=(DAY);\
bglib_temp_msg.cmd_hardware_rtc_set_alarm.hour=(HOUR);\
bglib_temp_msg.cmd_hardware_rtc_set_alarm.minute=(MINUTE);\
bglib_temp_msg.cmd_hardware_rtc_set_alarm.second=(SECOND);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)7+0)>>8)))|((((uint32)7+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0xb<<24);\
bglib_output(4+7,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to configure a UART interface.**/
#define wifi_cmd_hardware_uart_conf_set(ID,RATE,DATA_BITS,STOP_BITS,PARITY,FLOW_CTRL) \
{\
bglib_temp_msg.cmd_hardware_uart_conf_set.id=(ID);\
bglib_temp_msg.cmd_hardware_uart_conf_set.rate=(RATE);\
bglib_temp_msg.cmd_hardware_uart_conf_set.data_bits=(DATA_BITS);\
bglib_temp_msg.cmd_hardware_uart_conf_set.stop_bits=(STOP_BITS);\
bglib_temp_msg.cmd_hardware_uart_conf_set.parity=(PARITY);\
bglib_temp_msg.cmd_hardware_uart_conf_set.flow_ctrl=(FLOW_CTRL);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)9+0)>>8)))|((((uint32)9+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0xc<<24);\
bglib_output(4+9,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to read the current configuration of a UART interface.**/
#define wifi_cmd_hardware_uart_conf_get(ID) \
{\
bglib_temp_msg.cmd_hardware_uart_conf_get.id=(ID);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0xd<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to transfer data using an SPI interface.{p}The command can only be used when the interface is in SPI master mode. Due to synchronous full duplex nature of SPI, the command response will contain the same amount of read bytes as was written.{/p}**/
#define wifi_cmd_hardware_spi_transfer(CHANNEL,DATA_LEN,DATA_DATA) \
{\
bglib_temp_msg.cmd_hardware_spi_transfer.channel=(CHANNEL);\
bglib_temp_msg.cmd_hardware_spi_transfer.data.len=(DATA_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_hardware_spi_transfer.data.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_hardware_spi_transfer.data.len)&0xff)<<8)|((uint32)0x6<<16)|((uint32)0xe<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_hardware_spi_transfer.data.len,(uint8*)DATA_DATA);\
}
/**This command is used to manually initiate the defragmentation of the Persistent Store.{p}The Persistent Store is automatically defragmented if there is not enough space when adding a PS key.{/p}**/
#define wifi_cmd_flash_ps_defrag() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x7<<16)|((uint32)0x0<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to dump all the PS keys from the Persistent Store.{p}The command will generate a series of PS key events. The last PS key event is identified by the key index value 65535, indicating that the dump has finished listing all PS keys.{/p}**/
#define wifi_cmd_flash_ps_dump() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x7<<16)|((uint32)0x1<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to erase all PS keys from the Persistent Store.{p}The command removes all system and user keys except the MAC address.{/p}**/
#define wifi_cmd_flash_ps_erase_all() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0x7<<16)|((uint32)0x2<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to store a value in the Persistent Store.**/
#define wifi_cmd_flash_ps_save(KEY,VALUE_LEN,VALUE_DATA) \
{\
bglib_temp_msg.cmd_flash_ps_save.key=(KEY);\
bglib_temp_msg.cmd_flash_ps_save.value.len=(VALUE_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+bglib_temp_msg.cmd_flash_ps_save.value.len)>>8)))|((((uint32)3+bglib_temp_msg.cmd_flash_ps_save.value.len)&0xff)<<8)|((uint32)0x7<<16)|((uint32)0x3<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_flash_ps_save.value.len,(uint8*)VALUE_DATA);\
}
/**This command is used to retrieve the value of a PS key from the Persistent Store.**/
#define wifi_cmd_flash_ps_load(KEY) \
{\
bglib_temp_msg.cmd_flash_ps_load.key=(KEY);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+0)>>8)))|((((uint32)2+0)&0xff)<<8)|((uint32)0x7<<16)|((uint32)0x4<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to erase a single PS key and its value from the Persistent Store.**/
#define wifi_cmd_flash_ps_erase(KEY) \
{\
bglib_temp_msg.cmd_flash_ps_erase.key=(KEY);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+0)>>8)))|((((uint32)2+0)&0xff)<<8)|((uint32)0x7<<16)|((uint32)0x5<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to start an I2C transaction for reading data.{p}The transaction must be terminated with the {a href="#cmd_i2c_stop"}i2c_stop{/a} command.{/p}**/
#define wifi_cmd_i2c_start_read(CHANNEL,SLAVE_ADDRESS,LENGTH) \
{\
bglib_temp_msg.cmd_i2c_start_read.channel=(CHANNEL);\
bglib_temp_msg.cmd_i2c_start_read.slave_address=(SLAVE_ADDRESS);\
bglib_temp_msg.cmd_i2c_start_read.length=(LENGTH);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+0)>>8)))|((((uint32)3+0)&0xff)<<8)|((uint32)0x8<<16)|((uint32)0x0<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to start an I2C transaction for writing data.{p}The transaction must be terminated with the {a href="#cmd_i2c_stop"}i2c_stop{/a} command.{/p}**/
#define wifi_cmd_i2c_start_write(CHANNEL,SLAVE_ADDRESS,DATA_LEN,DATA_DATA) \
{\
bglib_temp_msg.cmd_i2c_start_write.channel=(CHANNEL);\
bglib_temp_msg.cmd_i2c_start_write.slave_address=(SLAVE_ADDRESS);\
bglib_temp_msg.cmd_i2c_start_write.data.len=(DATA_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+bglib_temp_msg.cmd_i2c_start_write.data.len)>>8)))|((((uint32)3+bglib_temp_msg.cmd_i2c_start_write.data.len)&0xff)<<8)|((uint32)0x8<<16)|((uint32)0x1<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_i2c_start_write.data.len,(uint8*)DATA_DATA);\
}
/**This command is used to stop a read or write I2C transaction.**/
#define wifi_cmd_i2c_stop(CHANNEL) \
{\
bglib_temp_msg.cmd_i2c_stop.channel=(CHANNEL);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0x8<<16)|((uint32)0x2<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to enable or disable built-in HTTP, DHCP or DNS servers.**/
#define wifi_cmd_https_enable(HTTPS,DHCPS,DNSS) \
{\
bglib_temp_msg.cmd_https_enable.https=(HTTPS);\
bglib_temp_msg.cmd_https_enable.dhcps=(DHCPS);\
bglib_temp_msg.cmd_https_enable.dnss=(DNSS);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+0)>>8)))|((((uint32)3+0)&0xff)<<8)|((uint32)0x9<<16)|((uint32)0x0<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to add a mapping between an HTTP server path and a resource.**/
#define wifi_cmd_https_add_path(RESOURCE,PATH_LEN,PATH_DATA) \
{\
bglib_temp_msg.cmd_https_add_path.resource=(RESOURCE);\
bglib_temp_msg.cmd_https_add_path.path.len=(PATH_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_https_add_path.path.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_https_add_path.path.len)&0xff)<<8)|((uint32)0x9<<16)|((uint32)0x1<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_https_add_path.path.len,(uint8*)PATH_DATA);\
}
/**This command is used to send HTTP response data to a pending HTTP request.**/
#define wifi_cmd_https_api_response(REQUEST,DATA_LEN,DATA_DATA) \
{\
bglib_temp_msg.cmd_https_api_response.request=(REQUEST);\
bglib_temp_msg.cmd_https_api_response.data.len=(DATA_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)5+bglib_temp_msg.cmd_https_api_response.data.len)>>8)))|((((uint32)5+bglib_temp_msg.cmd_https_api_response.data.len)&0xff)<<8)|((uint32)0x9<<16)|((uint32)0x2<<24);\
bglib_output(4+5,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_https_api_response.data.len,(uint8*)DATA_DATA);\
}
/**This command is used to signal that all HTTP response data has been sent and that the pending HTTP request can be closed.**/
#define wifi_cmd_https_api_response_finish(REQUEST) \
{\
bglib_temp_msg.cmd_https_api_response_finish.request=(REQUEST);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)4+0)>>8)))|((((uint32)4+0)&0xff)<<8)|((uint32)0x9<<16)|((uint32)0x3<<24);\
bglib_output(4+4,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**Set wired Ethernet data route**/
#define wifi_cmd_ethernet_set_dataroute(ROUTE) \
{\
bglib_temp_msg.cmd_ethernet_set_dataroute.route=(ROUTE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0xa<<16)|((uint32)0x0<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**Close wired Ethernet connection**/
#define wifi_cmd_ethernet_close() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0xa<<16)|((uint32)0x1<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**Test wired Ethernet cable connection**/
#define wifi_cmd_ethernet_connected() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0xa<<16)|((uint32)0x2<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to reset the certificate stores.{p}Flash and RAM stores are erased and the modifications to the compile-time store are reset.{/p}**/
#define wifi_cmd_x509_reset_store() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0xb<<16)|((uint32)0x0<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to add a certificate to a certificate store.**/
#define wifi_cmd_x509_add_certificate(STORE,SIZE) \
{\
bglib_temp_msg.cmd_x509_add_certificate.store=(STORE);\
bglib_temp_msg.cmd_x509_add_certificate.size=(SIZE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+0)>>8)))|((((uint32)3+0)&0xff)<<8)|((uint32)0xb<<16)|((uint32)0x1<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to upload a block of certificate data.**/
#define wifi_cmd_x509_add_certificate_data(DATA_LEN,DATA_DATA) \
{\
bglib_temp_msg.cmd_x509_add_certificate_data.data.len=(DATA_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_x509_add_certificate_data.data.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_x509_add_certificate_data.data.len)&0xff)<<8)|((uint32)0xb<<16)|((uint32)0x2<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_x509_add_certificate_data.data.len,(uint8*)DATA_DATA);\
}
/**This command is used to finish adding a certificate.{p}The command must be called once all the certificate data has been uploaded.{/p}**/
#define wifi_cmd_x509_add_certificate_finish() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0xb<<16)|((uint32)0x3<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to add a private key to the RAM certificate store.**/
#define wifi_cmd_x509_add_private_key(SIZE,FINGERPRINT_LEN,FINGERPRINT_DATA) \
{\
bglib_temp_msg.cmd_x509_add_private_key.size=(SIZE);\
bglib_temp_msg.cmd_x509_add_private_key.fingerprint.len=(FINGERPRINT_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+bglib_temp_msg.cmd_x509_add_private_key.fingerprint.len)>>8)))|((((uint32)3+bglib_temp_msg.cmd_x509_add_private_key.fingerprint.len)&0xff)<<8)|((uint32)0xb<<16)|((uint32)0x4<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_x509_add_private_key.fingerprint.len,(uint8*)FINGERPRINT_DATA);\
}
/**This command is used to upload a block of private key data.**/
#define wifi_cmd_x509_add_private_key_data(DATA_LEN,DATA_DATA) \
{\
bglib_temp_msg.cmd_x509_add_private_key_data.data.len=(DATA_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_x509_add_private_key_data.data.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_x509_add_private_key_data.data.len)&0xff)<<8)|((uint32)0xb<<16)|((uint32)0x5<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_x509_add_private_key_data.data.len,(uint8*)DATA_DATA);\
}
/**This command is used to finish adding a private key.{p}The command must be called once all the private key data has been uploaded.{/p}**/
#define wifi_cmd_x509_add_private_key_finish(PASSWORD_LEN,PASSWORD_DATA) \
{\
bglib_temp_msg.cmd_x509_add_private_key_finish.password.len=(PASSWORD_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_x509_add_private_key_finish.password.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_x509_add_private_key_finish.password.len)&0xff)<<8)|((uint32)0xb<<16)|((uint32)0x6<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_x509_add_private_key_finish.password.len,(uint8*)PASSWORD_DATA);\
}
/**This command is used to delete a certificate from the certificate store.**/
#define wifi_cmd_x509_delete_certificate(FINGERPRINT_LEN,FINGERPRINT_DATA) \
{\
bglib_temp_msg.cmd_x509_delete_certificate.fingerprint.len=(FINGERPRINT_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_x509_delete_certificate.fingerprint.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_x509_delete_certificate.fingerprint.len)&0xff)<<8)|((uint32)0xb<<16)|((uint32)0x7<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_x509_delete_certificate.fingerprint.len,(uint8*)FINGERPRINT_DATA);\
}
/**This command is used to retrieve information about added certificates.**/
#define wifi_cmd_x509_list_certificates() \
{\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)0+0)>>8)))|((((uint32)0+0)&0xff)<<8)|((uint32)0xb<<16)|((uint32)0x8<<24);\
bglib_output(4+0,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to open a file.{p}The maximum amount of open files is 10.{/p}**/
#define wifi_cmd_sdhc_fopen(MODE,FNAME_LEN,FNAME_DATA) \
{\
bglib_temp_msg.cmd_sdhc_fopen.mode=(MODE);\
bglib_temp_msg.cmd_sdhc_fopen.fname.len=(FNAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sdhc_fopen.fname.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sdhc_fopen.fname.len)&0xff)<<8)|((uint32)0xc<<16)|((uint32)0x0<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sdhc_fopen.fname.len,(uint8*)FNAME_DATA);\
}
/**This command is used to close an open file.**/
#define wifi_cmd_sdhc_fclose(FHANDLE) \
{\
bglib_temp_msg.cmd_sdhc_fclose.fhandle=(FHANDLE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+0)>>8)))|((((uint32)1+0)&0xff)<<8)|((uint32)0xc<<16)|((uint32)0x1<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to list files of a directory.{p}The command also lists files and folders with the hidden attribute set.{/p}**/
#define wifi_cmd_sdhc_fdir(MODE,PATH_LEN,PATH_DATA) \
{\
bglib_temp_msg.cmd_sdhc_fdir.mode=(MODE);\
bglib_temp_msg.cmd_sdhc_fdir.path.len=(PATH_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sdhc_fdir.path.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sdhc_fdir.path.len)&0xff)<<8)|((uint32)0xc<<16)|((uint32)0x2<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sdhc_fdir.path.len,(uint8*)PATH_DATA);\
}
/**This command is used to read data from a file.{p}The read data is sent in multiple {a href="#evt_sdhc_fdata"}evt_sdhc_fdata{/a} events, each containing up to 512 bytes of data.{/p}**/
#define wifi_cmd_sdhc_fread(FHANDLE,FSIZE) \
{\
bglib_temp_msg.cmd_sdhc_fread.fhandle=(FHANDLE);\
bglib_temp_msg.cmd_sdhc_fread.fsize=(FSIZE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)5+0)>>8)))|((((uint32)5+0)&0xff)<<8)|((uint32)0xc<<16)|((uint32)0x3<<24);\
bglib_output(4+5,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
/**This command is used to a write a block of data to a file.{p}The data will be appended to the end of the file.{/p}**/
#define wifi_cmd_sdhc_fwrite(FHANDLE,FDATA_LEN,FDATA_DATA) \
{\
bglib_temp_msg.cmd_sdhc_fwrite.fhandle=(FHANDLE);\
bglib_temp_msg.cmd_sdhc_fwrite.fdata.len=(FDATA_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)3+bglib_temp_msg.cmd_sdhc_fwrite.fdata.len)>>8)))|((((uint32)3+bglib_temp_msg.cmd_sdhc_fwrite.fdata.len)&0xff)<<8)|((uint32)0xc<<16)|((uint32)0x4<<24);\
bglib_output(4+3,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sdhc_fwrite.fdata.len,(uint8*)FDATA_DATA);\
}
/**This command is used to delete a file or an empty subdirectory in current active directory.**/
#define wifi_cmd_sdhc_fdelete(FNAME_LEN,FNAME_DATA) \
{\
bglib_temp_msg.cmd_sdhc_fdelete.fname.len=(FNAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_sdhc_fdelete.fname.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_sdhc_fdelete.fname.len)&0xff)<<8)|((uint32)0xc<<16)|((uint32)0x5<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sdhc_fdelete.fname.len,(uint8*)FNAME_DATA);\
}
/**This command is used to create a directory.**/
#define wifi_cmd_sdhc_fmkdir(DIR_NAME_LEN,DIR_NAME_DATA) \
{\
bglib_temp_msg.cmd_sdhc_fmkdir.dir_name.len=(DIR_NAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_sdhc_fmkdir.dir_name.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_sdhc_fmkdir.dir_name.len)&0xff)<<8)|((uint32)0xc<<16)|((uint32)0x6<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sdhc_fmkdir.dir_name.len,(uint8*)DIR_NAME_DATA);\
}
/**This command is used to change the active directory.**/
#define wifi_cmd_sdhc_fchdir(DIR_NAME_LEN,DIR_NAME_DATA) \
{\
bglib_temp_msg.cmd_sdhc_fchdir.dir_name.len=(DIR_NAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_sdhc_fchdir.dir_name.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_sdhc_fchdir.dir_name.len)&0xff)<<8)|((uint32)0xc<<16)|((uint32)0x7<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sdhc_fchdir.dir_name.len,(uint8*)DIR_NAME_DATA);\
}
/**This command is used to rename a file in the current active directory.**/
#define wifi_cmd_sdhc_frename(FHANDLE,NEW_NAME_LEN,NEW_NAME_DATA) \
{\
bglib_temp_msg.cmd_sdhc_frename.fhandle=(FHANDLE);\
bglib_temp_msg.cmd_sdhc_frename.new_name.len=(NEW_NAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sdhc_frename.new_name.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sdhc_frename.new_name.len)&0xff)<<8)|((uint32)0xc<<16)|((uint32)0x8<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sdhc_frename.new_name.len,(uint8*)NEW_NAME_DATA);\
}
/**This command  is used to change the attributes of a file in current active directory.**/
#define wifi_cmd_sdhc_fchmode(VALUE,FNAME_LEN,FNAME_DATA) \
{\
bglib_temp_msg.cmd_sdhc_fchmode.value=(VALUE);\
bglib_temp_msg.cmd_sdhc_fchmode.fname.len=(FNAME_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)2+bglib_temp_msg.cmd_sdhc_fchmode.fname.len)>>8)))|((((uint32)2+bglib_temp_msg.cmd_sdhc_fchmode.fname.len)&0xff)<<8)|((uint32)0xc<<16)|((uint32)0x9<<24);\
bglib_output(4+2,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_sdhc_fchmode.fname.len,(uint8*)FNAME_DATA);\
}
/**This command is used to convert a decimal value from an ASCII string format into a signed 32-bit integer format.**/
#define wifi_cmd_util_atoi(STRING_LEN,STRING_DATA) \
{\
bglib_temp_msg.cmd_util_atoi.string.len=(STRING_LEN);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)1+bglib_temp_msg.cmd_util_atoi.string.len)>>8)))|((((uint32)1+bglib_temp_msg.cmd_util_atoi.string.len)&0xff)<<8)|((uint32)0xd<<16)|((uint32)0x0<<24);\
bglib_output(4+1,(uint8*)&bglib_temp_msg,bglib_temp_msg.cmd_util_atoi.string.len,(uint8*)STRING_DATA);\
}
/**This command is used to convert an integer from a signed 32-bit integer format into decimal ASCII value format.**/
#define wifi_cmd_util_itoa(VALUE) \
{\
bglib_temp_msg.cmd_util_itoa.value=(VALUE);\
bglib_temp_msg.header=(((uint32)wifi_msg_type_cmd|wifi_dev_type_wifi|(((uint32)4+0)>>8)))|((((uint32)4+0)&0xff)<<8)|((uint32)0xd<<16)|((uint32)0x1<<24);\
bglib_output(4+4,(uint8*)&bglib_temp_msg,0,(uint8*)NULL);\
}
 
#ifdef __cplusplus
}
#endif
/*lint -restore*/
#endif
