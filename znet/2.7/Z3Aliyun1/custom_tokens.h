/***************************************************************************//**
 * @file
 * @brief Tokens for Z3Aliyun301.
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
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

#define CREATOR_KV_PAIRS            (0x6801)
#define NVM3KEY_KV_PAIRS            (NVM3KEY_DOMAIN_USER | 0x6801)

#define CREATOR_DEV_TABLE           (0x6901)
#define NVM3KEY_DEV_TABLE           (NVM3KEY_DOMAIN_USER | 0x6901)

#define CREATOR_WIFI_INFO           (0x6931)
#define NVM3KEY_WIFI_INFO           (NVM3KEY_DOMAIN_USER | 0x6931)

#ifdef DEFINETYPES
// Include or define any typedef for tokens here
typedef struct {
  char    kv_key[63];
  uint8_t value_len;
  uint8_t value[64];
} tokTypeKvs;

typedef struct {
  uint8_t     endpoint;
  uint16_t    deviceId;
  EmberNodeId nodeId;
  EmberEUI64  eui64;
} tokTypeDevTable;

typedef struct {
  char    ssid[64];
  char    passwd[64];
} tokTypeWiFiInfo;

#endif //DEFINETYPES

#ifdef DEFINETOKENS
// Define the actual token storage information here

#define MAX_KV_NUMBER 16
DEFINE_INDEXED_TOKEN(KV_PAIRS,
                     tokTypeKvs,
                     MAX_KV_NUMBER,
                     { {0, }, 0, {0, } })
                        
#define MAX_DEV_TABLE_NUMBER 32
DEFINE_INDEXED_TOKEN(DEV_TABLE,
                     tokTypeDevTable,
                     MAX_DEV_TABLE_NUMBER,
                     { 0xFF, 0xFFFF, 0xFFFF, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} })

DEFINE_BASIC_TOKEN(WIFI_INFO, tokTypeWiFiInfo, {0})                        
#endif //DEFINETOKENS

