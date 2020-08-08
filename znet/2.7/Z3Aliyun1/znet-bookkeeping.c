// This file is generated by Simplicity Studio.  Please do not edit manually.
//
//

#include PLATFORM_HEADER
#include CONFIGURATION_HEADER
#include "af.h"

// Init function declarations.
void emberAfMainInitCallback(void);  // Global
void emberAfInit(void);  // Global
void emberAfPluginNetworkCreatorSecurityInitCallback(void);  // Plugin: network-creator-security

void emAfInit(void)
{
  emberAfMainInitCallback();  // Global
  emberAfInit();  // Global
  emberAfPluginNetworkCreatorSecurityInitCallback();  // Plugin: network-creator-security
}

// Tick function declarations.
void emberAfMainTickCallback(void);  // Global
void emberAfTick(void);  // Global
void emberAfPluginIdleSleepTickCallback(void);  // Plugin: idle-sleep

void emAfTick(void)
{
  emberAfMainTickCallback();  // Global
  emberAfTick();  // Global
  emberAfPluginIdleSleepTickCallback();  // Plugin: idle-sleep
}

void emAfResetAttributes(uint8_t endpointId)
{
}

// PreCommandReceived function declarations.
bool emberAfPreCommandReceivedCallback(EmberAfClusterCommand* cmd);  // Global
bool emAfPluginDeviceTablePreCommandReceivedCallback(EmberAfClusterCommand* cmd);  // Plugin: device-table

bool emAfPreCommandReceived(EmberAfClusterCommand* cmd)
{
  return (emberAfPreCommandReceivedCallback(cmd)  /* Global */
          || emAfPluginDeviceTablePreCommandReceivedCallback(cmd)  /* Plugin: device-table */);
}

// PreZDOMessageReceived function declarations.
bool emberAfPreZDOMessageReceivedCallback(EmberNodeId emberNodeId,EmberApsFrame* apsFrame,uint8_t* message,uint16_t length);  // Global
bool emAfPluginDeviceTablePreZDOMessageReceived(EmberNodeId emberNodeId,EmberApsFrame* apsFrame,uint8_t* message,uint16_t length);  // Plugin: device-table

bool emAfPreZDOMessageReceived(EmberNodeId emberNodeId,EmberApsFrame* apsFrame,uint8_t* message,uint16_t length)
{
  return (emberAfPreZDOMessageReceivedCallback(emberNodeId, apsFrame, message, length)  /* Global */
          || emAfPluginDeviceTablePreZDOMessageReceived(emberNodeId, apsFrame, message, length)  /* Plugin: device-table */);
}

bool emAfRetrieveAttributeAndCraftResponse(uint8_t endpoint, EmberAfClusterId clusterId, EmberAfAttributeId attrId, uint8_t mask, uint16_t maunfacturerCode, uint16_t readLength)
{
  return 0; // false
}

// ZigbeeKeyEstablishment function declarations.
void emberAfZigbeeKeyEstablishmentCallback(EmberEUI64 partner, EmberKeyStatus status);  // Global
void emberAfPluginNetworkCreatorSecurityZigbeeKeyEstablishmentCallback(EmberEUI64 partner, EmberKeyStatus status);  // Plugin: network-creator-security
void emberAfPluginUpdateTcLinkKeyZigbeeKeyEstablishmentCallback(EmberEUI64 partner, EmberKeyStatus status);  // Plugin: update-tc-link-key

void emAfZigbeeKeyEstablishment(EmberEUI64 partner, EmberKeyStatus status)
{
  emberAfZigbeeKeyEstablishmentCallback(partner, status);  // Global
  emberAfPluginNetworkCreatorSecurityZigbeeKeyEstablishmentCallback(partner, status);  // Plugin: network-creator-security
  emberAfPluginUpdateTcLinkKeyZigbeeKeyEstablishmentCallback(partner, status);  // Plugin: update-tc-link-key
}

// ReadAttributesResponse function declarations.
bool emberAfReadAttributesResponseCallback(EmberAfClusterId clusterId,uint8_t* buffer,uint16_t bufLen);  // Global

bool emAfReadAttributesResponse(EmberAfClusterId clusterId,uint8_t* buffer,uint16_t bufLen)
{
  return emberAfReadAttributesResponseCallback(clusterId, buffer, bufLen);  // Global
}

// ReportAttributes function declarations.
bool emberAfReportAttributesCallback(EmberAfClusterId clusterId,uint8_t * buffer,uint16_t bufLen);  // Global

bool emAfReportAttributes(EmberAfClusterId clusterId,uint8_t * buffer,uint16_t bufLen)
{
  return emberAfReportAttributesCallback(clusterId, buffer, bufLen);  // Global
}

// PluginDeviceTableDeviceLeft function declarations.
void emberAfPluginDeviceTableDeviceLeftCallback(EmberEUI64 newNodeEui64);  // Plugin: device-table

void emAfPluginDeviceTableDeviceLeftCallback(EmberEUI64 newNodeEui64)
{
  emberAfPluginDeviceTableDeviceLeftCallback(newNodeEui64);  // Plugin: device-table
}
