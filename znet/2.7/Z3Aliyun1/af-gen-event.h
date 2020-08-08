// This file is generated by Simplicity Studio.  Please do not edit manually.
//
//

// Enclosing macro to prevent multiple inclusion
#ifndef __AF_GEN_EVENT__
#define __AF_GEN_EVENT__


// Code used to configure the cluster event mechanism
#define EMBER_AF_GENERATED_EVENT_CODE \
  extern EmberEventControl clearWiFiEventControl; \
  extern EmberEventControl commissionEventControl; \
  extern EmberEventControl delayRebootEventControl; \
  extern EmberEventControl emberAfPluginDeviceTableNewDeviceEventControl; \
  extern EmberEventControl emberAfPluginNetworkCreatorSecurityOpenNetworkEventControl; \
  extern EmberEventControl emberAfPluginNetworkSteeringFinishSteeringEventControl; \
  extern EmberEventControl emberAfPluginScanDispatchScanEventControl; \
  extern EmberEventControl emberAfPluginUpdateTcLinkKeyBeginTcLinkKeyUpdateEventControl; \
  extern EmberEventControl pollAttrEventControl; \
  extern EmberEventControl softWdgEventControl; \
  extern void clearWiFiEventHandler(void); \
  extern void commissionEventHandler(void); \
  extern void delayRebootEventHandler(void); \
  extern void emberAfPluginDeviceTableNewDeviceEventHandler(void); \
  extern void emberAfPluginNetworkCreatorSecurityOpenNetworkEventHandler(void); \
  extern void emberAfPluginNetworkSteeringFinishSteeringEventHandler(void); \
  extern void emberAfPluginScanDispatchScanEventHandler(void); \
  extern void emberAfPluginUpdateTcLinkKeyBeginTcLinkKeyUpdateEventHandler(void); \
  extern void pollAttrEventHandler(void); \
  extern void softWdgEventHandler(void); \


// EmberEventData structs used to populate the EmberEventData table
#define EMBER_AF_GENERATED_EVENTS   \
  { &clearWiFiEventControl, clearWiFiEventHandler }, \
  { &commissionEventControl, commissionEventHandler }, \
  { &delayRebootEventControl, delayRebootEventHandler }, \
  { &emberAfPluginDeviceTableNewDeviceEventControl, emberAfPluginDeviceTableNewDeviceEventHandler }, \
  { &emberAfPluginNetworkCreatorSecurityOpenNetworkEventControl, emberAfPluginNetworkCreatorSecurityOpenNetworkEventHandler }, \
  { &emberAfPluginNetworkSteeringFinishSteeringEventControl, emberAfPluginNetworkSteeringFinishSteeringEventHandler }, \
  { &emberAfPluginScanDispatchScanEventControl, emberAfPluginScanDispatchScanEventHandler }, \
  { &emberAfPluginUpdateTcLinkKeyBeginTcLinkKeyUpdateEventControl, emberAfPluginUpdateTcLinkKeyBeginTcLinkKeyUpdateEventHandler }, \
  { &pollAttrEventControl, pollAttrEventHandler }, \
  { &softWdgEventControl, softWdgEventHandler }, \


#define EMBER_AF_GENERATED_EVENT_STRINGS   \
  "Clear wi fi event control",  \
  "Commission event control",  \
  "Delay reboot event control",  \
  "Device Table Plugin NewDevice",  \
  "Network Creator Security Plugin OpenNetwork",  \
  "Network Steering Plugin FinishSteering",  \
  "Scan Dispatch Plugin Scan",  \
  "Update TC Link Key Plugin BeginTcLinkKeyUpdate",  \
  "Poll attr event control",  \
  "Event data",  \


#endif // __AF_GEN_EVENT__
