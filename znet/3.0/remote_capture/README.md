<details>
<summary><font size=5>Table of Contents</font> </summary>  

- [Remote Capture](#remote-capture)
  - [1. Summary](#1-summary)
  - [2. Gecko SDK version](#2-gecko-sdk-version)
  - [3. Hardware Required](#3-hardware-required)
  - [4. Connections Required](#4-connections-required)
  - [5. Setup](#5-setup)
    - [5.1. Device Side](#51-device-side)
    - [5.2. PC Side](#52-pc-side)
  - [6. How It Works](#6-how-it-works)
  - [7. Projects Used](#7-projects-used)
  - [8. How to Port to Another Part](#8-how-to-port-to-another-part)
  - [9. Special Notes](#9-special-notes)
</details>

********

# Remote Capture

## 1. Summary ##
Sometimes, we need to capture on the field to address some issue. It's not what we expect, but sometime we have to. To achieve that, we need to send a technician to the site and connect a debug interface to the device and make a capture on the field. This is not very convenient as we need to access to customers house to do that. It would be better if we could make the capture remotely. This is possible as there is a PTI interface integrated in EFR32. In this article, we will introduce an example about capturing remotely.

The architecture is as below
<div align="center">
    <img src="doc/arch.png">
</div>
<br>

The feature can be divided into two parts:
- Device side: capture the data through PTI interface. Users need to read AN1087 to learn more details about this part. To get AN1087, you need to sign a NDA with Silicon Labs. Please contact the local sales for details.
- PC side: it's actually a MQTT client. The captured data will be published to this client and then sent to Wireshark through a pipe.

Below is the detailed data flow:
<div align="center">
    <img src="doc/data-flow.png">
</div>
<br>

## 2. Gecko SDK version ##
Gecko SDK Suite 3.0.

## 3. Hardware Required ##
- BRD4164A

## 4. Connections Required ##
NA

## 5. Setup ##
### 5.1. Device Side

### 5.2. PC Side



## 6. How It Works ##
1. Join the device into a network;
2. Setup binding between the device and the coordinator;
3. The device should report the battery voltage when it changes.

## 7. Projects Used ##
- [Z3GatewayHostPi.sls](SimplicityStudio/Z3GatewayHostPi.sls)
- [bootloader-uart-xmodem_4164A.sls](SimplicityStudio/bootloader-uart-xmodem_4164A.sls)
- [ncp-uart-hw_4164A.sls](SimplicityStudio/ncp-uart-hw_4164A.sls)
- [Python Client](doc/RemoteCaptureClient.rar)

## 8. How to Port to Another Part ##
NA

## 9. Special Notes ##
NA
