/***************************************************************************//**
 * @file
 * @brief Definitions for the ncp-debug-print plugin.
 *******************************************************************************
 * # License
 * <b>Copyright 2020 Silicon Laboratories Inc. www.silabs.com</b>
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

#ifndef __NCP_DEBUG_PRINT_H__
#define __NCP_DEBUG_PRINT_H__

#include "hal/hal.h"
#include "plugin/serial/serial.h"

#define emberNcpDebugPrint(...)      emberSerialPrintf(BSP_SERIAL_APP_PORT,  __VA_ARGS__)
#define emberNcpDebugPrintln(...)    emberSerialPrintfLine(BSP_SERIAL_APP_PORT,  __VA_ARGS__)


#endif /*__NCP_DEBUG_PRINT_H__  */