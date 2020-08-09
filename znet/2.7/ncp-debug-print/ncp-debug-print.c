/***************************************************************************//**
 * @file
 * @brief 
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

#include PLATFORM_HEADER
#include "hal/micro/micro.h"
#include "hal/micro/cortexm3/diagnostic.h"
#include "ncp-debug-print.h"


void emberAfMainInitCallback(void)
{
	emberNcpDebugPrintln("Reset info: 0x%x (%p)",
						 halGetResetInfo(),
						 halGetResetString());
	emberNcpDebugPrintln("Extended Reset info: 0x%2X (%p)",
						 halGetExtendedResetInfo(),
						 halGetExtendedResetString());
	if (halResetWasCrash()) {
		halPrintCrashSummary(BSP_SERIAL_APP_PORT);
		halPrintCrashDetails(BSP_SERIAL_APP_PORT);
		halPrintCrashData(BSP_SERIAL_APP_PORT);
	}
}