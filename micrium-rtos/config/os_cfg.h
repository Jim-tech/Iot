/***************************************************************************//**
 * @file
 * @brief OS Configuration Template File
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement.
 * The software is governed by the sections of the MSLA applicable to Micrium
 * Software.
 *
 ******************************************************************************/

/*
 *********************************************************************************************************
 *********************************************************************************************************
 *                                               MODULE
 *********************************************************************************************************
 *********************************************************************************************************
 */

#ifndef SILABS_OS_CFG_H
#define SILABS_OS_CFG_H

/*
 *********************************************************************************************************
 *********************************************************************************************************
 *                                             INCLUDE FILES
 *********************************************************************************************************
 *********************************************************************************************************
 */

#include CONFIGURATION_HEADER
#include  <common/include/lib_def.h>

#define  OS_CFG_APP_HOOKS_EN                                DEF_ENABLED
#define  OS_CFG_COMPAT_INIT_EN                              DEF_ENABLED
#define  OS_CFG_DBG_EN                                      DEF_ENABLED
#define  OS_CFG_TS_EN                                       DEF_ENABLED
#define  OS_CFG_PRIO_MAX                                    32u
#define  OS_CFG_SCHED_LOCK_TIME_MEAS_EN                     DEF_ENABLED
#define  OS_CFG_SCHED_ROUND_ROBIN_EN                        DEF_DISABLED
#define  OS_CFG_STK_SIZE_MIN                                64u
#define  OS_CFG_FLAG_EN                                     DEF_ENABLED
#define  OS_CFG_FLAG_MODE_CLR_EN                            DEF_DISABLED
#define  OS_CFG_MEM_EN                                      DEF_DISABLED
#define  OS_CFG_MUTEX_EN                                    DEF_ENABLED
#define  OS_CFG_Q_EN                                        DEF_ENABLED
#define  OS_CFG_SEM_EN                                      DEF_ENABLED
#define  OS_CFG_MON_EN                                      DEF_DISABLED
#if defined(EMBER_AF_PLUGIN_MICRIUM_RTOS_CPU_USAGE)
#define  OS_CFG_STAT_TASK_EN                                DEF_ENABLED
#else
#define  OS_CFG_STAT_TASK_EN                                DEF_DISABLED
#endif
#define  OS_CFG_STAT_TASK_STK_CHK_EN                        DEF_ENABLED
#define  OS_CFG_TASK_IDLE_EN                                DEF_ENABLED
#define  OS_CFG_TASK_PROFILE_EN                             DEF_DISABLED
#define  OS_CFG_TASK_Q_EN                                   DEF_DISABLED
#define  OS_CFG_TASK_REG_TBL_SIZE                           3u
#define  OS_CFG_TASK_STK_REDZONE_EN                         DEF_ENABLED
#define  OS_CFG_TASK_STK_REDZONE_DEPTH                      8u
#define  OS_CFG_TASK_TICK_EN                                DEF_ENABLED
#define  OS_CFG_TLS_TBL_SIZE                                0u
#define  OS_CFG_TMR_EN                                      DEF_DISABLED
#define  OS_CFG_TRACE_EN                                    DEF_DISABLED

/*
 *********************************************************************************************************
 *********************************************************************************************************
 *                                             MODULE END
 *********************************************************************************************************
 *********************************************************************************************************
 */

#endif /* End of os_cfg.h module include.                      */
