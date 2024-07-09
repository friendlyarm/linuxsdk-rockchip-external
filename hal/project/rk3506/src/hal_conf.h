/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022 Rockchip Electronics Co., Ltd.
 */

#ifndef _HAL_CONF_H_
#define _HAL_CONF_H_

/* CPU config */
#define SOC_RK3506
#define HAL_AP_CORE

/* System timer designation (RK TIMER) */
#define SYS_TIMER TIMER5

/* HAL Driver Config */
#define HAL_UART_MODULE_ENABLED

#define HAL_DCACHE_MODULE_ENABLED
#define HAL_IRQ_HANDLER_MODULE_ENABLED
#define HAL_TIMER_MODULE_ENABLED

/* HAL_DBG SUB CONFIG */

#ifdef HAL_DBG_ON
#define HAL_DBG_USING_LIBC_PRINTF
#define HAL_DBG_ON
#define HAL_DBG_INFO_ON
#define HAL_DBG_WRN_ON
#define HAL_DBG_ERR_ON
#endif  /* End of HAL_DBG_ON */

#endif  /* End of _HAL_CONF_H_ */
