/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022 Rockchip Electronics Co., Ltd.
 */

#include "hal_bsp.h"

#ifdef HAL_CRU_MODULE_ENABLED
static struct CRU_BANK_INFO cruBanks[] = {
    CRU_BANK_CFG_FLAGS(TOPCRU_BASE, 0x100, 0x300, 0x400),
    CRU_BANK_CFG_FLAGS(PMU0CRU_BASE, 0x100, 0x180, 0x200),
    CRU_BANK_CFG_FLAGS(PMU1CRU_BASE, 0x100, 0x180, 0x200),
    CRU_BANK_CFG_FLAGS(DDRCRU_BASE, 0x100, 0x180, 0x200),
    CRU_BANK_CFG_FLAGS(SUBDDRCRU_BASE, 0x100, 0x180, 0x200),
    CRU_BANK_CFG_FLAGS(PERICRU_BASE, 0x100, 0x300, 0x400),
};

const struct HAL_CRU_DEV g_cruDev = {
    .banks = cruBanks,
    .banksNum = HAL_ARRAY_SIZE(cruBanks),
};
#endif  /* End of HAL_CRU_MODULE_ENABLED */

#ifdef HAL_I2C_MODULE_ENABLED
const struct HAL_I2C_DEV g_i2c0Dev =
{
    .pReg = I2C0,
    .irqNum = I2C0_IRQn,
    .clkID = CLK_PMU0_I2C0,
    .clkGateID = PCLK_PMU0_I2C0_GATE,
    .pclkGateID = CLK_PMU0_I2C0_GATE,
};

const struct HAL_I2C_DEV g_i2c1Dev =
{
    .pReg = I2C1,
    .irqNum = I2C1_IRQn,
    .clkID = CLK_I2C,
    .clkGateID = CLK_I2C1_GATE,
    .pclkGateID = PCLK_I2C1_GATE,
};

const struct HAL_I2C_DEV g_i2c2Dev =
{
    .pReg = I2C2,
    .irqNum = I2C2_IRQn,
    .clkID = CLK_I2C,
    .clkGateID = CLK_I2C2_GATE,
    .pclkGateID = PCLK_I2C2_GATE,
};
#endif  /* End of HAL_I2C_MODULE_ENABLED */

#ifdef HAL_SPI_MODULE_ENABLED
const struct HAL_SPI_DEV g_spi0Dev = {
    .base = SPI0_BASE,
    .clkId = CLK_PMU1_SPI0,
    .clkGateID = CLK_PMU1_SPI0_GATE,
    .pclkGateID = PCLK_PMU1_SPI0_GATE,
    .maxFreq = 200000000,
    .irqNum = SPI0_IRQn,
    .isSlave = false,
    .txDma = {
        .channel = DMA_REQ_SPI0_RX,
        .direction = DMA_MEM_TO_DEV,
        .addr = SPI0_BASE + 0x400,
    },
    .rxDma = {
        .channel = DMA_REQ_SPI0_TX,
        .direction = DMA_DEV_TO_MEM,
        .addr = SPI0_BASE + 0x800,
    },
};

const struct HAL_SPI_DEV g_spi1Dev = {
    .base = SPI1_BASE,
    .clkId = CLK_SPI1,
    .clkGateID = CLK_SPI1_GATE,
    .pclkGateID = PCLK_SPI1_GATE,
    .irqNum = SPI1_IRQn,
    .isSlave = false,
    .txDma = {
        .channel = DMA_REQ_SPI1_RX,
        .direction = DMA_MEM_TO_DEV,
        .addr = SPI1_BASE + 0x400,
    },
    .rxDma = {
        .channel = DMA_REQ_SPI1_TX,
        .direction = DMA_DEV_TO_MEM,
        .addr = SPI1_BASE + 0x800,
    },
};
#endif  /* End of HAL_SPI_MODULE_ENABLED */

#ifdef HAL_FSPI_MODULE_ENABLED
struct HAL_FSPI_HOST g_fspi0Dev =
{
    .instance = FSPI,
    .sclkGate = SCLK_SFC_GATE,
    .hclkGate = HCLK_SFC_GATE,
    .xipClkGate = 0,
    .sclkID = SCLK_SFC,
    .irqNum = FSPI0_IRQn,
    .xipMemCode = 0,
    .xipMemData = 0,
    .xmmcDev[0] =
    {
        .type = 0,
    },
};
#endif  /* End of HAL_FSPI_MODULE_ENABLED */

#ifdef HAL_UART_MODULE_ENABLED
const struct HAL_UART_DEV g_uart0Dev =
{
    .pReg = UART0,
    .sclkID = 0,
    .sclkGateID = 0,
    .pclkGateID = 0,
    .irqNum = UART0_IRQn,
    .isAutoFlow = false,
};

const struct HAL_UART_DEV g_uart1Dev =
{
    .pReg = UART1,
    .sclkID = 0,
    .sclkGateID = 0,
    .pclkGateID = 0,
    .irqNum = UART1_IRQn,
    .isAutoFlow = false,
};

const struct HAL_UART_DEV g_uart2Dev =
{
    .pReg = UART2,
    .sclkID = 0,
    .sclkGateID = 0,
    .pclkGateID = 0,
    .irqNum = UART2_IRQn,
    .isAutoFlow = false,
};

const struct HAL_UART_DEV g_uart3Dev =
{
    .pReg = UART3,
    .sclkID = 0,
    .sclkGateID = 0,
    .pclkGateID = 0,
    .irqNum = UART3_IRQn,
    .isAutoFlow = false,
};

const struct HAL_UART_DEV g_uart4Dev =
{
    .pReg = UART4,
    .sclkID = 0,
    .sclkGateID = 0,
    .pclkGateID = 0,
    .irqNum = UART4_IRQn,
    .isAutoFlow = false,
};
#endif  /* End of HAL_UART_MODULE_ENABLED */

#ifdef HAL_PWM_MODULE_ENABLED
const struct HAL_PWM_DEV g_pwm0Dev =
{
    .pReg = PWM0,
    .clkID = CLK_PMU1_PWM0,
    .clkGateID = CLK_PMU1_PWM0_GATE,
    .pclkGateID = PCLK_PMU1_PWM0_GATE,
    .irqNum[0] = PWM0_IRQn,
};

const struct HAL_PWM_DEV g_pwm1Dev =
{
    .pReg = PWM1,
    .clkID = CLK_PWM1_PERI,
    .clkGateID = CLK_PWM1_PERI_GATE,
    .pclkGateID = PCLK_PWM1_PERI_GATE,
    .irqNum[0] = PWM1_IRQn,
};

const struct HAL_PWM_DEV g_pwm2Dev =
{
    .pReg = PWM2,
    .clkID = CLK_PWM2_PERI,
    .clkGateID = CLK_PWM2_PERI_GATE,
    .pclkGateID = PCLK_PWM2_PERI_GATE,
    .irqNum[0] = PWM2_IRQn,
};

const struct HAL_PWM_DEV g_pwm3Dev =
{
    .pReg = PWM3,
    .clkID = CLK_PWM3_PERI,
    .clkGateID = CLK_PWM3_PERI_GATE,
    .pclkGateID = PCLK_PWM3_PERI_GATE,
    .irqNum[0] = PWM3_IRQn,
};
#endif  /* End of HAL_PWM_MODULE_ENABLED */

void BSP_Init(void)
{
}

void BSP_SetLoaderFlag(void)
{
}
