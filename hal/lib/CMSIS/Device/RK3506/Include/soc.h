/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023 Rockchip Electronics Co., Ltd.
 */

#ifndef __SOC_H
#define __SOC_H
#ifdef __cplusplus
  extern "C" {
#endif

#include "hal_conf.h"

/* IO definitions (access restrictions to peripheral registers) */
#ifdef __cplusplus
  #define   __I     volatile             /*!< brief Defines 'read only' permissions    */
#else
  #define   __I     volatile const       /*!< brief Defines 'read only' permissions    */
#endif
#define     __O     volatile             /*!< brief Defines 'write only' permissions   */
#define     __IO    volatile             /*!< brief Defines 'read / write' permissions */

/* ================================================================================ */
/* ================                    DMA REQ                      =============== */
/* ================================================================================ */
typedef enum {
    DMA_REQ_UART0_RX = 0,
    DMA_REQ_UART1_RX = 1,
    DMA_REQ_UART2_RX = 2,
    DMA_REQ_UART3_RX = 3,
    DMA_REQ_UART4_RX = 4,
    DMA_REQ_UART5_RX = 5,
    DMA_REQ_UART6_RX = 6,
    DMA_REQ_UART7_RX = 7,
    DMA_REQ_UART8_RX = 8,
    DMA_REQ_UART9_RX = 9,
    DMA_REQ_UART1_TX = 10,
    DMA_REQ_UART5_TX = 11,
    DMA_REQ_SPI0_RX  = 12,
    DMA_REQ_SPI0_TX  = 13,
    DMA_REQ_SPI1_RX  = 14,
    DMA_REQ_SPI1_TX  = 15,
    DMA_REQ_SPI2_RX  = 16,
    DMA_REQ_SPI2_TX  = 17,
    DMA_REQ_SAI0_RX  = 18,
    DMA_REQ_SAI0_TX  = 19,
    DMA_REQ_SAI1_RX  = 20,
    DMA_REQ_SAI1_TX  = 21,
    DMA_REQ_SAI2_RX  = 22,
    DMA_REQ_SAI2_TX  = 23,
    DMA_REQ_CAN0_RX  = 24,
    DMA_REQ_CAN9_TX  = 25,
    DMA_REQ_PWM0     = 26,
    DMA_REQ_PWM1     = 27,
    DMA_REQ_PWM2     = 28,
    DMA_REQ_PWM3     = 29,
    DMA_REQ_SPDIF    = 30,
    DMA_REQ_PDM      = 31,
    DMA_REQ_CAN1_RX  = 32,
    DMA_REQ_CAN1_TX  = 33,
    DMA_REQ_UART0_TX = 34,
    DMA_REQ_UART2_TX = 35,
    DMA_REQ_UART3_TX = 36,
    DMA_REQ_UART4_TX = 37,
    DMA_REQ_UART6_TX = 38,
    DMA_REQ_UART7_TX = 39,
    DMA_REQ_UART8_TX = 40,
    DMA_REQ_UART9_TX = 41,
} DMA_REQ_Type;

/* ================================================================================ */
/* ================                       IRQ                      ================ */
/* ================================================================================ */
#if defined(HAL_BUS_MCU_CORE)

#define INTMUX_NUM_INT_PER_CON    256
#define INTMUX_NUM_OUT_PER_CON    4
#define INTMUX_NUM_INT_PER_OUT    64
#define INTMUX_NUM_GROUP_PER_OUT  8
#define INTMUX_NUM_GROUP_PER_CON  32
#define INTMUX_NUM_INT_PER_GROUP  8
/* INTMUX IRQ start from GIC SPI(Shared Peripheral Interrupt) */
#define INTMUX_IRQ_START_NUM      32
#define INTMUX_IRQ_OUT0
#define INTMUX_IRQ_OUT1
#define INTMUX_IRQ_OUT2
#define INTMUX_IRQ_OUT3
#define INTMUX_OUT_IRQ_START_NUM  0

#define NUM_EXT_INTERRUPTS        256

typedef enum {
/* -------------------  Processor Exceptions Numbers  ----------------------------- */
  NonMaskableInt_IRQn       = -14,     /*  2 Non Maskable Interrupt */
  HardFault_IRQn            = -13,     /*  3 HardFault Interrupt */

  SVCall_IRQn               =  -5,     /* 11 SV Call Interrupt */

  PendSV_IRQn               =  -2,     /* 14 Pend SV Interrupt */
  SysTick_IRQn              =  -1,     /* 15 System Tick Interrupt */

/******  Platform Exceptions Numbers ***************************************************/
  INTMUX_OUT0_IRQn          =  0,      /*!< INTMUX OUT0 Interrupt         */
  INTMUX_OUT1_IRQn          =  1,      /*!< INTMUX OUT1 Interrupt         */
  INTMUX_OUT2_IRQn          =  2,      /*!< INTMUX OUT2 Interrupt         */
  INTMUX_OUT3_IRQn          =  3,      /*!< INTMUX OUT3 Interrupt         */
  MBOX_BB_IRQn              =  4,      /*!< MAILBOX_BB Interrupt          */
  TIMER0_IRQn               =  5,      /*!< TIMER0 Interrupt              */
  RSVD0_MCU_IRQn            =  6,      /*!< RSVD0 MCU Interrupt           */
  NUM_INTERRUPTS            =  8,      /*!< Number of internal IRQ        */
  GPIO0_IRQn                =  32 + NUM_INTERRUPTS,     /*!< GPIO0 Interrupt               */
  GPIO0_EXP_IRQn            =  33 + NUM_INTERRUPTS,     /*!< GPIO0 EXP Interrupt           */
  GPIO1_IRQn                =  34 + NUM_INTERRUPTS,     /*!< GPIO1 Interrupt               */
  GPIO1_EXP_IRQn            =  35 + NUM_INTERRUPTS,     /*!< GPIO1 EXP Interrupt           */
  GPIO2_IRQn                =  36 + NUM_INTERRUPTS,     /*!< GPIO2 Interrupt               */
  GPIO2_EXP_IRQn            =  37 + NUM_INTERRUPTS,     /*!< GPIO2 EXP Interrupt           */
  GPIO3_IRQn                =  38 + NUM_INTERRUPTS,     /*!< GPIO3 Interrupt               */
  GPIO3_EXP_IRQn            =  39 + NUM_INTERRUPTS,     /*!< GPIO3 EXP Interrupt           */
  GPIO4_IRQn                =  40 + NUM_INTERRUPTS,     /*!< GPIO4 Interrupt               */
  GPIO4_EXP_IRQn            =  41 + NUM_INTERRUPTS,     /*!< GPIO4 EXP Interrupt           */
  I2C0_IRQn                 =  44 + NUM_INTERRUPTS,     /*!< I2C0 Interrupt                */
  I2C1_IRQn                 =  45 + NUM_INTERRUPTS,     /*!< I2C1 Interrupt                */
  I2C2_IRQn                 =  46 + NUM_INTERRUPTS,     /*!< I2C2 Interrupt                */
  I2C3_IRQn                 =  47 + NUM_INTERRUPTS,     /*!< I2C3 Interrupt                */
  I2C4_IRQn                 =  48 + NUM_INTERRUPTS,     /*!< I2C4 Interrupt                */
  I2C5_IRQn                 =  49 + NUM_INTERRUPTS,     /*!< I2C5 Interrupt                */
  PWM0_IRQn                 =  52 + NUM_INTERRUPTS,     /*!< PWM0 Interrupt                */
  PWM0_PWR_IRQn             =  53 + NUM_INTERRUPTS,     /*!< PWM0 PWR Interrupt            */
  PWM1_IRQn                 =  54 + NUM_INTERRUPTS,     /*!< PWM1 Interrupt                */
  PWM1_PWR_IRQn             =  55 + NUM_INTERRUPTS,     /*!< PWM1 PWR Interrupt            */
  PWM2_IRQn                 =  56 + NUM_INTERRUPTS,     /*!< PWM2 Interrupt                */
  PWM2_PWR_IRQn             =  57 + NUM_INTERRUPTS,     /*!< PWM2 PWR Interrupt            */
  PWM3_IRQn                 =  58 + NUM_INTERRUPTS,     /*!< PWM3 Interrupt                */
  PWM3_PWR_IRQn             =  59 + NUM_INTERRUPTS,     /*!< PWM3 PWR Interrupt            */
  UART0_IRQn                =  62 + NUM_INTERRUPTS,     /*!< UART0 Interrupt               */
  UART1_IRQn                =  63 + NUM_INTERRUPTS,     /*!< UART1 Interrupt               */
  UART2_IRQn                =  64 + NUM_INTERRUPTS,     /*!< UART2 Interrupt               */
  UART3_IRQn                =  65 + NUM_INTERRUPTS,     /*!< UART3 Interrupt               */
  UART4_IRQn                =  66 + NUM_INTERRUPTS,     /*!< UART4 Interrupt               */
  UART5_IRQn                =  67 + NUM_INTERRUPTS,     /*!< UART5 Interrupt               */
  UART6_IRQn                =  68 + NUM_INTERRUPTS,     /*!< UART6 Interrupt               */
  UART7_IRQn                =  69 + NUM_INTERRUPTS,     /*!< UART7 Interrupt               */
  UART8_IRQn                =  70 + NUM_INTERRUPTS,     /*!< UART8 Interrupt               */
  UART9_IRQn                =  71 + NUM_INTERRUPTS,     /*!< UART9 Interrupt               */
  SARADC0_IRQn              =  72 + NUM_INTERRUPTS,     /*!< SARADC0 Interrupt             */
  TIMER1_IRQn               =  78 + NUM_INTERRUPTS,     /*!< TIMER1 Interrupt               */
  TIMER2_IRQn               =  79 + NUM_INTERRUPTS,     /*!< TIMER2 Interrupt               */
  TIMER3_IRQn               =  80 + NUM_INTERRUPTS,     /*!< TIMER3 Interrupt               */
  TIMER4_IRQn               =  81 + NUM_INTERRUPTS,     /*!< TIMER4 Interrupt               */
  TIMER5_IRQn               =  81 + NUM_INTERRUPTS,     /*!< TIMER5 Interrupt               */
  SPI0_IRQn                 =  84 + NUM_INTERRUPTS,     /*!< SPI0 Interrupt                 */
  SPI1_IRQn                 =  85 + NUM_INTERRUPTS,     /*!< SPI1 Interrupt                 */
  SPI2_IRQn                 =  86 + NUM_INTERRUPTS,     /*!< SPI2 Interrupt                 */
  WDT_IRQn                  =  134 + NUM_INTERRUPTS,    /*!< WDT Interrupt                  */
  SARADC1_IRQn              =  156 + NUM_INTERRUPTS,    /*!< SARADC1 Interrupt              */
  FSPI0_IRQn                =  160 + NUM_INTERRUPTS,    /*!< FSPI0 Interrupt                */
  TOTAL_INTERRUPTS          =  (INTMUX_IRQ_START_NUM + NUM_INTERRUPTS + NUM_EXT_INTERRUPTS),
} IRQn_Type;

#elif defined(HAL_PMU_MCU_CORE)

typedef enum {
/* -------------------  Processor Exceptions Numbers  ----------------------------- */
  NonMaskableInt_IRQn       = -14,     /*  2 Non Maskable Interrupt */
  HardFault_IRQn            = -13,     /*  3 HardFault Interrupt */

  SVCall_IRQn               =  -5,     /* 11 SV Call Interrupt */

  PendSV_IRQn               =  -2,     /* 14 Pend SV Interrupt */
  SysTick_IRQn              =  -1,     /* 15 System Tick Interrupt */

/******  Platform Exceptions Numbers ***************************************************/
  MBOX_BB_IRQn              =  0,      /*!< MAILBOX_BB Interrupt          */
  HPTIMER_IRQn              =  1,      /*!< HPTIMER Interrupt             */
  UART0_IRQn                =  2,      /*!< UART0 Interrupt               */
  WDT_IRQn                  =  3,      /*!< WDT Interrupt                 */
  GPIO0_IRQn                =  4,      /*!< GPIO0 Interrupt               */
  SPI0_IRQn                 =  5,      /*!< SPI0 Interrupt                */
  PWM0_IRQn                 =  6,      /*!< PWM0 Interrupt                */
  I2C0_IRQn                 =  7,      /*!< I2C0 Interrupt                */
  NUM_INTERRUPTS            =  8,      /*!< Number of internal IRQ        */
  DUMMY_IRQn                =  256,    /*!< Avoid compile warning: overflow in conversion   */
} IRQn_Type;

#else
typedef enum
{
  CNTHP_IRQn                =  26,     /*!< CNTHP Interrupt               */
  CNTV_IRQn                 =  27,
  CNTPS_IRQn                =  29,
  CNTPNS_IRQn               =  30,
  
  GPIO0_0_IRQn              =  32,
  GPIO0_1_IRQn              =  33,
  GPIO0_2_IRQn              =  34,
  GPIO0_3_IRQn              =  35,
  GPIO1_0_IRQn              =  36,
  GPIO1_1_IRQn              =  37,
  GPIO1_2_IRQn              =  38,
  GPIO1_3_IRQn              =  39,
  GPIO2_0_IRQn              =  40,
  GPIO2_1_IRQn              =  41,
  GPIO2_2_IRQn              =  42,
  GPIO2_3_IRQn              =  43,
  GPIO3_0_IRQn              =  44,
  GPIO3_1_IRQn              =  45,
  GPIO3_2_IRQn              =  46,
  GPIO3_3_IRQn              =  47,
  GPIO4_0_IRQn              =  48,
  GPIO4_1_IRQn              =  49,
  GPIO4_2_IRQn              =  50,
  GPIO4_3_IRQn              =  51,
  TOUCH_KEY_POS_IRQn        =  52,
  TOUCH_KEY_NEG_IRQn        =  53,
  PWM0_IRQn                 =  54,
  PWM1_IRQn                 =  55,
  PWM2_IRQn                 =  56,
  PWM3_IRQn                 =  57,
  PWM4_IRQn                 =  58,
  PWM5_IRQn                 =  59,
  PWM6_IRQn                 =  60,
  PWM7_IRQn                 =  61,
  PWM8_IRQn                 =  62,
  PWM9_IRQn                 =  63,
  PWM10_IRQn                =  64,
  PWM11_IRQn                =  65,
  UART0_IRQn                =  66,
  UART1_IRQn                =  67,
  UART2_IRQn                =  68,
  UART3_IRQn                =  69,
  UART4_IRQn                =  70,
  UART5_IRQn                =  71,
  I2C0_IRQn                 =  72,
  I2C1_IRQn                 =  73,
  I2C2_IRQn                 =  74,
  SPI0_IRQn                 =  75,
  SPI1_IRQn                 =  76,
  CAN0_IRQn                 =  77,
  CAN1_IRQn                 =  78,
  SPDIF_TX_IRQn             =  79,
  SPDIF_RX_IRQn             =  80,
  PDM_IRQn                  =  81,
  SAI0_IRQn                 =  82,
  SAI1_IRQn                 =  83,
  SAI2_IRQn                 =  84,
  SAI3_IRQn                 =  85,
  SAI4_IRQn                 =  86,
  ASRC0_IRQn                =  87,
  ASRC1_IRQn                =  88,
  SARADC_IRQn               =  89,
  TSADC_IRQn                =  90,
  VOP_IRQn                  =  91,
  MIPI_DSIHOST_IRQn         =  92,
  RGA_IRQn                  =  93,
  OTPC_NS_IRQn              =  94,
  OTPC_S_IRQn               =  95,
  KEY_READER_IRQn           =  96,
  OTPC_MASK_IRQn            =  97,
  MAC0_SBD_IRQn             =  98,
  MAC0_SBD_TX_IRQn          =  99,
  MAC0_SBD_RX_IRQn          =  100,
  MAC0_PMT_IRQn             =  101,
  MAC1_SBD_IRQn             =  102,
  MAC1_SBD_TX_IRQn          =  103,
  MAC1_SBD_RX_IRQn          =  104,
  MAC1_PMT_IRQn             =  105,
  OTG0_IRQn                 =  106,
  OTG0_BVALID_IRQn          =  107,
  OTG0_ID_IRQn              =  108,
  OTG0_LINESTATE_IRQn       =  109,
  OTG0_DISCONNECT_IRQn      =  110,
  OTG1_IRQn                 =  111,
  OTG1_BVALID_IRQn          =  112,
  OTG1_ID_IRQn              =  113,
  OTG1_LINESTATE_IRQn       =  114,
  OTG1_DISCONNECT_IRQn      =  115,
  SPI2APB_IRQn              =  116,
  FSPI_IRQn                 =  117,
  SDMMC_IRQn                =  118,
  DDRC_AWPOISON0_IRQn       =  119,
  DDRC_AWPOISON1_IRQn       =  120,
  DDRC_ARPOISON0_IRQn       =  121,
  DDRC_ARPOISON1_IRQn       =  122,
  DDRC_DFI_ALERT_ERR_IRQn   =  123,
  DDR_MONITOR_IRQn          =  124,
  DDRPHY_IRQn               =  125,
  TIMER0_IRQn               =  126,
  TIMER1_IRQn               =  127,
  TIMER2_IRQn               =  128,
  TIMER3_IRQn               =  129,
  TIMER4_IRQn               =  130,
  TIMER5_IRQn               =  131,
  TIMER6_IRQn               =  132,
  TIMER7_IRQn               =  133,
  TIMER8_IRQn               =  134,
  TIMER9_IRQn               =  135,
  TIMER10_IRQn              =  136,
  TIMER11_IRQn              =  137,
  HPTIMER_IRQn              =  138,
  WDT0_IRQn                 =  139,
  WDT1_IRQn                 =  140,
  MAILBOX_BB_IRQn           =  141,
  MAILBOX_AP_IRQn           =  142,
  CRYPTO_IRQn               =  143,
  CRYPTO_KLAD_IRQn          =  144,
  CRYPTO_SC_IRQn            =  145,
  NS_TRNG_IRQn              =  146,
  S_TRNG_IRQn               =  147,
  DMAC0_IRQn                =  148,
  DMAC0_ABORT_IRQn          =  149,
  DMAC1_IRQn                =  150,
  DMAC1_ABORT_IRQn          =  151,
  PERF_CORE_IRQn            =  152,
  A7_PMUIRQ_0_IRQn          =  153,
  A7_PMUIRQ_1_IRQn          =  154,
  A7_PMUIRQ_2_IRQn          =  155,
  A7_PMUIRQ_3_IRQn          =  156,
  A7_AXIERRIRQ_IRQn         =  157,
  DSMC_IRQn                 =  158,
  FLEXBUS_IRQn              =  159,
  PMU_IRQn                  =  160,
  NPOR_POWERGOOD_IRQn       =  161,
  GPIO1_SHADOW_0_IRQn       =  162,
  GPIO1_SHADOW_1_IRQn       =  163,
  GPIO1_SHADOW_2_IRQn       =  164,
  GPIO1_SHADOW_3_IRQn       =  165,
  NUM_INTERRUPTS            =  166,      /*!< Number of internal IRQ        */
} IRQn_Type;
#endif

#if defined(HAL_BUS_MCU_CORE)

#define RSVD_MCU_IRQn(_N)               (RSVD0_MCU_IRQn + (_N))
#define HAS_CUSTOME_INTC

#endif

/* ================================================================================ */
/* ================      Processor and Core Peripheral Section     ================ */
/* ================================================================================ */

#define PLL_INPUT_32K_RATE       (32 * 1000)
#define PLL_INPUT_OSC_RATE       (24 * 1000 * 1000)

/* --------  Configuration of Core Peripherals  ----------------------------------- */
#if defined(HAL_AP_CORE) && defined(HAL_MCU_CORE)
#error "HAL_AP_CORE and HAL_MCU_CORE only one of them can be enabled"
#endif

#if !defined(HAL_AP_CORE) && !defined(HAL_MCU_CORE)
#error "Please define HAL_AP_CORE or HAL_MCU_CORE on hal_conf.h"
#endif

/* GIC Base */
#define GIC_DISTRIBUTOR_BASE       (0xFF581000)
#define GIC_CPU_INTERFACE_BASE     (0xFF582000)

#ifdef HAL_AP_CORE
#define __CA_REV                  0x0005U    /* Core revision r0p5                            */
#define __CORTEX_A                7U         /* Cortex-A7 Core                                */
#define __FPU_PRESENT             1U         /* FPU present                                   */
#define __TIM_PRESENT             1U         /* TIM present                                   */
#define __L2C_PRESENT             0U         /* L2C present                                   */
#else
#define __CM0_REV                 0x0000U   /* Core revision r0p0 */
#define __MPU_PRESENT             0U        /* no MPU present */
#define __VTOR_PRESENT            0U        /* no VTOR present */
#define __NVIC_PRIO_BITS          2U        /* Number of Bits used for Priority Levels */
#define __Vendor_SysTickConfig    0U        /* Set to 1 if different SysTick Config is used */

#define NVIC_PERIPH_IRQ_OFFSET    16U
#define MAX_INTERRUPT_VECTOR      64U
#endif

#ifndef __ASSEMBLY__
#include "cmsis_compiler.h"               /* CMSIS compiler specific defines */
#ifdef HAL_AP_CORE
#include "core_ca.h"
#else
#include "core_cm0.h"
#endif
#include "system_rk3506.h"
#endif /* __ASSEMBLY__ */
#include "rk3506.h"

/*****************************************CACHE*****************************************/
#ifdef HAL_AP_CORE
/* CACHE LINE SIZE */
#define CACHE_LINE_SHIFT (6U)
#define CACHE_LINE_SIZE  (0x1U << CACHE_LINE_SHIFT)
#else
/* CACHE LINE SIZE */
#define CACHE_LINE_SHIFT                (5U)
#define CACHE_LINE_SIZE                 (0x1U << CACHE_LINE_SHIFT)
#define CACHE_LINE_ADDR_MASK            (0xFFFFFFFFU << CACHE_LINE_SHIFT)
#define CACHE_M_CLEAN                   0x0U
#define CACHE_M_INVALID                 0x2U
#define CACHE_M_CLEAN_INVALID           0x4U
#define CACHE_M_INVALID_ALL             0x6U
#define CACHE_REVISION                  (0x00000100U)

#if defined(HAL_BUS_MCU_CORE) && !defined(HAL_CACHE_DECODED_ADDR_BASE)
#error "Please define HAL_CACHE_DECODED_ADDR_BASE on hal_conf.h"
#endif

#endif

/****************************************************************************************/
/*                                                                                      */
/*                           Platform Differences Section                               */
/*                                                                                      */
/****************************************************************************************/

/******************************************CRU*******************************************/
#define CRU_CLK_USE_CON_BANK
#define CLK64(mux, div) ((((mux) & 0xffffffffULL) << 32) | ((div) & 0xffffffffULL))

#ifndef __ASSEMBLY__
typedef enum CLOCK_Name {
    /* TODO */
    CLK_INVALID = 0U,
} eCLOCK_Name;
#endif /* __ASSEMBLY__ */

/****************************************MBOX********************************************/
#define MBOX_CNT             2
#define MBOX_CHAN_CNT        4

/****************************************GPIO********************************************/
#ifdef GPIO_VER_ID
#undef GPIO_VER_ID
#define GPIO_VER_ID             (0x01000C2BU)
#endif
#define GPIO0_IRQn              GPIO0_0_IRQn
#define GPIO1_IRQn              GPIO1_0_IRQn
#define GPIO2_IRQn              GPIO2_0_IRQn
#define GPIO3_IRQn              GPIO3_0_IRQn
#define GPIO4_IRQn              GPIO4_0_IRQn

/****************************************FSPI********************************************/
#define FSPI_CHIP_CNT                            (2)

/****************************************WDT*********************************************/
#define GLB_RST_SND_WDT GLB_RST_SND_WDT0
#define GLB_RST_FST_WDT GLB_RST_FST_WDT0

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __SOC_H */
