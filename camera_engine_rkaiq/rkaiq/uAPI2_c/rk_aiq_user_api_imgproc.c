/*
 *  Copyright (c) 2019 Rockchip Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "include/uAPI2/rk_aiq_user_api2_imgproc.h"
#include "uAPI2_c/rk_aiq_user_api2_common.h"
#include "uAPI2/rk_aiq_user_api2_ae.h"

#ifdef ISP_HW_V39
#include "rk_aiq_user_api2_isp39.h"
#elif  defined(ISP_HW_V33)
#include "rk_aiq_user_api2_isp33.h"
#elif  defined(ISP_HW_V32)
#include "rk_aiq_user_api2_isp32.h"
#elif defined(ISP_HW_V35)
#include "rk_aiq_user_api2_isp35.h"
#endif

#ifdef RK_SIMULATOR_HW
#define CHECK_USER_API_ENABLE
#endif

#define RKAIQ_IMGPROC_CHECK_RET(ret, format, ...) \
    if (ret) { \
        LOGE(format, ##__VA_ARGS__); \
        return ret; \
    }

#define IMGPROC_FUNC_ENTER LOGD("%s: enter", __FUNCTION__);
#define IMGPROC_FUNC_EXIT LOGD("%s: exit", __FUNCTION__);

RKAIQ_BEGIN_DECLARE

static bool isHDRmode(const rk_aiq_sys_ctx_t* ctx)
{
    RKAIQ_API_SMART_LOCK(ctx);
    int mode = RK_AIQ_WORKING_MODE_NORMAL;
    const rk_aiq_sys_ctx_t* sys_ctx = rk_aiq_user_api2_common_getSysCtx(ctx);
    mode = sys_ctx->_analyzer->mAlogsComSharedParams.working_mode;

    if (RK_AIQ_WORKING_MODE_NORMAL == mode)
        return false;
    else
        return true;
}

static int getHDRFrameNum(const rk_aiq_sys_ctx_t* ctx)
{
    RKAIQ_API_SMART_LOCK(ctx);
    int FrameNum = 1, working_mode = RK_AIQ_WORKING_MODE_NORMAL;

    const rk_aiq_sys_ctx_t* sys_ctx = rk_aiq_user_api2_common_getSysCtx(ctx);
    working_mode = sys_ctx->_analyzer->mAlogsComSharedParams.working_mode;

    switch (working_mode)
    {
    case RK_AIQ_WORKING_MODE_NORMAL:
        FrameNum = 1;
        break;
    case RK_AIQ_ISP_HDR_MODE_2_FRAME_HDR:
    case RK_AIQ_ISP_HDR_MODE_2_LINE_HDR:
        FrameNum = 2;
        break;
    case RK_AIQ_ISP_HDR_MODE_3_FRAME_HDR:
    case RK_AIQ_ISP_HDR_MODE_3_LINE_HDR:
        FrameNum = 3;
        break;
    default:
        FrameNum = 1;
        break;
    }
    return FrameNum;
}

/*
**********************************************************
*                        API of AEC module of V2
**********************************************************
*/

/*
*****************************
* Desc: set ae mode
* Argument:
*   mode contains: auto & manual
*
*****************************
*/
XCamReturn rk_aiq_uapi_setAeLock(
    const rk_aiq_sys_ctx_t* ctx,
    bool on)
{
    IMGPROC_FUNC_ENTER
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param invalid!");
    }

    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "failed in getExpSwAttr!");
    expSwAttr.commCtrl.sw_aeT_algo_en = (!on);
    ret = rk_aiq_user_api2_ae_setExpSwAttr(ctx, expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "failed in setExpSwAttr!");
    IMGPROC_FUNC_EXIT
    return (ret);
}
XCamReturn rk_aiq_uapi_setExpMode(
    const rk_aiq_sys_ctx_t* ctx,
    opMode_t mode)
{
    IMGPROC_FUNC_ENTER
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param invalid!");
    }

    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setExpMode failed in getExpSwAttr!");
    if (mode == OP_AUTO) {
        expSwAttr.commCtrl.sw_aeT_opt_mode = RK_AIQ_OP_MODE_AUTO;
    } else if (mode == OP_MANUAL) {
        if (isHDRmode(ctx)) {
            expSwAttr.commCtrl.sw_aeT_opt_mode = RK_AIQ_OP_MODE_MANUAL;
            expSwAttr.commCtrl.meCtrl.hdrMe.sw_aeT_manTime_en = true;
            expSwAttr.commCtrl.meCtrl.hdrMe.sw_aeT_manGain_en = true;
        } else {
            expSwAttr.commCtrl.sw_aeT_opt_mode = RK_AIQ_OP_MODE_MANUAL;
            expSwAttr.commCtrl.meCtrl.linMe.sw_aeT_manTime_en = true;
            expSwAttr.commCtrl.meCtrl.linMe.sw_aeT_manGain_en = true;
        }
    } else {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "mode is not supported!");
    }
    ret = rk_aiq_user_api2_ae_setExpSwAttr(ctx, expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setExpMode failed in setExpSwAttr!");
    IMGPROC_FUNC_EXIT
    return (ret);
}
XCamReturn rk_aiq_uapi_getExpMode(
    const rk_aiq_sys_ctx_t* ctx,
    opMode_t* mode)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    IMGPROC_FUNC_ENTER
    if ((ctx == NULL) || (mode == NULL)) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param invalid!");
    }
    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getExpMode failed in getExpSwAttr!");
    if (expSwAttr.commCtrl.sw_aeT_opt_mode == RK_AIQ_OP_MODE_AUTO) {
        *mode = OP_AUTO;
    } else if (expSwAttr.commCtrl.sw_aeT_opt_mode == RK_AIQ_OP_MODE_MANUAL) {
        *mode = OP_MANUAL;
    }
    IMGPROC_FUNC_EXIT
    return (ret);
}

XCamReturn rk_aiq_uapi_setManualExp(const rk_aiq_sys_ctx_t* ctx, float gain, float time)
{
    IMGPROC_FUNC_ENTER
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param invalid!");
    }
    if (gain < 0.0f || time < 0.0f) {
        ret = XCAM_RETURN_NO_ERROR;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param invalid!");
    }
    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setManualExp failed in getExpSwAttr!");
    if (isHDRmode(ctx)) {
        expSwAttr.commCtrl.sw_aeT_opt_mode = RK_AIQ_OP_MODE_MANUAL;
        expSwAttr.commCtrl.meCtrl.hdrMe.sw_aeT_manGain_en = true;
        expSwAttr.commCtrl.meCtrl.hdrMe.sw_aeT_manTime_en = true;
        expSwAttr.commCtrl.meCtrl.hdrMe.sw_aeT_manGain_val[0] = gain;
        expSwAttr.commCtrl.meCtrl.hdrMe.sw_aeT_manGain_val[1] = gain;
        expSwAttr.commCtrl.meCtrl.hdrMe.sw_aeT_manGain_val[2] = gain;
        expSwAttr.commCtrl.meCtrl.hdrMe.sw_aeT_manTime_val[0] = time;
        expSwAttr.commCtrl.meCtrl.hdrMe.sw_aeT_manTime_val[1] = time;
        expSwAttr.commCtrl.meCtrl.hdrMe.sw_aeT_manTime_val[2] = time;
    } else {
        expSwAttr.commCtrl.sw_aeT_opt_mode = RK_AIQ_OP_MODE_MANUAL;
        expSwAttr.commCtrl.meCtrl.linMe.sw_aeT_manGain_en = true;
        expSwAttr.commCtrl.meCtrl.linMe.sw_aeT_manTime_en = true;
        expSwAttr.commCtrl.meCtrl.linMe.sw_aeT_manGain_val = gain;
        expSwAttr.commCtrl.meCtrl.linMe.sw_aeT_manTime_val = time;
    }
    ret = rk_aiq_user_api2_ae_setExpSwAttr(ctx, expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setManualExp failed in setExpSwAttr!");
    IMGPROC_FUNC_EXIT
    return (ret);
}

/*
*****************************
* Desc: set frame rate
* Argument:
*   info.mode OP_AUTO or OP_MANUAL
*
*****************************
*/
XCamReturn rk_aiq_uapi_setFrameRate(const rk_aiq_sys_ctx_t* ctx, frameRateInfo_t info)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    IMGPROC_FUNC_ENTER
    if ((ctx == NULL) || (info.mode < OP_AUTO || info.mode >= OP_INVAL)) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }
    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get exp attr failed!\nsetFrameRate failed!");
    if (info.mode == OP_AUTO) {
        expSwAttr.commCtrl.frmRate.sw_aeT_frmRate_mode = ae_frmRate_auto_mode;
        expSwAttr.commCtrl.frmRate.sw_aeT_frmRate_val  = info.fps;
    } else if (info.mode == OP_MANUAL) {
        expSwAttr.commCtrl.frmRate.sw_aeT_frmRate_mode = ae_frmRate_fix_mode;
        expSwAttr.commCtrl.frmRate.sw_aeT_frmRate_val  = info.fps;
    }
    ret = rk_aiq_user_api2_ae_setExpSwAttr(ctx, expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set exp attr failed!\nsetFrameRate failed!");
    IMGPROC_FUNC_EXIT
    return ret;

}

XCamReturn rk_aiq_uapi_getFrameRate(const rk_aiq_sys_ctx_t* ctx, frameRateInfo_t *info)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }
    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get exp attr failed!\nsetFrameRate failed!");
    if (expSwAttr.commCtrl.frmRate.sw_aeT_frmRate_mode == ae_frmRate_auto_mode) {
        info->fps = expSwAttr.commCtrl.frmRate.sw_aeT_frmRate_val;
        info->mode = OP_AUTO;
    } else if (expSwAttr.commCtrl.frmRate.sw_aeT_frmRate_mode == ae_frmRate_fix_mode) {
        info->fps = expSwAttr.commCtrl.frmRate.sw_aeT_frmRate_val;
        info->mode = OP_MANUAL;
    }
    IMGPROC_FUNC_EXIT
    return ret;

}

/*
*****************************
*
* Desc: set exposure parameter
* Argument:
*    auto exposure mode:
*      exposure gain will be adjust between [gain->min, gain->max]
*    manual exposure mode:
*      gain->min == gain->max
*
*****************************
*/
XCamReturn rk_aiq_uapi_setExpGainRange(
    const rk_aiq_sys_ctx_t* ctx,
    paRange_t* gain)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    IMGPROC_FUNC_ENTER
    if ((ctx == NULL) || (gain == NULL)) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param invalid!");
    }
    LOGD("set range: [%f, %f]", gain->min, gain->max);

    if (gain->min < 1.0f || gain->max < 1.0f || (gain->min > gain->max)) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "gain range is wrong!");
    }
    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get exp attr failed!\nsetExpGainRange failed!");

    expSwAttr.advanced.sw_aeT_advAeRange_en = true;
    if (isHDRmode(ctx)) {
        expSwAttr.advanced.hdrExpRange[0].sw_aeT_gain_max = gain->max;
        expSwAttr.advanced.hdrExpRange[0].sw_aeT_gain_min = gain->min;
        expSwAttr.advanced.hdrExpRange[1].sw_aeT_gain_max = gain->max;
        expSwAttr.advanced.hdrExpRange[1].sw_aeT_gain_min = gain->min;
        expSwAttr.advanced.hdrExpRange[2].sw_aeT_gain_max = gain->max;
        expSwAttr.advanced.hdrExpRange[2].sw_aeT_gain_min = gain->min;
    } else {
        expSwAttr.advanced.linExpRange.sw_aeT_gain_max = gain->max;
        expSwAttr.advanced.linExpRange.sw_aeT_gain_min = gain->min;
    }
    ret = rk_aiq_user_api2_ae_setExpSwAttr(ctx, expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set exp attr failed!\nsetExpGainRange failed!");
    IMGPROC_FUNC_EXIT
    return (ret);
}
XCamReturn rk_aiq_uapi_getExpGainRange(
    const rk_aiq_sys_ctx_t* ctx,
    paRange_t* gain)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_queryInfo_t queryInfo;
    IMGPROC_FUNC_ENTER
    if ((ctx == NULL) || (gain == NULL)) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }

    ret = rk_aiq_user_api2_ae_queryExpResInfo(ctx, &queryInfo);
    RKAIQ_IMGPROC_CHECK_RET(ret, "query exp info failed!\ngetExpGainRange failed!");
    if (isHDRmode(ctx)) {
        int index = getHDRFrameNum(ctx);
        gain->max = queryInfo.hdrExpInfo.expRange[index - 1].sw_aeT_gain_max;
        gain->min = queryInfo.hdrExpInfo.expRange[index - 1].sw_aeT_gain_min;
    } else {
        gain->max = queryInfo.linExpInfo.expRange.sw_aeT_gain_max;
        gain->min = queryInfo.linExpInfo.expRange.sw_aeT_gain_min;
    }

    IMGPROC_FUNC_EXIT
    return (ret);
}
/*
*****************************
*
* Desc: set exposure parameter
* Argument:
*    auto exposure mode:
*       exposure time will be adjust between [time->min, time->max]
*    manual exposure mode:
*       exposure time will be set gain->min == gain->max;
*
*****************************
*/
XCamReturn rk_aiq_uapi_setExpTimeRange(
    const rk_aiq_sys_ctx_t* ctx,
    paRange_t* time)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    IMGPROC_FUNC_ENTER
    if ((ctx == NULL) || (time == NULL)) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }
    if (time->min > time->max) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "time range is wrong!");
    }
    LOGD("set range: [%f, %f]", time->min, time->max);
    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get exp attr failed!\nsetExpTimeRange failed!");

    expSwAttr.advanced.sw_aeT_advAeRange_en = true;
    if (isHDRmode(ctx)) {
        expSwAttr.advanced.hdrExpRange[0].sw_aeT_time_max = time->max;
        expSwAttr.advanced.hdrExpRange[0].sw_aeT_time_min = time->min;
        expSwAttr.advanced.hdrExpRange[1].sw_aeT_time_max = time->max;
        expSwAttr.advanced.hdrExpRange[1].sw_aeT_time_min = time->min;
        expSwAttr.advanced.hdrExpRange[2].sw_aeT_time_max = time->max;
        expSwAttr.advanced.hdrExpRange[2].sw_aeT_time_min = time->min;
    } else {
        expSwAttr.advanced.linExpRange.sw_aeT_time_max = time->max;
        expSwAttr.advanced.linExpRange.sw_aeT_time_min = time->min;
    }
    ret = rk_aiq_user_api2_ae_setExpSwAttr(ctx, expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set exp attr failed!\nsetExpTimeRange failed!");
    IMGPROC_FUNC_EXIT
    return (ret);
}
XCamReturn rk_aiq_uapi_getExpTimeRange(
    const rk_aiq_sys_ctx_t* ctx,
    paRange_t* time)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_queryInfo_t queryInfo;
    IMGPROC_FUNC_ENTER
    if ((ctx == NULL) || (time == NULL)) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }

    ret = rk_aiq_user_api2_ae_queryExpResInfo(ctx, &queryInfo);
    RKAIQ_IMGPROC_CHECK_RET(ret, "query exp info failed!\ngetExpTimeRange failed!");
    if (isHDRmode(ctx)) {
        int index = getHDRFrameNum(ctx);
        time->max = queryInfo.hdrExpInfo.expRange[index - 1].sw_aeT_time_max;
        time->min = queryInfo.hdrExpInfo.expRange[index - 1].sw_aeT_time_min;
    } else {
        time->max = queryInfo.linExpInfo.expRange.sw_aeT_time_max;
        time->min = queryInfo.linExpInfo.expRange.sw_aeT_time_min;
    }

    IMGPROC_FUNC_EXIT
    return (ret);
}
/*
*****************************
*
* Desc: backlight compensation
* Argument:
*      on:  1  on
*           0  off
*      areaType: backlight compensation area
*
*****************************
*/
XCamReturn rk_aiq_uapi_setBLCMode(const rk_aiq_sys_ctx_t* ctx, bool on, aeMeasAreaType_t areaType)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    ae_api_linExpAttr_t LineExpAttr;
    memset(&LineExpAttr, 0x00, sizeof(ae_api_linExpAttr_t));
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }
    if (isHDRmode(ctx)) {
        ret = XCAM_RETURN_ERROR_FAILED;
        RKAIQ_IMGPROC_CHECK_RET(ret, "Not support in HDR mode!");
    }

    ret = rk_aiq_user_api2_ae_getLinExpAttr(ctx, &LineExpAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getLinExpAttr error!");
    LineExpAttr.backLightCtrl.sw_aeT_backLit_en = on ? 1 : 0;
    LineExpAttr.backLightCtrl.sw_aeT_measArea_mode = (ae_measArea_mode_t)areaType;
    LineExpAttr.backLightCtrl.sw_aeT_backLitBias_strg = 0;
    ret = rk_aiq_user_api2_ae_setLinExpAttr(ctx, LineExpAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setBLCMode error!");
    IMGPROC_FUNC_EXIT
    return ret;
}
/*
*****************************
*
* Desc: backlight compensation strength,only available in normal mode
* Argument:
*      strength:  [1,100]
*****************************
*/
XCamReturn rk_aiq_uapi_setBLCStrength(const rk_aiq_sys_ctx_t* ctx, int strength)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_linExpAttr_t LineExpAttr;
    memset(&LineExpAttr, 0x00, sizeof(ae_api_linExpAttr_t));

    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }
    if (isHDRmode(ctx)) {
        ret = XCAM_RETURN_ERROR_FAILED;
        RKAIQ_IMGPROC_CHECK_RET(ret, "Not support in HDR mode!");
    } else {
        ret = rk_aiq_user_api2_ae_getLinExpAttr(ctx, &LineExpAttr);
        RKAIQ_IMGPROC_CHECK_RET(ret, "getLinExpAttr error!");
        if (0 == LineExpAttr.backLightCtrl.sw_aeT_backLit_en)
            RKAIQ_IMGPROC_CHECK_RET(ret, "blc mode is not enabled!");
        LineExpAttr.backLightCtrl.sw_aeT_backLitBias_strg = strength;
        ret = rk_aiq_user_api2_ae_setLinExpAttr(ctx, LineExpAttr);
        RKAIQ_IMGPROC_CHECK_RET(ret, "setBLCStrength error!");
    }

    IMGPROC_FUNC_EXIT
    return ret;
}
/*
*****************************
*
* Desc: highlight compensation
* Argument:
*      on:  1  on
*           0  off
*****************************
*/
XCamReturn rk_aiq_uapi_setHLCMode(const rk_aiq_sys_ctx_t* ctx, bool on)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_linExpAttr_t LinExpAttr;
    memset(&LinExpAttr, 0x00, sizeof(ae_api_linExpAttr_t));
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }

    if (isHDRmode(ctx)) {
        ret = XCAM_RETURN_ERROR_FAILED;
        RKAIQ_IMGPROC_CHECK_RET(ret, "Not support in HDR mode!");
    } else {
        ret = rk_aiq_user_api2_ae_getLinExpAttr(ctx, &LinExpAttr);
        RKAIQ_IMGPROC_CHECK_RET(ret, "get exp attr failed!\n setHLCMode failed!");
        LinExpAttr.overExpCtrl.sw_aeT_overExp_en = on ? 1 : 0;
        LinExpAttr.overExpCtrl.sw_aeT_overExpBias_strg = 0;
        ret = rk_aiq_user_api2_ae_setLinExpAttr(ctx, LinExpAttr);
        RKAIQ_IMGPROC_CHECK_RET(ret, "set exp attr failed!\n setHLCMode failed!");
    }
    IMGPROC_FUNC_EXIT
    return ret;
}
/*
*****************************
*
* Desc: highlight compensation strength
* Argument:
*      strength:  [1,100]
*****************************
*/
XCamReturn rk_aiq_uapi_setHLCStrength(const rk_aiq_sys_ctx_t* ctx, int strength)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_linExpAttr_t LinExpAttr;
    memset(&LinExpAttr, 0x00, sizeof(ae_api_linExpAttr_t));
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }
    if (isHDRmode(ctx)) {
        ret = XCAM_RETURN_ERROR_FAILED;
        RKAIQ_IMGPROC_CHECK_RET(ret, "Not support in HDR mode!");
    } else {
        ret = rk_aiq_user_api2_ae_getLinExpAttr(ctx, &LinExpAttr);
        RKAIQ_IMGPROC_CHECK_RET(ret, "getLinExpAttr error!");
        if (0 == LinExpAttr.overExpCtrl.sw_aeT_overExp_en)
            RKAIQ_IMGPROC_CHECK_RET(ret, "hlc mode is not enabled!");
        LinExpAttr.overExpCtrl.sw_aeT_overExpBias_strg = strength;
        ret = rk_aiq_user_api2_ae_setLinExpAttr(ctx, LinExpAttr);
        RKAIQ_IMGPROC_CHECK_RET(ret, "setHLCStrength error!");
    }
    IMGPROC_FUNC_EXIT
    return ret;
}
/*
*****************************
*
* Desc: set anti-flicker mode
* Argument:
*    mode
*
*****************************
*/
XCamReturn rk_aiq_uapi_setAntiFlickerEn(const rk_aiq_sys_ctx_t* ctx, bool on)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }

    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get exp attr failed!\nsetAntiFlickerEn failed!");
    expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_en = on;

    ret = rk_aiq_user_api2_ae_setExpSwAttr(ctx, expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set exp attr failed!\nsetAntiFlickerEn failed!");
    IMGPROC_FUNC_EXIT
    return ret;
}
/*
*****************************
*
* Desc: set anti-flicker mode
* Argument:
*    mode
*
*****************************
*/
XCamReturn rk_aiq_uapi_getAntiFlickerEn(const rk_aiq_sys_ctx_t* ctx, bool* on)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }

    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get exp attr failed!\ngetAntiFlickerEn!");
    *on = expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_en;
    IMGPROC_FUNC_EXIT
    return ret;
}
/*
*****************************
*
* Desc: set anti-flicker mode
* Argument:
*    mode
*
*****************************
*/

XCamReturn rk_aiq_uapi_setAntiFlickerMode(const rk_aiq_sys_ctx_t* ctx, antiFlickerMode_t mode)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }

    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get exp attr failed!\nsetAntiFlickerMode failed!");
    if (mode == ANTIFLICKER_AUTO_MODE) {
        expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_en = true;
        expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_mode = ae_antiFlicker_auto_mode;
    } else if (mode == ANTIFLICKER_NORMAL_MODE) {
        expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_en = true;
        expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_mode = ae_antiFlicker_normal_mode;
    } else {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "mode is invalid!");
    }
    ret = rk_aiq_user_api2_ae_setExpSwAttr(ctx, expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set exp attr failed!\nsetAntiFlickerMode failed!");
    IMGPROC_FUNC_EXIT
    return ret;
}
XCamReturn rk_aiq_uapi_getAntiFlickerMode(const rk_aiq_sys_ctx_t* ctx, antiFlickerMode_t* mode)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }

    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);

    RKAIQ_IMGPROC_CHECK_RET(ret, "get exp attr failed!\ngetAntiFlickerMode!");
    if (expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_mode == ae_antiFlicker_auto_mode)
        *mode = ANTIFLICKER_AUTO_MODE;
    else if (expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_mode == ae_antiFlicker_normal_mode)
        *mode = ANTIFLICKER_NORMAL_MODE;
    IMGPROC_FUNC_EXIT
    return ret;
}
/*
*****************************
*
* Desc: set power line frequence
* Argument:
*    freq
*
*****************************
*/
XCamReturn rk_aiq_uapi_setExpPwrLineFreqMode(const rk_aiq_sys_ctx_t* ctx, expPwrLineFreq_t freq)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }
    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get exp attr failed!\nsetExpPwrLineFreqMode failed!");
    if (freq == EXP_PWR_LINE_FREQ_50HZ) {
        expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_en = true;
        expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_freq = ae_antiFlicker_50hz_freq;
    } else if (freq == EXP_PWR_LINE_FREQ_60HZ) {
        expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_en = true;
        expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_freq = ae_antiFlicker_60hz_freq;
    } else if (freq == EXP_PWR_LINE_FREQ_DIS) {
        expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_en = false;
        expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_freq = ae_antiFlicker_off_freq;
    } else {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "freq is invalid!");
    }
    ret = rk_aiq_user_api2_ae_setExpSwAttr(ctx, expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set exp attr failed!\nsetExpPwrLineFreqMode failed!");
    IMGPROC_FUNC_EXIT
    return (ret);
}
XCamReturn rk_aiq_uapi_getExpPwrLineFreqMode(
    const rk_aiq_sys_ctx_t* ctx,
    expPwrLineFreq_t* freq)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    ae_api_expSwAttr_t expSwAttr;
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }

    ret = rk_aiq_user_api2_ae_getExpSwAttr(ctx, &expSwAttr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get exp attr failed!\nsetExpPwrLineFreqMode failed!");
    if (expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_freq == ae_antiFlicker_50hz_freq) {
        *freq = EXP_PWR_LINE_FREQ_50HZ;
    } else if (expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_freq == ae_antiFlicker_60hz_freq) {
        *freq = EXP_PWR_LINE_FREQ_60HZ;
    } else if (expSwAttr.commCtrl.antiFlicker.sw_aeT_antiFlicker_freq == ae_antiFlicker_off_freq) {
        *freq = EXP_PWR_LINE_FREQ_DIS;
    } else {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "freq is invalid!");
    }
    IMGPROC_FUNC_EXIT
    return (ret);
}

/*
**********************************************************
* White balance & Color
**********************************************************
*/
/*
*****************************
*
* Desc: set white balance mode
* Argument:
*   mode:  auto: auto white balance
*          manual: manual white balance
*****************************
*/
XCamReturn rk_aiq_uapi_setWBMode(const rk_aiq_sys_ctx_t* ctx, opMode_t mode)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    rk_aiq_op_mode_t mode2;
    IMGPROC_FUNC_ENTER
    if (mode >= OP_INVAL || mode < OP_AUTO) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "mode is invalid!");
    }
    if (mode == OP_AUTO) {
        mode2 = RK_AIQ_OP_MODE_AUTO;
    } else if (mode == OP_MANUAL) {
        mode2 = RK_AIQ_OP_MODE_MANUAL;
    } else {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "Not supported mode!");
    }
    awb_gainCtrl_t attr;
    ret = rk_aiq_user_api2_awb_GetWbGainCtrlAttrib(ctx, &attr );
    RKAIQ_IMGPROC_CHECK_RET(ret, "GetWbGainCtrlAttrib failed!");
    attr.opMode = mode2;
    ret = rk_aiq_user_api2_awb_SetWbGainCtrlAttrib(ctx, &attr );
    RKAIQ_IMGPROC_CHECK_RET(ret, "GetWbGainCtrlAttrib failed!");
    IMGPROC_FUNC_EXIT
    return ret;
}
XCamReturn rk_aiq_uapi_getWBMode(const rk_aiq_sys_ctx_t* ctx, opMode_t *mode)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    rk_aiq_wb_querry_info_t query_info;
    ret = rk_aiq_user_api2_awb_QueryWBInfo(ctx, &query_info);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getWBMode failed!");
    if (query_info.opMode == RK_AIQ_OP_MODE_AUTO) {
        *mode = OP_AUTO;
    } else if (query_info.opMode == RK_AIQ_OP_MODE_MANUAL) {
        *mode = OP_MANUAL;
    } else {
        *mode = OP_INVAL;
    }
    IMGPROC_FUNC_EXIT
    return ret;
}



/*
*****************************
*
* Desc: lock/unlock auto white balance
* Argument:
*
*
*****************************
*/
XCamReturn rk_aiq_uapi_lockAWB(const rk_aiq_sys_ctx_t* ctx)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_awb_Lock(ctx);
    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_unlockAWB(const rk_aiq_sys_ctx_t* ctx)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_awb_Unlock(ctx);
    IMGPROC_FUNC_EXIT
    return ret;
}

/*
*****************************
*
* Desc: set manual white balance scene mode
* Argument:
*   ct_scene:
*
*****************************
*/
XCamReturn rk_aiq_uapi_setMWBScene(const rk_aiq_sys_ctx_t* ctx, rk_aiq_wb_scene_t scene)
{
    LOGE("not support to call %s for current chip", __FUNCTION__);
    return XCAM_RETURN_ERROR_UNKNOWN;
}

XCamReturn rk_aiq_uapi_getMWBScene(const rk_aiq_sys_ctx_t* ctx, rk_aiq_wb_scene_t *scene)
{
    LOGE("not support to call %s for current chip", __FUNCTION__);
    return XCAM_RETURN_ERROR_UNKNOWN;
}


/*
*****************************
*
* Desc: set manual white balance r/b gain
* Argument:
*   ct_scene:
*
*****************************
*/
XCamReturn rk_aiq_uapi_setMWBGain(const rk_aiq_sys_ctx_t* ctx, rk_aiq_wb_gain_t *gain)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    IMGPROC_FUNC_ENTER
    if ((ctx == NULL) || (gain == NULL)) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, setMWBGain failed!");
    }
    awb_gainCtrl_t attr;
    ret = rk_aiq_user_api2_awb_GetWbGainCtrlAttrib(ctx, &attr );
    RKAIQ_IMGPROC_CHECK_RET(ret, "GetWbGainCtrlAttrib failed!");
    attr.manualPara.mode = mwb_mode_wbgain;
    attr.manualPara.cfg.manual_wbgain[0] = gain->rgain;
    attr.manualPara.cfg.manual_wbgain[1] = gain->grgain;
    attr.manualPara.cfg.manual_wbgain[2] = gain->gbgain;
    attr.manualPara.cfg.manual_wbgain[3] = gain->bgain;
    ret = rk_aiq_user_api2_awb_SetWbGainCtrlAttrib(ctx, &attr );
    RKAIQ_IMGPROC_CHECK_RET(ret, "GetWbGainCtrlAttrib failed!");
    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_getWBGain(const rk_aiq_sys_ctx_t* ctx, rk_aiq_wb_gain_t *gain)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    rk_aiq_wb_querry_info_t query_info;
    IMGPROC_FUNC_ENTER
    if ((ctx == NULL) || (gain == NULL)) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, getMWBGain failed!");
    }
    ret = rk_aiq_user_api2_awb_QueryWBInfo(ctx, &query_info);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getMWBGain failed!");
    *gain = query_info.gain;
    IMGPROC_FUNC_EXIT

    return ret;
}
/*
*****************************
*
* Desc: set manual white balance color temperature
* Argument:
*   ct: color temperature value [2800, 7500]K
*
*****************************
*/
XCamReturn rk_aiq_uapi_setMWBCT(const rk_aiq_sys_ctx_t* ctx, unsigned int ct)
{
    LOGE("not support to call %s for current chip", __FUNCTION__);
    return XCAM_RETURN_ERROR_UNKNOWN;
}

XCamReturn rk_aiq_uapi_getWBCT(const rk_aiq_sys_ctx_t* ctx, unsigned int *ct)
{
    LOGE("not support to call %s for current chip", __FUNCTION__);
    return XCAM_RETURN_ERROR_UNKNOWN;
}

XCamReturn rk_aiq_uapi_setFocusMode(const rk_aiq_sys_ctx_t* ctx, opMode_t mode)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    rk_aiq_af_attrib_t attr;
    ret = rk_aiq_user_api2_af_GetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setFocusMode failed!");
    if (mode == OP_AUTO) {
        attr.AfMode = RKAIQ_AF_MODE_CONTINUOUS_PICTURE;
    } else if (mode == OP_MANUAL) {
        attr.AfMode = RKAIQ_AF_MODE_FIXED;
    } else if (mode == OP_SEMI_AUTO) {
        attr.AfMode = RKAIQ_AF_MODE_ONESHOT_AFTER_ZOOM;
    } else {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "Not supported mode!");
    }

    attr.sync.sync_mode = RK_AIQ_UAPI_MODE_SYNC;
    ret = rk_aiq_user_api2_af_SetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setFocusMode failed!");
    return ret;
}

XCamReturn rk_aiq_uapi_getFocusMode(const rk_aiq_sys_ctx_t* ctx, opMode_t *mode)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    rk_aiq_af_attrib_t attr;
    ret = rk_aiq_user_api2_af_GetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getFocusMode failed!");
    if (attr.AfMode == RKAIQ_AF_MODE_FIXED) {
        *mode = OP_MANUAL;
    } else if (attr.AfMode == RKAIQ_AF_MODE_NOT_SET) {
        *mode = OP_INVAL;
    } else if (attr.AfMode == RKAIQ_AF_MODE_ONESHOT_AFTER_ZOOM) {
        *mode = OP_SEMI_AUTO;
    } else {
        *mode = OP_AUTO;
    }

    return ret;
}

XCamReturn rk_aiq_uapi_setFocusWin(const rk_aiq_sys_ctx_t* ctx, paRect_t *rect)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    rk_aiq_af_attrib_t attr;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_GetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setFocusWin failed!");

    attr.h_offs = rect->x;
    attr.v_offs = rect->y;
    attr.h_size = rect->w;
    attr.v_size = rect->h;
    attr.sync.sync_mode = RK_AIQ_UAPI_MODE_SYNC;
    ret = rk_aiq_user_api2_af_SetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setFocusWin failed!");
    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_getFocusWin(const rk_aiq_sys_ctx_t* ctx, paRect_t *rect)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    rk_aiq_af_attrib_t attr;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_GetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getFocusWin failed!");

    rect->x = attr.h_offs;
    rect->y = attr.v_offs;
    rect->w = attr.h_size;
    rect->h = attr.v_size;
    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_lockFocus(const rk_aiq_sys_ctx_t* ctx)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_Lock(ctx);
    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_unlockFocus(const rk_aiq_sys_ctx_t* ctx)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_Unlock(ctx);
    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_oneshotFocus(const rk_aiq_sys_ctx_t* ctx)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_Oneshot(ctx);
    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_manualTrigerFocus(const rk_aiq_sys_ctx_t* ctx)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_ManualTriger(ctx);
    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_trackingFocus(const rk_aiq_sys_ctx_t* ctx)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_Tracking(ctx);
    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_getSearchPath(const rk_aiq_sys_ctx_t* ctx, rk_aiq_af_sec_path_t* path)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_GetSearchPath(ctx, path);
    IMGPROC_FUNC_EXIT

    return ret;
}

XCamReturn rk_aiq_uapi_getSearchResult(const rk_aiq_sys_ctx_t* ctx, rk_aiq_af_result_t* result)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_GetSearchResult(ctx, result);
    IMGPROC_FUNC_EXIT

    return ret;
}

XCamReturn rk_aiq_uapi_getZoomRange(const rk_aiq_sys_ctx_t* ctx, rk_aiq_af_zoomrange * range)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_GetZoomRange(ctx, range);
    IMGPROC_FUNC_EXIT

    return ret;
}

XCamReturn rk_aiq_uapi_getFocusRange(const rk_aiq_sys_ctx_t* ctx, rk_aiq_af_focusrange* range)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_GetFocusRange(ctx, range);
    IMGPROC_FUNC_EXIT

    return ret;
}

XCamReturn rk_aiq_uapi_setOpZoomPosition(const rk_aiq_sys_ctx_t* ctx, int pos)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_SetZoomIndex(ctx, pos);
    IMGPROC_FUNC_EXIT

    return ret;
}

XCamReturn rk_aiq_uapi_getOpZoomPosition(const rk_aiq_sys_ctx_t* ctx, int *pos)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_GetZoomIndex(ctx, pos);
    IMGPROC_FUNC_EXIT

    return ret;
}

XCamReturn rk_aiq_uapi_endOpZoomChange(const rk_aiq_sys_ctx_t* ctx)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_EndZoomChg(ctx);
    IMGPROC_FUNC_EXIT

    return ret;
}

XCamReturn rk_aiq_uapi_startZoomCalib(const rk_aiq_sys_ctx_t* ctx)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_StartZoomCalib(ctx);
    IMGPROC_FUNC_EXIT

    return ret;
}

XCamReturn rk_aiq_uapi_resetZoom(const rk_aiq_sys_ctx_t* ctx)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    ret = rk_aiq_user_api2_af_resetZoom(ctx);
    IMGPROC_FUNC_EXIT

    return ret;
}


/*
*****************************
*
* Desc: set/get dark area boost strength
*    this function is active for normal mode
* Argument:
*   level: [1, 10]
*
*****************************
*/
XCamReturn rk_aiq_uapi_getDarkAreaBoostStrth(const rk_aiq_sys_ctx_t* ctx, unsigned int *level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

#if RKAIQ_HAVE_DRC_V10
    ret = XCAM_RETURN_ERROR_PARAM;
    RKAIQ_IMGPROC_CHECK_RET(ret, "ISP2.1 do not support tmo api!");
#endif
#if RKAIQ_HAVE_DRC_V11
    ret = XCAM_RETURN_ERROR_PARAM;
    RKAIQ_IMGPROC_CHECK_RET(ret, "ISP3.0 do not support tmo api!");
#endif
#if RKAIQ_HAVE_DRC_V12
    ret = XCAM_RETURN_ERROR_PARAM;
    RKAIQ_IMGPROC_CHECK_RET(ret, "ISP3.2 do not support tmo api!");
#endif
#if RKAIQ_HAVE_DRC_V12_LITE
    ret = XCAM_RETURN_ERROR_PARAM;
    RKAIQ_IMGPROC_CHECK_RET(ret, "ISP3.2 lite do not support tmo api!");
#endif
#if RKAIQ_HAVE_DRC_V20
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, ctx is NULL!");
    }

    adrc_strength_t ctrl;
    memset(&ctrl, 0, sizeof(adrc_strength_t));
    ret = rk_aiq_user_api2_drc_GetStrength(ctx, &ctrl);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getDarkAreaBoostStrth GetStrength failed!");

    *level = ctrl.darkAreaBoostStrength;

    IMGPROC_FUNC_EXIT
#endif

    return ret;
}

XCamReturn rk_aiq_uapi_setDarkAreaBoostStrth(const rk_aiq_sys_ctx_t* ctx, unsigned int level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    IMGPROC_FUNC_ENTER

#if RKAIQ_HAVE_DRC_V10
    ret = XCAM_RETURN_ERROR_PARAM;
    RKAIQ_IMGPROC_CHECK_RET(ret, "ISP2.1 do not support tmo api!");
#endif
#if RKAIQ_HAVE_DRC_V11
    ret = XCAM_RETURN_ERROR_PARAM;
    RKAIQ_IMGPROC_CHECK_RET(ret, "ISP3.0 do not support tmo api!");
#endif
#if RKAIQ_HAVE_DRC_V12
    ret = XCAM_RETURN_ERROR_PARAM;
    RKAIQ_IMGPROC_CHECK_RET(ret, "ISP3.2 do not support tmo api!");
#endif
#if RKAIQ_HAVE_DRC_V12_LITE
    ret = XCAM_RETURN_ERROR_PARAM;
    RKAIQ_IMGPROC_CHECK_RET(ret, "ISP3.2 lite do not support tmo api!");
#endif
#if RKAIQ_HAVE_DRC_V20
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, ctx is NULL!");
    }

    if (level > 100) {
        LOGE("params error, level need in range [0, 100]");
        return XCAM_RETURN_ERROR_PARAM;
    }

    adrc_strength_t ctrl;
    memset(&ctrl, 0, sizeof(adrc_strength_t));
    ret = rk_aiq_user_api2_drc_GetStrength(ctx, &ctrl);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setDarkAreaBoostStrth GetStrength failed!");

    ctrl.darkAreaBoostEn       = true;
    ctrl.darkAreaBoostStrength = level;

    ret = rk_aiq_user_api2_drc_SetStrength(ctx, ctrl);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setDarkAreaBoostStrth SetStrength failed!");

#endif

    IMGPROC_FUNC_EXIT
    return ret;
}

/*
*****************************
*
* Desc: set/get manual hdr strength
*    this function is active for HDR is manual mode
* Argument:
*   level: [1, 100]
*
*****************************
*/
XCamReturn rk_aiq_uapi_setMHDRStrth(const rk_aiq_sys_ctx_t* ctx, bool on, unsigned int level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, ctx is NULL!");
    }

    if ((level > 100)) {
        LOGE("params error, level need in range [0, 100]");
        return XCAM_RETURN_ERROR_PARAM;
    }

    adrc_strength_t ctrl;
    memset(&ctrl, 0, sizeof(adrc_strength_t));
    ret = rk_aiq_user_api2_drc_GetStrength(ctx, &ctrl);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setHDRStrth GetStrength failed!");

    ctrl.hdrStrengthEn = true;
    ctrl.hdrStrength   = level;

    ret = rk_aiq_user_api2_drc_SetStrength(ctx, ctrl);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setHDRStrth SetStrength failed!");

    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_getMHDRStrth(const rk_aiq_sys_ctx_t* ctx, bool * on, unsigned int *level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, ctx is NULL!");
    }

    adrc_strength_t ctrl;
    memset(&ctrl, 0, sizeof(adrc_strength_t));
    ret = rk_aiq_user_api2_drc_GetStrength(ctx, &ctrl);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getHDRStrth GetStrength failed!");

    *level = ctrl.hdrStrength;
    *on    = ctrl.hdrStrengthEn;

    IMGPROC_FUNC_EXIT
    return ret;
}

/*
**********************************************************
* Noise reduction
**********************************************************
*/
/*
*****************************
*
* Desc: set noise reduction mode
* Argument:
*   mode:
*     auto: auto noise reduction
*     manualï¼manual noise reduction
*
*****************************
*/
XCamReturn rk_aiq_uapi_setNRMode(const rk_aiq_sys_ctx_t* ctx, opMode_t mode)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER

    if (CHECK_ISP_HW_V39()) {
        ynr_api_attrib_t  ynr_attr;
        cnr_api_attrib_t  cnr_attr;
        btnr_api_attrib_t btnr_attr;

        ret = rk_aiq_user_api2_ynr_GetAttrib(ctx, &ynr_attr);
        ret = rk_aiq_user_api2_cnr_GetAttrib(ctx, &cnr_attr);
        ret = rk_aiq_user_api2_btnr_GetAttrib(ctx, &btnr_attr);

        if (mode == OP_AUTO) {
            ynr_attr.opMode = RK_AIQ_OP_MODE_AUTO;
            cnr_attr.opMode = RK_AIQ_OP_MODE_AUTO;
            btnr_attr.opMode = RK_AIQ_OP_MODE_AUTO;
        } else if (mode == OP_MANUAL) {
            ynr_attr.opMode = RK_AIQ_OP_MODE_MANUAL;
            cnr_attr.opMode = RK_AIQ_OP_MODE_MANUAL;
            btnr_attr.opMode = RK_AIQ_OP_MODE_MANUAL;
        } else {
            ret = XCAM_RETURN_ERROR_PARAM;
            RKAIQ_IMGPROC_CHECK_RET(ret, "Not supported mode!");
        }

        ret = rk_aiq_user_api2_ynr_SetAttrib(ctx, &ynr_attr);
        ret = rk_aiq_user_api2_cnr_SetAttrib(ctx, &cnr_attr);
        ret = rk_aiq_user_api2_btnr_SetAttrib(ctx, &btnr_attr);

        LOGE("not support to call %s for current chip", __FUNCTION__);
        ret = XCAM_RETURN_ERROR_UNKNOWN;
    }

    RKAIQ_IMGPROC_CHECK_RET(ret, "setNRMode failed!", ret);
    IMGPROC_FUNC_EXIT

    return ret;
}


XCamReturn rk_aiq_uapi_getNRMode(const rk_aiq_sys_ctx_t* ctx, opMode_t *mode)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER

    ynr_api_attrib_t  ynr_attr;
    cnr_api_attrib_t  cnr_attr;
    btnr_api_attrib_t btnr_attr;

    ret = rk_aiq_user_api2_ynr_GetAttrib(ctx, &ynr_attr);
    ret = rk_aiq_user_api2_cnr_GetAttrib(ctx, &cnr_attr);
    ret = rk_aiq_user_api2_btnr_GetAttrib(ctx, &btnr_attr);

    if (ynr_attr.opMode == RK_AIQ_OP_MODE_AUTO &&
            cnr_attr.opMode == RK_AIQ_OP_MODE_AUTO &&
            btnr_attr.opMode == RK_AIQ_OP_MODE_AUTO) {
        *mode = OP_AUTO;
    } else if (ynr_attr.opMode == RK_AIQ_OP_MODE_MANUAL &&
               cnr_attr.opMode == RK_AIQ_OP_MODE_MANUAL &&
               btnr_attr.opMode == RK_AIQ_OP_MODE_MANUAL) {
        *mode = OP_MANUAL;
    } else {
        LOGE_ANR("ynr.opMode:%d cnr.opMode:%d bayertnr.opMode:%d\n",
                 ynr_attr.opMode,
                 cnr_attr.opMode,
                 btnr_attr.opMode);
    }

    IMGPROC_FUNC_EXIT

    return ret;
}



/*
*****************************
*
* Desc: set normal noise reduction strength
* Argument:
*   level: [0, 100]
* Normal mode
*****************************
*/
XCamReturn rk_aiq_uapi_setANRStrth(const rk_aiq_sys_ctx_t* ctx, unsigned int level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER

    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "ctx is null, setANRStrth failed!");
    }

    aynr_strength_t ynrStrength;
    ynrStrength.en = true;
    ynrStrength.percent = level / 100.0;
    ret = rk_aiq_user_api2_ynr_SetStrength(ctx, &ynrStrength);
    abtnr_strength_t btnrStrength;
    btnrStrength.en = true;
    btnrStrength.percent = level / 100.0;
    ret = rk_aiq_user_api2_btnr_SetStrength(ctx, &btnrStrength);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setANRStrth failed!", ret);


    IMGPROC_FUNC_EXIT
    return ret;
}


XCamReturn rk_aiq_uapi_getANRStrth(const rk_aiq_sys_ctx_t* ctx, unsigned int *level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    float percent = 0.0f;

    IMGPROC_FUNC_ENTER

    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "ctx is null, getANRStrth failed!");
    }

    abtnr_strength_t btnrStrength;
    ret = rk_aiq_user_api2_btnr_GetStrength(ctx, &btnrStrength);
    RKAIQ_IMGPROC_CHECK_RET(ret, "setANRStrth failed!", ret);
    *level = (unsigned int)(btnrStrength.percent * 100);


    IMGPROC_FUNC_EXIT

    return ret;
}


/*
*****************************
*
* Desc: set manual spatial noise reduction strength
*    this function is active for NR is manual mode
* Argument:
*   level: [0, 100]
*
*****************************
*/
XCamReturn rk_aiq_uapi_setMSpaNRStrth(const rk_aiq_sys_ctx_t* ctx, bool on, unsigned int level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    IMGPROC_FUNC_ENTER

    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "ctx is null, setMSpaNRStrth failed!");
    }

    aynr_strength_t ynrStrength;
    ynrStrength.en = true;
    ynrStrength.percent = level / 100.0;
    ret = rk_aiq_user_api2_ynr_SetStrength(ctx, &ynrStrength);

    RKAIQ_IMGPROC_CHECK_RET(ret, "setMSpaNRStrth failed!", ret);
    IMGPROC_FUNC_EXIT

    return ret;
}



/*
*****************************
*
* Desc: get manual spatial noise reduction strength
*    this function is active for NR is manual mode
* Argument:
*   level: [0, 100]
*
*****************************
*/
XCamReturn rk_aiq_uapi_getMSpaNRStrth(const rk_aiq_sys_ctx_t* ctx, bool * on, unsigned int *level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    float percent = 0.0f;
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "ctx is null, getMSpaNRStrth failed!");
    }

    aynr_strength_t ynrStrength;
    ret = rk_aiq_user_api2_ynr_GetStrength(ctx, &ynrStrength);
    percent = ynrStrength.percent;

    RKAIQ_IMGPROC_CHECK_RET(ret, "getMSpaNRStrth failed!", ret);
    *level = (unsigned int)(percent * 100);
    IMGPROC_FUNC_EXIT

    return ret;
}



/*
*****************************
*
* Desc: set manual time noise reduction strength
*     this function is active for NR is manual mode
* Argument:
*   level: [0, 100]
*
*****************************
*/
XCamReturn rk_aiq_uapi_setMTNRStrth(const rk_aiq_sys_ctx_t* ctx, bool on, unsigned int level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    LOGD("level=%d", level);
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "ctx is null, setMTNRStrth failed!");
    }

    abtnr_strength_t btnrStrength;
    btnrStrength.en = true;
    btnrStrength.percent = level / 100.0;
    ret = rk_aiq_user_api2_btnr_SetStrength(ctx, &btnrStrength);

    RKAIQ_IMGPROC_CHECK_RET(ret, "setMTNRStrth failed!", ret);
    IMGPROC_FUNC_EXIT

    return ret;
}



/*
*****************************
*
* Desc: get manual time noise reduction strength
*     this function is active for NR is manual mode
* Argument:
*   level: [0, 100]
*
*****************************
*/
XCamReturn rk_aiq_uapi_getMTNRStrth(const rk_aiq_sys_ctx_t* ctx, bool * on, unsigned int *level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    float percent = 0.0f;
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "ctx is null, getMTNRStrth failed!");
    }

    abtnr_strength_t btnrStrength;
    ret = rk_aiq_user_api2_btnr_GetStrength(ctx, &btnrStrength);
    percent = btnrStrength.percent;

    RKAIQ_IMGPROC_CHECK_RET(ret, "getMTNRStrth failed!", ret);
    *level = (unsigned int)(percent * 100);
    IMGPROC_FUNC_EXIT
    return ret;
}

/*
*****************************
*
* Desc: Adjust image sharpness level
* Argument:
*    level: sharpness level, [0, 100]
*****************************
*/
XCamReturn rk_aiq_uapi_setSharpness(const rk_aiq_sys_ctx_t* ctx, unsigned int level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    float fPercent = 0.0f;

    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "ctx is null, set sharpeness failed!");
    }

    LOGD("setSharpness enter, level=%d\n", level);
    if ((int)level < 0 || level > 100) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "level out of range, set sharpeness failed!");
    }
    fPercent = level / 100.0f;

    asharp_strength_t sharpStrength;
    sharpStrength.en = true;
    sharpStrength.percent = fPercent;
    ret = rk_aiq_user_api2_sharp_SetStrength(ctx, &sharpStrength);

    RKAIQ_IMGPROC_CHECK_RET(ret, "set sharpeness failed!");
    IMGPROC_FUNC_EXIT

    return ret;
}

XCamReturn rk_aiq_uapi_getSharpness(const rk_aiq_sys_ctx_t* ctx, unsigned int *level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    float fPercent = 0.0f;

    IMGPROC_FUNC_ENTER
    if (level == NULL || ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, get sharpeness failed!");
    }

    asharp_strength_t sharpStrength;
    ret = rk_aiq_user_api2_sharp_GetStrength(ctx, &sharpStrength);
    fPercent = sharpStrength.percent;
    RKAIQ_IMGPROC_CHECK_RET(ret, "get sharpeness failed!");

    *level = (unsigned int)(fPercent * 100);
    IMGPROC_FUNC_EXIT

    return ret;
}


/*
*****************************
*
* Desc: Adjust image contrast level
* Argument:
*    level: contrast level, [0, 255]
*****************************
*/
XCamReturn rk_aiq_uapi_setContrast(const rk_aiq_sys_ctx_t* ctx, unsigned int level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    IMGPROC_FUNC_ENTER

    LOGD("setContrast enter, level=%d\n", level);
    if ((int)level < 0 || level > 255) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "level out of range, setContrast failed!");
    }
#if RKAIQ_HAVE_DEHAZE_V14
    bool update_attr = false;
    dehaze_api_attrib_t attr;
    memset(&attr, 0, sizeof(dehaze_api_attrib_t));
    ret = rk_aiq_user_api2_dehaze_GetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set contrast(dehaze GetAttrib) failed!");
    if (attr.opMode == RK_AIQ_OP_MODE_MANUAL || attr.en == false) {
        attr.en = true;
        attr.opMode = RK_AIQ_OP_MODE_AUTO;
        update_attr = true;
        LOGW_ADEHAZE("%s is only supported in AUTO mode.", __FUNCTION__);
    }

    for (int i = 0; i < DEHAZE_ISO_STEP_MAX; i++) {
        if (attr.stAuto.dyn[i].sw_dhazT_work_mode != dhaz_enhance_mode) {
            update_attr = true;
            attr.stAuto.dyn[i].sw_dhazT_work_mode = dhaz_enhance_mode;
        }
    }
    if (update_attr) {
        ret = rk_aiq_user_api2_dehaze_SetAttrib(ctx, &attr);
        RKAIQ_IMGPROC_CHECK_RET(ret, "set contrast(dehaze SetAttrib) failed!");
    }

    adehaze_strength_t ctrl;
    memset(&ctrl, 0, sizeof(adehaze_strength_t));
    ret = rk_aiq_user_api2_getDehazeEnhanceStrth(ctx, &ctrl);
    level /= 2.55;
    ctrl.MEnhanceStrth = level;
    ret = rk_aiq_user_api2_setDehazeEnhanceStrth(ctx, ctrl);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set contrast(setMEnhanceStrth) failed!");

#elif RKAIQ_HAVE_ENHANCE_V10
    enh_api_attrib_t attr;
    memset(&attr, 0, sizeof(enh_api_attrib_t));
    ret = rk_aiq_user_api2_enh_GetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set contrast(enh GetAttrib) failed!");
    if (attr.opMode == RK_AIQ_OP_MODE_MANUAL || attr.en == false || attr.bypass) {
        attr.en = true;
        attr.bypass = false;
        attr.opMode = RK_AIQ_OP_MODE_AUTO;
        LOGW_ADEHAZE("%s is only supported in AUTO mode.", __FUNCTION__);
        ret = rk_aiq_user_api2_enh_SetAttrib(ctx, &attr);
        RKAIQ_IMGPROC_CHECK_RET(ret, "set contrast(enh SetAttrib) failed!");
    }

    aenh_strength_t strg;
    memset(&strg, 0, sizeof(aenh_strength_t));
    ret = rk_aiq_user_api2_enh_GetEnhanceStrth(ctx, &strg);
    level /= 2.55;
    strg.MEnhanceStrth = level;
    ret = rk_aiq_user_api2_enh_SetEnhanceStrth(ctx, &strg);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set contrast(setEnhanceStrth) failed!");

#else
    cp_api_attrib_t attrib;
    ret = rk_aiq_user_api2_cp_GetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getAttrib error,set contrast failed!");
    if(attrib.opMode == RK_AIQ_OP_MODE_AUTO)
        attrib.stAuto.sta.contrast = level;
    else
        attrib.stMan.sta.contrast = level;
    ret = rk_aiq_user_api2_cp_SetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set contrast failed!");
#endif
    IMGPROC_FUNC_EXIT

    return ret;
}

XCamReturn rk_aiq_uapi_getContrast(const rk_aiq_sys_ctx_t* ctx, unsigned int *level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    IMGPROC_FUNC_ENTER

#if RKAIQ_HAVE_DEHAZE_V14
    adehaze_strength_t ctrl;
    memset(&ctrl, 0, sizeof(adehaze_strength_t));
    ret = rk_aiq_user_api2_getDehazeEnhanceStrth(ctx, &ctrl);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get contrast(getMEnhanceStrth) failed!");
    *level = ctrl.MEnhanceStrth * 2.55;

#elif RKAIQ_HAVE_ENHANCE_V10
    aenh_strength_t strg;
    memset(&strg, 0, sizeof(aenh_strength_t));
    ret = rk_aiq_user_api2_enh_GetEnhanceStrth(ctx, &strg);
    *level = strg.MEnhanceStrth * 2.55;
    RKAIQ_IMGPROC_CHECK_RET(ret, "get contrast(getEnhanceStrth) failed!");

#else
    cp_api_attrib_t attrib;
    if (level == NULL || ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, getContrast failed!");
    }
    ret = rk_aiq_user_api2_cp_GetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get contrast failed!");
    if(attrib.opMode == RK_AIQ_OP_MODE_AUTO)
        *level = attrib.stAuto.sta.contrast;
    else
        *level = attrib.stMan.sta.contrast;
#endif
    IMGPROC_FUNC_EXIT

    return ret;
}

/*
*****************************
*
* Desc: Adjust image brightness level
* Argument:
*    level: brightness level, [0, 255]
*****************************
*/
XCamReturn rk_aiq_uapi_setBrightness(const rk_aiq_sys_ctx_t* ctx, unsigned int level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    cp_api_attrib_t attrib;

    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "ctx is null, set brightness failed!");
    }

    LOGD("setBrightness enter, level=%d\n", level);
    if ((int)level < 0 || level > 255) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "level out of range, set brightness failed!");
    }
    ret = rk_aiq_user_api2_cp_GetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getAttrib error,set brightness failed!");
    if(attrib.opMode == RK_AIQ_OP_MODE_AUTO)
        attrib.stAuto.sta.brightness = level;
    else
        attrib.stMan.sta.brightness = level;
    ret = rk_aiq_user_api2_cp_SetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set brightness failed!");
    IMGPROC_FUNC_EXIT

    return ret;
}

XCamReturn rk_aiq_uapi_getBrightness(const rk_aiq_sys_ctx_t* ctx, unsigned int *level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    IMGPROC_FUNC_ENTER
    cp_api_attrib_t attrib;
    if (level == NULL || ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, get brightness failed!");
    }
    ret = rk_aiq_user_api2_cp_GetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get brightness failed!");
    if(attrib.opMode == RK_AIQ_OP_MODE_AUTO)
        *level = attrib.stAuto.sta.brightness;
    else
        *level = attrib.stMan.sta.brightness;
    IMGPROC_FUNC_EXIT
    return ret;
}

/*
*****************************
*
* Desc: Adjust image saturation level
* Argument:
*    level: saturation level, [0, 255]
*****************************
*/
XCamReturn rk_aiq_uapi_setSaturation(const rk_aiq_sys_ctx_t* ctx, unsigned int level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    cp_api_attrib_t attrib;

    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "ctx is null, set saturation failed!");
    }

    LOGD("setSaturation enter, level=%d\n", level);
    if ((int)level < 0 || level > 255) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "level out of range, set saturation failed!");
    }
    ret = rk_aiq_user_api2_cp_GetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getAttrib error,set saturation failed!");
    if(attrib.opMode == RK_AIQ_OP_MODE_AUTO)
        attrib.stAuto.sta.saturation = level;
    else
        attrib.stMan.sta.saturation = level;
    ret = rk_aiq_user_api2_cp_SetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set saturation failed!");
    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_getSaturation(const rk_aiq_sys_ctx_t* ctx, unsigned int* level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    cp_api_attrib_t attrib;
    if (level == NULL || ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, get saturation failed!");
    }
    ret = rk_aiq_user_api2_cp_GetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get saturation failed!");
    if(attrib.opMode == RK_AIQ_OP_MODE_AUTO)
        *level = attrib.stAuto.sta.saturation;
    else
        *level = attrib.stMan.sta.saturation;
    IMGPROC_FUNC_EXIT
    return ret;
}

/*
*****************************
*
* Desc: Adjust image hue level
* Argument:
*    level: hue level, [0, 255]
*****************************
*/
XCamReturn rk_aiq_uapi_setHue(const rk_aiq_sys_ctx_t* ctx, unsigned int level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    cp_api_attrib_t attrib;

    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "ctx is null, set hue failed!");
    }

    LOGD("setHue enter, level=%d\n", level);
    if ((int)level < 0 || level > 255) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "level out of range, set hue failed!");
    }
    ret = rk_aiq_user_api2_cp_GetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "getAttrib error,set hue failed!");
    if(attrib.opMode == RK_AIQ_OP_MODE_AUTO)
        attrib.stAuto.sta.hue = level;
    else
        attrib.stMan.sta.hue = level;
    ret = rk_aiq_user_api2_cp_SetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "set hue failed!");
    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_getHue(const rk_aiq_sys_ctx_t* ctx, unsigned int* level)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    cp_api_attrib_t attrib;
    if (level == NULL || ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, get hue failed!");
    }
    ret = rk_aiq_user_api2_cp_GetAttrib(ctx, &attrib);
    RKAIQ_IMGPROC_CHECK_RET(ret, "get hue failed!");
    if(attrib.opMode == RK_AIQ_OP_MODE_AUTO)
        *level = attrib.stAuto.sta.hue;
    else
        *level = attrib.stMan.sta.hue;
    IMGPROC_FUNC_EXIT
    return ret;
}

/*
*****************************
*
* Desc: Adjust image gamma
*
* Argument:
*   GammaCoef: [0, 100]
*   SlopeAtZero: [-0.05, 0.05]
*****************************
*/
XCamReturn rk_aiq_uapi_setGammaCoef(const rk_aiq_sys_ctx_t* ctx, float GammaCoef, float SlopeAtZero)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;

    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "ctx is null, setGammaCoef failed!");
    }

    if (GammaCoef < 0 || GammaCoef > 100) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, GammaCoef range is [0,100]!");
    }
    if (SlopeAtZero < -0.05 || SlopeAtZero > 0.05) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error, SlopeAtZero range is [-0.05,0.05]!");
    }

    gamma_api_attrib_t gammaAttr;
    memset(&gammaAttr, 0x0, sizeof(gamma_api_attrib_t));

    gammaAttr.opMode                                    = RK_AIQ_OP_MODE_AUTO;
    gammaAttr.en         = true;

    float gamma_X_v11[CALIBDB_GAMMA_KNOTS_NUM_V11]   = {
        0,    1,    2,    3,    4,    5,    6,    7,    8,    10,  12,   14,   16,
        20,   24,   28,   32,   40,   48,   56,   64,   80,   96,  112,  128,  160,
        192,  224,  256,  320,  384,  448,  512,  640,  768,  896, 1024, 1280, 1536,
        1792, 2048, 2304, 2560, 2816, 3072, 3328, 3584, 3840, 4095
    };
    float gamma_Y_v11[CALIBDB_GAMMA_KNOTS_NUM_V11];
    for (int i = 0; i < GAMMA_ISO_STEP_MAX; i++) {
        gammaAttr.stAuto.dyn[i].hw_gammaT_outCurve_offset = 0;
        for (int j = 0; j < CALIBDB_GAMMA_KNOTS_NUM_V11; j++) {
            gamma_Y_v11[j] = 4095 * pow(gamma_X_v11[j] / 4095, 1 / GammaCoef + SlopeAtZero);
            gamma_Y_v11[j] = gamma_Y_v11[j] > 4095 ? 4095 : gamma_Y_v11[j] < 0 ? 0 : gamma_Y_v11[j];
            gammaAttr.stAuto.dyn[i].hw_gammaT_outCurve_val[j] = (int)(gamma_Y_v11[j] + 0.5);
        }
    }
    ret = rk_aiq_user_api2_gamma_SetAttrib(ctx, &gammaAttr);

    IMGPROC_FUNC_EXIT
    return ret;
}

XCamReturn rk_aiq_uapi_setGrayMode(const rk_aiq_sys_ctx_t* ctx, rk_aiq_gray_mode_t mode)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    rk_aiq_sys_ctx_array_t ctx_array = rk_aiq_user_api2_common_getSysCtxArray(ctx);
    for (int i = 0; i < ctx_array.num; i++) {
        ret = AiqCore_setGrayMode(ctx_array.ctx[i]->_analyzer, mode);
    }

    return ret;
}

rk_aiq_gray_mode_t rk_aiq_uapi_getGrayMode(const rk_aiq_sys_ctx_t* ctx)
{
    const rk_aiq_sys_ctx_t* sys_ctx = rk_aiq_user_api2_common_getSysCtx(ctx);
    return AiqCore_getGrayMode(sys_ctx->_analyzer);
}

XCamReturn rk_aiq_uapi_setMirrorFlip(const rk_aiq_sys_ctx_t* ctx, bool mirror, bool flip,
                                      int skip_frm_cnt) {
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }

    bool set_btnr_bypass = false;
    btnr_status_t btnr_sta;
    btnr_api_attrib_t btnr_attr;
    ret = rk_aiq_user_api2_btnr_GetAttrib(ctx, &btnr_attr);
    if (btnr_sta.en && !btnr_sta.bypass) {
        btnr_attr.bypass = true;
        rk_aiq_user_api2_btnr_SetAttrib(ctx, &btnr_attr);
        int wait_param_effect_sleep_cnt = 13;
        do {
            if (wait_param_effect_sleep_cnt == 0) {
                LOGW("BTNR bypass no current effect before set mirror/flip");
                break;
            }
            usleep(5 * 1000);
            rk_aiq_user_api2_btnr_QueryStatus(ctx, &btnr_sta);
            wait_param_effect_sleep_cnt--;
        } while((btnr_sta.en && !btnr_sta.bypass));
        set_btnr_bypass = true;
    }
    ret = AiqManager_setMirrorFlip(ctx->_rkAiqManager, mirror, flip, skip_frm_cnt);
    if (set_btnr_bypass) {
        rk_aiq_user_api2_btnr_GetAttrib(ctx, &btnr_attr);
        btnr_attr.bypass = false;
        rk_aiq_user_api2_btnr_SetAttrib(ctx, &btnr_attr);
    }
    return ret;
}

XCamReturn rk_aiq_uapi_getMirrorFlip(const rk_aiq_sys_ctx_t* ctx, bool* mirror, bool* flip) {
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
    IMGPROC_FUNC_ENTER
    if (ctx == NULL || mirror == NULL || flip == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }
    return AiqManager_getMirrorFlip(ctx->_rkAiqManager, mirror, flip);
}

XCamReturn rk_aiq_uapi_setLdchEn(const rk_aiq_sys_ctx_t* ctx, bool en)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
#if RKAIQ_HAVE_LDCH_V22
    IMGPROC_FUNC_ENTER
    if (ctx == NULL) {
        ret = XCAM_RETURN_ERROR_PARAM;
        RKAIQ_IMGPROC_CHECK_RET(ret, "param error!");
    }

    ldc_api_attrib_t attr;
    ret = rk_aiq_user_api2_ldc_GetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "Failed to get LDCH attrib.");

    attr.en     = en;
    attr.opMode = RK_AIQ_OP_MODE_AUTO;
    attr.bypass = 0;

    ret = rk_aiq_user_api2_ldc_SetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "Failed to set LDCH attrib.");

    IMGPROC_FUNC_EXIT
#else
    LOGE("not support to call %s for current chip", __FUNCTION__);
    ret = XCAM_RETURN_ERROR_UNKNOWN;
#endif
    return ret;
}

XCamReturn rk_aiq_uapi_setLdchCorrectLevel(const rk_aiq_sys_ctx_t* ctx, int correctLevel)
{
    XCamReturn ret = XCAM_RETURN_NO_ERROR;
#if RKAIQ_HAVE_LDCH_V22
    ldc_api_attrib_t attr;

    ret = rk_aiq_user_api2_ldc_GetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "Failed to get LDCH attrib.");

    attr.tunning.autoGenMesh.sw_ldcT_correctStrg_val = correctLevel;

    ret = rk_aiq_user_api2_ldc_SetAttrib(ctx, &attr);
    RKAIQ_IMGPROC_CHECK_RET(ret, "Failed to set LDCH attrib.");
#else
    LOGE("not support to call %s for current chip", __FUNCTION__);
    ret = XCAM_RETURN_ERROR_UNKNOWN;
#endif
    return ret;
}
