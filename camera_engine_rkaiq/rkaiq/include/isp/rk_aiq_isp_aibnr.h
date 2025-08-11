/*
 *  Copyright (c) 2024 Rockchip Corporation
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

#ifndef _RK_AIQ_PARAM_AIBNR_H_
#define _RK_AIQ_PARAM_AIBNR_H_

#define AIBNR_MODEL_DIRNAME_LEN     128
#define AIBNR_MODEL_FILENAME_LEN    64

typedef struct aibnr_param_calib_s {
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrC_blkPrev_offset),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(-511.0, 511.0),
        M4_DEFAULT(0),
        M4_DIGIT_EX(6),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(0),
        M4_NOTES(The value of black level.\n
        Freq of use: High))  */
    float sw_aiBnrC_blkPrev_offset;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrC_blkPost_offset),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(-511.0, 511.0),
        M4_DEFAULT(0),
        M4_DIGIT_EX(6),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(1),
        M4_NOTES(The value of black level.\n
        Freq of use: High))  */
    float sw_aiBnrC_blkPost_offset;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrC_shotNoise_val),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 128.0),
        M4_DEFAULT(16.0),
        M4_DIGIT_EX(6),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(2),
        M4_NOTES(The value of shot noise.\n
        Freq of use: High))  */
    float sw_aiBnrC_shotNoise_val;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrC_readNoise_val),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 128.0),
        M4_DEFAULT(1.6),
        M4_DIGIT_EX(6),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(3),
        M4_NOTES(The value of read noise.\n
        Freq of use: High))  */
    float sw_aiBnrC_readNoise_val;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrC_fixedNoise_val),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 128.0),
        M4_DEFAULT(0.16),
        M4_DIGIT_EX(6),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(4),
        M4_NOTES(The value of fixed noise.\n
        Freq of use: High))  */
    float sw_aiBnrC_fixedNoise_val;
} aibnr_param_calib_t;

typedef struct aibnr_param_tunning_s {
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_totalNr_strg),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 8.0),
        M4_DEFAULT(1.0),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(4),
        M4_NOTES(The value of total noise reduce strength.\n
        Freq of use: High))  */
    float sw_aiBnrT_totalNr_strg;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_shotNr_strg),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 8.0),
        M4_DEFAULT(1.0),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(5),
        M4_NOTES(The value of shot noise reduce strength.\n
        Freq of use: High))  */
    float sw_aiBnrT_shotNr_strg;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_readNr_strg),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 8.0),
        M4_DEFAULT(1.0),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(6),
        M4_NOTES(The value of read noise reduce strength.\n
        Freq of use: High))  */
    float sw_aiBnrT_readNr_strg;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_fixedNr_strg),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 8.0),
        M4_DEFAULT(1.0),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(7),
        M4_NOTES(The value of fixed noise reduce strength.\n
        Freq of use: High))  */
    float sw_aiBnrT_fixedNr_strg;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_motionBias_offset),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(1.0, 32.0),
        M4_DEFAULT(20.0),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(8),
        M4_NOTES(The value of motion bias offset.\n
        Freq of use: High))  */
    float sw_aiBnrT_motionBias_offset;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_motionGain_strg),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 4.0),
        M4_DEFAULT(0),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(9),
        M4_NOTES(The value of motion gain strength.\n
        Freq of use: High))  */
    float sw_aiBnrT_motionGain_strg;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_noiseAdd_ratio),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 1.0),
        M4_DEFAULT(0.05),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(10),
        M4_NOTES(The value of noise add ratio.\n
        Freq of use: High))  */
    float sw_aiBnrT_noiseAdd_ratio;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_noiseAdd_limit),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 1.0),
        M4_DEFAULT(0.5),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(11),
        M4_NOTES(The value of noise add limit.\n
        Freq of use: High))  */
    float sw_aiBnrT_noiseAdd_limit;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_noiseAddMot_offset),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(1.0, 32.0),
        M4_DEFAULT(10.0),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(12),
        M4_NOTES(The value of motion offset for adding noise.\n
        Freq of use: High))  */
    float sw_aiBnrT_noiseAddMot_offset;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_noiseAddMot_coeff),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(-8, 8),
        M4_DEFAULT(0),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(13),
        M4_NOTES(The value of motion coefficient for adding noise.\n
        Freq of use: High))  */
    float sw_aiBnrT_noiseAddMot_coeff;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_noiseAddLuma_offset),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 255.0),
        M4_DEFAULT(114),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(14),
        M4_NOTES(The value of luma offset for adding noise.\n
        Freq of use: High))  */
    float sw_aiBnrT_noiseAddLuma_offset;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_noiseAddLuma_coeff),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 32.0),
        M4_DEFAULT(32),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(15),
        M4_NOTES(The value of luma coefficient for adding noise.\n
        Freq of use: High))  */
    float sw_aiBnrT_noiseAddLuma_coeff;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_noiseAddLumaClip_th),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 1.0),
        M4_DEFAULT(1.0),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(16),
        M4_NOTES(The value of luma clip threshold for adding noise.\n
        Freq of use: High))  */
    float sw_aiBnrT_noiseAddLumaClip_th;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_noiseAddLumaStatic_th),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(1.0, 32.0),
        M4_DEFAULT(1.0),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(17),
        M4_NOTES(The value of luma static threshold for adding noise.\n
        Freq of use: High))  */
    float sw_aiBnrT_noiseAddLumaStatic_th;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_nonLinear_scale),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 1.0),
        M4_DEFAULT(0.7),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(18),
        M4_NOTES(Non linear scale value.\n
        Freq of use: High))  */
    float sw_aiBnrT_nonLinear_scale;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_nonLinear_ratio),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 5.0),
        M4_DEFAULT(0.5),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(19),
        M4_NOTES(Non linear ratio value.\n
        Freq of use: High))  */
    float sw_aiBnrT_nonLinear_ratio;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_nonLinear_adjust),
        M4_TYPE(f32),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0.0, 3.0),
        M4_DEFAULT(1.0),
        M4_DIGIT_EX(3),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(20),
        M4_NOTES(Non linear ratio value.\n
        Freq of use: High))  */
    float sw_aiBnrT_nonLinear_adjust;
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_model_file),
        M4_TYPE(string),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0, 64),
        M4_DEFAULT("iso50.bin"),
        M4_HIDE_EX(0),
        M4_RO(1),
        M4_ORDER(21),
        M4_NOTES(Model info file.\n
        Freq of use: High))  */
    char sw_aiBnrT_model_file[AIBNR_MODEL_FILENAME_LEN];
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_doRknn_en),
        M4_TYPE(bool),
        M4_DEFAULT(0),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(22),
        M4_NOTES(The enable bit of the rknn after AIBNR.\n
        Freq of use: low))  */
    bool sw_aiBnrT_doRknn_en;
} aibnr_param_tunning_t;

typedef struct aibnr_param_dyn_s {
    /* M4_GENERIC_DESC(
        M4_ALIAS(calib),
        M4_TYPE(struct),
        M4_UI_MODULE(normal_ui_style),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(0),
        M4_NOTES(TODO))  */
    aibnr_param_calib_t   calib;
    /* M4_GENERIC_DESC(
        M4_ALIAS(tunning),
        M4_TYPE(struct),
        M4_UI_MODULE(normal_ui_style),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(1),
        M4_NOTES(TODO))  */
    aibnr_param_tunning_t tunning;
} aibnr_param_dyn_t;

typedef enum aibnr_debug_mode_e {
    aibnr_debugOff_mode = 0,
    aibnr_debugGain_mode = 1,
    aibnr_debugNarmap_mode = 2
} aibnr_debug_mode_t;

typedef struct aibnr_debug_static_s {
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_debug_mode),
        M4_TYPE(enum),
        M4_ENUM_DEF(aibnr_debug_mode_t),
        M4_DEFAULT(aibnr_debugOff_mode),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(0),
        M4_NOTES(Debug mode selection. Reference enum types.\nFreq of use: high))  */
    aibnr_debug_mode_t sw_aiBnrT_debug_mode;
} aibnr_debug_static_t;

typedef struct aibnr_model_dir_s {
    /* M4_GENERIC_DESC(
        M4_ALIAS(sw_aiBnrT_model_file),
        M4_TYPE(string),
        M4_SIZE_EX(1,1),
        M4_RANGE_EX(0, 128),
        M4_DEFAULT("/etc/iqfiles/"),
        M4_HIDE_EX(0),
        M4_RO(1),
        M4_ORDER(20),
        M4_NOTES(Model info file.\n
        Freq of use: High))  */
    char sw_aiBnrCfg_model_dir[AIBNR_MODEL_DIRNAME_LEN];
} aibnr_model_dir_t;

typedef struct aibnr_params_static_s {
    /* M4_GENERIC_DESC(
        M4_ALIAS(debug),
        M4_TYPE(struct),
        M4_UI_MODULE(normal_ui_style),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(0),
        M4_NOTES(TODO))  */
    aibnr_debug_static_t debug;
    /* M4_GENERIC_DESC(
        M4_ALIAS(model_dir),
        M4_TYPE(struct),
        M4_UI_MODULE(normal_ui_style),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(1),
        M4_NOTES(TODO))  */
    aibnr_model_dir_t model_dir;
} aibnr_params_static_t;

typedef struct aibnr_param_s {
    /* M4_GENERIC_DESC(
        M4_ALIAS(sta),
        M4_TYPE(struct),
        M4_UI_MODULE(static_ui),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(0),
        M4_NOTES(The static params of aibnr module))  */
    aibnr_params_static_t sta;
    /* M4_GENERIC_DESC(
        M4_ALIAS(dyn),
        M4_TYPE(struct),
        M4_UI_MODULE(dynamic_ui),
        M4_HIDE_EX(0),
        M4_RO(0),
        M4_ORDER(1),
        M4_NOTES(TODO))  */
    aibnr_param_dyn_t dyn;
} aibnr_param_t;

#endif
