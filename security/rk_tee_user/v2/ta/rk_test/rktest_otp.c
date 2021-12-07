// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021 Rockchip Electronics Co. Ltd.
 */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_api_defines.h>
#include "rktest_handle.h"

//define for OEM OTP test
const TEE_UUID UUID_INTERNAL = { 0x527f12de, 0x3f8e, 0x434f,
	{ 0x8f, 0x40, 0x03, 0x07, 0xae, 0x86, 0x4b, 0xaf }
};
#define OS_SERVICE_CMD_READ_OEM_OTP	130
#define OS_SERVICE_CMD_WRITE_OEM_OTP	140


TEE_Result handle_otp_read(void)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t param_type;
	TEE_Param params[4];
	TEE_TASessionHandle session = TEE_HANDLE_NULL;
	uint32_t error_origin = 0;
	/*
	 * RK356x platform require the address and length of OTP must be
	 * an integral multiple of 2 integer(half word).
	 */
	uint32_t read_len = 4;
	uint32_t read_offset = 0;
	uint8_t *read_data;

	param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	res = TEE_OpenTASession(&UUID_INTERNAL, 0, param_type, params,
				&session, &error_origin);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenTASession failed with code 0x%x origin 0x%x",
		     res, error_origin);
		goto out;
	}

	param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	//The memory used to invoke internal TA MUST BE secure memory, instead of CA memory.
	read_data = TEE_Malloc(read_len, 0);

	TEE_MemFill(params, 0, sizeof(params));
	params[0].value.a = read_offset;
	params[1].memref.buffer = read_data;
	params[1].memref.size = read_len;

	res = TEE_InvokeTACommand(session, 0, OS_SERVICE_CMD_READ_OEM_OTP,
				  param_type, params, &error_origin);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeTACommand failed with code 0x%x origin 0x%x\n",
		     res, error_origin);
		goto out1;
	}
	IMSG("OEM OTP read done.");
	for (uint32_t i = 0; i < read_len; i++)
		IMSG("0x%02x", read_data[i]);

out1:
	TEE_Free(read_data);
	TEE_CloseTASession(session);
out:
	session = TEE_HANDLE_NULL;
	return res;
}

TEE_Result handle_otp_write(void)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t param_type;
	TEE_Param params[4];
	TEE_TASessionHandle session = TEE_HANDLE_NULL;
	uint32_t error_origin = 0;
	/*
	 * RK356x platform require the address and length of OTP must be
	 * an integral multiple of 2 integer(half word).
	 */
	uint32_t write_len = 2;
	uint8_t data[2] = {0xaa, 0xaa};
	uint32_t write_offset = 0;
	uint8_t *write_data;

	param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	res = TEE_OpenTASession(&UUID_INTERNAL, 0, param_type, params,
				&session, &error_origin);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenTASession failed with code 0x%x origin 0x%x",
		     res, error_origin);
		goto out;
	}

	param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	//The memory used to invoke internal TA MUST BE secure memory, instead of CA memory.
	write_data = TEE_Malloc(write_len, 0);
	TEE_MemMove(write_data, &data, write_len);

	TEE_MemFill(params, 0, sizeof(params));
	params[0].value.a = write_offset;
	params[1].memref.buffer = write_data;
	params[1].memref.size = write_len;

	res = TEE_InvokeTACommand(session, 0, OS_SERVICE_CMD_WRITE_OEM_OTP,
				  param_type, params, &error_origin);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeTACommand failed with code 0x%x origin 0x%x\n", res,
		     error_origin);
	else
		IMSG("OEM OTP write done.");

	TEE_Free(write_data);
	TEE_CloseTASession(session);
out:
	session = TEE_HANDLE_NULL;
	return res;
}

