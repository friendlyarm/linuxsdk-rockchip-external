// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021 Rockchip Electronics Co. Ltd.
 */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_api_defines.h>
#include "rktest_handle.h"


//define a RSA key for RSA rest
static uint8_t g_rsa2048_n[] = {
	0xc6, 0x23, 0x15, 0x60, 0xd5, 0xf5, 0x34, 0x1a, 0xd9, 0xa0, 0x1a, 0x55,
	0x4f, 0x04, 0xfb, 0x2f, 0x83, 0x42, 0x90, 0x71, 0x73, 0xb0, 0xa3, 0xf1,
	0x33, 0xbd, 0x21, 0x59, 0x9c, 0xff, 0x87, 0xd1, 0xda, 0x49, 0xdb, 0xe2,
	0xa5, 0xd1, 0xb3, 0x88, 0x36, 0xdf, 0xea, 0x54, 0xc0, 0x53, 0x27, 0xae,
	0x02, 0x5a, 0xce, 0x17, 0x40, 0xd7, 0x01, 0x44, 0xaf, 0xff, 0xbf, 0x28,
	0x3b, 0x4c, 0xc9, 0x66, 0x56, 0x36, 0x02, 0xd0, 0x09, 0x15, 0x5e, 0x4c,
	0x08, 0x84, 0x4c, 0xa5, 0x7a, 0x30, 0x8e, 0x68, 0xff, 0x8d, 0x5a, 0x66,
	0x61, 0xcb, 0x16, 0xf3, 0x8b, 0x10, 0x6e, 0x5c, 0xff, 0xa6, 0xf3, 0xf3,
	0xe9, 0xb3, 0x8f, 0xe7, 0x7d, 0x7d, 0xea, 0x4d, 0x98, 0x96, 0x39, 0x45,
	0xe5, 0xcf, 0xb6, 0x69, 0x8a, 0xf1, 0x1a, 0xfd, 0xee, 0xb0, 0xa5, 0x4b,
	0x15, 0x76, 0x1f, 0x7b, 0x95, 0x12, 0x9d, 0x9f, 0x52, 0x2e, 0x8b, 0x3d,
	0x5c, 0x41, 0x94, 0xbc, 0x16, 0x64, 0xcf, 0x58, 0x61, 0xc8, 0x06, 0xdf,
	0xca, 0xeb, 0xf4, 0x82, 0xd0, 0x43, 0x62, 0xbc, 0x1e, 0x1c, 0x83, 0xaa,
	0xee, 0x8f, 0x47, 0x7f, 0x87, 0xb1, 0x58, 0xee, 0xb1, 0x49, 0x56, 0x95,
	0x1c, 0xf9, 0x49, 0x8e, 0xa6, 0xa3, 0x5b, 0x77, 0xe6, 0xb4, 0x2e, 0xeb,
	0x96, 0x69, 0x00, 0xb6, 0xc2, 0xbb, 0xbd, 0x50, 0xbf, 0x6a, 0x15, 0xb0,
	0x35, 0xc9, 0x67, 0x70, 0x6c, 0xaf, 0xd5, 0xfa, 0x9f, 0xbf, 0x2d, 0xaa,
	0x8e, 0x81, 0xed, 0x5e, 0x09, 0x17, 0x55, 0x32, 0x7d, 0xc7, 0x23, 0x0e,
	0x2e, 0xd3, 0xa5, 0x36, 0xcf, 0xc1, 0x80, 0xab, 0x37, 0x62, 0x05, 0xb4,
	0x8b, 0x10, 0xe7, 0x4e, 0x83, 0x80, 0x06, 0xf4, 0x2e, 0x91, 0x44, 0xff,
	0x2c, 0x9a, 0xc9, 0x99, 0x6c, 0x44, 0x83, 0x65, 0x3e, 0xcb, 0xa5, 0x0d,
	0x9f, 0x5f, 0xf1, 0x79
};
static uint32_t g_rsa2048_len_n = 256U;
static uint8_t g_rsa2048_d[] = {
	0x7a, 0x5f, 0x9e, 0xcb, 0x91, 0x3a, 0x01, 0xb5, 0x77, 0xa5, 0xff, 0xbd,
	0xa2, 0xb1, 0x63, 0xe6, 0x63, 0x7e, 0x90, 0x31, 0xd2, 0x0f, 0x4e, 0x22,
	0x22, 0x1f, 0x74, 0xe2, 0xa1, 0x29, 0xdd, 0x9c, 0x09, 0xe3, 0x46, 0x30,
	0x84, 0xd3, 0xb0, 0xbb, 0xb7, 0x90, 0xb2, 0x6d, 0x27, 0xdf, 0xf4, 0x08,
	0xf0, 0x21, 0x5f, 0x5a, 0x53, 0x4c, 0xb7, 0xd6, 0xd1, 0x90, 0xf6, 0x62,
	0x85, 0xc5, 0x96, 0x3a, 0x63, 0x92, 0xb6, 0x48, 0x00, 0xe4, 0x36, 0xba,
	0x65, 0x24, 0x39, 0x26, 0x97, 0x02, 0x38, 0x62, 0xb7, 0x3b, 0x79, 0x92,
	0xf4, 0x61, 0x77, 0xca, 0x71, 0xa0, 0x73, 0x59, 0x72, 0xf8, 0x8d, 0x81,
	0x9f, 0x5c, 0xac, 0xcb, 0x7f, 0xe1, 0x6d, 0xfe, 0x00, 0xf8, 0xff, 0x64,
	0xa1, 0x5c, 0x99, 0xc0, 0x33, 0xf5, 0x58, 0x03, 0x70, 0x11, 0x9f, 0xf5,
	0x70, 0xca, 0xe5, 0x04, 0xf1, 0xfc, 0x6e, 0x66, 0xab, 0x1e, 0x6b, 0xff,
	0x2f, 0xee, 0x70, 0xc1, 0xc5, 0x19, 0xf9, 0x70, 0x5e, 0xcb, 0x62, 0xf3,
	0x48, 0x8e, 0x6a, 0x9a, 0x2e, 0xea, 0x23, 0x7b, 0xba, 0x09, 0x33, 0xeb,
	0x43, 0xe2, 0xb4, 0x36, 0xae, 0x72, 0x78, 0x10, 0x11, 0x04, 0x81, 0xcc,
	0x49, 0xf2, 0x40, 0xef, 0xfe, 0x94, 0x27, 0xc3, 0x06, 0x2d, 0xb8, 0x7a,
	0x58, 0xdd, 0x3f, 0x47, 0x01, 0x6f, 0x5f, 0xb5, 0xc9, 0x29, 0x33, 0xc9,
	0x07, 0x50, 0x04, 0xcd, 0x69, 0x9a, 0x43, 0xd7, 0xb2, 0xff, 0x62, 0xe5,
	0x30, 0x78, 0xe3, 0xb9, 0xde, 0x0f, 0x4e, 0x71, 0xa3, 0x64, 0x5b, 0xb8,
	0xf9, 0xf1, 0xa7, 0xf8, 0x67, 0xad, 0x99, 0x94, 0x39, 0x3a, 0xd3, 0x98,
	0x97, 0x5d, 0xe8, 0xfa, 0x92, 0xc8, 0x78, 0x79, 0xa3, 0x7b, 0x15, 0x3a,
	0x6b, 0x00, 0xfa, 0x9b, 0xe3, 0x58, 0x4c, 0x03, 0x62, 0x80, 0xf2, 0x50,
	0x8b, 0xa5, 0x6b, 0xa5
};
static uint32_t g_rsa2048_len_d = 256U;
static uint8_t g_rsa2048_e[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x01
};
static uint32_t g_rsa2048_len_e = 256U;

static TEE_Result crypto_sha(uint32_t alg, uint32_t mode,
	void *chunk, uint32_t chunk_len, void *hash, uint32_t *hash_len)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle handle;

	res = TEE_AllocateOperation(&handle, alg, mode, 0);
	if (res != TEE_SUCCESS) {
		EMSG("AllocateOperation ERR: 0x%x.", res);
		return res;
	}

	TEE_DigestUpdate(handle, chunk, chunk_len);

	res = TEE_DigestDoFinal(handle, NULL, 0, hash, hash_len);
	if (res != TEE_SUCCESS)
		EMSG("DigestDoFinal ERR: 0x%x.", res);

	TEE_FreeOperation(handle);
	return res;
}

TEE_Result handle_crypto_sha(void)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t alg = TEE_ALG_SHA256;
	uint32_t mod = TEE_MODE_DIGEST;
	uint8_t in_data[] = {'C', 'h', 'e', 'c', 'k', ' ', 't', 'h', 'e', ' ',
	's', 'h', 'a', '2', '5', '6', ' ', 't', 'e', 's', 't', ' ', 'r', 'e',
	's', 'u', 'l', 't', '.'};
	uint8_t out_data[128] = {'\0'};
	uint32_t out_len = sizeof(out_data);
	uint8_t sha_refer[] = {0x7a, 0x3e, 0x37, 0xc2, 0xdc, 0xe7,
		0xd3, 0xba, 0x41, 0xcd, 0x59, 0xff, 0xea, 0x8d, 0x25, 0xe0,
		0xdf, 0x91, 0xdd, 0xb1, 0xd1, 0x87, 0xa1, 0x02, 0xc5,
		0x48, 0x0e, 0x25, 0xbe, 0x7f, 0x6d, 0xd4};

	res = crypto_sha(alg, mod, in_data, sizeof(in_data), out_data, &out_len);
	if (res != TEE_SUCCESS) {
		EMSG("CryptoSHA ERR: 0x%x.", res);
		return res;
	}
	IMSG("Crypto SHA256 done.");

	//Compare with referance data
	if (TEE_MemCompare(out_data, sha_refer, out_len))
		EMSG("SHA256 compare ERR!");
	else
		IMSG("SHA256 compare OK.");
	return res;
}

static TEE_Result crypto_aes(uint32_t algorithm, uint32_t mode,
	void *key, uint32_t key_len, void *iv, uint32_t iv_len, void *src_data, uint32_t src_len,
	void *dest_data, uint32_t *dest_len)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle op_handle;
	TEE_ObjectHandle ob_handle;
	TEE_Attribute attribute;
	uint32_t max_key_size = (key_len * 8);

	res = TEE_AllocateOperation(&op_handle, algorithm, mode, max_key_size);
	if (res != TEE_SUCCESS) {
		EMSG("AllocateOperation ERR: 0x%x.", res);
		return res;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, max_key_size, &ob_handle);
	if (res != TEE_SUCCESS) {
		EMSG("AllocateTransientObject ERR: 0x%x.", res);
		goto out;
	}

	TEE_InitRefAttribute(&attribute, TEE_ATTR_SECRET_VALUE, key, key_len);
	res = TEE_PopulateTransientObject(ob_handle, &attribute, 1);
	if (res != TEE_SUCCESS) {
		EMSG("PopulateTransientObject ERR: 0x%x.", res);
		goto out1;
	}

	res = TEE_SetOperationKey(op_handle, ob_handle);
	if (res != TEE_SUCCESS) {
		EMSG("SetOperationKey ERR: 0x%x.", res);
		goto out1;
	}

	TEE_CipherInit(op_handle, iv, iv_len);
	res = TEE_CipherDoFinal(op_handle, src_data, src_len,
		dest_data, dest_len);
	if (res != TEE_SUCCESS)
		EMSG("CipherDoFinal ERR: 0x%x.", res);

out1:
	TEE_FreeTransientObject(ob_handle);
out:
	TEE_FreeOperation(op_handle);
	return res;
}

TEE_Result handle_crypto_aes(void)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t aes_128key[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	uint8_t aes_128iv[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	uint8_t in_data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	uint8_t enc_out_data[32] = {0};
	uint8_t dec_out_data[32] = {0};
	uint32_t enc_out_len = sizeof(enc_out_data);
	uint32_t dec_out_len = sizeof(dec_out_data);

	uint32_t alg = TEE_ALG_AES_CBC_NOPAD;
	uint32_t mod;

	//AES CBC ENC
	mod = TEE_MODE_ENCRYPT;
	res = crypto_aes(alg, mod, aes_128key, sizeof(aes_128key),
		aes_128iv, sizeof(aes_128iv), in_data, sizeof(in_data),
		enc_out_data, &enc_out_len);
	if (res != TEE_SUCCESS) {
		EMSG("AES ENC ERR: 0x%x.", res);
		return res;
	}
	IMSG("AES ENC done.");

	//AES CBC DEC
	mod = TEE_MODE_DECRYPT;
	res = crypto_aes(alg, mod, aes_128key, sizeof(aes_128key),
		aes_128iv, sizeof(aes_128iv), enc_out_data, enc_out_len,
		dec_out_data, &dec_out_len);
	if (res != TEE_SUCCESS) {
		EMSG("AES DEC ERR: 0x%x.", res);
		return res;
	}
	IMSG("AES DEC done.");

	//Compare data
	if (TEE_MemCompare(dec_out_data, in_data, sizeof(in_data)))
		EMSG("AES test ERR!");
	else
		IMSG("AES test OK.");

	return res;
}

static TEE_Result crypto_rsa_enc(void *src_data, uint32_t src_len,
	void *dest_data, uint32_t *dest_len)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle op_handle;
	TEE_ObjectHandle ob_handle;
	TEE_ObjectType ob_type;
	uint32_t count;
	TEE_Attribute attribute[2];
	uint32_t max_key_size = g_rsa2048_len_n * 8;

	res = TEE_AllocateOperation(&op_handle,
		TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, max_key_size);
	if (res != TEE_SUCCESS) {
		EMSG("AllocateOperation ERR: 0x%x.", res);
		return res;
	}

	ob_type = TEE_TYPE_RSA_PUBLIC_KEY;
	count = 2;

	res = TEE_AllocateTransientObject(ob_type, max_key_size, &ob_handle);
	if (res != TEE_SUCCESS) {
		EMSG("AllocateTransientObject ERR: 0x%x.", res);
		goto out;
	}

	TEE_MemFill(attribute, 0, 2*(sizeof(TEE_Attribute)));
	/* Set attribute[0] data with N data */
	attribute[0].attributeID = TEE_ATTR_RSA_MODULUS;
	attribute[0].content.ref.buffer = g_rsa2048_n;
	attribute[0].content.ref.length = g_rsa2048_len_n;
	/* Set attribute[1] data with E data */
	attribute[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
	attribute[1].content.ref.buffer = g_rsa2048_e;
	attribute[1].content.ref.length = g_rsa2048_len_e;

	res = TEE_PopulateTransientObject(ob_handle, attribute, count);
	if (res != TEE_SUCCESS) {
		EMSG("PopulateTransientObject ERR: 0x%x.", res);
		goto out1;
	}

	res = TEE_SetOperationKey(op_handle, ob_handle);
	if (res != TEE_SUCCESS) {
		EMSG("SetOperationKey ERR: 0x%x.", res);
		goto out1;
	}

	res = TEE_AsymmetricEncrypt(op_handle, NULL, 0,
		src_data, src_len, dest_data, dest_len);
	if (res != TEE_SUCCESS)
		EMSG("AsymmetricEncrypt ERR: 0x%x.", res);

out1:
	TEE_FreeTransientObject(ob_handle);
out:
	TEE_FreeOperation(op_handle);
	return res;
}

static TEE_Result crypto_rsa_dec(void *src_data, uint32_t src_len,
	void *dest_data, uint32_t *dest_len)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle op_handle;
	TEE_ObjectHandle ob_handle;
	TEE_ObjectType ob_type;
	uint32_t count;
	TEE_Attribute attribute[3];
	uint32_t max_key_size = g_rsa2048_len_n * 8;

	res = TEE_AllocateOperation(&op_handle,
		TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT, max_key_size);
	if (res != TEE_SUCCESS) {
		EMSG("AllocateOperation ERR: 0x%x.", res);
		return res;
	}

	ob_type = TEE_TYPE_RSA_KEYPAIR;
	count = 3;

	res = TEE_AllocateTransientObject(ob_type, max_key_size, &ob_handle);
	if (res != TEE_SUCCESS) {
		EMSG("AllocateTransientObject ERR: 0x%x.", res);
		goto out;
	}

	TEE_MemFill(attribute, 0, 3*(sizeof(TEE_Attribute)));
	/* Set attribute[0] data with N data */
	attribute[0].attributeID = TEE_ATTR_RSA_MODULUS;
	attribute[0].content.ref.buffer = g_rsa2048_n;
	attribute[0].content.ref.length = g_rsa2048_len_n;
	/* Set attribute[1] data with E data */
	attribute[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
	attribute[1].content.ref.buffer = g_rsa2048_e;
	attribute[1].content.ref.length = g_rsa2048_len_e;
	/*Set attribute[1] data with D data */
	attribute[2].attributeID = TEE_ATTR_RSA_PRIVATE_EXPONENT;
	attribute[2].content.ref.buffer = g_rsa2048_d;
	attribute[2].content.ref.length = g_rsa2048_len_d;

	res = TEE_PopulateTransientObject(ob_handle, attribute, count);
	if (res != TEE_SUCCESS) {
		EMSG("PopulateTransientObject ERR: 0x%x.", res);
		goto out1;
	}

	res = TEE_SetOperationKey(op_handle, ob_handle);
	if (res != TEE_SUCCESS) {
		EMSG("SetOperationKey ERR: 0x%x.", res);
		goto out1;
	}

	res = TEE_AsymmetricDecrypt(op_handle, NULL, 0,
		src_data, src_len, dest_data, dest_len);
	if (res != TEE_SUCCESS)
		EMSG("AsymmetricDecrypt ERR: 0x%x.", res);

out1:
	TEE_FreeTransientObject(ob_handle);
out:
	TEE_FreeOperation(op_handle);
	return res;
}

static TEE_Result crypto_rsa_sign(void *src_data, uint32_t src_len,
	void *dest_data, uint32_t *dest_len)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle op_handle;
	TEE_ObjectHandle ob_handle;
	TEE_ObjectType ob_type;
	uint32_t count;
	TEE_Attribute attribute[3];
	uint32_t max_key_size = g_rsa2048_len_n * 8;
	uint8_t hash[32] = {0}; //sha256
	uint32_t hash_len = sizeof(hash);

	//Calculate the hash 256 value of input data.
	res = crypto_sha(TEE_ALG_SHA256, TEE_MODE_DIGEST,
		src_data, src_len, (void *)hash, &hash_len);
	if (res != TEE_SUCCESS) {
		EMSG("CryptoSHA ERR: 0x%x.", res);
		return res;
	}

	res = TEE_AllocateOperation(&op_handle,
		TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_SIGN, max_key_size);
	if (res != TEE_SUCCESS) {
		EMSG("AllocateOperation ERR: 0x%x.", res);
		return res;
	}

	ob_type = TEE_TYPE_RSA_KEYPAIR;
	count = 3;

	res = TEE_AllocateTransientObject(ob_type, max_key_size, &ob_handle);
	if (res != TEE_SUCCESS) {
		EMSG("AllocateTransientObject ERR: 0x%x.", res);
		goto out;
	}

	TEE_MemFill(attribute, 0, 3*(sizeof(TEE_Attribute)));
	/* Set attribute[0] data with N data */
	attribute[0].attributeID = TEE_ATTR_RSA_MODULUS;
	attribute[0].content.ref.buffer = g_rsa2048_n;
	attribute[0].content.ref.length = g_rsa2048_len_n;
	/* Set attribute[1] data with E data */
	attribute[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
	attribute[1].content.ref.buffer = g_rsa2048_e;
	attribute[1].content.ref.length = g_rsa2048_len_e;
	/*Set attribute[1] data with D data */
	attribute[2].attributeID = TEE_ATTR_RSA_PRIVATE_EXPONENT;
	attribute[2].content.ref.buffer = g_rsa2048_d;
	attribute[2].content.ref.length = g_rsa2048_len_d;

	res = TEE_PopulateTransientObject(ob_handle, attribute, count);
	if (res != TEE_SUCCESS) {
		EMSG("PopulateTransientObject ERR: 0x%x.", res);
		goto out1;
	}

	res = TEE_SetOperationKey(op_handle, ob_handle);
	if (res != TEE_SUCCESS) {
		EMSG("SetOperationKey ERR: 0x%x.", res);
		goto out1;
	}

	res = TEE_AsymmetricSignDigest(op_handle, NULL, 0,
		hash, hash_len, dest_data, dest_len);
	if (res != TEE_SUCCESS)
		EMSG("AsymmetricSignDigest ERR: 0x%x.", res);

out1:
	TEE_FreeTransientObject(ob_handle);
out:
	TEE_FreeOperation(op_handle);
	return res;
}

static TEE_Result crypto_rsa_verify(void *src_data, uint32_t src_len,
	void *sign_data, uint32_t sign_len)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle op_handle;
	TEE_ObjectHandle ob_handle;
	TEE_ObjectType ob_type;
	uint32_t count;
	TEE_Attribute attribute[2];
	uint32_t max_key_size = g_rsa2048_len_n * 8;
	uint8_t hash[32] = {0}; //sha256
	uint32_t hash_len = sizeof(hash);

	//Calculate the hash 256 value of input data.
	res = crypto_sha(TEE_ALG_SHA256, TEE_MODE_DIGEST,
		src_data, src_len, (void *)hash, &hash_len);
	if (res != TEE_SUCCESS) {
		EMSG("CryptoSHA ERR: 0x%x.", res);
		return res;
	}

	res = TEE_AllocateOperation(&op_handle,
		TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_VERIFY, max_key_size);
	if (res != TEE_SUCCESS) {
		EMSG("AllocateOperation ERR: 0x%x.", res);
		return res;
	}

	ob_type = TEE_TYPE_RSA_PUBLIC_KEY;
	count = 2;

	res = TEE_AllocateTransientObject(ob_type, max_key_size, &ob_handle);
	if (res != TEE_SUCCESS) {
		EMSG("AllocateTransientObject ERR: 0x%x.", res);
		goto out;
	}

	TEE_MemFill(attribute, 0, 2*(sizeof(TEE_Attribute)));
	/* Set attribute[0] data with N data */
	attribute[0].attributeID = TEE_ATTR_RSA_MODULUS;
	attribute[0].content.ref.buffer = g_rsa2048_n;
	attribute[0].content.ref.length = g_rsa2048_len_n;
	/* Set attribute[1] data with E data */
	attribute[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
	attribute[1].content.ref.buffer = g_rsa2048_e;
	attribute[1].content.ref.length = g_rsa2048_len_e;

	res = TEE_PopulateTransientObject(ob_handle, attribute, count);
	if (res != TEE_SUCCESS) {
		EMSG("PopulateTransientObject ERR: 0x%x.", res);
		goto out1;
	}

	res = TEE_SetOperationKey(op_handle, ob_handle);
	if (res != TEE_SUCCESS) {
		EMSG("SetOperationKey ERR: 0x%x.", res);
		goto out1;
	}

	res = TEE_AsymmetricVerifyDigest(op_handle, NULL, 0,
		hash, hash_len, sign_data, sign_len);
	if (res != TEE_SUCCESS)
		EMSG("AsymmetricVerifyDigest ERR: 0x%x.", res);

out1:
	TEE_FreeTransientObject(ob_handle);
out:
	TEE_FreeOperation(op_handle);
	return res;
}

TEE_Result handle_crypto_rsa(void)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t in_data[] = "The data for testing RSA enc, dec, sign and verify.";
	uint8_t out_data_1[256] = {0};
	uint8_t out_data_2[256] = {0};
	uint32_t out_len_1 = sizeof(out_data_1);
	uint32_t out_len_2 = sizeof(out_data_2);

	res = crypto_rsa_enc(in_data, sizeof(in_data), out_data_1, &out_len_1);
	if (res != TEE_SUCCESS) {
		EMSG("CryptoRSAEnc_ta ERR: 0x%x.", res);
		return res;
	}
	IMSG("RSA ENC done.");

	res = crypto_rsa_dec(out_data_1, out_len_1, out_data_2, &out_len_2);
	if (res != TEE_SUCCESS) {
		EMSG("CryptoRSAEnc_ta ERR: 0x%x.", res);
		return res;
	}
	IMSG("RSA DEC done.");

	//Compare data
	if (TEE_MemCompare(in_data, out_data_2, sizeof(in_data)))
		EMSG("RSA ENC and DEC compare ERR!");
	IMSG("RSA ENC and DEC compare OK.");

	res = crypto_rsa_sign(in_data, sizeof(in_data), out_data_1, &out_len_1);
	if (res != TEE_SUCCESS) {
		EMSG("CryptoRSASign_ta ERR: 0x%x.", res);
		return res;
	}
	IMSG("RSA Sign done.");

	res = crypto_rsa_verify(in_data, sizeof(in_data), out_data_1, out_len_1);
	if (res != TEE_SUCCESS) {
		EMSG("CryptoRSAVerify_ta ERR: 0x%x.", res);
		return res;
	}
	IMSG("RSA Verity OK.");
	return res;
}

