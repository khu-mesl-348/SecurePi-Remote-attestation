// Basic Header
#include <stdio.h>
#include <string.h>

// TPM Header
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <tss/tss_error.h>
#include <trousers/trousers.h>

// OpenSSL Header
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

void TPM_ERROR_PRINT(int res, char* msg)
{
#if DEBUG
	DBG(msg, res);
#endif
	if (res != 0) exit(1);
}

int generate_hash_extend(char* extendValue)
{
	TSS_HPCRS hPcrs;
	TSS_HTPM hTpm;
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HKEY hSRK;
	TSS_HPOLICY hSRKPolicy;
	TSS_PCR_EVENT *prgPcrEvents, *extendEvents;
	TSS_HHASH hHash;
	BYTE hash_value[20], *f_data;
	UINT32 PCR_length, number = 23;

	FILE* fp;
	int i;
	char buf[256];

	// SHA1 Value
	SHA_CTX sha1;
	char sha1_result[4][SHA_DIGEST_LENGTH];

	// SecurePi Serial Number Value
	char serial[16 + 1];

	result = Tspi_Context_Create(&hContext);
	TPM_ERROR_PRINT(result, "Create TPM Context\n");

	result = Tspi_Context_Connect(hContext, NULL);
	TPM_ERROR_PRINT(result, "Connect to TPM\n");

	result = Tspi_Context_GetTpmObject(hContext, &hTpm);
	TPM_ERROR_PRINT(result, "Get TPM Handle\n");

	// Hash u-boot.bin
	for (i = 0; i < 4; i++)
		memset(sha1_result[i], 0, sizeof(sha1_result[i]));
	memset(buf, 0, sizeof(buf));
	memset(serial, 0, sizeof(serial));

	if (!(fp = fopen("/boot/u-boot.bin", "rb")))
	{
		printf("/boot/u-boot.bin Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&ctx, buf, i);
	SHA1_Final(sha1_result[0], &ctx);
	fclose(fp);

	result = Tspi_TPM_PcrExtend(hTpm, 16, 20, (BYTE *)sha1_result[0], NULL, &PCR_length, &f_data);
	TPM_ERROR_PRINT(result, "TPM PCR and Bootloader Hash Extend\n");

	// Hash image.fit
	memset(buf, 0, sizeof(buf));

	if (!(fp = fopen("/boot/image.fit", "rb")))
	{
		printf("/boot/image.fit Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&ctx, buf, i);
	SHA1_Final(sha1_result[1], &ctx);

	fclose(fp);

	result = Tspi_TPM_PcrExtend(hTpm, 16, 20, (BYTE *)sha1_result[1], NULL, &PCR_length, &f_data);
	TPM_ERROR_PRINT(result, "TPM PCR and Kernel Hash Extend\n");

	// Hash Secure_boot_daemon
	if (!(fp = fopen("/Boot/Secure_boot_daemon", "rb"))) {
		printf("/Boot/Secure_boot_daemon Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0) {
		SHA1_Update(&ctx, buf, i);
	}
	SHA1_Final(sha1_result[2], &ctx);
	fclose(fp);

	result = Tspi_TPM_PcrExtend(hTpm, 16, 20, (BYTE *)sha1_result[2], NULL, &PCR_length, &f_data);
	TPM_ERROR_PRINT(result, "TPM PCR and Secure_boot_daemon Hash Extend\n");

	// Hash SecurePi Serial Number
	memset(buf, 0, sizeof(buf));

	if (!(fp = fopen("/proc/cpuinfo", "r")))
	{
		printf("/proc/cpuinfo Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);

	while (fgets(buf, 256, fp))
		if (strncmp(buf, "Serial", 6) == 0)
			strcpy(serial, strchr(buf, ':') + 2);

	SHA1_Update(&ctx, serial, sizeof(serial));
	SHA1_Final(sha1_result[3], &ctx);
	fclose(fp);

	result = Tspi_TPM_PcrExtend(hTpm, 16, 20, (BYTE *)sha1_result[3], NULL, &PCR_length, &f_data);
	TPM_ERROR_PRINT(result, "TPM PCR and Serial Hash Extend\n");

	memcpy(extendValue, f_data, 20);

	result = Tspi_Context_FreeMemory(hContext, NULL);
	TPM_ERROR_PRINT(result, "Free TPM Memory\n");

	result = Tspi_Context_Close(hContext);
	TPM_ERROR_PRINT(result, "Close TPM\n");

	return 0;
}

int createAIK()
{
	TSS_HTPM hTPM;
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HKEY hSRK;
	TSS_HPOLICY hSRKPolicy, hTPMPolicy;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	TSS_HKEY hPCA;
	int initFlags = TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048;
	TSS_HKEY hAIK;
	BYTE *lab, *blob, derBlob[BLOBLEN];
	UINT32 blobLen, derBlobLen;
	FILE* out = NULL;
	BIO *outb = NULL;
	unsigned char *blob_asn1 = NULL;
	int asn1_len;
	ASN1_OCTET_STRING *blob_str = NULL;

	result = Tspi_Context_Create(&hContext);
	TPM_ERROR_PRINT(result, "Create TPM Context\n");

	result = Tspi_Context_Connect(hContext, NULL);
	TPM_ERROR_PRINT(result, "Connect to TPM\n");

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	TPM_ERROR_PRINT(result, "Get SRK Handle\n");

	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
	TPM_ERROR_PRINT(result, "Get SRK Policy\n");

	result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
	TPM_ERROR_PRINT(result, "Set SRK Secret\n");

	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	TPM_ERROR_PRINT(result, "Get TPM Handle\n");

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hTPMPolicy);
	TPM_ERROR_PRINT(result, "Get TPM Policy\n");

	result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
	TPM_ERROR_PRINT(result, "Assign TPM Object\n");

	result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
	TPM_ERROR_PRINT(result, "Set SRK Secret\n");

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TYPE_LEGACY | TSS_KEY_SIZE_2048, hPCA);
	TPM_ERROR_PRINT(result, "Create the PCA Object\n");

	result = Tspi_Key_CreateKey(hPCA, hSRK, 0);
	TPM_ERROR_PRINT(result, "Create the PCA\n");

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hAIK);
	TPM_ERROR_PRINT(result, "Create the AIK Object\n");

	result = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hPCA, 0, lab, hAIK, TSS_ALG_AES, &blobLen, &blob);
	TPM_ERROR_PRINT(result, "Collate Identity Request\n");

	result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, &blobLen, &blob);
	TPM_ERROR_PRINT(result, "Get AIK Attribute\n");

	outb = BIO_new_file("AIK", "wb");
	blob_str = ASN1_OCTET_STRING_new();
	ASN1_STRING_set(blob_str, blob, blobLen);
	asn1_len = i2d_ASN1_OCTET_STRING(blob_str, &blob_asn1);
	PEM_write_bio(outb, "TSS KEY BLOB", "", blob_asn1, asn1_len);
	BIO_free(outb);

	result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, *blobLen, &blob);
	TPM_ERROR_PRINT(result, "Get AIK Public Key\n");

	result = Tspi_EncodeDER_TssBlob(blobLen, blob, TSS_BLOB_TYPE_PUBKEY, &derBlobLen, derBlob);
	TPM_ERROR_PRINT(result, "Encode DER to TssBlob\n");

	derBlobLen = sizeof(derBlob);

	result = Tspi_EncodeDER_TssBlob(blobLen, blob, TSS_BLOB_TYPE_PUBKEY, &derBlobLen, derBlob);
	TPM_ERROR_PRINT(result, "Encode DER to TssBlob\n");

	if (!(out = fopen("AIK_public", "wb")))
	{
		printf("AIK_public open error\n");
		return 1;
	}
	fwrite(derBlob, 1, derBlobLen, out);
	fclose(out);

	result = Tspi_Context_FreeMemory(hContext, blob);
	TPM_ERROR_PRINT(result, "Free TPM Memory\n");

	result = Tspi_Context_Close(hContext);
	TPM_ERROR_PRINT(result, "Close TPM\n");

	return 0;
}

EVP_PKEY *load()
{
	const char *engineId = "tpm";
	ENGINE *e;
	EVP_PKEY *key;
	EVP_PKEY *pubkey;
	FILE *fp;

	ENGINE_load_builtin_engines();

	e = ENGINE_by_id(engineId);
	if (!e)
	{
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (!ENGINE_init(e))
	{
		ERR_print_errors_fp(stderr);
		ENGINE_free(e);
		ENGINE_finish(e);

		return NULL;
	}

	if (!ENGINE_set_default_RSA(e) || !ENGINE_set_default_RAND(e))
	{
		ERR_print_errors_fp(stderr);
		ENGINE_free(e);
		ENGINE_finish(e);

		return NULL;
	}

	ENGINE_ctrl_cmd(e, "PIN", 0, "1", NULL, 0);
	ENGINE_free(e);

	if ((key = ENGINE_load_private_key(e, "AIK", NULL, NULL)) == NULL)
	{
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	pubkey = ENGINE_load_public_key(e, "AIK", NULL, NULL);

	if (!(fp = fopen("AIK_public", "wb")))
	{
		printf("AIK_public Open Fail\n");
		return NULL;
	}
	PEM_write_PUBKEY(fp, pubkey);
	fclose(fp);

	ENGINE_finish(e);
	e = NULL;

	return key;
}

int sendData(BIO* sbio, unsigned char* sign)
{
	FILE* fp = NULL;
	int sendlen;
	char *sendBuf = NULL;
	int pubkeylen, signlen;
	char *pubkeybuf = NULL;
	int len;
	char pubkeylenbuf[10] = "", signlenbuf[10] = "";

	// Read AIK Public Key
	if (!(fp = fopen("AIK_public", "rb")))
	{
		printf("AIK_public Open Fail\n");
		return 1;
	}
	fseek(fp, 0L, SEEK_END);
	pubkeylen = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	pubkeybuf = (char*)calloc(pubkeylen, sizeof(char));
	fread(buf, 1, pubkeylen, fp);
	fclose(fp);

	// Assign sendBuf
	len = sprintf(pubkeylenbuf, "%d", pubkeylen);
	sendLen = len + pubkeylen;

	signLen = 256;
	len = sprintf(signlenBuf, "%d", signLen);
	sendLen = sendLen + len + 256; // 256 is Signature Length

	sendBuf = (char*)calloc(sendLen + 4, sizeof(char)); // 4 are add space length(4)

	strcpy(sendBuf, pubkeylenbuf);
	strcat(sendBuf, "  ");

	strcat(sendBuf, signlenBuf);
	strcat(sendBuf, "  ");

	strcat(sendBuf, pubkeybuf);
	strcat(sendBuf, sign);

	if (BIO_write(sbio, sendBuf, sendLen + 4) < 0)
	{
		printf("Send Attestation Value Fail\n");
		free(sendBuf);
		return 1;
	}

	return 0;
}

int receiveData(BIO* sbio, char* recvData)
{
	BIO_read(sbio, recvData, 10);
}

int generate_signature(char* extendValue, unsigned char* sign)
{
	RSA *rsa = EVP_PKEY_get1_RSA(load());
	if (rsa == NULL)
	{
		printf("TPM RSA key load failed\n");
		return 1;
	}

	result = RSA_private_encrypt(20, extendValue, sign, rsa, RSA_PKCS1_PADDING);
	if (result < 0)
	{
		printf("RSA Signature encryption failed\n");
		return 1;
	}

	return 0;
}

int main(void)
{
	int result;
	char extendValue[20];
	unsigned char sign[256];
	char recvbuf[10];

	// SSL Value
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *sbio, *out;
	BIO *bio_err = 0;
	int len, res;

	// SSL Connection Start
	if (!bio_err)
	{
		SSL_library_init();
		SSL_load_error_strings();
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	ctx = SSL_CTX_new(SSLv23_client_method());
	sbio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(sbio, &ssl);

	if (!ssl)
	{
		fprintf(stderr, "Can't locate SSL pointer\n");
		exit(1);
	}

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(sbio, "163.180.118.145:4000");
	out = BIO_new_fp(stdout, BIO_NOCLOSE);

	res = BIO_do_connect(sbio);
	if (res <= 0)
	{
		fprintf(stderr, "Error connecting to server\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	res = BIO_do_handshake(sbio);
	if (res <= 0)
	{
		fprintf(stderr, "Error establishing SSL connection \n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	else
		printf("SSL Connection Success\n");

	// Generate Extend Value
	if (generate_hash_extend(extendValue) != 0)
	{
		printf("Attestation_Signature generation failed\n");
		return 1;
	}

	// Generate AIK
	if (createAIK() != 0)
	{
		printf("AIK Creation failed\n");
		return 1;
	}

	// Generate Signature
	if (generate_signature(extendValue, sign) != 0)
	{
		printf("Signature Generation Fail\n");
		return 1;
	}

	sendData(sbio, sign);
	receiveData(sbio, recvbuf);

	if (strcmp(recvbuf, "fail") == 0)
		printf("Failure\n\n");
	else
		printf("Success\n\n");

	return 0;
}
