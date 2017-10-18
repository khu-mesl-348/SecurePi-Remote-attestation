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
#include <openssl/bio.h>
#include <openssl.rsa.h>

#define SIGN_KEY_UUID {0, 0, 0, 0, 0, {0, 0, 0, 7, 15}}
#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1
#define BLOBLEN (1 << 10)

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
	SHA_CTX ctx;
	unsigned char digest[SHA_DIGEST_LENGTH];
	unsigned char buf[1024];

	result = Tspi_Context_Create(&hContext);
#if DEBUG
	DBG("Create TPM Context\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_Connect(hContext, NULL);
#if DEBUG
	DBG("Connect to TPM\n", result);
#endif
	if (result != 0) return 1;

	if (!(fp = fopen("/boot/u-boot.bin", "rb")))
	{
		printf("/boot/u-boot.bin Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&ctx, buf, i);
	SHA1_Final(digest, &ctx);
	fclose(fp);

	result = Tspi_TPM_PcrExtend(hTpm, 16, 20, (BYTE *)digest, NULL, &PCR_length, &f_data);
#if DEBUG
	DBG("PCR Extend\n", result);
#endif
	if (result != 0) return 1;

	if (!(fp = fopen("/boot/image.fit", "rb")))
	{
		printf("/boot/image.fit Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&ctx, buf, i);
	SHA1_Final(digest, &ctx);
	fclose(fp);

	result = Tspi_TPM_PcrExtend(hTpm, 16, 20, (BYTE *)digest, NULL, &PCR_length, &f_data);
#if DEBUG
	DBG("PCR Extend\n", result);
#endif
	if (result != 0) return 1;

	// Secure_boot_daemon hash //
	if (!(fp = fopen("/Boot/Secure_boot_daemon", "rb"))) {
		printf("File open error\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0) {
		SHA1_Update(&ctx, buf, i);
	}
	SHA1_Final(digest, &ctx);
	fclose(fp);

	result = Tspi_TPM_PcrExtend(hTpm, 16, 20, (BYTE *)digest, NULL, &PCR_length, &f_data);
#if DEBUG
	DBG("PCR Extend\n", result);
#endif
	if (result != 0) return 1;

	memcpy(extendValue, f_data, 20);

	result = Tspi_Context_FreeMemory(hContext, NULL);
#if DEBUG
	DBG("Free Memory\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_Close(hContext);
#if DEBUG
	DBG("Close TPM\n", result);
#endif
	if (result != 0) return 1;

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
#if DEBUG
	DBG("Context Create\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_Connect(hContext, NULL);
#if DEBUG
	DBG("Context Connect\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
#if DEBUG
	DBG("Get SRK handle\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
#if DEBUG
	DBG("Get Policy\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
	DBG("Set Secret\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
#if DEBUG
	DBG("Get TPM Object\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hTPMPolicy);
#if DEBUG
	DBG("Create Context\n");
#endif
	if (result != 0) return 1;

	result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
#if DEBUG
	DBG("Policy Assign\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
#if DEBUG
	DBG("Set Secret\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TYPE_LEGACY | TSS_KEY_SIZE_2048, hPCA);
#if DEBUG
	DBG("Create PCA\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Key_CreateKey(hPCA, hSRK, 0);
#if DEBUG
	DBG("Create Key\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hAIK);
#if DEBUG
	DBG("Create AIK Object\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hPCA, 0, lab, hAIK, TSS_ALG_AES, &blobLen, &blob);
#if DEBUG
	DBG("Create AIK\n", result);
#endif
	if (result != 0) return 1;

	result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, &blobLen, &blob);
#if DEBUG
	DBG("Get Attribute\n", result);
#endif
	if (result != 0) return 1;

	outb = BIO_new_file("AIK", "wb");
	blob_str = ASN1_OCTET_STRING_new();
	ASN1_STRING_set(blob_str, blob, blobLen);
	asn1_len = i2d_ASN1_OCTET_STRING(blob_str, &blob_asn1);
	PEM_write_bio(outb, "TSS KEY BLOB", "", blob_asn1, asn1_len);
	BIO_free(outb);

	result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, *blobLen, &blob);
#if DEBUG
	DBG("Get Attribute\n", result);
#endif
	if (resutl != 0) return 1;

	result = Tspi_EncodeDER_TssBlob(blobLen, blob, TSS_BLOB_TYPE_PUBKEY, &derBlobLen, derBlob);
#if DEBUG
	DBG("Encode\n", result);
#endif
	if (result != 0) return 1;

	derBlobLen = sizeof(derBlob);

	result = Tspi_EncodeDER_TssBlob(blobLen, blob, TSS_BLOB_TYPE_PUBKEY, &derBlobLen, derBlob);
#if DEBUG
	DBG("Encode\n", result);
#endif
	if (result != 0) return 1;

	if (!(out = fopen("AIK_public", "wb")))
	{
		printf("AIK_public open error\n");
		return 1;
	}
	fwrite(derBlob, 1, derBlobLen, out);
	fclose(out);

	result = Tspi_Context_FreeMemory(hContext, blob);
#if DEBUG
	DBG("Free Memory\n", result);
#endif
	if (result != 0) return 1;

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

int sendData(BIO* sbio)
{
	int len;
	FILE* fp = NULL;
	char* buf = NULL;

	if (!(fp = fopen("AIK_public", "rb")))
	{
		printf("AIK_public Open Fail\n");
		return 1;
	}
	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	buf = (char*)calloc(len, sizeof(char));

	fread(buf, 1, len, fp);
	BIO_write(sbio, buf, len);
	fclose(fp);
	free(buf);

	if (!(fp = fopen("Signature", "rb")))
	{
		printf("Signature Open Fail\n");
		return 1;
	}
	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	buf = (char*)calloc(len, sizeof(char));

	fread(buf, 1, len, fp);
	BIO_write(sbio, buf, len);
	fclose(fp);
	free(buf);

	return 0;
}

int receiveData(BIO* sbio, char* recvData)
{
	BIO_read(sbio, recvData, 10);
}

int main(void)
{
	int result;
	char extendValue[20];
	unsigned char encrypted[256];
	FILE* fp = NULL;
	char recvbuf[10];

	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *sbio, *out;
	BIO *bio_err = 0;

	if (!bio_err) {
		SSL_library_init();
		SSL_load_error_strings();
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);
	sbio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(sbio, &ssl);
	if (!ssl) {
		fprintf(stderr, "Can't locate SSL pointer\n");
		exit(1);
	}
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(sbio, "serverIP:Port");
	out = BIO_new_fp(stdout, BIO_NOCLOSE);
	res = BIO_do_connect(sbio);
	if (res <= 0) {
		fprintf(stderr, "Error connecting to server\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	res = BIO_do_handshake(sbio);
	if (res <= 0) {
		fprintf(stderr, "Error establishing SSL connection \n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (generate_hash_extend(extendValue) != 0)
	{
		printf("Attestation_Signature generation failed\n");
		return 1;
	}

	if (createAIK() != 0)
	{
		printf("AIK Creation failed\n");
		return 1;
	}

	RSA *rsa = EVP_PKEY_get1_RSA(load());
	if (rsa == NULL)
	{
		printf("TPM RSA key load failed\n");
		return 1;
	}

	result = RSA_private_encrypt(20, extendValue, encrypted, rsa, RSA_PKCS1_PADDING);
	if (result < 0)
	{
		printf("RSA Signature encryption failed\n");
		return 1;
	}

	if (!(fp = fopen("Signature", "wb")))
	{
		printf("File open error\n");
		return 1;
	}
	fwrite(encrypted, 1, 256, fp);
	fclose(fp);

	sendData(sbio);
	receiveData(sbio, recvbuf);

	if (strcmp(recvbuf, "fail") == 0)
		printf("Failure\n\n");
	else
		printf("Success\n\n");

	return 0;
}
