// Basic Header
#include <stdio.h>

// OpenSSL Header
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

void dividestr(char* dest, char* source, int start, int end)
{
	int i, j = 0;

	for (i = start; i < end; i++)
		dest[j++] = source[i];
}

int attestation_server_hash(unsigned char* xor_result)
{
	FILE *fp;
	int i, j;
	unsigned char buf[256];

	// SHA1 Value
	SHA_CTX ctx;
	char sha1_result[4][SHA_DIGEST_LENGTH];

	// Hash u-boot.bin
	for (i = 0; i < 4; i++)
		memset(sha1_result[i], 0, sizeof(sha1_result[i]));
	memset(buf, 0, sizeof(buf));

	if (!(fp = fopen("u-boot.bin", "rb")))
	{
		printf("u-boot.bin Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&ctx, buf, i);
	SHA1_Final(sha1_result[0], &ctx);

	fclose(fp);

	// Hash image.fit
	memset(buf, 0, sizeof(buf));

	if (!(fp = fopen("image.fit", "rb")))
	{
		printf("image.fit Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&ctx, buf, i);
	SHA1_Final(sha1_result[1], &ctx);

	fclose(fp);

	// Hash Secure_boot_daemon
	if (!(fp = fopen("Secure_boot_daemon", "rb"))) {
		printf("Secure_boot_daemon Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0) {
		SHA1_Update(&ctx, buf, i);
	}
	SHA1_Final(sha1_result[2], &ctx);
	fclose(fp);

	// Hash SecurePi Serial Number
	memset(buf, 0, sizeof(buf));

	if (!(fp = fopen("serial", "rb")))
	{
		printf("serial Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&ctx, buf, i);
	SHA1_Final(sha1_result[3], &ctx);
		fclose(fp);

	for (i = 0; i < 4; i++)
		for (j = 0; j < SHA_DIGEST_LENGTH; j++)
			xor_result[j] = xor_result[j] ^ sha1_result[i][j];

	return 0;
}
int receiveData(BIO *sbio, unsigned char* sign)
{
	int len;
	FILE* fp;
	char buf[2048];
	char data[2048];
	char fileLen[2][10];
	char* token = NULL;
	int i, start, end;

	for (i = 0; i < 2; i++)
		memset(fileLen[i], 0, 10);
	memset(data, 0, 2048);

	// Data Rececive Start
	while ((len = BIO_read(sbio, buf, 2048)) != 0);

	token = strtok(buf, "  ");
	strcpy(fileLen[0], token);

	token = strtok(NULL, "  ");
	strcpy(fileLen[1], token);

	token = strtok(NULL, "");
	strcpy(data, token);

	// Store New Bootloader
	if (!(fp = fopen("AIK", "wb")))
	{
		printf("AIK Open Fail\n");
		return 1;
	}

	memset(buf, 0, 2048);
	start = 1;
	end = atoi(fileLen[0]);
	dividestr(buf, data, start, end);
	fwrite((void*)buf, 1, atoi(fileLen[0]), fp);
	fclose(fp);

	memset(buf, 0, 2048);
	start = end;
	end = start + atoi(fileLen[1]);
	dividestr(buf, data, start, end);
	strcpy(sign, buf);

	return 0;
}

int decrypt_signature(unsigned char* xor_result, unsigned char* sign)
{
	char decrypt_sign[20];
	int sign_len = 0;

	FILE *key = fopen("AIK", "rb");
	EVP_PKEY *pubkey = NULL;
	PEM_read_PUBKEY(key, &pubkey, NULL, NULL);
	RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
	fclose(key);

	sign_len = RSA_public_decrypt(256, sign, decrypt_sign, rsa, padding);
	if (sign_len < 0)
	{
		printf("Signature decryption failed\n");
		return 1;
	}

	if (strncmp(xor_result, decrypt_sign, 20) != 0) {
		printf("Verify fail\n");
		return 1;
	}
	else {
		printf("Verify Success\n");
		return 0;
	}

	return 0;
}

int main()
{
	unsigned char xor_result[20];
	// Signature Value
	unsigned char sign[256];

	// SSL Value
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *sbio, *out;
	BIO *bio_err = 0;
	int len, res;

	memset(xor_result, 0, 20);
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

	if (attestation_server_hash(xor_result) != 0)
	{
		printf("Attestation_server_hash falied\n");
		return 1;
	}

	receiveData(sbio, sign);

	if (decrypt_signature(xor_result, sign) != 0)
	{
		printf("Signature decryption failed\n");
		return 1;
	}

	return 0;
}