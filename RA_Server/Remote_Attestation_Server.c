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

	memset(xor_result, 0, sizeof(xor_result));
	memset(buf, 0, sizeof(buf));

	if (!(fp = fopen("Device_Value", "rb")))
	{
		printf("Device_Value Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&ctx, buf, i);
	SHA1_Final(xor_result, &ctx);

	fclose(fp);

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
	int padding = RSA_PKCS1_PADDING;

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
	BIO *bio, *abio, *out;
	BIO *bio_err = 0;
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	int res, len;

	memset(xor_result, 0, 20);
	// SSL Connection Start
	if (!bio_err)
	{
		SSL_library_init();
		SSL_load_error_strings();
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}
	
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	res = SSL_CTX_use_certificate_chain_file(ctx, "cert");

	res = SSL_CTX_use_PrivateKey_file(ctx, "private", SSL_FILETYPE_PEM);
	
	res = SSL_CTX_check_private_key(ctx);

	bio = BIO_new_ssl(ctx, 0);
	BIO_get_ssl(bio, &ssl);

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	abio = BIO_new_accept("4000");

	BIO_set_accept_bios(abio, bio);
	if (BIO_do_accept(abio) <= 0)
	{
		fprintf(stderr, "Error setting up accept BIO\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (BIO_do_accept(abio) <= 0)
	{
		fprintf(stderr, "Error in connection\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	out = BIO_pop(abio);

	if (BIO_do_handshake(out) <= 0)
	{
		fprintf(stderr, "Error in SSL handshake\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}
	else
		printf("SSL Connection Success\n");

	if (attestation_server_hash(xor_result) != 0)
	{
		printf("Attestation_server_hash falied\n");
		return 1;
	}

	receiveData(out, sign);

	if (decrypt_signature(xor_result, sign) != 0)
	{
		printf("Signature decryption failed\n");
		return 1;
	}

	return 0;
}
