// Basic Header
#include <stdio.h>

// OpenSSL Header
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <assert.h>

int attestation_server_hash(unsigned char* xor_result)
{
	FILE *fp; // File Pointer
	int i; // for value
	unsigned char digest[SHA_DIGEST_LENGTH]; // SHA256 result temp save value
	unsigned char buf[1024]; // File read data buffer
	SHA_CTX ctx; // SHA256 Context

	// u-boot.bin hash //
	if (!(fp = fopen("u-boot.bin", "rb"))) {
		printf("File open error\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0) {
		SHA1_Update(&ctx, buf, i);
	}
	SHA1_Final(digest, &ctx);
	fclose(fp);

	// image.fit hash //
	if (!(fp = fopen("image.fit", "rb"))) {
		printf("File open error\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0) {
		SHA1_Update(&ctx, buf, i);
	}
	SHA1_Final(xor_result, &ctx);
	fclose(fp);

	for (i = 0; i<20; i++)
		xor_result[i] = xor_result[i] ^ digest[i];

	// Secure_boot_daemon hash //
	if (!(fp = fopen("Secure_boot_daemon", "rb"))) {
		printf("File open error\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0) {
		SHA1_Update(&ctx, buf, i);
	}
	SHA1_Final(digest, &ctx);
	fclose(fp);

	for (i = 0; i<20; i++)
		xor_result[i] = xor_result[i] ^ digest[i];

	return 0;
}

int receiveData(BIO* sbio)
{
	FILE* fp;
	int len;
	char tmpbuf[512];

	fp = fopen("AIK", "wb");
	len = BIO_read(sbio, tmpbuf, 451);
	fwrite(tmpbuf, 1, len, fp);
	fclose(fp);

	fp = fopen("Signature", "wb");
	len = BIO_read(sbio, tmpbuf, 256);
	fwrite(tmpbuf, 1, len, fp);
	fclose(fp);

	return 0;
}

int decrypt_signature(unsigned char* xor_result)
{
	FILE *fp = NULL;
	char sign[256];
	char decrypt_sign[20];
	int sign_len = 0;

	FILE *key = fopen("AIK", "rb");
	EVP_PKEY *pubkey = NULL;
	PEM_read_PUBKEY(key, &pubkey, NULL, NULL);
	RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
	fclose(key);

	if (!(fp = fopen("Signature", "rb")))
	{
		printf("File open error\n");
		return 1;
	}
	fread(sign_b, 1, 256, fp);
	fclose(fp);

	sign_len = RSA_public_decrypt(256, sign_b, decrypt_sign, rsa, padding);
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
	BIO *sbio, *bbio, *acpt, *out;
	BIO *bio_err = 0;
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;

	unsigned char xor_result[20];

	if (!bio_err) {
		SSL_library_init();
		SSL_load_error_strings();
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	res = SSL_CTX_use_certificate_chain_file(ctx, "cert");
	assert(res);

	res = SSL_CTX_use_PrivateKey_file(ctx, "private", SSL_FILETYPE_PEM);
	assert(res);

	res = SSL_CTX_check_private_key(ctx);
	assert(res);

	sbio = BIO_new_ssl(ctx, 0);
	BIO_get_ssl(sbio, &ssl);
	assert(ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	bbio = BIO_new(BIO_f_buffer());
	sbio = BIO_push(bbio, sbio);
	acpt = BIO_new_accept("PORT");

	BIO_set_accept_bios(acpt, sbio);
	out = BIO_new_fp(stdout, BIO_NOCLOSE);
	if (BIO_do_accept(acpt) <= 0) {
		fprintf(stderr, "Error setting up accept BIO\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (BIO_do_accept(acpt) <= 0) {
		fprintf(stderr, "Error in connection\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	sbio = BIO_pop(acpt);
	BIO_free_all(acpt);

	if (BIO_do_handshake(sbio) <= 0) {
		fprintf(stderr, "Error in SSL handshake\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (attestation_server_hash(xor_result) != 0)
	{
		printf("Attestation_server_hash falied\n");
		return 1;
	}

	receiveData(sbio);

	if (decrypt_signature(xor_result) != 0)
	{
		printf("Signature decryption failed\n");
		return 1;
	}

	return 0;
}