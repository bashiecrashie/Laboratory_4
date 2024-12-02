#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define red "\033[1;31m"
#define blue "\033[1;34m"
#define green "\033[1;32m"
#define ret "\033[00m"

void print_help()
{
	char *help =
"./lab_4_client <server ip> <server port> <client ceritifcate.pem> <four random number>\n"
"example:./lab_4_client localhost 1234 ca_cert.pem 1122\n";
	puts(help);
}

int run_tls_client(const char* hostname, const char* port, const char* trusted_cert_fname, FILE* error_stream, const char *nums);

int main(int argc, char** argv) 
{
	int exit_code = 0;
	
	if(argc != 5)
	{
		printf("%s[-]%sInvalid number of arguments !\n", red, green);
		print_help();
		exit(1);
	}

	int err = run_tls_client(argv[1], argv[2], argv[3], stderr, argv[4]);

	if (err) {
		fprintf(stderr, "%s[-]%sTLS communication failed\n", red, green);
		goto failure;
	}

	fprintf(stderr, "%s[+] TLS communication succeeded\n", green);

	goto cleanup;

	failure:
		exit_code = 1;

	cleanup:
		return exit_code;
}

int run_tls_client(const char* hostname, const char* port, const char* trusted_cert_fname, FILE* error_stream, const char *nums) 
{
	
	int exit_code = 0;
	int err = 1;
	SSL_CTX* ctx = NULL;
	BIO* ssl_bio = NULL;
	SSL* ssl = NULL;
	const size_t BUF_SIZE = 16 * 1024;
	char* in_buf = malloc(BUF_SIZE);
	assert(in_buf);
	char* out_buf = malloc(BUF_SIZE);
	assert(out_buf);
	ERR_clear_error();
	ctx = SSL_CTX_new(TLS_client_method());
	assert(ctx);

	if (trusted_cert_fname)
		err = SSL_CTX_load_verify_locations(ctx, trusted_cert_fname, NULL);
	else
		err = SSL_CTX_set_default_verify_paths(ctx);

	if (err <= 0) {
		if (error_stream)
			fprintf(error_stream, "%s[-]%sCould not load trusted certificates\n", red, green);
			goto failure;
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	ssl_bio = BIO_new_ssl_connect(ctx);
	assert(ssl_bio);
	BIO_set_conn_hostname(ssl_bio, hostname);
	BIO_set_conn_port(ssl_bio, port);
	err = BIO_get_ssl(ssl_bio, &ssl);
	assert(err == 1);
	assert(ssl);
	err = SSL_set_tlsext_host_name(ssl, hostname);
	assert(err == 1);
	err = SSL_set1_host(ssl, hostname);
	assert(err == 1);
	err = BIO_do_connect(ssl_bio);

	if (err <= 0) {
		if (error_stream)
			fprintf(error_stream, "%s[-]%sCould not connect to server %s on port %s\n", red, green, hostname, port);
		goto failure;
	}

	strcpy(out_buf, nums);
	int request_length = strlen(out_buf);
	printf("%s[*]%sSending to the server: %s\n", blue, green, out_buf);
	int nbytes_written = BIO_write(ssl_bio, out_buf,request_length);
	
	if (nbytes_written != request_length) {
		if (error_stream)
			fprintf(error_stream, "%s[-]%sCould not send all data to the server\n", red, green);
			goto failure;
	}

	printf("%s[*]%sReceiving from the server: ", blue, green);
	
	while ((SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) != SSL_RECEIVED_SHUTDOWN) {
		int nbytes_read = BIO_read(ssl_bio, in_buf, BUF_SIZE);
		if (nbytes_read <= 0) {
			int ssl_error = SSL_get_error(ssl, nbytes_read);
		if (ssl_error == SSL_ERROR_ZERO_RETURN)
			break;
		if (error_stream)
			fprintf(error_stream, "%s[-]%sError %i while reading data from the server\n", red, green, ssl_error);
			goto failure;
	}
	fwrite(in_buf, 1, nbytes_read, stdout);
	puts("\n");
	}

	BIO_ssl_shutdown(ssl_bio);
	goto cleanup;
	
	failure:
		exit_code = 1;
	cleanup:
		if (ssl_bio)
			BIO_free_all(ssl_bio);
		if (ctx)
			SSL_CTX_free(ctx);
	free(out_buf);
	free(in_buf);

	if (ERR_peek_error()) {
		exit_code = 1;
	if (error_stream) {
		fprintf(error_stream, "%s[-]%sErrors from the OpenSSL error queue:\n", red, green);
		ERR_print_errors_fp(error_stream);
	}
	ERR_clear_error();
	}
	return exit_code;
}
