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

void print_logo()
{
	char *logo = 
"███████ ███████ ██████  ██    ██ ███████ ██████  \n"
"██      ██      ██   ██ ██    ██ ██      ██   ██ \n"
"███████ █████   ██████  ██    ██ █████   ██████  \n"
"     ██ ██      ██   ██  ██  ██  ██      ██   ██ \n"
"███████ ███████ ██   ██   ████   ███████ ██   ██ \n";

	puts(logo);
}

void print_help()
{
	char *help = 
"./lab_4_server <port number> <key pair file.pem> <certificate file.pem>\n"
"example: ./lab_4_server 1234 server_keypair.pem server_cert.pem\n";
	puts(help);
}

int run_tls_server(const char* port, const char* server_keypair_fname, const char* server_cert_chain_fname, FILE* error_stream);
int handle_accepted_connection(BIO* ssl_bio, FILE* error_stream);

int main(int argc, char** argv) 
{
	int exit_code = 0;
	
	if(argc != 4)
	{
		printf("%s[-]%sInvalid number of arguments !\n", red, green);
		print_help();
		exit(1);
	}

	print_logo();

	int err = run_tls_server(argv[1], argv[2], argv[3], stderr);
	
	if (err) {
		fprintf(stderr, "TLS communication failed\n");
		goto failure;
	}
	fprintf(stderr, "TLS communication succeeded\n");

	goto cleanup;

	failure:
		exit_code = 1;
	cleanup:
		return exit_code;
}

int run_tls_server(const char* port, const char *server_keypair_fname, const char* server_cert_chain_fname, FILE *error_stream) 
{
	int exit_code = 0;
	int err = 1;
	SSL_CTX* ctx = NULL;
	BIO* accept_bio = NULL;
	
	ERR_clear_error();
	ctx = SSL_CTX_new(TLS_server_method());
	assert(ctx);
	err = SSL_CTX_use_PrivateKey_file(ctx, server_keypair_fname, 	SSL_FILETYPE_PEM);
	
	if (err <= 0) {
		if (error_stream)
			fprintf(error_stream, "%s[-]%sCould not load server keypair from file %s\n", red, green, server_keypair_fname);
			goto failure;
	}

	err = SSL_CTX_use_certificate_chain_file(ctx, server_cert_chain_fname);

	if (err <= 0) {
		if (error_stream)
			fprintf(error_stream, "%s[-]%sCould not load server certificate chain from file %s\n", red, green, server_cert_chain_fname);
			goto failure;
	}

	err = SSL_CTX_check_private_key(ctx);
	
	if (err <= 0) {
		if (error_stream)
			fprintf(error_stream, "%s[-]%sServer keypair does not match server certificate\n", red, green);
			goto failure;
	}

	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	accept_bio = BIO_new_accept(port);
	assert(accept_bio);
	err = BIO_do_accept(accept_bio);

	if (err <= 0) {
		if (error_stream)
			fprintf(error_stream, "%s[-]%sCould not bind to port %s and start listening for incoming TCP connections\n", red, green, port);
			goto failure;
	}

	if (ERR_peek_error()) {
		if (error_stream)
			fprintf(error_stream, "%s[-]%sUnexpected error during TLS server setup\n", red, green);
			goto failure;
	}

	while (1) {
		printf("%s[*]%s Keep listening...\n", blue, green);
		
		err = BIO_do_accept(accept_bio);
		if (err <= 0) {
			if (error_stream)
				fprintf(error_stream, "%s[-]%sError when trying to accept connection\n", red, green);

			if (ERR_peek_error()) {
				if (error_stream) {
					fprintf(error_stream, "%s[-]%sErrors from the OpenSSL error queue:\n", red, green);
					ERR_print_errors_fp(error_stream);
				}

				ERR_clear_error();
			}
			continue;
			}

		BIO* socket_bio = BIO_pop(accept_bio);
		assert(socket_bio);
		BIO* ssl_bio = BIO_new_ssl(ctx, 0);
		assert(ssl_bio);
		BIO_push(ssl_bio, socket_bio);
		handle_accepted_connection(ssl_bio, error_stream);
	} 

	goto cleanup;
	failure:
		exit_code = 1;
	cleanup:
		if (accept_bio)
			BIO_free_all(accept_bio);
		if (ctx)
			SSL_CTX_free(ctx);
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

int handle_accepted_connection(BIO* ssl_bio, FILE* error_stream)
{
	int exit_code = 0;
	int err = 1;
	SSL* ssl = NULL;
	char in_buf[5];
	assert(in_buf);
	ERR_clear_error();
	err = BIO_do_handshake(ssl_bio);
	if (err <= 0) {
		if (error_stream)
			fprintf(error_stream, "%s[-]%sTLS handshaking error\n", red, green);
			goto failure;
	}

	err = BIO_get_ssl(ssl_bio, &ssl);
	assert(err == 1);
	assert(ssl);
	printf("%s[*]%sReceiving from the client...\n", blue, green);

	BIO_get_line(ssl_bio, in_buf, 5);;
	
	int nums[4];
	char res[5];
	for(int i = 0; i < 4; ++i)
		nums[i] = in_buf[i] - '0';
	for(int i = 0; i < 4; ++i)
	{
		if((nums[i] % 2) == 0)
			res[i] = nums[i] + '0';
		else
			res[i] = 32;
	}
	res[5] = '\0';
	
	int response_length = strlen(res);
	
	printf("%s[*]%sSending to the client: %s\n", blue, green, res);

	int nbytes_written = BIO_write(ssl_bio, res, response_length);

	if (nbytes_written != response_length) {
		if (error_stream)
			fprintf(error_stream, "%s[-]%sCould not send data all to the client\n", red, green);
	goto failure;
	}

	printf("%s[+] Sending to the client finished\n", green);
	BIO_ssl_shutdown(ssl_bio);
	goto cleanup;
	failure:
		exit_code = 1;
	cleanup:
		if (ssl_bio)
			BIO_free_all(ssl_bio);
			
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
