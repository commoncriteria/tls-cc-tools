#ifndef __SSL_H
#define __SSL_H

#include <openssl/ssl.h>

#define RECV_WAIT_ERROR -1
#define RECV_TIMEOUT    -2

#define HANDSHAKE_UNSUCCESSFUL  0
#define HANDSHAKE_SUCCESSFUL    1
#define HANDSHAKE_BAD_DIGEST    2 //successful except bad final digest

typedef unsigned char* (*MUTATOR)(void*, unsigned char*, int, int*);

void init_ssl();

SSL* init_ssl_with_cipher(SSL_CTX* ssl_ctx, const char* cipher_name);

SSL_CTX* init_ssl_server_ctx(const SSL_METHOD* method, X509* server_cert, EVP_PKEY* server_priv_key, const char* dh_params, const char* ecdh_curve, X509* ecdsa_cert, EVP_PKEY* ecdsa_privkey, X509* root_cert);

int SSL_CTX_build_cert_chain(SSL_CTX* ssl_ctx, X509** certs, int count);

void print_ssl_error_stack(int level);

int send_bio_data(int sockfd, BIO* wbio, MUTATOR mutate, void* state);

int put_bio_data(int sockfd, BIO* rbio, MUTATOR mutate, void* state);

int recv_wait(int sockfd, BIO* rbio, long sec, long us, MUTATOR mutate, void* state);

int do_handshake(int sockfd, SSL* ssl, BIO* rbio, BIO* wbio, MUTATOR in_mut, void* in_state, MUTATOR out_mut, void* out_state);

void shutdown_ssl(SSL* ssl, int sockfd, BIO* rbio, BIO* wbio);

int get_ssl_record(SSL* ssl, int sockfd, BIO* rbio, unsigned char* buf, unsigned int len);

int send_ssl_record(SSL* ssl, int sockfd, BIO* wbio, unsigned char* buf, unsigned int len);

#endif