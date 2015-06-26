#ifndef __TESTS_H
#define __TESTS_H

#include <openssl/ssl.h>

#include "common.h"
#include "raw_ssl.h"

#define PUBLIC_SUFFX "com"

typedef struct
{
    buffered_ssl_ctx bssl;
    int is_restricted;
    int cipher_count;
    cipher_suite_info* cipher_list;
    int ec_count;
    ec_info* ec_list;
} handshake_cipher_state;

typedef struct
{
    buffered_ssl_ctx bssl;
    unsigned int success;
    unsigned short new_cipher;
} handshake_cipher_mod;

typedef struct
{
    buffered_ssl_ctx bssl;
    unsigned int success;
} tls_generic_success;

typedef struct
{
    buffered_ssl_ctx bssl;
    int weak_list_count;
    cipher_suite_info* weak_list;
    int success;
} handshake_enum_ciphers;

typedef struct
{
    buffered_ssl_ctx bssl;
    int success;
} handshake_key_exch;

typedef struct
{
    buffered_ssl_ctx bssl;
    int has_changed_cipher_spec;
} tls_change_cipher_spec;

typedef struct
{
    buffered_ssl_ctx bssl;
    unsigned char* modulus;
    unsigned int size;
} handshake_server_cert;


// Establishes a TLS connection with each of the the mandatory/optional cipher suites. It'll report
// if the connection was successful or if it was prematurely terminated.
// req_count is the number of mandatory ciphers. Ensure mandatory ciphers are listed first.
//
// Will also examine the ClientHello for any unsupported cipher suites and fail if any unsupported
// suites are detected.
//
// This function will only succeed if the mandatory cipher suite has a successful connection
// and there are only mandatory/optional cipher suites in the ClientHello message.
int FCS_TLSC_EXT_1_1_TEST_1(int ssock, SSL_CTX* ssl_ctx, cipher_suite_info* cipher_list, int cipher_count, int req_count, ec_info* ec_list, int ec_count);

// Automatically generate a non-server authentication certificate and serve it to the client
// I don't test the part where it requres a valid server authetication field, because that's tested in
// FCS_TLSC_EXT_1_1 Test 1. It seemed kind of redudant.
int FCS_TLSC_EXT_1_1_TEST_2(int ssock, SSL_CTX* ssl_ctx, X509* ca_cert, EVP_PKEY* ca_private_key, int bits, const EVP_MD* hash, const char* cipher_suite);

// Will tell OpenSSL to serve a certificate with the specified cipher_name. However, the mutator on
// outbound data will modify the selected algorithm to be alt_cipher_id.
//
// For Test 3, a EC cipher is selected, but is then changed to a normal cipher. This will make OpenSSL
// send a EC certificate but with a non-EC cipher.
//
// For Test 4, this just enables the ability to select the NULL cipher
//
// Note we don't fix the hash for the finalization messages, because the connection should die
// before the hash of the messages are ever compared. If there are any other handshake messages
// from the client after the server hello, we immediately fail.
int FCS_TLSC_EXT_1_1_TEST_3_4(int ssock, SSL_CTX* ssl_ctx, const char* cipher_name, unsigned short alt_cipher_id);

// Changes the TLS version number in the ServerHello message to FAKE_SSL_VERSION.
// Reports failure if the client decides to continue handshaking instead of terminating the
// connection.
int FCS_TLSC_EXT_1_1_TEST_5__1(int ssock, SSL_CTX* ssl_ctx, const char* cipher_name);

// Changes the server's nonce and checks to see if the connection is successful.
// Reports failure if a TLS tunnel is successfully established.
int FCS_TLSC_EXT_1_1_TEST_5__2(int ssock, SSL_CTX* ssl_ctx, const char* cipher_name);

// Forces OpenSSL to pick a cipher on the weak_list by replacing all the ciphers in the ClientHello
// to be the unsupported cipher. This will cause the Finished handshake to fail, but the handshake
// should terminate before it gets that far. The weak_cipher selected will be one that isn't in
// the ClientHello to force a mismatch. Any further handhsake messagse from the client after the
// ServerHello will cause a failure.
int FCS_TLSC_EXT_1_1_TEST_5__3(int ssock, SSL_CTX* ssl_ctx, int weak_list_count, cipher_suite_info* weak_list);

// Changes the last byte in the ServerKeyExchange message. If the client decides to continue
// to send any handshake message, fail.
int FCS_TLSC_EXT_1_1_TEST_5__4(int ssock, SSL_CTX* ssl_ctx, const char* dh_cipher_name);

// Modifies the 6th byte in the first encrypted handshake message (Server Finished). Fails if
// connection is successful.
int FCS_TLSC_EXT_1_1_TEST_5__5(int ssock, SSL_CTX* ssl_ctx, const char* cipher_name);

// Overrides the next message after ChangeCipherSpec sent by the server with random data. The function fails
// if the connection succeeds.
int FCS_TLSC_EXT_1_1_TEST_5__6(int ssock, SSL_CTX* ssl_ctx, const char* cipher_name);


// Generates a certificate chain that has a non-matching CN an SAN. Fails on successful connection.
int FCS_TLSC_EXT_1_2_TEST_1(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates a non-matching SAN but with a matching CN. Fails on successful connection.
// NOTE: This only generates a bad URI. The other SAN types are not tested.
//       This does NOT match the application PP precisely.
int FCS_TLSC_EXT_1_2_TEST_2(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates a certificate with a matching CN but no SAN. Success on successful connection.
int FCS_TLSC_EXT_1_2_TEST_3(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates a certificate with a non-matching CN but a matching SAN. Success on successful connection.
int FCS_TLSC_EXT_1_2_TEST_4(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// NOTE: The 1.2 Test 5.* only tests CNs which does not match the PP's requirement of testing all
//       supported reference identifiers.

// Generates a certificate with a CN in the format of WILD_START.*.common_name. Fails on successful connection.
int FCS_TLSC_EXT_1_2_TEST_5__1(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates a certificate with a CN in the format of *.common_name. Success on successful connection.
int FCS_TLSC_EXT_1_2_TEST_5__2a(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Same as 2a, except it fails on a successful connection.
int FCS_TLSC_EXT_1_2_TEST_5__2b(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates with a CN of *.PUBLIC_SUFFX. Fails on successful connection.
int FCS_TLSC_EXT_1_2_TEST_5__3(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// NOTE: FCS_TLSC_EXT.1.2 Test 6 and Test 7 are skipped.


// Generates a normal cert chain with 2 intermediate CAs as part of the cert chain. Success if successful connection.
int FCS_TLSC_EXT_1_3_TEST_1a(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Same as 1a, except fail if unsuccessful.
int FCS_TLSC_EXT_1_3_TEST_1b(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates a standard CA chain. When the client connects, it will require client authentication and will
// include the standard CA along with another CA that will be modified in transit as acceptable CAs. Produces
// a correct client CA as the file CLIENT_CERT which can be inserted into the browser. Fails if connection is successful.
int FCS_TLSC_EXT_1_4_TEST_1(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates a ECDSA certificate with the given ec_curve (should be unsupported). Fails on successful connection.
int FCS_TLSC_EXT_1_5_TEST_1(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, const char* ec_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates an RSA cert signed with SHA1. Fails on successful connection.
int FCS_TLSC_EXT_1_6_TEST_1(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);


// Generates a certificate chain and outputs the chain to a file. Requires the chain to be manually imported to the client as the server
// will not send the certificate chain. It will attempt multiple connections and succeed or fail according to the protection profile.
int FIA_X509_EXT_1_1_TEST_1(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates an expired certificate and attempts to serve it to the client. Fails if connection is successful.
int FIA_X509_EXT_1_1_TEST_2(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// TODO: CRL stuff hasn't been implemented. It is skipped for now.

// Generates a certificate and modifies the first byte of the cert before sending it to the client. Fails on successful connection.
int FIA_X509_EXT_1_1_TEST_5(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates a certificate and modifies the last byte of the cert before sending it to the client. Fails on successful connection.
int FIA_X509_EXT_1_1_TEST_6(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates a certificate and modifies the public key before sending it to the client. Rather than parsing everything, this function just
// searches the TLS handshake for the public key, and then modifies it. Fails on successful connection.
int FIA_X509_EXT_1_1_TEST_7(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates a CA without the basicConstraints extension. Fails on successful connection.
int FIA_X509_EXT_1_2_TEST_1(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates a CA with the basicConstraints CA flag set to false. Fails on successful connection.
int FIA_X509_EXT_1_2_TEST_2(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

// Generates a CA with the basicConstraints CA flag set to true. Success on successful connection.
int FIA_X509_EXT_1_2_TEST_3(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

#endif