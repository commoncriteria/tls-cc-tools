#ifndef __CERT_GEN_H
#define __CERT_GEN_H

#include <openssl/x509v3.h>
#include <openssl/evp.h>

#define SET_CA_NONE     0
#define SET_CA_FALSE    1
#define SET_CA_TRUE     2

int export_pk_to_pem(EVP_PKEY* priv_key, const char* file, int append);
int export_cert_to_pem(X509* cert, const char* file, int append);
int export_key_pair_to_pkcs12(X509* cert, EVP_PKEY* pk, const char* file, char* password, char* name);
int add_x509_extension(X509* cert, int nid, const char* value);

int create_rsa_cert_v3(int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int days_valid, X509** out_cert, EVP_PKEY** out_private_key);
int create_rsa_cert_v3_ex(int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int sec_start, int sec_end, X509** out_cert, EVP_PKEY** out_private_key);
int create_ecdsa_cert_v3(const char* ecdh_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int days_valid, X509** out_cert, EVP_PKEY** out_private_key);
int create_ecdsa_cert_v3_ex(const char* ecdh_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int sec_start, int sec_end, X509** out_cert, EVP_PKEY** out_private_key);
int generate_rsa_ca(int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int days_valid, X509** out_cert, EVP_PKEY** out_private_key, const EVP_MD* hash);
int sign_x509_cert(X509* issuer, EVP_PKEY* issuer_private_key, X509* cert, const EVP_MD* hash);

int build_rsa_x509_chain_ex(int depth, X509** cert_stack, EVP_PKEY** pk_stack, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid, int set_ca, int set_server_auth);
int build_rsa_x509_chain(int depth, X509** cert_stack, EVP_PKEY** pk_stack, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid);

int generate_rsa_client_cert(int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int days_valid, X509* ca_cert, EVP_PKEY* ca_private_key, X509** out_cert, EVP_PKEY** out_private_key, const EVP_MD* hash);

#endif