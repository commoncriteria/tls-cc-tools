#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "tcp_sock.h"
#include "printer.h"
#include "ssl.h"
#include "common.h"
#include "tests.h"
#include "cert_gen.h"

#define CIPHER_SUITES_COUNT     20
#define CIPHER_SUITES_CRITICAL  1
#define WEAK_CIPHER_COUNT       8
#define EC_CURVE_COUNT          3

#define RUN_FCS_TLSC_EXT_1_1_TESTS
#define RUN_FCS_TLSC_EXT_1_2_TESTS
#define RUN_FCS_TLSC_EXT_1_3_TESTS
#define RUN_FCS_TLSC_EXT_1_4_TESTS
#define RUN_FCS_TLSC_EXT_1_5_TESTS
#define RUN_FCS_TLSC_EXT_1_6_TESTS

#define RUN_FIA_X509_EXT_1_1_TESTS
#define RUN_FIA_X509_EXT_1_2_TESTS



#ifdef RUN_FCS_TLSC_EXT_1_1_TESTS

#define RUN_FCS_TLSC_EXT_1_1_TEST_1
#define RUN_FCS_TLSC_EXT_1_1_TEST_2
#define RUN_FCS_TLSC_EXT_1_1_TEST_3
#define RUN_FCS_TLSC_EXT_1_1_TEST_4
#define RUN_FCS_TLSC_EXT_1_1_TEST_5__1
#define RUN_FCS_TLSC_EXT_1_1_TEST_5__2
#define RUN_FCS_TLSC_EXT_1_1_TEST_5__3
#define RUN_FCS_TLSC_EXT_1_1_TEST_5__4
#define RUN_FCS_TLSC_EXT_1_1_TEST_5__5
#define RUN_FCS_TLSC_EXT_1_1_TEST_5__6

#endif


#ifdef RUN_FCS_TLSC_EXT_1_2_TESTS

#define RUN_FCS_TLSC_EXT_1_2_TEST_1
#define RUN_FCS_TLSC_EXT_1_2_TEST_2
#define RUN_FCS_TLSC_EXT_1_2_TEST_3
#define RUN_FCS_TLSC_EXT_1_2_TEST_4
#define RUN_FCS_TLSC_EXT_1_2_TEST_5__1
#define RUN_FCS_TLSC_EXT_1_2_TEST_5__2
#define RUN_FCS_TLSC_EXT_1_2_TEST_5__3

#endif


#ifdef RUN_FCS_TLSC_EXT_1_3_TESTS

#define RUN_FCS_TLSC_EXT_1_3_TEST_1

#endif

#ifdef RUN_FCS_TLSC_EXT_1_4_TESTS

#define RUN_FCS_TLSC_EXT_1_4_TEST_1

#endif

#ifdef RUN_FCS_TLSC_EXT_1_5_TESTS

#define RUN_FCS_TLSC_EXT_1_5_TEST_1

#endif

#ifdef RUN_FCS_TLSC_EXT_1_6_TESTS

#define RUN_FCS_TLSC_EXT_1_6_TEST_1

#endif


#ifdef RUN_FIA_X509_EXT_1_1_TESTS

#define RUN_FIA_X509_EXT_1_1_TEST_1
#define RUN_FIA_X509_EXT_1_1_TEST_2
#define RUN_FIA_X509_EXT_1_1_TEST_3
#define RUN_FIA_X509_EXT_1_1_TEST_4
#define RUN_FIA_X509_EXT_1_1_TEST_5
#define RUN_FIA_X509_EXT_1_1_TEST_6
#define RUN_FIA_X509_EXT_1_1_TEST_7

#endif

#ifdef RUN_FIA_X509_EXT_1_2_TESTS

#define RUN_FIA_X509_EXT_1_2_TEST_1
#define RUN_FIA_X509_EXT_1_2_TEST_2
#define RUN_FIA_X509_EXT_1_2_TEST_3

#endif

const char* port = "443";
const char* dh_param_file = "dhparams.pem";
const char* root_ca_file = "rsa_root_ca.pem";
const char* root_ca_pk_file = 0;
char* root_ca_pk_pass = 0;
int gen_ca = 1;
int proto = AF_UNSPEC;

void print_help(int argc, char** argv)
{
    fprintf(stderr, "Usage: %s [-C ca_file] [-c ca_file] [-h] [-K pk_file] [-d dh_params] [-p port] [-r proto]\n", argv[0]);
    fprintf(stderr, "  -C ca_file     Use existing certificate authority file in PEM format. Requires use of -K to specify private key.\n");
    fprintf(stderr, "  -c ca_file     Automatically generate certificate authority and save as %s.\n", root_ca_file);
    fprintf(stderr, "  -d dh_params   DH parameters. Default is dhparams.pem\n");
    fprintf(stderr, "  -h             This help message\n");
    fprintf(stderr, "  -K pk_file     CA private key in PEM format. Must be used with -C.\n");
    fprintf(stderr, "  -P pk_pass     CA private key password.\n");
    fprintf(stderr, "  -p port        Listen on user specified port. Default is 443.\n");
    fprintf(stderr, "  -r proto       Select IPv4 or IPv6. Defaults to automatic selection.\n");
    fprintf(stderr, "                 proto:\n");
    fprintf(stderr, "                   ipv4       IPv4\n");
    fprintf(stderr, "                   ipv6       IPv6\n");
    fprintf(stderr, "                   auto       Automatic selection\n");
}

int parse_cmd_line(int argc, char** argv)
{
    extern char* optarg;
    extern int optind;
    int choice;
    
    while ((choice = getopt(argc, argv, "hC:c:d:K:P:p:r:")) != -1)
    {
        switch (choice)
        {
            case 'C':
                root_ca_file = optarg;
                gen_ca = 0;
                break;
            case 'c':
                root_ca_file = optarg;
                gen_ca = 1;
                break;
            case 'd':
                dh_param_file = optarg;
                break;
            case 'h':
                print_help(argc, argv); 
                return 0;
            case 'K':
                root_ca_pk_file = optarg;
                break;
            case 'P':
                root_ca_pk_pass = optarg;
                break;
            case 'p':
                port = optarg;
                break;
            case 'r':
                if (strcmp(optarg, "ipv4") == 0)
                    proto = AF_INET;
                else if (strcmp(optarg, "ipv6") == 0)
                    proto = AF_INET6;
                else if (strcmp(optarg, "auto") == 0)
                    proto = AF_UNSPEC;
                else
                {
                    proto = AF_UNSPEC;
                    write_out(PRINT_WARNING, "Invalid protocol specifier. Defaulting to auto.");
                }
                break;
        }
    }
    
    return 1;
}

void initialize_cipher_suites(cipher_suite_info* cipher_suites, ec_info* ec_list)
{
    //be sure to update CIPHER_SUITES_COUNT and EC_CURVE_COUNT
    cipher_suites[0].id             = 0x002f;
    cipher_suites[0].openssl_name   = "AES128-SHA";
    //cipher_suites[0].openssl_name   = "NULL-MD5";
    cipher_suites[0].std_name       = "TLS_RSA_WITH_AES_128_CBC_SHA";
    
    cipher_suites[1].id             = 0x0035;
    cipher_suites[1].openssl_name   = "AES256-SHA";
    cipher_suites[1].std_name       = "TLS_RSA_WITH_AES_256_CBC_SHA";
    
    cipher_suites[2].id             = 0x0033;
    cipher_suites[2].openssl_name   = "DHE-RSA-AES128-SHA";
    cipher_suites[2].std_name       = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
    
    cipher_suites[3].id             = 0x0039;
    cipher_suites[3].openssl_name   = "DHE-RSA-AES256-SHA";
    cipher_suites[3].std_name       = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
    
    cipher_suites[4].id             = 0xc013;
    cipher_suites[4].openssl_name   = "ECDHE-RSA-AES128-SHA";
    cipher_suites[4].std_name       = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
    
    cipher_suites[5].id             = 0xc014;
    cipher_suites[5].openssl_name   = "ECDHE-RSA-AES256-SHA";
    cipher_suites[5].std_name       = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
    
    cipher_suites[6].id             = 0xc009;
    cipher_suites[6].openssl_name   = "ECDHE-ECDSA-AES128-SHA";
    cipher_suites[6].std_name       = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
    
    cipher_suites[7].id             = 0xc00a;
    cipher_suites[7].openssl_name   = "ECDHE-ECDSA-AES256-SHA";
    cipher_suites[7].std_name       = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
    
    cipher_suites[8].id             = 0x003c;
    cipher_suites[8].openssl_name   = "AES128-SHA256";
    cipher_suites[8].std_name       = "TLS_RSA_WITH_AES_128_CBC_SHA256";
    
    cipher_suites[9].id             = 0x003d;
    cipher_suites[9].openssl_name   = "AES256-SHA256";
    cipher_suites[9].std_name       = "TLS_RSA_WITH_AES_256_CBC_SHA256";
    
    cipher_suites[10].id            = 0x0067;
    cipher_suites[10].openssl_name  = "DHE-RSA-AES128-SHA256";
    cipher_suites[10].std_name      = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
    
    cipher_suites[11].id            = 0x006b;
    cipher_suites[11].openssl_name  = "DHE-RSA-AES256-SHA256";
    cipher_suites[11].std_name      = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
    
    cipher_suites[12].id            = 0xc023;
    cipher_suites[12].openssl_name  = "ECDHE-ECDSA-AES128-SHA256";
    cipher_suites[12].std_name      = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
    
    cipher_suites[13].id            = 0xc024;
    cipher_suites[13].openssl_name  = "ECDHE-ECDSA-AES256-SHA384";
    cipher_suites[13].std_name      = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
    
    cipher_suites[14].id            = 0xc02b;
    cipher_suites[14].openssl_name  = "ECDHE-ECDSA-AES128-GCM-SHA256";
    cipher_suites[14].std_name      = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    
    cipher_suites[15].id            = 0xc02c;
    cipher_suites[15].openssl_name  = "ECDHE-ECDSA-AES256-GCM-SHA384";
    cipher_suites[15].std_name      = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    
    cipher_suites[16].id            = 0xc027;
    cipher_suites[16].openssl_name  = "ECDHE-RSA-AES128-SHA256";
    cipher_suites[16].std_name      = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";

    cipher_suites[17].id            = 0xc02f;
    cipher_suites[17].openssl_name  = "ECDHE-RSA-AES128-GCM-SHA256";
    cipher_suites[17].std_name      = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    
    cipher_suites[18].id            = 0xc028;
    cipher_suites[18].openssl_name  = "ECDHE-RSA-AES256-SHA384";
    cipher_suites[18].std_name      = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
    
    cipher_suites[19].id            = 0xc030;
    cipher_suites[19].openssl_name  = "ECDHE-RSA-AES256-GCM-SHA384";
    cipher_suites[19].std_name      = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    
    ec_list[0].id                   = 0x0017;
    ec_list[0].curve_name           = "secp256r1";
    
    ec_list[1].id                   = 0x0018;
    ec_list[1].curve_name           = "secp384r1";
    
    ec_list[2].id                   = 0x0019;
    ec_list[2].curve_name           = "secp521r1";
}

void initialize_weak_cipher_suites(cipher_suite_info* cipher_suites)
{
    //be sure to update WEAK_CIPHER_COUNT
    cipher_suites[0].id             = 0x0001;
    cipher_suites[0].openssl_name   = "NULL-MD5";
    cipher_suites[0].std_name       = "TLS_RSA_WITH_NULL_MD5";
    
    cipher_suites[1].id             = 0x0002;
    cipher_suites[1].openssl_name   = "NULL-SHA";
    cipher_suites[1].std_name       = "TLS_RSA_WITH_NULL_SHA";
    
    cipher_suites[2].id             = 0x003b;
    cipher_suites[2].openssl_name   = "NULL-SHA256";
    cipher_suites[2].std_name       = "TLS_RSA_WITH_NULL_SHA256";
    
    cipher_suites[3].id             = 0xc001;
    cipher_suites[3].openssl_name   = "ECDH-ECDSA-NULL-SHA";
    cipher_suites[3].std_name       = "TLS_ECDH_ECDSA_WITH_NULL_SHA";
    
    cipher_suites[4].id             = 0xc00b;
    cipher_suites[4].openssl_name   = "ECDH-RSA-NULL-SHA";
    cipher_suites[4].std_name       = "TLS_ECDH_RSA_WITH_NULL_SHA";
    
    cipher_suites[5].id             = 0xc015;
    cipher_suites[5].openssl_name   = "AECDH-NULL-SHA";
    cipher_suites[5].std_name       = "TLS_ECDH_anon_WITH_NULL_SHA";
    
    cipher_suites[6].id             = 0xc006;
    cipher_suites[6].openssl_name   = "ECDHE-ECDSA-NULL-SHA";
    cipher_suites[6].std_name       = "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
    
    cipher_suites[7].id             = 0xc010;
    cipher_suites[7].openssl_name   = "ECDHE-RSA-NULL-SHA";
    cipher_suites[7].std_name       = "TLS_ECDHE_RSA_WITH_NULL_SHA";
}

void do_FCS_TLSC_EXT_1_1_tests(int ssock, X509* rsa_root_cert, EVP_PKEY* rsa_root_pk, int rsa_bits, const char* ec_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name)
{
    SSL_CTX* ssl_ctx;
    
    X509* rsa_cert;
    X509* ecdsa_cert;
    EVP_PKEY* rsa_priv_key;
    EVP_PKEY* ecdsa_priv_key;
    
    cipher_suite_info cipher_suites[CIPHER_SUITES_COUNT];
    cipher_suite_info weak_ciphers[WEAK_CIPHER_COUNT];
    ec_info accepted_ec[EC_CURVE_COUNT];
    
    
    
    initialize_cipher_suites(cipher_suites, accepted_ec);
    initialize_weak_cipher_suites(weak_ciphers);
    
    write_out(PRINT_INFO, "Generating %d bit RSA certificate...", rsa_bits);
    if (!create_rsa_cert_v3(rsa_bits, country, org_name, org_unit, common_name, rand(), 1, &rsa_cert, &rsa_priv_key))
    {
        write_out(PRINT_ERROR, "Unable to generate RSA certificate!");
        return;
    }
    
    if (alt_name)
        if (!add_x509_extension(rsa_cert, NID_subject_alt_name, alt_name))
            write_out(PRINT_WARNING, "Unable to add alt extension to certificate!");
    
    if (!add_x509_extension(rsa_cert, NID_ext_key_usage, "serverAuth"))
        write_out(PRINT_WARNING, "Unable to add alt extension to certificate!");
    
    write_out(PRINT_INFO, "Signing RSA cert...");
    write_raise_level();
    if (!sign_x509_cert(rsa_root_cert, rsa_root_pk, rsa_cert, EVP_sha256()))
    {
        write_out(PRINT_ERROR, "Unable to sign RSA certificate!");
        return;
    }
    write_lower_level();
    
    write_out(PRINT_INFO, "Generating ECDSA certificate using curve %s...", ec_curve);
    if (!create_ecdsa_cert_v3(ec_curve, country, org_name, org_unit, common_name, rand(), 1, &ecdsa_cert, &ecdsa_priv_key))
    {
        write_out(PRINT_ERROR, "Unable to generate ECDSA certificate!");
        return;
    }
    
    if (alt_name)
        if (!add_x509_extension(ecdsa_cert, NID_subject_alt_name, alt_name))
            write_out(PRINT_WARNING, "Unable to add alt extension to certificate!");
    
    if (!add_x509_extension(ecdsa_cert, NID_ext_key_usage, "serverAuth"))
        write_out(PRINT_WARNING, "Unable to add serverAuth to certificate!");
    
    write_out(PRINT_INFO, "Signing ECDSA cert...");
    write_raise_level();
    if (!sign_x509_cert(rsa_root_cert, rsa_root_pk, ecdsa_cert, EVP_sha256()))
    {
        write_out(PRINT_ERROR, "Unable to sign ECDSA certificate!");
        return;
    }
    write_lower_level();
    
    //ssl_ctx = init_ssl_server_ctx(TLSv1_2_method(), "cert.pem", "privkey.pem", "dhparams.pem", "secp384r1", "ecdsa_cert.pem", "ecdsa_privkey.pem", 0);
    ssl_ctx = init_ssl_server_ctx(TLSv1_2_method(), rsa_cert, rsa_priv_key, dh_param_file, TEST_EC_CURVE, ecdsa_cert, ecdsa_priv_key, rsa_root_cert);
    
    if (!ssl_ctx)
    {
        write_out(PRINT_ERROR, "Error creating SSL context.");

        return;
    }
    
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.1 Tests.");
    write_raise_level();

#ifdef RUN_FCS_TLSC_EXT_1_1_TEST_1
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.1 Test 1.");
    if (FCS_TLSC_EXT_1_1_TEST_1(ssock, ssl_ctx, cipher_suites, CIPHER_SUITES_COUNT, CIPHER_SUITES_CRITICAL, accepted_ec, EC_CURVE_COUNT))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.1 Test 1");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.1 Test 1");
#endif
#ifdef RUN_FCS_TLSC_EXT_1_1_TEST_2
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.1 Test 2.");
    if (FCS_TLSC_EXT_1_1_TEST_2(ssock, ssl_ctx, rsa_cert, rsa_priv_key, rsa_bits, EVP_sha256(), DEFAULT_CIPHER))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.1 Test 2");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.1 Test 2");
#endif
#ifdef RUN_FCS_TLSC_EXT_1_1_TEST_3
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.1 Test 3.");
    if (FCS_TLSC_EXT_1_1_TEST_3_4(ssock, ssl_ctx, DEFAULT_EC_CIPHER, 0x002f))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.1 Test 3");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.1 Test 3");
#endif
#ifdef RUN_FCS_TLSC_EXT_1_1_TEST_4
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.1 Test 4.");
    //if (FCS_TLSC_EXT_1_1_TEST_4(ssock, ssl_ctx))
    if (FCS_TLSC_EXT_1_1_TEST_3_4(ssock, ssl_ctx, DEFAULT_CIPHER, 0x0000))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.1 Test 4");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.1 Test 4");
#endif
#ifdef RUN_FCS_TLSC_EXT_1_1_TEST_5__1
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.1 Test 5.1.");
    if (FCS_TLSC_EXT_1_1_TEST_5__1(ssock, ssl_ctx, DEFAULT_CIPHER))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.1 Test 5.1");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.1 Test 5.1");
#endif
#ifdef RUN_FCS_TLSC_EXT_1_1_TEST_5__2
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.1 Test 5.2.");
    if (FCS_TLSC_EXT_1_1_TEST_5__2(ssock, ssl_ctx, DEFAULT_CIPHER))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.1 Test 5.2");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.1 Test 5.2");
#endif
#ifdef RUN_FCS_TLSC_EXT_1_1_TEST_5__3
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.1 Test 5.3.");
    if (FCS_TLSC_EXT_1_1_TEST_5__3(ssock, ssl_ctx, WEAK_CIPHER_COUNT, weak_ciphers))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.1 Test 5.3");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.1 Test 5.3");
#endif
#ifdef RUN_FCS_TLSC_EXT_1_1_TEST_5__4
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.1 Test 5.4.");
    if (FCS_TLSC_EXT_1_1_TEST_5__4(ssock, ssl_ctx, DEFAULT_DH_CIPHER))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.1 Test 5.4");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.1 Test 5.4");
#endif
    
#ifdef RUN_FCS_TLSC_EXT_1_1_TEST_5__5
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.1 Test 5.5.");
    if (FCS_TLSC_EXT_1_1_TEST_5__5(ssock, ssl_ctx, DEFAULT_CIPHER))
    //if (FCS_TLSC_EXT_1_1_TEST_5__5(ssock, ssl_ctx, "NULL-MD5"))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.1 Test 5.5");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.1 Test 5.5");
#endif
    
#ifdef RUN_FCS_TLSC_EXT_1_1_TEST_5__6
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.1 Test 5.6.");
    if (FCS_TLSC_EXT_1_1_TEST_5__6(ssock, ssl_ctx, DEFAULT_CIPHER))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.1 Test 5.6");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.1 Test 5.6");
#endif
    
    SSL_CTX_free(ssl_ctx);
    
    write_lower_level();
}

void do_FCS_TLSC_EXT_1_2_tests(int ssock, X509* rsa_root_cert, EVP_PKEY* rsa_root_pk, int rsa_bits, const char* ec_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int depth)
{
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.2 Tests.");
    write_raise_level();
#ifdef RUN_FCS_TLSC_EXT_1_2_TEST_1
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.2 Test 1.");
    if (FCS_TLSC_EXT_1_2_TEST_1(ssock, DEFAULT_CIPHER, depth, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.2 Test 1");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.2 Test 1");
#endif
    
#ifdef RUN_FCS_TLSC_EXT_1_2_TEST_2
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.2 Test 2.");
    if (FCS_TLSC_EXT_1_2_TEST_2(ssock, DEFAULT_CIPHER, depth, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.2 Test 2");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.2 Test 2");
#endif
    
#ifdef RUN_FCS_TLSC_EXT_1_2_TEST_3
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.2 Test 3.");
    if (FCS_TLSC_EXT_1_2_TEST_3(ssock, DEFAULT_CIPHER, depth, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.2 Test 3");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.2 Test 3");
#endif
    
    
#ifdef RUN_FCS_TLSC_EXT_1_2_TEST_4
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.2 Test 4.");
    if (FCS_TLSC_EXT_1_2_TEST_4(ssock, DEFAULT_CIPHER, depth, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.2 Test 4");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.2 Test 4");
#endif
    
#ifdef RUN_FCS_TLSC_EXT_1_2_TEST_5__1
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.2 Test 5.1.");
    if (FCS_TLSC_EXT_1_2_TEST_5__1(ssock, DEFAULT_CIPHER, depth, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.2 Test 5.1");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.2 Test 5.1");
#endif
    
#ifdef RUN_FCS_TLSC_EXT_1_2_TEST_5__2
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.2 Test 5.2.");
    
    write_raise_level();
    write_out(PRINT_OUTPUT, "INSTRUCTIONS: Connect with *.%s", common_name);
    write_lower_level();
    
    if (FCS_TLSC_EXT_1_2_TEST_5__2a(ssock, DEFAULT_CIPHER, depth, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.2 Test 5.2a");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.2 Test 5.2a");
    
    write_raise_level();
    write_out(PRINT_OUTPUT, "INSTRUCTIONS: Connect with only %s", common_name);
    write_lower_level();
    
    if (FCS_TLSC_EXT_1_2_TEST_5__2b(ssock, DEFAULT_CIPHER, depth, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.2 Test 5.2b");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.2 Test 5.2b");
    
    write_raise_level();
    write_out(PRINT_OUTPUT, "INSTRUCTIONS: Connect with *.*.%s", common_name);
    write_lower_level();
    
    if (FCS_TLSC_EXT_1_2_TEST_5__2b(ssock, DEFAULT_CIPHER, depth, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.2 Test 5.2a");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.2 Test 5.2a");
#endif
    
#ifdef RUN_FCS_TLSC_EXT_1_2_TEST_5__3
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.2 Test 5.3.");
    
    write_raise_level();
    write_out(PRINT_OUTPUT, "INSTRUCTIONS: Connect with *.%s", PUBLIC_SUFFX);
    write_lower_level();
    
    if (FCS_TLSC_EXT_1_2_TEST_5__3(ssock, DEFAULT_CIPHER, depth, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.2 Test 5.3a");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.2 Test 5.3a");
    
    write_raise_level();
    write_out(PRINT_OUTPUT, "INSTRUCTIONS: Connect with *.*.%s", PUBLIC_SUFFX);
    write_lower_level();
    
    if (FCS_TLSC_EXT_1_2_TEST_5__3(ssock, DEFAULT_CIPHER, depth, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.2 Test 5.3a");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.2 Test 5.3a");
#endif
    write_lower_level();
}
    
void do_FCS_TLSC_EXT_1_3_tests(int ssock, X509* rsa_root_cert, EVP_PKEY* rsa_root_pk, int rsa_bits, const char* ec_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name)
{
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.3 Tests. Also requires FIA_X509_EXT.1.1 to pass.");
    write_raise_level();
    
#ifdef RUN_FCS_TLSC_EXT_1_3_TEST_1
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.3 Test 1.");
    
    write_raise_level();
    write_out(PRINT_OUTPUT, "INSTRUCTIONS: Add root authority and connect");
    write_lower_level();
    
    if (FCS_TLSC_EXT_1_3_TEST_1a(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.3 Test 1a");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.3 Test 1a");
    
    write_raise_level();
    write_out(PRINT_OUTPUT, "INSTRUCTIONS: Remove root authority and connect");
    write_lower_level();
    
    if (FCS_TLSC_EXT_1_3_TEST_1b(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.3 Test 1b");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.3 Test 1b");
#endif
    
    write_lower_level();
}

void do_FCS_TLSC_EXT_1_4_tests(int ssock, X509* rsa_root_cert, EVP_PKEY* rsa_root_pk, int rsa_bits, const char* ec_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name)
{
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.4 Tests. Also requires FIA_X509_EXT.2.1 to pass.");
    write_raise_level();
    
#ifdef RUN_FCS_TLSC_EXT_1_4_TEST_1
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.4 Test 1.");
    if (FCS_TLSC_EXT_1_4_TEST_1(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.4 Test 1");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.4 Test 1");
#endif
    
    write_lower_level();
}

void do_FCS_TLSC_EXT_1_5_tests(int ssock, X509* rsa_root_cert, EVP_PKEY* rsa_root_pk, int rsa_bits, const char* ec_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name)
{
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.5 Tests.");
    write_raise_level();
    
#ifdef RUN_FCS_TLSC_EXT_1_5_TEST_1
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.5 Test 1.");
    if (FCS_TLSC_EXT_1_5_TEST_1(ssock, DEFAULT_EC_CIPHER, rsa_root_cert, rsa_root_pk, ec_curve, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.5 Test 1");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.5 Test 1");
#endif
    
    write_lower_level();
}

void do_FCS_TLSC_EXT_1_6_tests(int ssock, X509* rsa_root_cert, EVP_PKEY* rsa_root_pk, int rsa_bits, const char* ec_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name)
{
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.6 Tests.");
    write_raise_level();
    
#ifdef RUN_FCS_TLSC_EXT_1_6_TEST_1
    write_out(PRINT_OUTPUT, "Starting FCS_TLSC_EXT.1.6 Test 1.");
    if (FCS_TLSC_EXT_1_6_TEST_1(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FCS_TLSC_EXT.1.6 Test 1");
    else
        write_out(PRINT_OUTPUT, "FAIL: FCS_TLSC_EXT.1.6 Test 1");
#endif
    
    write_lower_level();
}

void do_FIA_X509_EXT_1_1_tests(int ssock, X509* rsa_root_cert, EVP_PKEY* rsa_root_pk, int rsa_bits, const char* ec_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name)
{
    write_out(PRINT_OUTPUT, "Starting FIA_X509_EXT.1.1 Tests.");
    write_raise_level();
    
#ifdef RUN_FIA_X509_EXT_1_1_TEST_1
    write_out(PRINT_OUTPUT, "Starting FIA_X509_EXT.1.1 Test 1.");
    if (FIA_X509_EXT_1_1_TEST_1(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FIA_X509_EXT.1.1 Test 1");
    else
        write_out(PRINT_OUTPUT, "FAIL: FIA_X509_EXT.1.1 Test 1");
#endif
    
#ifdef RUN_FIA_X509_EXT_1_1_TEST_2
    write_out(PRINT_OUTPUT, "Starting FIA_X509_EXT.1.1 Test 2.");
    if (FIA_X509_EXT_1_1_TEST_2(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FIA_X509_EXT.1.1 Test 2");
    else
        write_out(PRINT_OUTPUT, "FAIL: FIA_X509_EXT.1.1 Test 2");
#endif
    
#ifdef RUN_FIA_X509_EXT_1_1_TEST_3
    write_out(PRINT_OUTPUT, "Skipping FIA_X509_EXT.1.1 Test 3.");
#endif
    
#ifdef RUN_FIA_X509_EXT_1_1_TEST_4
    write_out(PRINT_OUTPUT, "Skipping FIA_X509_EXT.1.1 Test 4.");
#endif
    
#ifdef RUN_FIA_X509_EXT_1_1_TEST_5
    write_out(PRINT_OUTPUT, "Starting FIA_X509_EXT.1.1 Test 5.");
    if (FIA_X509_EXT_1_1_TEST_5(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FIA_X509_EXT.1.1 Test 5");
    else
        write_out(PRINT_OUTPUT, "FAIL: FIA_X509_EXT.1.1 Test 5");
#endif
    
#ifdef RUN_FIA_X509_EXT_1_1_TEST_6
    write_out(PRINT_OUTPUT, "Starting FIA_X509_EXT.1.1 Test 6.");
    if (FIA_X509_EXT_1_1_TEST_6(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FIA_X509_EXT.1.1 Test 6");
    else
        write_out(PRINT_OUTPUT, "FAIL: FIA_X509_EXT.1.1 Test 6");
#endif
    
#ifdef RUN_FIA_X509_EXT_1_1_TEST_7
    write_out(PRINT_OUTPUT, "Starting FIA_X509_EXT.1.1 Test 7.");
    if (FIA_X509_EXT_1_1_TEST_7(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FIA_X509_EXT.1.1 Test 7");
    else
        write_out(PRINT_OUTPUT, "FAIL: FIA_X509_EXT.1.1 Test 7");
#endif
    
    write_lower_level();
}

void do_FIA_X509_EXT_1_2_tests(int ssock, X509* rsa_root_cert, EVP_PKEY* rsa_root_pk, int rsa_bits, const char* ec_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name)
{
    write_out(PRINT_OUTPUT, "Starting FIA_X509_EXT.1.2 Tests.");
    write_raise_level();
    
#ifdef RUN_FIA_X509_EXT_1_2_TEST_1
    write_out(PRINT_OUTPUT, "Starting FIA_X509_EXT.1.2 Test 1.");
    if (FIA_X509_EXT_1_2_TEST_1(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FIA_X509_EXT.1.2 Test 1");
    else
        write_out(PRINT_OUTPUT, "FAIL: FIA_X509_EXT.1.2 Test 1");
#endif
    
#ifdef RUN_FIA_X509_EXT_1_2_TEST_2
    write_out(PRINT_OUTPUT, "Starting FIA_X509_EXT.1.2 Test 2.");
    if (FIA_X509_EXT_1_2_TEST_2(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FIA_X509_EXT.1.2 Test 2");
    else
        write_out(PRINT_OUTPUT, "FAIL: FIA_X509_EXT.1.2 Test 2");
#endif
    
#ifdef RUN_FIA_X509_EXT_1_2_TEST_3
    write_out(PRINT_OUTPUT, "Starting FIA_X509_EXT.1.2 Test 3.");
    if (FIA_X509_EXT_1_2_TEST_3(ssock, DEFAULT_CIPHER, rsa_root_cert, rsa_root_pk, rsa_bits, country, org_name, org_unit, common_name, alt_name, rand(), 1))
        write_out(PRINT_OUTPUT, "PASS: FIA_X509_EXT.1.2 Test 3");
    else
        write_out(PRINT_OUTPUT, "FAIL: FIA_X509_EXT.1.2 Test 3");
#endif
    
    write_lower_level();
}

int main(int argc, char** argv)
{
    int ssock;
    int bits = 2048;
    X509* rsa_cert;
    EVP_PKEY* rsa_priv_key;
    FILE* f;
    
    
    if (!parse_cmd_line(argc, argv))
        return 1;
    
    
    if ((ssock = create_server_sock(0, port, 10, proto, 1)) == -1)
    {
        write_out(PRINT_ERROR, "Unable to establish listener.");
        return 1;
    }
    
    write_out(PRINT_INFO, "Listener established.");
    
    srand(time(0)); //don't care about entropy
    
    init_ssl();
    
    if (gen_ca)
    {
        write_out(PRINT_INFO, "Generating %d bit RSA root CA certificate...", bits);
        if (!generate_rsa_ca(bits, COUNTRY, ORG_NAME, ORG_UNIT, ROOT_CA_NAME, rand(), 1, &rsa_cert, &rsa_priv_key, EVP_sha256()))
        {
            write_out(PRINT_ERROR, "Unable to generate RSA root CA certificate!");
            return 1;
        }
        
        write_out(PRINT_OUTPUT, "Use %s as root CA.", root_ca_file);
        export_cert_to_pem(rsa_cert, root_ca_file, 0);
    }
    else
    {
        if (!root_ca_pk_file)
        {
            write_out(PRINT_ERROR, "No private key specified for root CA!");
            return 1;
        }
        
        write_out(PRINT_INFO, "Using CA certificate %s and private key %s.", root_ca_file, root_ca_pk_file);
        
        if (!(f = fopen(root_ca_file, "r")))
        {
            write_out(PRINT_ERROR, "Unable to open CA file %s!", root_ca_file);
            return 1;
        }
        
        if (!(rsa_cert = PEM_read_X509(f, 0, 0, 0)))
        {
            write_out(PRINT_ERROR, "Unable to parse CA file %s as a PEM!", root_ca_file);
            return 1;
        }
        
        fclose(f);
        
        if (!(f = fopen(root_ca_pk_file, "r")))
        {
            write_out(PRINT_ERROR, "Unable to open CA private key file %s!", root_ca_file);
            return 1;
        }
        
        if (!(rsa_priv_key = PEM_read_PrivateKey(f, 0, 0, root_ca_pk_pass)))
        {
            write_out(PRINT_ERROR, "Unable to parse CA private key file %s as a PEM!", root_ca_file);
            return 1;
        }
        
        fclose(f);
    }
    
    do_FCS_TLSC_EXT_1_1_tests(ssock, rsa_cert, rsa_priv_key, bits, TEST_EC_CURVE, COUNTRY, ORG_NAME, ORG_UNIT, COMMON_NAME, ALT_NAME);
    do_FCS_TLSC_EXT_1_2_tests(ssock, rsa_cert, rsa_priv_key, bits, TEST_EC_CURVE, COUNTRY, ORG_NAME, ORG_UNIT, COMMON_NAME, ALT_NAME, 3);
    do_FCS_TLSC_EXT_1_3_tests(ssock, rsa_cert, rsa_priv_key, bits, TEST_EC_CURVE, COUNTRY, ORG_NAME, ORG_UNIT, COMMON_NAME, ALT_NAME);
    do_FCS_TLSC_EXT_1_4_tests(ssock, rsa_cert, rsa_priv_key, bits, TEST_EC_CURVE, COUNTRY, ORG_NAME, ORG_UNIT, COMMON_NAME, ALT_NAME);
    do_FCS_TLSC_EXT_1_5_tests(ssock, rsa_cert, rsa_priv_key, bits, BAD_EC_CURVE, COUNTRY, ORG_NAME, ORG_UNIT, COMMON_NAME, ALT_NAME);
    do_FCS_TLSC_EXT_1_6_tests(ssock, rsa_cert, rsa_priv_key, bits, TEST_EC_CURVE, COUNTRY, ORG_NAME, ORG_UNIT, COMMON_NAME, ALT_NAME);
    
    do_FIA_X509_EXT_1_1_tests(ssock, rsa_cert, rsa_priv_key, bits, TEST_EC_CURVE, COUNTRY, ORG_NAME, ORG_UNIT, COMMON_NAME, ALT_NAME);
    do_FIA_X509_EXT_1_2_tests(ssock, rsa_cert, rsa_priv_key, bits, TEST_EC_CURVE, COUNTRY, ORG_NAME, ORG_UNIT, COMMON_NAME, ALT_NAME);
    
    close(ssock);
    
    return 0;
}
