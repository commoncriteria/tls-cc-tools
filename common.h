#ifndef __COMMON_H
#define __COMMON_H

#define BUFFER_SIZE (1024 * 4)

#define TEST_MSG        "Hello, world!"
#define TEST_MSG_LEN    13

//because we know the cipher suites beforehand, we can statically define things
#define CIPHER_SUITE_INFO_MAX_LEN 128
#define CERT_NAME_SIZE   255

#define BAD_EC_CURVE            "prime192v1"
#define TEST_EC_CURVE           "prime256v1"

#define DEFAULT_CIPHER          "AES128-SHA"
//#define DEFAULT_CIPHER          "NULL-MD5"
#define DEFAULT_EC_CIPHER       "ECDHE-ECDSA-AES128-SHA"
#define DEFAULT_DH_CIPHER       "DHE-RSA-AES128-SHA"

#define COUNTRY                 "USA"
#define ORG_NAME                "AAA"
#define ORG_UNIT                "IAD"
#define COMMON_NAME             "awesome.com"
#define ROOT_CA_NAME            "MY FAKE ROOT"
//#define ALT_NAME                "IP:127.0.0.1"
#define ALT_NAME                "DNS:awesome.com"

typedef struct
{
    unsigned short id;
    const char* openssl_name;
    const char* std_name;
} cipher_suite_info;

typedef struct
{
    unsigned short id;
    const char* curve_name;
} ec_info;

#endif
