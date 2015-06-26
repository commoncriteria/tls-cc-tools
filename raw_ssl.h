#ifndef __RAW_SSL_H
#define __RAW_SSL_H

#define TLS_RECORD_HANDSHAKE 22
#define TLS_CHANGE_CIPHER_SPEC 20
#define TLS_HANDSHAKE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_SERVER_HELLO 2
#define TLS_HANDSHAKE_CERTIFICATE 11
#define TLS_CLIENT_KEY_EXCH 16
#define TLS_SERVER_KEY_EXCH 12
#define TLS_SERVER_CERT_REQUEST 13

#define ELLIPTIC_CURVE_EXT 0x000a


typedef struct __attribute__ ((__packed__))
{
    unsigned char record_type;
    unsigned short version;
    unsigned short length;
} TLS_record;

typedef struct __attribute__ ((__packed__))
{
    unsigned char handshake_type;
    unsigned char length[3];
    unsigned short version;
    //time + random = TLS random field
    unsigned int time;
    unsigned char random[28];
    unsigned char session_length;
    //var len session id
} TLS_handshake_1;

//there's more, but we don't care about the rest of the TLS handshake

typedef struct __attribute__ ((__packed__))
{
    unsigned char handshake_type;
    unsigned char length[3];
    //more things here
} TLS_handshake_generic;

typedef struct __attribute__ ((__packed__))
{
    unsigned short type;
    unsigned short total_length;
} TLS_extensions;

typedef struct  __attribute__ ((__packed__))
{
    unsigned char ukn1[2];
    unsigned char ukn2[4];
    unsigned char id[3];
    unsigned char type;
    unsigned char str_size;
    unsigned char string[0];
} TLS_rdn_sequence;

typedef struct __attribute__ ((__packed__))
{
    unsigned short length;
    unsigned char ukn1[2];
    TLS_rdn_sequence sequences[0];
} TLS_cert_req_distinguished_str;

typedef struct __attribute__ ((__packed__))
{
    unsigned int length;
} TLS_cert;

typedef struct
{
    unsigned int data_length;
    unsigned int buffer_size;
    unsigned char* buffer;
} buffered_ssl_ctx;

typedef struct
{
    unsigned int length;
    unsigned char* data;
} data_buffer;

unsigned short* ssl_get_cipher_suites(TLS_handshake_1* handshake);
TLS_extensions* ssl_get_extension(unsigned short extension, TLS_handshake_1* handshake);
unsigned char* ssl_cert_req_get_distinguished_names(TLS_handshake_generic* handshake);
char* get_distinguished_string(TLS_rdn_sequence* seq);
unsigned int get_ssl_3_byte_number(unsigned char* bytes);

void buffered_ssl_ctor(buffered_ssl_ctx* ctx);
int buffered_ssl_add_data(buffered_ssl_ctx* ctx, unsigned char* data, unsigned int length);
data_buffer* buffered_ssl_get_record(buffered_ssl_ctx* ctx);
void buffered_ssl_dtor(buffered_ssl_ctx* ctx);

void data_buffer_ctor(data_buffer* db);
int data_buffer_merge(data_buffer* dest, data_buffer* src);
void data_buffer_dtor(data_buffer* db);

#endif