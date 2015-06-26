#include "raw_ssl.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "printer.h"

#define EXPAND_INTERVAL 1024

unsigned short* ssl_get_cipher_suites(TLS_handshake_1* handshake)
{
    return (unsigned short*)(((unsigned char*)(handshake + 1)) + handshake->session_length);
}

TLS_extensions* ssl_get_extension(unsigned short extension, TLS_handshake_1* handshake)
{
    unsigned short* cipher_suite_len = ssl_get_cipher_suites(handshake);
    unsigned char* compression_len = (((unsigned char*)(cipher_suite_len + 1)) + ntohs(*cipher_suite_len));
    unsigned short* extension_len = (unsigned short*)(compression_len + *compression_len + 1);
    TLS_extensions* extension_data = 0;
    int i;
    int length = 0;
    
    extension_data = (TLS_extensions*)(extension_len + 1);
    
    for (i = 0; i < ntohs(*extension_len); i += length)
    {
        if (ntohs(extension_data->type) != extension)
        {
            length = sizeof(TLS_extensions) + ntohs(extension_data->total_length);
            extension_data = (TLS_extensions*)(((unsigned char*)extension_data) + length);
        }
        else
            return extension_data;
    }
    
    return 0;
}

unsigned char* ssl_cert_req_get_distinguished_names(TLS_handshake_generic* handshake)
{
    unsigned char* cert_type_count = (unsigned char*)(handshake + 1);
    unsigned short* sig_hash_algos = (unsigned short*)(cert_type_count + *cert_type_count + 1);
    unsigned short* distinguished_len = (unsigned short*)(((unsigned char*)(sig_hash_algos + 1)) + ntohs(*sig_hash_algos));
    
    return (unsigned char*)distinguished_len;
}

//free returned memory
char* get_distinguished_string(TLS_rdn_sequence* seq)
{
    char* str;
    
    if (seq->type != 0x13)
        return 0;
    
    if (!(str = malloc(seq->str_size + 1)))
        return 0;
    
    memcpy(str, seq->string, seq->str_size);
    str[seq->str_size] = 0;
    
    return str;
}

unsigned int get_ssl_3_byte_number(unsigned char* bytes)
{
   return ((bytes[0] << 16) | (bytes[1] << 8) | (bytes[2] << 0)) & 0x00ffffff;
}

int buffered_ssl_expand_buffer(buffered_ssl_ctx* ctx, int size)
{
    unsigned int rem;
    unsigned char* new_buffer;
    
    if (size <= ctx->buffer_size)
        return 1;
    
    //round size up to the nearest 1024
    rem = size % EXPAND_INTERVAL;
    if (rem != 0)
        size += (EXPAND_INTERVAL - rem); 
    
    new_buffer = (unsigned char*)malloc(size);
    if (!new_buffer)
        return 0;
    
    if (ctx->buffer)
    {
        memcpy(new_buffer, ctx->buffer, ctx->data_length);
        free(ctx->buffer);
    }
    
    ctx->buffer = new_buffer;
    ctx->buffer_size = size;
    
    return 1;
}

void buffered_ssl_ctor(buffered_ssl_ctx* ctx)
{
    ctx->data_length = 0;
    ctx->buffer_size = 0;
    ctx->buffer = 0;
}

int buffered_ssl_add_data(buffered_ssl_ctx* ctx, unsigned char* data, unsigned int length)
{
    if (!buffered_ssl_expand_buffer(ctx, ctx->data_length + length))
        return 0;
    
    memcpy(ctx->buffer + ctx->data_length, data, length);
    ctx->data_length += length;
    
    if (ctx->data_length > ctx->buffer_size)
    {
        write_out(PRINT_ERROR, "CRITICAL ERROR: Buffer overflow while buffering TLS data.");
        return 0;
    }
    
    return 1;
}

data_buffer* buffered_ssl_get_record(buffered_ssl_ctx* ctx)
{
    TLS_record* record;
    data_buffer* data;
    unsigned int record_len;
    unsigned int total_size;
    
    if (ctx->data_length < sizeof(TLS_record))
        return 0;
    
    record = (TLS_record*)(ctx->buffer);
    
    record_len = ntohs(record->length);
    total_size = record_len + sizeof(TLS_record); //the size excludes the actual header itself

    if (ctx->data_length < total_size)
        return 0;
    
    data = (data_buffer*)malloc(sizeof(data_buffer));
    data_buffer_ctor(data);
    data->data = (unsigned char*)malloc(total_size);
    data->length = total_size;
    
    memcpy(data->data, ctx->buffer, total_size);
    
    ctx->data_length -= total_size;
    memmove(ctx->buffer, ctx->buffer + total_size, ctx->data_length);
    
    return data;
}

void buffered_ssl_dtor(buffered_ssl_ctx* ctx)
{
    if (ctx->buffer)
        free(ctx->buffer);
    
    ctx->buffer = 0;
    ctx->data_length = 0;
    ctx->buffer_size = 0;
}

void data_buffer_ctor(data_buffer* db)
{
    db->length = 0;
    db->data = 0;
}

int data_buffer_merge(data_buffer* dest, data_buffer* src)
{
    unsigned char* tmp_buf;
    unsigned int total_len;
    
    total_len = dest->length + src->length;
    if (!(tmp_buf = (unsigned char*)malloc(total_len)))
        return 0;
    
    if (dest->data)
    {
        memcpy(tmp_buf, dest->data, dest->length);
        free(dest->data);
    }
    
    if (src->data)
        memcpy(tmp_buf + dest->length, src->data, src->length);
    
    dest->data = tmp_buf;
    dest->length = total_len;
    
    return 1;
}

void data_buffer_dtor(data_buffer* db)
{
    if (db->data)
        free(db->data);
    db->length = 0;
}

