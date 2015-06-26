#include "tests.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#include "ssl.h"
#include "printer.h"
#include "tcp_sock.h"
#include "common.h"
#include "raw_ssl.h"
#include "cert_gen.h"

#define FAKE_SSL_VERSION 0x0304
#define BAD_CN_1        "invalidcn.com"
#define BAD_CN_2        "badcn.org"
#define BAD_ALT_1       "URI:invalidalt.com"
#define BAD_ALT_2       "URI:badalt.org"

#define FAKE_COUNTRY    "FAKE COUNTRY"
#define FAKE_ORG        "FAKE ORGANIZATION"
#define FAKE_UNIT       "FAKE ORG UNIT"
#define FAKE_CA         "FAKE CA"
#define FAKE_BITS       2048

#define CLIENT_COUNTRY  "CLIENT COUNTRY"
#define CLIENT_ORG      "CLIENT ORGANIZATION"
#define CLIENT_UNIT     "CLIENT ORG UNIT"
#define CLIENT_NAME     "CLIENT NAME"

#define CLIENT_CERT     "client_cert.pem"
#define CLIENT_CERT_P12 "client_cert.pfx"
#define CLIENT_P12_NAME "Fake PKCS12 Certificate"
#define CLIENT_P12_PWD  ""

#define WILD_START      "foo"

#define INTER_CERT      "ica_"

int get_rsa_mod(X509* cert, unsigned char* buf, unsigned int size)
{
    int algid;
    EVP_PKEY* pub_key = 0;
    RSA* rsa_key = 0;
    //int key_len;
    int ret;
    
    algid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
    
    if (algid != NID_rsaEncryption)
    {
        ret = 0;
        goto error_die;
    }
    
    if (!(pub_key = X509_get_pubkey(cert)))
    {
        ret = 0;
        goto error_die;
    }
    
    if (!(rsa_key = EVP_PKEY_get1_RSA(pub_key)))
    {
        ret = 0;
        goto error_die;
    }
    
    if (size < BN_num_bytes(rsa_key->n))
    {
        ret = 0;
        goto error_die;
    }
    
    ret = BN_bn2bin(rsa_key->n, buf);
    if (ret > size)
    {
        write_out(PRINT_ERROR, "Buffer overflow when extracting RSA modulus!");
        ret = 0;
        goto error_die;
    }
    
error_die:
    if (pub_key)
        EVP_PKEY_free(pub_key);
    
    if (rsa_key)
        RSA_free(rsa_key);
    
    return ret;
}

int is_cipher_in_list(unsigned short cipher, cipher_suite_info* cipher_list, int cipher_count)
{
    int i;
    
    for (i = 0; i < cipher_count; ++i)
        if (cipher == cipher_list[i].id)
            return 1;
    
    return 0;
}

int is_ec_in_list(unsigned short ec, ec_info* ec_list, int ec_count)
{
    int i;
    
    for (i = 0; i < ec_count; ++i)
        if (ec == ec_list[i].id)
            return 1;
    
    return 0;
}

int test_connection(int rsock, SSL* ssl, BIO* rbio, BIO* wbio)
{
    char msg[TEST_MSG_LEN + 1];
    unsigned char buffer[BUFFER_SIZE];
    int count;
    int ret;
    
    ret = recv_wait(rsock, rbio, 1, 0, 0, 0);
    if (ret == RECV_WAIT_ERROR)
        return 0;
    else if (ret > 0)
    {
        count = get_ssl_record(ssl, rsock, rbio, buffer, BUFFER_SIZE); //make sure we process alerts
        if (count > 0) //we got an actual message
            return 1;
        else if (count <= 0) //disconnect or err
            return 0;
    }
    
    if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)
        return 0;
    
    //try sending it data to make sure the connection is still there
    strcpy(msg, TEST_MSG);
    if (send_ssl_record(ssl, rsock, wbio, (unsigned char*)msg, TEST_MSG_LEN))
        return 1;
    return 0;
}

int do_tls_connection(int ssock, SSL* ssl, MUTATOR in_mut, void* in_state, MUTATOR out_mut, void* out_state, int should_connect, int bad_digest_expected)
{
    BIO* bio_ssl_read;
    BIO* bio_ssl_write;
    int rsock;
    int ret = 0;
    
    write_out(PRINT_INFO, "Waiting for app to connect...");
    if ((rsock = accept_connection(ssock, 0)) == -1)
    {
        write_out(PRINT_INFO, "Unable to accept remote connection!");
        return 0;
    }
    
    bio_ssl_read = BIO_new(BIO_s_mem());
    bio_ssl_write = BIO_new(BIO_s_mem());
    
    SSL_set_bio(ssl, bio_ssl_read, bio_ssl_write);
    
    switch (do_handshake(rsock, ssl, bio_ssl_read, bio_ssl_write, in_mut, in_state, out_mut, out_state))
    {
        case HANDSHAKE_SUCCESSFUL:
            if (test_connection(rsock, ssl, bio_ssl_read, bio_ssl_write))
            {
                write_out(PRINT_INFO, "SSL handshake successful!");
                ret = should_connect ? 1 : 0;
            }
            else
            {
                write_out(PRINT_INFO, "Connection terminated after successful SSL handshake.");
                ret = should_connect ? 0 : 1;
            }
            break;
        case HANDSHAKE_BAD_DIGEST:
            if (bad_digest_expected)
            {
                write_out(PRINT_INFO, "Bad digest expected... ignoring.");
                ret = should_connect ? 1 : 0;
            }
            else
            {
                write_out(PRINT_INFO, "SSL handshake failed!");
                ret = should_connect ? 0 : 1;
            }
            break;
        case HANDSHAKE_UNSUCCESSFUL:
            write_out(PRINT_INFO, "SSL handshake failed!");
            ret = should_connect ? 0 : 1;
            break;
    }
    
    shutdown_ssl(ssl, rsock, bio_ssl_read, bio_ssl_write);
    close(rsock);
    
    return ret;
}

unsigned char* get_cipher_suites(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    TLS_handshake_1* handshake;
    TLS_extensions* tls_ext;
    handshake_cipher_state* hstate = (handshake_cipher_state*)state;
    data_buffer* db;
    data_buffer ret;
    unsigned short* cipher_suites;
    unsigned short* supported_ec;
    int cipher_suite_count;
    int ec_count;
    int i;
    
    if (!buffered_ssl_add_data(&hstate->bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);

    while ((db = buffered_ssl_get_record(&hstate->bssl)))
    {
        record = (TLS_record*)db->data;
        
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
        {
            handshake = (TLS_handshake_1*)(record + 1);
            if (handshake->handshake_type == TLS_HANDSHAKE_CLIENT_HELLO) //client hello
            {
                hstate->is_restricted = 1;
                cipher_suites = ssl_get_cipher_suites(handshake);
                cipher_suite_count = ntohs(*cipher_suites) / 2; //this is the size, and each entry is 2 bytes long
                ++cipher_suites;
                
                for (i = 0; i < cipher_suite_count; ++i)
                    if (!is_cipher_in_list(ntohs(cipher_suites[i]), hstate->cipher_list, hstate->cipher_count))
                    {
                        write_out(PRINT_INFO, "Unapproved cipher suite 0x%04hx is enabled.", ntohs(cipher_suites[i]));
                        hstate->is_restricted = 0;
                    }
                
                tls_ext = ssl_get_extension(ELLIPTIC_CURVE_EXT, handshake); //elliptic curves extension
                if (tls_ext)
                {
                    supported_ec = (unsigned short*)(tls_ext + 1);
                    ec_count = ntohs(*supported_ec) / 2;
                    ++supported_ec;
                    
                    for (i = 0; i < ec_count; ++i)
                        if (!is_ec_in_list(ntohs(supported_ec[i]), hstate->ec_list, hstate->ec_count))
                        {
                            write_out(PRINT_INFO, "Unapproved elliptic curve 0x%04hx is enabled.", ntohs(supported_ec[i]));
                            hstate->is_restricted = 0;
                        }
                }
            }
        }
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_chosen_cipher(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    TLS_handshake_1* handshake;
    unsigned short* cipher_suite;
    handshake_cipher_mod* hstate = (handshake_cipher_mod*)state;
    data_buffer* db;
    data_buffer ret;
    
    if (!buffered_ssl_add_data(&hstate->bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(&hstate->bssl)))
    {
        record = (TLS_record*)db->data;
            
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
        {
            handshake = (TLS_handshake_1*)(record + 1);
            
            if (handshake->handshake_type == TLS_HANDSHAKE_SERVER_HELLO) //server hello
            {
                cipher_suite = ssl_get_cipher_suites(handshake);
                write_out(PRINT_INFO, "Changing cipher suite from 0x%04x to 0x%04x.", ntohs(*cipher_suite), hstate->new_cipher);
                *cipher_suite = htons(hstate->new_cipher);
                hstate->success = 1;
            }
        }
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_chosen_cipher_term(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    handshake_cipher_mod* hstate = (handshake_cipher_mod*)state;
    data_buffer* db;
    data_buffer ret;
    
    if (!buffered_ssl_add_data(&hstate->bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(&hstate->bssl)))
    {
        record = (TLS_record*)db->data;
            
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
            hstate->success = 0; //there should be no more handshakes after this is set
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_server_version(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    TLS_handshake_1* handshake;
    tls_generic_success* hstate = (tls_generic_success*)state;
    data_buffer* db;
    data_buffer ret;
    
    if (!buffered_ssl_add_data(&hstate->bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(&hstate->bssl)))
    {
        record = (TLS_record*)db->data;
            
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
        {
            handshake = (TLS_handshake_1*)(record + 1);
            
            if (handshake->handshake_type == TLS_HANDSHAKE_SERVER_HELLO) //server hello
            {
                write_out(PRINT_INFO, "Changing Server Hello version from from 0x%04x to 0x%04x.", ntohs(handshake->version), FAKE_SSL_VERSION);
                handshake->version = htons(FAKE_SSL_VERSION);
                hstate->success = 1;
            }
        }
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_server_version_term(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    tls_generic_success* hstate = (tls_generic_success*)state;
    data_buffer* db;
    data_buffer ret;
    
    if (!buffered_ssl_add_data(&hstate->bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(&hstate->bssl)))
    {
        record = (TLS_record*)db->data;
            
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
            hstate->success = 0; //there should be no more handshakes after this is set
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_server_nonce(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    TLS_handshake_1* handshake;
    buffered_ssl_ctx* bssl = (buffered_ssl_ctx*)state;
    data_buffer* db;
    data_buffer ret;
    
    if (!buffered_ssl_add_data(bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(bssl)))
    {
        record = (TLS_record*)db->data;
            
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
        {
            handshake = (TLS_handshake_1*)(record + 1);
            
            if (handshake->handshake_type == TLS_HANDSHAKE_SERVER_HELLO) //server hello
            {
                write_out(PRINT_INFO, "Changing last byte in Server Hello nonce from from 0x%02x to 0x%02x.", (unsigned int)handshake->random[27], (unsigned int)(handshake->random[27] + 1));
                ++handshake->random[27];
            }
        }
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_client_cert_request(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    TLS_handshake_generic* handshake;
    buffered_ssl_ctx* bssl = (buffered_ssl_ctx*)state;
    unsigned char* data_ptr;
    data_buffer* db;
    data_buffer ret;
    unsigned short dname_length;
    TLS_cert_req_distinguished_str* ptr_to_dstr;
    TLS_rdn_sequence* ptr_to_rdn;
    char* string;
    unsigned int total;
    unsigned int outer_total;
    unsigned int length;
    int good_name;
    int good_org;
    int good_org_unit;
    
    if (!buffered_ssl_add_data(bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(bssl)))
    {
        record = (TLS_record*)db->data;
            
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
        {
            handshake = (TLS_handshake_generic*)(record + 1);
            
            if (handshake->handshake_type == TLS_SERVER_CERT_REQUEST) //cert request
            {
                data_ptr = ssl_cert_req_get_distinguished_names(handshake);
                dname_length = ntohs(*((unsigned short*)data_ptr));
                
                ptr_to_dstr = (TLS_cert_req_distinguished_str*)(data_ptr + 2);
                for (outer_total = 0; outer_total < dname_length;)
                {
                    length = ntohs(ptr_to_dstr->length);
                    if (length >= sizeof(TLS_cert_req_distinguished_str))
                    {
                        good_name = 0;
                        good_org = 0;
                        good_org_unit = 0;
                        
                        ptr_to_rdn = ptr_to_dstr->sequences;
                        for (total = 2; total < length;)
                        {
                            //find our fake cert
                            string = get_distinguished_string(ptr_to_rdn);
                            
                            if (strcmp(FAKE_CA, string) == 0)
                                good_name = 1;
                            else if (strcmp(FAKE_ORG, string) == 0)
                                good_org = 1;
                            else if (strcmp(FAKE_UNIT, string) == 0)
                                good_org_unit = 1;
                            free(string);
                            
                            total += sizeof(TLS_rdn_sequence) + ptr_to_rdn->str_size;
                            ptr_to_rdn = (TLS_rdn_sequence*)(((unsigned char*)ptr_to_rdn) + sizeof(TLS_rdn_sequence) + ptr_to_rdn->str_size);
                        }
                        
                        if (good_name && good_org && good_org_unit)
                        {
                            //modify our fake cert
                            ptr_to_rdn = ptr_to_dstr->sequences;
                            ++ptr_to_rdn->string[0];
                            break;
                        }
                        
                        outer_total += length + 2;
                        ptr_to_dstr = (TLS_cert_req_distinguished_str*)ptr_to_rdn;
                    }
                    else
                        break;
                }
            }
        }
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned short get_weak_cipher(int cipher_count, unsigned short* cipher_list, int weak_list_count, cipher_suite_info* weak_list)
{
    int i;
    int j;
    int found;
    
    for (i = 0; i < weak_list_count; ++i)
    {
        found = 0;
        for (j = 0; j < cipher_count; ++j)
            if (weak_list[i].id == ntohs(cipher_list[j]))
            {
                found = 1;
                break;
            }
        
        if (!found)
            return weak_list[i].id;
    }
    
    return 0x0000;
}

unsigned char* change_client_ciphers(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    TLS_handshake_1* handshake;
    handshake_enum_ciphers* hstate = (handshake_enum_ciphers*)state;
    data_buffer* db;
    data_buffer ret;
    unsigned short* cipher_suites;
    unsigned short cipher;
    int cipher_suite_count;
    int i;
    
    if (!buffered_ssl_add_data(&hstate->bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);

    while ((db = buffered_ssl_get_record(&hstate->bssl)))
    {
        record = (TLS_record*)db->data;
        
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
        {
            hstate->success = 0;
            handshake = (TLS_handshake_1*)(record + 1);
            if (handshake->handshake_type == TLS_HANDSHAKE_CLIENT_HELLO) //client hello
            {
                cipher_suites = ssl_get_cipher_suites(handshake);
                cipher_suite_count = ntohs(*cipher_suites) / 2; //this is the size, and each entry is 2 bytes long
                ++cipher_suites;
                
                //replace all entries with our weak cipher so that the server will be forced to select a weak cipher
                cipher = htons(get_weak_cipher(cipher_suite_count, cipher_suites, hstate->weak_list_count, hstate->weak_list));
                if (!cipher)
                    write_out(PRINT_WARNING, "Unable to select find non-existant cipher. Defaulting to 0x0000.");
                for (i = 0; i < cipher_suite_count; ++i)
                    cipher_suites[i] = cipher;
                hstate->success = 1;
            }
        }
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_server_key_exch(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    TLS_handshake_1* handshake;
    handshake_key_exch* hstate = (handshake_key_exch*)state;
    data_buffer* db;
    data_buffer ret;
    unsigned char* exch;
    
    if (!buffered_ssl_add_data(&hstate->bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(&hstate->bssl)))
    {
        record = (TLS_record*)db->data;
            
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
        {
            handshake = (TLS_handshake_1*)(record + 1);
            
            if (handshake->handshake_type == TLS_SERVER_KEY_EXCH) //server key exchange
            {
                //find last byte
                exch = ((unsigned char*)handshake) + ntohs(record->length) - 1;
                
                //tweak last byte
                write_out(PRINT_INFO, "Changing last byte in server key exchange from from 0x%02x to 0x%02x.", (unsigned int)*exch, (unsigned int)(*exch + 1));
                *exch += 1;
                hstate->success = 1;
            }
        }
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_server_key_exch_term(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    handshake_key_exch* hstate = (handshake_key_exch*)state;
    data_buffer* db;
    data_buffer ret;
    
    if (!buffered_ssl_add_data(&hstate->bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(&hstate->bssl)))
    {
        record = (TLS_record*)db->data;
            
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
            hstate->success = 0;
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_server_fin(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    unsigned char* finished_data;
    tls_change_cipher_spec* hstate = (tls_change_cipher_spec*)state;
    data_buffer* db;
    data_buffer ret;
    
    if (!buffered_ssl_add_data(&hstate->bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(&hstate->bssl)))
    {
        record = (TLS_record*)db->data;
        if (record->record_type == TLS_CHANGE_CIPHER_SPEC)
            hstate->has_changed_cipher_spec = 1;
        else if ((record->record_type == TLS_RECORD_HANDSHAKE) && (hstate->has_changed_cipher_spec))
        {   //this is the TLS Finished message according to the spec
            finished_data = ((unsigned char*)(record + 1)) + 6; //skip past the handshake type, length, and version fields
            
            write_out(PRINT_INFO, "Changing 6th byte in finished message from 0x%02x to 0x%02x.", (unsigned int)*finished_data, (unsigned int)(*finished_data + 1));
            *finished_data += 1;
        }
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_server_scram_next(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    tls_change_cipher_spec* hstate = (tls_change_cipher_spec*)state;
    data_buffer* db;
    data_buffer ret;
    unsigned short record_len;
    int i;
    
    if (!buffered_ssl_add_data(&hstate->bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(&hstate->bssl)))
    {
        record = (TLS_record*)db->data;
        if (hstate->has_changed_cipher_spec)
        {
            write_out(PRINT_INFO, "Overriding record with random data...");
            record_len = ntohs(record->length) + sizeof(TLS_record);
            
            //memset(db->data, 0, record_len);
            for (i = 0; i < record_len; ++i)
                db->data[i] = rand();
            hstate->has_changed_cipher_spec = 0;
        }
        else if (record->record_type == TLS_CHANGE_CIPHER_SPEC)   
            hstate->has_changed_cipher_spec = 1;
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_server_cert_start(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    TLS_handshake_generic* handshake;
    buffered_ssl_ctx* bssl = (buffered_ssl_ctx*)state;
    data_buffer* db;
    data_buffer ret;
    unsigned char* pos;
    unsigned int total_length;
    
    if (!buffered_ssl_add_data(bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(bssl)))
    {
        record = (TLS_record*)db->data;
            
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
        {
            handshake = (TLS_handshake_generic*)(record + 1);
            
            if (handshake->handshake_type == TLS_HANDSHAKE_CERTIFICATE) //certificate
            {
                //the first certificate is the one that's suppose to validate the site
                total_length = get_ssl_3_byte_number(handshake->length);
                if (total_length > 6)
                {
                    pos = (unsigned char*)(handshake + 1);
                    pos += 3; //skip the total cert length
                    write_out(PRINT_INFO, "Changing first byte of the first certificate from 0x%02x to 0x%02x.", pos[3], pos[3] + 1);
                    ++pos[3]; //first byte of data
                }
            }
        }
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_server_cert_end(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    TLS_handshake_generic* handshake;
    buffered_ssl_ctx* bssl = (buffered_ssl_ctx*)state;
    data_buffer* db;
    data_buffer ret;
    unsigned char* pos;
    unsigned int total_length;
    unsigned int cert_length;
    
    if (!buffered_ssl_add_data(bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(bssl)))
    {
        record = (TLS_record*)db->data;
            
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
        {
            handshake = (TLS_handshake_generic*)(record + 1);
            
            if (handshake->handshake_type == TLS_HANDSHAKE_CERTIFICATE) //certificate
            {
                //the first certificate is the one that's suppose to validate the site
                total_length = get_ssl_3_byte_number(handshake->length);
                if (total_length > 6)
                {
                    pos = (unsigned char*)(handshake + 1);
                    pos += 3; //skip the total cert length
                    cert_length = get_ssl_3_byte_number(pos);
                    
                    pos += cert_length + 3 - 1; //go to the last byte
                    write_out(PRINT_INFO, "Changing last byte of the first certificate from 0x%02x to 0x%02x.", *pos, (*pos) + 1);
                    ++(*pos); //last byte of data
                }
            }
        }
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

unsigned char* mod_server_cert_middle(void* state, unsigned char* data, int len, int* out_len)
{
    TLS_record* record;
    TLS_handshake_generic* handshake;
    handshake_server_cert* hstate = (handshake_server_cert*)state;
    data_buffer* db;
    data_buffer ret;
    unsigned char* pos;
    unsigned char* mod_pos;
    unsigned int total_length;
    
    if (!buffered_ssl_add_data(&hstate->bssl, data, len))
    {
        write_out(PRINT_ERROR, "Unable to buffer TLS data. The internal data stream is likely out of sync.");
        return 0;
    }
    
    data_buffer_ctor(&ret);
    ret.data = (unsigned char*)malloc(0);
    
    while ((db = buffered_ssl_get_record(&hstate->bssl)))
    {
        record = (TLS_record*)db->data;
            
        if (record->record_type == TLS_RECORD_HANDSHAKE) //TLS handshake
        {
            handshake = (TLS_handshake_generic*)(record + 1);
            
            if (handshake->handshake_type == TLS_HANDSHAKE_CERTIFICATE) //certificate
            {
                //the first certificate is the one that's suppose to validate the site
                total_length = get_ssl_3_byte_number(handshake->length);
                if (total_length > 6)
                {
                    pos = (unsigned char*)(handshake + 1);
                    mod_pos = (unsigned char*)memmem(pos, total_length, hstate->modulus, hstate->size);
                    
                    if (mod_pos)
                    {
                        write_out(PRINT_INFO, "Changing first byte of certificate modulus from 0x%02x to 0x%02x.", *mod_pos, (*mod_pos) + 1);
                        ++(*mod_pos); //last byte of data
                    }
                }
            }
        }
        
        data_buffer_merge(&ret, db);
        data_buffer_dtor(db);
    }
    
    //we're not going to destruct ret, but we're just going to return the pieces
    *out_len = ret.length;
    return ret.data;
}

int FCS_TLSC_EXT_1_1_TEST_1_extra_ciphers(int ssock, SSL_CTX* ssl_ctx, cipher_suite_info* cipher_list, int cipher_count, int req_count, ec_info* ec_list, int ec_count)
{
    SSL* ssl;
    BIO* bio_ssl_read;
    BIO* bio_ssl_write;
    int rsock;
    handshake_cipher_state hstate;
    
    write_out(PRINT_OUTPUT, "Testing for unapproved cipher suites...");
    write_raise_level();
        
    write_out(PRINT_INFO, "Waiting for app to connect...");
    if ((rsock = accept_connection(ssock, 0)) == -1)
    {
        write_out(PRINT_INFO, "Unable to accept remote connection!");
        write_lower_level();
        return 0;
    }

    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_list[0].openssl_name)))
    {
        write_lower_level();
        return 0;
    }
    
    bio_ssl_read = BIO_new(BIO_s_mem());
    bio_ssl_write = BIO_new(BIO_s_mem());
    
    SSL_set_bio(ssl, bio_ssl_read, bio_ssl_write);
    
    hstate.is_restricted = 0;
    hstate.cipher_count = cipher_count;
    hstate.cipher_list = cipher_list;
    hstate.ec_count = ec_count;
    hstate.ec_list = ec_list;
    buffered_ssl_ctor(&hstate.bssl);
    
    do_handshake(rsock, ssl, bio_ssl_read, bio_ssl_write, &get_cipher_suites, &hstate, 0, 0);
    
    buffered_ssl_dtor(&hstate.bssl);
    
    shutdown_ssl(ssl, rsock, bio_ssl_read, bio_ssl_write);
    
    //SSL_free takes care of this
    //BIO_free_all(bio_ssl_read);
    //BIO_free_all(bio_ssl_write);
    
    close(rsock);
    
    SSL_free(ssl);
    
    write_lower_level();
    
    if (!hstate.is_restricted)
        return 0;
    
    return 1;
}

int FCS_TLSC_EXT_1_1_TEST_1_test_connections(int ssock, SSL_CTX* ssl_ctx, cipher_suite_info* cipher_list, int cipher_count, int req_count)
{
    SSL* ssl;
    int ret = 1;
    int i;
    
    for (i = 0; i < cipher_count; ++i)
    {
        write_out(PRINT_OUTPUT, "Testing %s cipher suite %s.", ((i < req_count) ? "mandatory" : "optional") , cipher_list[i].std_name);
        
        write_raise_level();
        
        if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_list[i].openssl_name)))
        {
            if (i < req_count)
                ret = 0;
        }
        else
            if (!do_tls_connection(ssock, ssl, 0, 0, 0, 0, 1, 0))
            {
                if (i < req_count)
                    ret = 0;
                SSL_free(ssl);
            }
        
        write_lower_level();
    }
    
    return ret;
}

int FCS_TLSC_EXT_1_1_TEST_1(int ssock, SSL_CTX* ssl_ctx, cipher_suite_info* cipher_list, int cipher_count, int req_count, ec_info* ec_list, int ec_count)
{
    write_raise_level();
    
    if (!FCS_TLSC_EXT_1_1_TEST_1_test_connections(ssock, ssl_ctx, cipher_list, cipher_count, req_count))
    {
        write_out(PRINT_OUTPUT, "Failed to establish required TLS connection using a required crypto suite.");
        write_lower_level();
        
        return 0;
    }
    
    if (!FCS_TLSC_EXT_1_1_TEST_1_extra_ciphers(ssock, ssl_ctx, cipher_list, cipher_count, req_count, ec_list, ec_count))
    {
        write_out(PRINT_OUTPUT, "TLS connection supports unapproved crypto suite(s) or elliptic curve.");
        write_lower_level();
        
        return 0;
    }
    
    write_lower_level();
    return 1;
}

int FCS_TLSC_EXT_1_1_TEST_2(int ssock, SSL_CTX* ssl_ctx, X509* ca_cert, EVP_PKEY* ca_private_key, int bits, const EVP_MD* hash, const char* cipher_suite)
{
    SSL* ssl = 0;
    X509* rsa_cert = 0;
    EVP_PKEY* rsa_priv_key = 0;
    int ret = 0;
    
    write_raise_level();
    
    
    write_out(PRINT_INFO, "Generating %d bit RSA non-server authentication cert.", bits);
    if (!create_rsa_cert_v3(bits, "USA", "QQQ", "IAD", "qqq.gov", rand(), 1, &rsa_cert, &rsa_priv_key))
    {
        write_out(PRINT_ERROR, "Unable to generate non-server authentication cert.");
        goto error_die;
    }
    
    if (!add_x509_extension(rsa_cert, NID_subject_alt_name, "IP:127.0.0.1"))
        write_out(PRINT_WARNING, "Unable to add alt extension to certificate!");
    
    if (!sign_x509_cert(ca_cert, ca_private_key, rsa_cert, EVP_sha256()))
    {
        write_out(PRINT_ERROR, "Unable to sign non-server authentication cert.");
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_suite)))
    {
        goto error_die;
    }
    
    if (SSL_use_certificate(ssl, rsa_cert) != 1)
    {
        write_out(PRINT_ERROR, "Unable to load RSA certificate.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
    
    if (SSL_use_PrivateKey(ssl, rsa_priv_key) != 1)
    {
        write_out(PRINT_ERROR, "Unable to load RSA private key.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
    
    if (!SSL_check_private_key(ssl))
    {
        write_out(PRINT_ERROR, "RSA Certificate and private key do not match!");
        
        goto error_die;
    }
    
    ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0);
    
error_die:
    write_lower_level();
    
    if (ssl)
        SSL_free(ssl);
    if (rsa_cert)
        X509_free(rsa_cert);
    if (rsa_priv_key)
        EVP_PKEY_free(rsa_priv_key);
    
    return ret;
}

int FCS_TLSC_EXT_1_1_TEST_3_4(int ssock, SSL_CTX* ssl_ctx, const char* cipher_name, unsigned short alt_cipher_id)
{
    SSL* ssl;
    handshake_cipher_mod hstate;
    int ret;
    
    write_raise_level();
    
    buffered_ssl_ctor(&hstate.bssl);
    hstate.success = 0;
    hstate.new_cipher = alt_cipher_id;
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
        ret = 0;
    else
    {
        do_tls_connection(ssock, ssl, &mod_chosen_cipher_term, &hstate, &mod_chosen_cipher, &hstate, 0, 0);
        ret = hstate.success;
        SSL_free(ssl);
    }
    
    buffered_ssl_dtor(&hstate.bssl);
    
    write_lower_level();
    
    return ret;
}

int FCS_TLSC_EXT_1_1_TEST_5__1(int ssock, SSL_CTX* ssl_ctx, const char* cipher_name)
{
    SSL* ssl;
    tls_generic_success hstate;
    int ret;
    
    write_raise_level();
    
    buffered_ssl_ctor(&hstate.bssl);
    hstate.success = 0;
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
        ret = 0;
    else
    {
        do_tls_connection(ssock, ssl, &mod_server_version_term, &hstate, &mod_server_version, &hstate, 0, 0);
        ret = hstate.success;
        SSL_free(ssl);
    }
    
    buffered_ssl_dtor(&hstate.bssl);
    
    write_lower_level();
    
    return ret;
}

int FCS_TLSC_EXT_1_1_TEST_5__2(int ssock, SSL_CTX* ssl_ctx, const char* cipher_name)
{
    SSL* ssl;
    buffered_ssl_ctx bssl;
    int ret;
    
    
    buffered_ssl_ctor(&bssl);
    
    write_raise_level();
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
        ret = 0;
    else
    {
        ret = do_tls_connection(ssock, ssl, 0, 0, &mod_server_nonce, &bssl, 0, 0);
        SSL_free(ssl);
    }
    
    write_lower_level();
    
    buffered_ssl_dtor(&bssl);
    
    
    return ret;
}

int FCS_TLSC_EXT_1_1_TEST_5__3(int ssock, SSL_CTX* ssl_ctx, int weak_list_count, cipher_suite_info* weak_list)
{
    SSL* ssl;
    int ret;
    handshake_enum_ciphers hstate;
    
    write_raise_level();
    
    buffered_ssl_ctor(&hstate.bssl);
    hstate.weak_list_count = weak_list_count;
    hstate.weak_list = weak_list;
    hstate.success = 0;
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, "ALL:COMPLEMENTOFALL")))
        ret = 0;
    else
    {
        do_tls_connection(ssock, ssl, &change_client_ciphers, &hstate, 0, 0, 0, 0);
        ret = hstate.success;
        
        SSL_free(ssl);
    }
    
    buffered_ssl_dtor(&hstate.bssl);
    
    write_lower_level();
    
    return ret;
}

int FCS_TLSC_EXT_1_1_TEST_5__4(int ssock, SSL_CTX* ssl_ctx, const char* dh_cipher_name)
{
    SSL* ssl;
    int ret;
    handshake_key_exch hstate;
    
    write_raise_level();
    
    buffered_ssl_ctor(&hstate.bssl);
    hstate.success = 0;
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, dh_cipher_name)))
        ret = 0;
    else
    {
        do_tls_connection(ssock, ssl, &mod_server_key_exch_term, &hstate, &mod_server_key_exch, &hstate, 0, 0);
        ret = hstate.success;
        SSL_free(ssl);
    }
    
    buffered_ssl_dtor(&hstate.bssl);
    
    write_lower_level();
    
    return ret;
}

int FCS_TLSC_EXT_1_1_TEST_5__5(int ssock, SSL_CTX* ssl_ctx, const char* cipher_name)
{
    SSL* ssl;
    int ret;
    tls_change_cipher_spec hstate;
    
    write_raise_level();
    
    buffered_ssl_ctor(&hstate.bssl);
    hstate.has_changed_cipher_spec = 0;
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
        ret = 0;
    else
    {
        ret = do_tls_connection(ssock, ssl, 0, 0, &mod_server_fin, &hstate, 0, 0);
        SSL_free(ssl);
    }
    
    buffered_ssl_dtor(&hstate.bssl);
    
    write_lower_level();
    
    return ret;
}

int FCS_TLSC_EXT_1_1_TEST_5__6(int ssock, SSL_CTX* ssl_ctx, const char* cipher_name)
{
    SSL* ssl;
    int ret;
    tls_change_cipher_spec hstate;
    
    
    write_raise_level();
    
    buffered_ssl_ctor(&hstate.bssl);
    hstate.has_changed_cipher_spec = 0;
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
        ret = 0;
    else
    {
        ret = do_tls_connection(ssock, ssl, 0, 0, &mod_server_scram_next, &hstate, 0, 0);
        SSL_free(ssl);
    }
    
    buffered_ssl_dtor(&hstate.bssl);
    
    write_lower_level();
    
    return ret;
}

int build_test_cert_chains_output(SSL_CTX** out_ssl_ctx, X509** out_cert, EVP_PKEY** out_pk, X509* root_cert, EVP_PKEY* root_pk, int depth, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    char path[BUFFER_SIZE];
    SSL_CTX* ssl_ctx = 0;
    X509** cert_stack = 0;
    EVP_PKEY** pk_stack = 0;
    int i;
    int ret = 0;
    
    cert_stack = (X509**)malloc(depth * sizeof(X509*));
    pk_stack = (EVP_PKEY**)malloc(depth * sizeof(EVP_PKEY*));
    
    if (!cert_stack || !pk_stack)
    {
        write_out(PRINT_ERROR, "Error allocating memory.");
        ret = 0;
        goto error_die;
    }

    //build our chain of certificates
    if (!build_rsa_x509_chain(depth, cert_stack, pk_stack, root_cert, root_pk, bits, country, org_name, org_unit, common_name, alt_name, serial, days_valid))
    {
        write_out(PRINT_ERROR, "Unable to generate certificate chain.");
        ret = 0;
        goto error_die;
    }
    
    for (i = 0; i < depth - 1; ++i)
    {
        snprintf(path, BUFFER_SIZE, "%s%03d.pem", INTER_CERT, i);
        if (!export_cert_to_pem(cert_stack[i], path, 0))
            write_out(PRINT_WARNING, "Unable to export %s", path);
    }

    //make the ssl context with 
    ssl_ctx = init_ssl_server_ctx(TLSv1_2_method(), cert_stack[depth - 1], pk_stack[depth - 1], 0, 0, 0, 0, root_cert);
    if (!ssl_ctx)
    {
        write_out(PRINT_ERROR, "Error creating SSL context.");

        ret = 0;
        goto error_die;
    }
    
    *out_ssl_ctx = ssl_ctx;
    *out_cert = cert_stack[depth - 1];
    *out_pk = pk_stack[depth - 1];
    ret = 1;
    
error_die:
    if (cert_stack)
    {
        
        for (i = 0; i < depth - 1; ++i)
            if (cert_stack[i])
            {
                X509_free(cert_stack[i]);
                cert_stack[i] = 0;
            }

        if (!ret)
        {
            X509_free(cert_stack[depth - 1]);
            cert_stack[depth - 1] = 0;
        }
        free(cert_stack);
    }
    
    if (pk_stack)
    {
        for (i = 0; i < depth - 1; ++i)
            if (pk_stack[i])
            {
                EVP_PKEY_free(pk_stack[i]);
                pk_stack[i] = 0;
            }
            
        if (!ret)
        {
            EVP_PKEY_free(pk_stack[depth - 1]);
            pk_stack[depth - 1] = 0;
        }
        free(pk_stack);
    }

    return ret;
}

int build_test_cert_chains_ex(SSL_CTX** out_ssl_ctx, X509** out_cert, EVP_PKEY** out_pk, X509* root_cert, EVP_PKEY* root_pk, int depth, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid, int set_ca, int set_server_auth)
{
    SSL_CTX* ssl_ctx = 0;
    X509** cert_stack = 0;
    EVP_PKEY** pk_stack = 0;
    int i;
    int ret = 0;
    
    cert_stack = (X509**)malloc(depth * sizeof(X509*));
    pk_stack = (EVP_PKEY**)malloc(depth * sizeof(EVP_PKEY*));
    
    if (!cert_stack || !pk_stack)
    {
        write_out(PRINT_ERROR, "Error allocating memory.");
        ret = 0;
        goto error_die;
    }

    //build our chain of certificates
    if (!build_rsa_x509_chain_ex(depth, cert_stack, pk_stack, root_cert, root_pk, bits, country, org_name, org_unit, common_name, alt_name, serial, days_valid, set_ca, set_server_auth))
    {
        write_out(PRINT_ERROR, "Unable to generate certificate chain.");
        ret = 0;
        goto error_die;
    }

    //make the ssl context with 
    ssl_ctx = init_ssl_server_ctx(TLSv1_2_method(), cert_stack[depth - 1], pk_stack[depth - 1], 0, 0, 0, 0, root_cert);
    if (!ssl_ctx)
    {
        write_out(PRINT_ERROR, "Error creating SSL context.");

        ret = 0;
        goto error_die;
    }
    
    //add the rest of our certificate chain
    //this will cause SSL_CTX to take ownership of everything in cert_stack
    if (!SSL_CTX_build_cert_chain(ssl_ctx, cert_stack, depth - 1))
    {
        ret = 0;
        goto error_die;
    }
    
    *out_ssl_ctx = ssl_ctx;
    *out_cert = cert_stack[depth - 1];
    *out_pk = pk_stack[depth - 1];
    ret = 1;
    
error_die:
    if (cert_stack)
    {
        if (!ret)
        {
            for (i = 0; i < depth - 1; ++i)
                if (cert_stack[i])
                {
                    X509_free(cert_stack[i]);
                    cert_stack[i] = 0;
                }

            X509_free(cert_stack[depth - 1]);
            cert_stack[depth - 1] = 0;
        }
        free(cert_stack);
    }
    
    if (pk_stack)
    {
        for (i = 0; i < depth - 1; ++i)
            if (pk_stack[i])
            {
                EVP_PKEY_free(pk_stack[i]);
                pk_stack[i] = 0;
            }
        if (!ret)
        {
            EVP_PKEY_free(pk_stack[depth - 1]);
            pk_stack[depth - 1] = 0;
        }
        free(pk_stack);
    }

    return ret;
}

int build_test_cert_chains(SSL_CTX** out_ssl_ctx, X509** out_cert, EVP_PKEY** out_pk, X509* root_cert, EVP_PKEY* root_pk, int depth, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    return build_test_cert_chains_ex(out_ssl_ctx, out_cert, out_pk, root_cert, root_pk, depth, bits, country, org_name, org_unit, common_name, alt_name, serial, days_valid, SET_CA_TRUE, 1);
}

int FCS_TLSC_EXT_1_2_TEST_1(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    const char* cn_str = 0;
    const char* alt_str = 0;
    
    write_raise_level();
    
    //hacky way to do a quick check
    if (strcasecmp(common_name, BAD_CN_1) != 0)
        cn_str = BAD_CN_1;
    else
        cn_str = BAD_CN_2;
    
    if (strcasecmp(alt_name, BAD_ALT_1) != 0)
        alt_str = BAD_ALT_1;
    else
        alt_str = BAD_ALT_2;
    
    if (!build_test_cert_chains(&ssl_ctx, &cert, &pk, root_cert, root_pk, depth, bits, country, org_name, org_unit, cn_str, alt_str, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
    }
    else
        if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
            ret = 0;
        else
        {
            ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0);
            SSL_free(ssl);
        }
    
    write_lower_level();
    
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FCS_TLSC_EXT_1_2_TEST_2(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    const char* alt_str = 0;
    
    write_raise_level();
    
    //hacky way to do a quick check
    
    if (strcasecmp(alt_name, BAD_ALT_1) != 0)
        alt_str = BAD_ALT_1;
    else
        alt_str = BAD_ALT_2;
    
    if (!build_test_cert_chains(&ssl_ctx, &cert, &pk, root_cert, root_pk, depth, bits, country, org_name, org_unit, common_name, alt_str, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
    }
    else
        if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
            ret = 0;
        else
        {
            ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0); //TODO: Test all the SANs
            SSL_free(ssl);
        }
    
    write_lower_level();
    
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FCS_TLSC_EXT_1_2_TEST_3(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    
    write_raise_level();
    
    if (!build_test_cert_chains(&ssl_ctx, &cert, &pk, root_cert, root_pk, depth, bits, country, org_name, org_unit, common_name, 0, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
    }
    else
        if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
            ret = 0;
        else
        {
            ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 1, 0);
            SSL_free(ssl);
        }
    
    write_lower_level();
    
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FCS_TLSC_EXT_1_2_TEST_4(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    const char* cn_str = 0;
    
    write_raise_level();
    
    //hacky way to do a quick check
    if (strcasecmp(common_name, BAD_CN_1) != 0)
        cn_str = BAD_CN_1;
    else
        cn_str = BAD_CN_2;
    
    if (!build_test_cert_chains(&ssl_ctx, &cert, &pk, root_cert, root_pk, depth, bits, country, org_name, org_unit, cn_str, alt_name, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
    }
    else
        if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
            ret = 0;
        else
        {
            ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 1, 0);
            SSL_free(ssl);
        }

    write_lower_level();
    
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FCS_TLSC_EXT_1_2_TEST_5__1(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    char wild_char_domain[CERT_NAME_SIZE];
    
    write_raise_level();
    
    snprintf(wild_char_domain, CERT_NAME_SIZE, "%s.*.%s", WILD_START, common_name);
    
    if (!build_test_cert_chains(&ssl_ctx, &cert, &pk, root_cert, root_pk, depth, bits, country, org_name, org_unit, wild_char_domain, 0, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
    }
    else
        if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
            ret = 0;
        else
        {
            ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0);
            SSL_free(ssl);
        }
    
    write_lower_level();
    
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FCS_TLSC_EXT_1_2_TEST_5__2a(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    char wild_char_domain[CERT_NAME_SIZE];
    
    write_raise_level();
    
    snprintf(wild_char_domain, CERT_NAME_SIZE, "*.%s", common_name);
    
    if (!build_test_cert_chains(&ssl_ctx, &cert, &pk, root_cert, root_pk, depth, bits, country, org_name, org_unit, wild_char_domain, 0, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
    }
    else
        if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
            ret = 0;
        else
        {
            ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 1, 0);
            SSL_free(ssl);
        }
    
    write_lower_level();
    
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FCS_TLSC_EXT_1_2_TEST_5__2b(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    char wild_char_domain[CERT_NAME_SIZE];
    
    write_raise_level();
    
    snprintf(wild_char_domain, CERT_NAME_SIZE, "*.%s", common_name);
    
    if (!build_test_cert_chains(&ssl_ctx, &cert, &pk, root_cert, root_pk, depth, bits, country, org_name, org_unit, wild_char_domain, 0, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
    }
    else
        if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
            ret = 0;
        else
        {
            ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0);
            SSL_free(ssl);
        }
    
    write_lower_level();
    
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FCS_TLSC_EXT_1_2_TEST_5__3(int ssock, const char* cipher_name, int depth, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    char wild_char_domain[CERT_NAME_SIZE];
    
    write_raise_level();
    
    snprintf(wild_char_domain, CERT_NAME_SIZE, "*.%s", PUBLIC_SUFFX);
    
    if (!build_test_cert_chains(&ssl_ctx, &cert, &pk, root_cert, root_pk, depth, bits, country, org_name, org_unit, wild_char_domain, 0, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
    }
    else
        if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
            ret = 0;
        else
        {
            ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0);    
            SSL_free(ssl);
        }
    
    write_lower_level();
    
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FCS_TLSC_EXT_1_3_TEST_1a(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    
    write_raise_level();
    
    if (!build_test_cert_chains(&ssl_ctx, &cert, &pk, root_cert, root_pk, 3, bits, country, org_name, org_unit, common_name, 0, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
    }
    else
        if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
            ret = 0;
        else
        {
            ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 1, 0);
            SSL_free(ssl);
        }
    
    write_lower_level();
    
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FCS_TLSC_EXT_1_3_TEST_1b(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    
    write_raise_level();
    
    if (!build_test_cert_chains(&ssl_ctx, &cert, &pk, root_cert, root_pk, 3, bits, country, org_name, org_unit, common_name, 0, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
    }
    else
        if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
            ret = 0;
        else
        {
            ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0);
            SSL_free(ssl);
        }
    
    write_lower_level();
    
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FCS_TLSC_EXT_1_4_TEST_1(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl = 0;
    int ret = 1;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    X509* fake_cert = 0;
    EVP_PKEY* fake_pk = 0;
    X509* client_cert = 0;
    EVP_PKEY* client_pk = 0;
    buffered_ssl_ctx bssl;
    
    write_raise_level();
    
    if (!generate_rsa_client_cert(bits, CLIENT_COUNTRY, CLIENT_ORG, CLIENT_UNIT, CLIENT_NAME, rand(), 1, root_cert, root_pk, &client_cert, &client_pk, EVP_sha256()))
    {
        ret = 0;
        goto error_die;
    }
    
    write_out(PRINT_OUTPUT, "Use %s or %s as client authentication certs.", CLIENT_CERT, CLIENT_CERT_P12);
    export_cert_to_pem(client_cert, CLIENT_CERT, 0);
    export_pk_to_pem(client_pk, CLIENT_CERT, 1);
    export_key_pair_to_pkcs12(client_cert, client_pk, CLIENT_CERT_P12, CLIENT_P12_PWD, CLIENT_P12_NAME);
    
    if (!build_test_cert_chains(&ssl_ctx, &cert, &pk, root_cert, root_pk, 3, bits, country, org_name, org_unit, common_name, 0, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
        goto error_die;
    }

    if (!generate_rsa_ca(FAKE_BITS, FAKE_COUNTRY, FAKE_ORG, FAKE_UNIT, FAKE_CA, rand(), 1, &fake_cert, &fake_pk, EVP_sha256()))
    {
        ret = 0;
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
    {
        ret = 0;
        goto error_die;
    }

    //SSL_set_verify(ssl, SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER, 0);
    SSL_set_verify(ssl, SSL_VERIFY_PEER, 0);
    SSL_add_client_CA(ssl, root_cert);
    SSL_add_client_CA(ssl, fake_cert);
    
    buffered_ssl_ctor(&bssl);
    
    ret = do_tls_connection(ssock, ssl, 0, 0, &mod_client_cert_request, &bssl, 0, 1);
    
    buffered_ssl_dtor(&bssl);
    
error_die:
    write_lower_level();
    
    if (ssl)
        SSL_free(ssl);
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    if (fake_cert)
        X509_free(fake_cert);
    if (fake_pk)
        EVP_PKEY_free(fake_pk);
    if (client_cert)
        X509_free(client_cert);
    if (client_pk)
        EVP_PKEY_free(client_pk);
    
    return ret;
}

int FCS_TLSC_EXT_1_5_TEST_1(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, const char* ec_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl = 0;
    X509* ecdsa_cert = 0;
    EVP_PKEY* ecdsa_priv_key = 0;
    int ret = 1;
    
    write_raise_level();
    
    write_out(PRINT_INFO, "Generating ECDSA certificate using curve %s...", ec_curve);
    if (!create_ecdsa_cert_v3(ec_curve, country, org_name, org_unit, common_name, rand(), 1, &ecdsa_cert, &ecdsa_priv_key))
    {
        write_out(PRINT_ERROR, "Unable to generate ECDSA certificate!");
        
        ret = 0;
        goto error_die;
    }
    
    if (alt_name)
        if (!add_x509_extension(ecdsa_cert, NID_subject_alt_name, alt_name))
            write_out(PRINT_WARNING, "Unable to add alt extension to certificate!");
    
    if (!add_x509_extension(ecdsa_cert, NID_ext_key_usage, "serverAuth"))
        write_out(PRINT_WARNING, "Unable to add serverAuth to certificate!");
    
    write_out(PRINT_INFO, "Signing ECDSA cert...");
    write_raise_level();
    if (!sign_x509_cert(root_cert, root_pk, ecdsa_cert, EVP_sha256()))
    {
        write_out(PRINT_ERROR, "Unable to sign ECDSA certificate!");
        
        ret = 0;
        goto error_die;
    }
    write_lower_level();
    
    ssl_ctx = init_ssl_server_ctx(TLSv1_2_method(), 0, 0, 0, ec_curve, ecdsa_cert, ecdsa_priv_key, root_cert);
    
    if (!ssl_ctx)
    {
        write_out(PRINT_ERROR, "Error creating SSL context.");

        ret = 0;
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
    {
        ret = 0;
        goto error_die;
    }
    
    ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0);
    
error_die:
    write_lower_level();
    
    if (ssl)
        SSL_free(ssl);
    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    if (ecdsa_priv_key)
        EVP_PKEY_free(ecdsa_priv_key);
    if (ecdsa_cert)
        X509_free(ecdsa_cert);
    
    return ret;
}

int FCS_TLSC_EXT_1_6_TEST_1(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl = 0;
    X509* rsa_cert = 0;
    EVP_PKEY* rsa_priv_key = 0;
    int ret = 1;
    
    write_raise_level();
    
    write_out(PRINT_INFO, "Generating %d bit RSA certificate...", bits);
    if (!create_rsa_cert_v3(bits, country, org_name, org_unit, common_name, rand(), 1, &rsa_cert, &rsa_priv_key))
    {
        write_out(PRINT_ERROR, "Unable to generate RSA certificate!");
        
        ret = 0;
        goto error_die;
    }
    
    if (alt_name)
        if (!add_x509_extension(rsa_cert, NID_subject_alt_name, alt_name))
            write_out(PRINT_WARNING, "Unable to add alt extension to certificate!");
    
    if (!add_x509_extension(rsa_cert, NID_ext_key_usage, "serverAuth"))
        write_out(PRINT_WARNING, "Unable to add alt extension to certificate!");
    
    write_out(PRINT_INFO, "Signing RSA cert with SHA1...");
    write_raise_level();
    if (!sign_x509_cert(root_cert, root_pk, rsa_cert, EVP_sha1()))
    {
        write_out(PRINT_ERROR, "Unable to sign RSA certificate!");
        
        ret = 0;
        goto error_die;
    }
    write_lower_level();
    
    ssl_ctx = init_ssl_server_ctx(TLSv1_2_method(), rsa_cert, rsa_priv_key, 0, 0, 0, 0, root_cert);
    
    if (!ssl_ctx)
    {
        write_out(PRINT_ERROR, "Error creating SSL context.");

        ret = 0;
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
    {
        ret = 0;
        goto error_die;
    }
    
    ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0);
    
error_die:
    write_lower_level();

    if (ssl)
        SSL_free(ssl);
    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    if (rsa_priv_key)
        EVP_PKEY_free(rsa_priv_key);
    if (rsa_cert)
        X509_free(rsa_cert);
    
    return ret;
}

int FIA_X509_EXT_1_1_TEST_1(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl = 0;
    int ret = 1;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    
    write_raise_level();
    
    if (!build_test_cert_chains_output(&ssl_ctx, &cert, &pk, root_cert, root_pk, 3, bits, country, org_name, org_unit, common_name, 0, serial, days_valid))
    {
        cert = 0;
        pk = 0;
        ret = 0;
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
    {
        ret = 0;
        goto error_die;
    }
    
    write_out(PRINT_OUTPUT, "Ensure a valid certification path DOES NOT exist before connecting.");
    if (!(ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0)))
        goto error_die;
    write_out(PRINT_OUTPUT, "Add the %s*.pem certificates to create a valid validation path before connecting.", INTER_CERT);
    if (!(ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 1, 0)))
        goto error_die;
    write_out(PRINT_OUTPUT, "Remove one of the %s*.pem certificates from the validation path.", INTER_CERT);
    if (!(ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0)))
        goto error_die;
    
    
error_die:
    write_lower_level();
    
    if (ssl)
        SSL_free(ssl);
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FIA_X509_EXT_1_1_TEST_2(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl = 0;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    
    write_raise_level();
    
    if (!create_rsa_cert_v3_ex(bits, country, org_name, org_unit, common_name, serial, -60 * 60 * 24 * 2, -60 * 60 * 24 * 1, &cert, &pk))
    {
        ret = 0;
        goto error_die;
    }
    
    if (!sign_x509_cert(root_cert, root_pk, cert, EVP_sha256()))
    {
        X509_free(cert);
        cert = 0;
        EVP_PKEY_free(pk);
        pk = 0;
        ret = 0;
        goto error_die;
    }
    
    ssl_ctx = init_ssl_server_ctx(TLSv1_2_method(), cert, pk, 0, 0, 0, 0, root_cert);
    if (!ssl_ctx)
    {
        write_out(PRINT_ERROR, "Error creating SSL context.");

        ret = 0;
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
    {
        ret = 0;
        goto error_die;
    }
    
    ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0);
    
error_die:
    write_lower_level();
    
    if (ssl)
        SSL_free(ssl);
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FIA_X509_EXT_1_1_TEST_5(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl = 0;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    buffered_ssl_ctx bssl;
    
    write_raise_level();
    
    if (!build_rsa_x509_chain(1, &cert, &pk, root_cert, root_pk, bits, country, org_name, org_unit, common_name, alt_name, serial, days_valid))
    {
        write_out(PRINT_ERROR, "Unable to generate certificate.");
        ret = 0;
        goto error_die;
    }
    
    ssl_ctx = init_ssl_server_ctx(TLSv1_2_method(), cert, pk, 0, 0, 0, 0, root_cert);
    if (!ssl_ctx)
    {
        write_out(PRINT_ERROR, "Error creating SSL context.");

        ret = 0;
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
    {
        ret = 0;
        goto error_die;
    }
    
    buffered_ssl_ctor(&bssl);
    
    ret = do_tls_connection(ssock, ssl, 0, 0, &mod_server_cert_start, &bssl, 0, 0);
    
    buffered_ssl_dtor(&bssl);
    
error_die:
    write_lower_level();
    
    if (ssl)
        SSL_free(ssl);
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FIA_X509_EXT_1_1_TEST_6(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl = 0;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    buffered_ssl_ctx bssl;
    
    write_raise_level();
    
    if (!build_rsa_x509_chain(1, &cert, &pk, root_cert, root_pk, bits, country, org_name, org_unit, common_name, alt_name, serial, days_valid))
    {
        write_out(PRINT_ERROR, "Unable to generate certificate.");
        ret = 0;
        goto error_die;
    }
    
    ssl_ctx = init_ssl_server_ctx(TLSv1_2_method(), cert, pk, 0, 0, 0, 0, root_cert);
    if (!ssl_ctx)
    {
        write_out(PRINT_ERROR, "Error creating SSL context.");

        ret = 0;
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
    {
        ret = 0;
        goto error_die;
    }
    
    buffered_ssl_ctor(&bssl);
    
    ret = do_tls_connection(ssock, ssl, 0, 0, &mod_server_cert_end, &bssl, 0, 0);
    
    buffered_ssl_dtor(&bssl);
    
error_die:
    write_lower_level();
    
    if (ssl)
        SSL_free(ssl);
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FIA_X509_EXT_1_1_TEST_7(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl = 0;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    handshake_server_cert hstate;
    unsigned char* modulus = 0;
    unsigned int bytes = bits / 8;
    
    write_raise_level();
    
    if (!build_rsa_x509_chain(1, &cert, &pk, root_cert, root_pk, bits, country, org_name, org_unit, common_name, alt_name, serial, days_valid))
    {
        write_out(PRINT_ERROR, "Unable to generate certificate.");
        ret = 0;
        goto error_die;
    }
    
    ssl_ctx = init_ssl_server_ctx(TLSv1_2_method(), cert, pk, 0, 0, 0, 0, root_cert);
    if (!ssl_ctx)
    {
        write_out(PRINT_ERROR, "Error creating SSL context.");

        ret = 0;
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
    {
        ret = 0;
        goto error_die;
    }
    
    if (!(modulus = (unsigned char*)malloc(bytes)))
    {
        ret = 0;
        goto error_die;
    }
    
    if (!get_rsa_mod(cert, modulus, bytes))
    {
        ret = 0;
        goto error_die;
    }
    
    buffered_ssl_ctor(&hstate.bssl);
    hstate.modulus = modulus;
    hstate.size = bytes;
    
    ret = do_tls_connection(ssock, ssl, 0, 0, &mod_server_cert_middle, &hstate, 0, 0);
    
    buffered_ssl_dtor(&hstate.bssl);
    
    goto error_die;
    
error_die:
    write_lower_level();
    
    if (modulus)
        free(modulus);
    if (ssl)
        SSL_free(ssl);
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FIA_X509_EXT_1_2_TEST_1(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl = 0;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    buffered_ssl_ctx bssl;
    
    write_raise_level();
    
    if (!build_test_cert_chains_ex(&ssl_ctx, &cert, &pk, root_cert, root_pk, 2, bits, country, org_name, org_unit, common_name, alt_name, serial, days_valid, SET_CA_NONE, 1))
    {
        write_out(PRINT_ERROR, "Unable to generate certificates.");
        ret = 0;
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
    {
        ret = 0;
        goto error_die;
    }
    
    buffered_ssl_ctor(&bssl);
    
    ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0);
    
    buffered_ssl_dtor(&bssl);
    
error_die:
    write_lower_level();
    
    if (ssl)
        SSL_free(ssl);
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FIA_X509_EXT_1_2_TEST_2(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl = 0;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    buffered_ssl_ctx bssl;
    
    write_raise_level();
    
    if (!build_test_cert_chains_ex(&ssl_ctx, &cert, &pk, root_cert, root_pk, 2, bits, country, org_name, org_unit, common_name, alt_name, serial, days_valid, SET_CA_FALSE, 1))
    {
        write_out(PRINT_ERROR, "Unable to generate certificates.");
        ret = 0;
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
    {
        ret = 0;
        goto error_die;
    }
    
    buffered_ssl_ctor(&bssl);
    
    ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 0, 0);
    
    buffered_ssl_dtor(&bssl);
    
error_die:
    write_lower_level();
    
    if (ssl)
        SSL_free(ssl);
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}

int FIA_X509_EXT_1_2_TEST_3(int ssock, const char* cipher_name, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    SSL_CTX* ssl_ctx = 0;
    SSL* ssl = 0;
    int ret = 0;
    X509* cert = 0;
    EVP_PKEY* pk = 0;
    buffered_ssl_ctx bssl;
    
    write_raise_level();
    
    if (!build_test_cert_chains_ex(&ssl_ctx, &cert, &pk, root_cert, root_pk, 2, bits, country, org_name, org_unit, common_name, alt_name, serial, days_valid, SET_CA_TRUE, 1))
    {
        write_out(PRINT_ERROR, "Unable to generate certificates.");
        ret = 0;
        goto error_die;
    }
    
    if (!(ssl = init_ssl_with_cipher(ssl_ctx, cipher_name)))
    {
        ret = 0;
        goto error_die;
    }
    
    buffered_ssl_ctor(&bssl);
    
    ret = do_tls_connection(ssock, ssl, 0, 0, 0, 0, 1, 0);
    
    buffered_ssl_dtor(&bssl);
    
error_die:
    write_lower_level();
    
    if (ssl)
        SSL_free(ssl);
    if (ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    if (cert)
        X509_free(cert);
    if (pk)
        EVP_PKEY_free(pk);
    
    return ret;
}
