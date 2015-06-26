#include "ssl.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
//#include <openssl/x509_vfy.h>
#include <sys/socket.h>

#include "printer.h"
#include "common.h"

void print_ssl_error_stack(int level)
{
    unsigned long err_num;
    
    while ((err_num = ERR_get_error()))
        write_out(level, "%s", ERR_error_string(err_num, 0));
}

void init_ssl()
{
    SSL_load_error_strings();
    SSL_library_init();
}

SSL* init_ssl_with_cipher(SSL_CTX* ssl_ctx, const char* cipher_name)
{
    SSL* ssl;
    
    ssl = SSL_new(ssl_ctx);
    if (!SSL_set_cipher_list(ssl, cipher_name))
    {
        write_out(PRINT_ERROR, "Unable to initialize SSL with %s.", cipher_name);
        write_raise_level();
        write_out(PRINT_ERROR, "Your version of OpenSSL may be outdated. Update OpenSSL and try again.");
        write_out(PRINT_ERROR, "If your version of OpenSSL is current, then %s cipher may have been disabled at compile time.", cipher_name);
        write_lower_level();
        if (ssl)
            SSL_free(ssl);
        return 0;
    }
    
    return ssl;
}

//SSL_CTX* init_ssl_server_ctx(const SSL_METHOD* method, const char* server_cert, const char* server_priv_key, const char* dh_params, const char* ecdh_curve, const char* ecdsa_cert, const char* ecdsa_privkey, int check_client)
SSL_CTX* init_ssl_server_ctx(const SSL_METHOD* method, X509* server_cert, EVP_PKEY* server_priv_key, const char* dh_params, const char* ecdh_curve, X509* ecdsa_cert, EVP_PKEY* ecdsa_privkey, X509* root_cert)
{
    SSL_CTX* ssl_ctx = 0;
    DH* dh = 0;
    EC_KEY* ecdh = 0;
    FILE* param_file = 0;
    X509_STORE* x509_store;
    int nid;
    
    //make ssl context
    if (!(ssl_ctx = SSL_CTX_new(method)))
    {
        write_out(PRINT_ERROR, "Unable to initialize OpenSSL.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
    
    //disable renegotiation to ensure a fresh start
    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_NO_TICKET);
    
    if (server_cert && server_priv_key)
    {
        //load rsa certs
        //if (SSL_CTX_use_certificate_file(ssl_ctx, server_cert, SSL_FILETYPE_PEM) != 1)
        if (SSL_CTX_use_certificate(ssl_ctx, server_cert) != 1)
        {
            write_out(PRINT_ERROR, "Unable to load RSA certificate.");
            write_raise_level();
            print_ssl_error_stack(PRINT_ERROR);
            write_lower_level();
            
            goto error_die;
        }
        
        if (SSL_CTX_use_PrivateKey(ssl_ctx, server_priv_key) != 1)
        {
            write_out(PRINT_ERROR, "Unable to load RSA private key.");
            write_raise_level();
            print_ssl_error_stack(PRINT_ERROR);
            write_lower_level();
            
            goto error_die;
        }
        
        if (!SSL_CTX_check_private_key(ssl_ctx))
        {
            write_out(PRINT_ERROR, "RSA Certificate and private key do not match!");
            
            goto error_die;
        }
    }
    
    if (dh_params)
    {    
        //load dh params
        param_file = fopen(dh_params, "rb");
        if (!param_file)
        {
            write_out(PRINT_ERROR, "DH Parameter file could not be read: %s", dh_params);
        }
        
        dh = PEM_read_DHparams(param_file, 0, 0, 0);
        if (!dh)
        {
            write_out(PRINT_ERROR, "DH Parameters could not be loaded!");
            write_raise_level();
            print_ssl_error_stack(PRINT_ERROR);
            write_lower_level();
            
            goto error_die;
        }
        
        fclose(param_file);
        param_file = 0;

        if (SSL_CTX_set_tmp_dh(ssl_ctx, dh) != 1)
        {
            write_out(PRINT_ERROR, "DH Parameters could not be set!");
            write_raise_level();
            print_ssl_error_stack(PRINT_ERROR);
            write_lower_level();
            
            goto error_die;
        }
        
        DH_free(dh);
        dh = 0;
    }
    
    if (ecdh_curve)
    {
        //load ecdh params
        if ((nid = OBJ_sn2nid(ecdh_curve)) == NID_undef)
        {
            write_out(PRINT_ERROR, "Unable to find elliptic curve %s.", ecdh_curve);
            goto error_die;
        }
        
        if ((ecdh = EC_KEY_new_by_curve_name(nid)) == 0)
        {
            write_out(PRINT_ERROR, "Unable to create elliptic curve %s.", ecdh_curve);
            goto error_die;
        }
        
        if (SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh) != 1)
        {
            write_out(PRINT_ERROR, "ECDH Parameters could not be set!");
            write_raise_level();
            print_ssl_error_stack(PRINT_ERROR);
            write_lower_level();
            
            goto error_die;
        }
        
        EC_KEY_free(ecdh);
        ecdh = 0;
    }
    
    if (ecdsa_cert && ecdsa_privkey)
    {
        //load ecdsa certs
        //if (SSL_CTX_use_certificate_file(ssl_ctx, ecdsa_cert, SSL_FILETYPE_PEM) != 1)
        if (SSL_CTX_use_certificate(ssl_ctx, ecdsa_cert) != 1)
        {
            write_out(PRINT_ERROR, "Unable to load ECDSA certificate.");
            write_raise_level();
            print_ssl_error_stack(PRINT_ERROR);
            write_lower_level();
            
            goto error_die;
        }
        
        //if (SSL_CTX_use_PrivateKey_file(ssl_ctx, ecdsa_privkey, SSL_FILETYPE_PEM) != 1)
        if (SSL_CTX_use_PrivateKey(ssl_ctx, ecdsa_privkey) != 1)
        {
            write_out(PRINT_ERROR, "Unable to load ECDSA private key.");
            write_raise_level();
            print_ssl_error_stack(PRINT_ERROR);
            write_lower_level();
            
            goto error_die;
        }
        
        if (!SSL_CTX_check_private_key(ssl_ctx))
        {
            write_out(PRINT_ERROR, "ECDSA Certificate and private key do not match!");
            
            goto error_die;
        }
    }

    //setup the root_cert for verification
    if (root_cert)
    {
        x509_store = SSL_CTX_get_cert_store(ssl_ctx);
        
        X509_STORE_add_cert(x509_store, root_cert);
    }
    
    return ssl_ctx;
    
error_die:
    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    
    if (param_file)
        fclose(param_file);
    
    if (dh)
        DH_free(dh);
    
    if (ecdh)
        EC_KEY_free(ecdh);
    
    return 0;
}

int SSL_CTX_build_cert_chain(SSL_CTX* ssl_ctx, X509** certs, int count)
{
    int i;

    for (i = count - 1; i >= 0; --i)
        if (!SSL_CTX_add_extra_chain_cert(ssl_ctx, certs[i]))
        {
            write_out(PRINT_ERROR, "Unable to build certificate chain.");
            write_raise_level();
            print_ssl_error_stack(PRINT_ERROR);
            write_lower_level();
            return 0;
        }
    
    return 1;
}

int send_bio_data(int sockfd, BIO* wbio, MUTATOR mutate, void* state)
{
    int n;
    int mn;
    int bytes;
    int sent;
    unsigned char buf[BUFFER_SIZE];
    unsigned char* mbuf;
    
    while (BIO_pending(wbio) > 0)
    {
        n = BIO_read(wbio, buf, BUFFER_SIZE);
        
        if (mutate)
            mbuf = mutate(state, buf, n, &mn);
        else
        {
            mbuf = buf;
            mn = n;
        }
        
        sent = 0;
        for (sent = 0; sent < mn; sent += bytes)
        {
            bytes = send(sockfd, mbuf + sent, mn - sent, MSG_NOSIGNAL);
            
            if (bytes <= 0)
            {
                write_out(PRINT_ERROR, "Error sending data: %s\n", strerror(errno));
                if (mutate)
                    free(mbuf);
                return 0;
            }
        }
        
        if (mutate)
            free(mbuf);
    }

    return 1;
}

int put_bio_data(int sockfd, BIO* rbio, MUTATOR mutate, void* state)
{
    int n;
    int mn;
    unsigned char buf[BUFFER_SIZE];
    unsigned char* mbuf;
    
    n = recv(sockfd, buf, BUFFER_SIZE, 0);
    if (n < 0)
    {
        write_out(PRINT_ERROR, "Socket recv error: %s", strerror(errno));
        return n;
    }
    
    if (n == 0)
        return n;
    
    if (mutate)
    {
        mbuf = mutate(state, buf, n, &mn);
    
        BIO_write(rbio, mbuf, mn);
    
        free(mbuf);
    }
    else
        BIO_write(rbio, buf, n);
    
    return n;
}

int recv_wait(int sockfd, BIO* rbio, long sec, long us, MUTATOR mutate, void* state)
{
    fd_set rfds;
    struct timeval tv;
    int retval;
    int bytes;
    
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    
    tv.tv_sec = sec;
    tv.tv_usec = us;
    
    retval = select(sockfd + 1, &rfds, 0, 0, &tv);
    
    if (retval == -1)
        return RECV_WAIT_ERROR;
    if (retval > 0)
        if (FD_ISSET(sockfd, &rfds))
        {
            bytes = put_bio_data(sockfd, rbio, mutate, state);
            return bytes;
        }
        else
            return RECV_TIMEOUT;
    else
        return RECV_TIMEOUT;
}

int do_handshake(int sockfd, SSL* ssl, BIO* rbio, BIO* wbio, MUTATOR in_mut, void* in_state, MUTATOR out_mut, void* out_state)
{
    int err;

    SSL_set_accept_state(ssl);
    
    write_out(PRINT_INFO, "Starting TLS handshake...");
    write_raise_level();
    while (!SSL_is_init_finished(ssl))
    {
        //write_out(PRINT_INFO, "SSL_accept");
        err = SSL_accept(ssl);
        if (err <= 0)
        {
            err = SSL_get_error(ssl, err);
            switch (err)
            {
                case SSL_ERROR_WANT_READ:
                    //grab handshake info in the BIO and send it out to the client if there is any
                    if (!send_bio_data(sockfd, wbio, out_mut, out_state))
                    {
                        write_out(PRINT_ERROR, "TLS handshake error while sending data!");
                        write_lower_level();
                        return HANDSHAKE_UNSUCCESSFUL;
                    }
                    
                    if (!put_bio_data(sockfd, rbio, in_mut, in_state))
                    {
                        write_out(PRINT_ERROR, "TLS handshake error while recv'ing data!");
                        write_lower_level();
                        return HANDSHAKE_UNSUCCESSFUL;
                    }
                    
                    break;
                case SSL_ERROR_SSL:
                    if (ERR_peek_error() == 0x1408C095)
                    {
                        write_out(PRINT_ERROR, "Bad TLS finished digest.");
                        write_lower_level();
                        return HANDSHAKE_BAD_DIGEST;
                    }
                default:
                    write_out(PRINT_ERROR, "TLS accept error: %d", err);
                    print_ssl_error_stack(PRINT_ERROR);
                    write_lower_level();
                    
                    return HANDSHAKE_UNSUCCESSFUL;
            }
        }
    }
    
    //send the final encrypted handshake
    if (!send_bio_data(sockfd, wbio, out_mut, out_state))
    {
        write_out(PRINT_ERROR, "TLS handshake error while sending data!");
        write_lower_level();
        return 0;
    }
    
    write_out(PRINT_INFO, "TLS handshake complete.");
    write_lower_level();
    
    return HANDSHAKE_SUCCESSFUL;
}

void shutdown_ssl(SSL* ssl, int sockfd, BIO* rbio, BIO* wbio)
{
    int err;
    
    write_out(PRINT_INFO, "Attempting to gracefully shutdown TLS socket.");
    for (;;)
    {
        err = SSL_shutdown(ssl);

        if (err < 0)
        {
            err = SSL_get_error(ssl, err);
            
            switch (err)
            {
                case SSL_ERROR_WANT_WRITE:
                    put_bio_data(sockfd, rbio, 0, 0);
                    break;
                case SSL_ERROR_WANT_READ:
                    send_bio_data(sockfd, wbio, 0, 0);
                    if (put_bio_data(sockfd, rbio, 0, 0) <= 0)
                        goto for_break;
                    break;                
                default:
                    write_out(PRINT_WARNING, "Error in TLS shutdown!");
                    write_raise_level();
                    write_out(PRINT_ERROR, "TLS error: %d", SSL_get_error(ssl, err));
                    print_ssl_error_stack(PRINT_ERROR);
                    write_lower_level();
            }
        }
        else if (err == 1)
            break;
    }
for_break: ;
}

int get_ssl_record(SSL* ssl, int sockfd, BIO* rbio, unsigned char* buf, unsigned int len)
{
    int n;
    int err;
    
    for (;;)
    {
        n = SSL_read(ssl, buf, len);
        if (n == 0)
            return -1;
        else if (n < 0)
        {
            err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ)
                if ((n = put_bio_data(sockfd, rbio, 0, 0)) <= 0)
                    return n;
                else;
            else
            {
                write_out(PRINT_ERROR, "TLS Error: %d", err);
                return -1;
            }
        }
        else
            return n;
    }
}

int send_ssl_record(SSL* ssl, int sockfd, BIO* wbio, unsigned char* buf, unsigned int len)
{
    SSL_write(ssl, buf, len);
    return send_bio_data(sockfd, wbio, 0, 0);
}