#include "cert_gen.h"

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

#include "common.h"
#include "printer.h"
#include "ssl.h"

#define ICOUNTRY    "Fake Country "
#define IORG_NAME   "Fake Org "
#define IORG_UNIT   "Fake Unit "
#define ICOMM_NAME  "Fake Name "


int add_x509_extension(X509* cert, int nid, const char* value)
{
    X509_EXTENSION* extension = 0;
    char* copy = strdup(value);
    
    if (!copy)
        return 1;
    
    if ((extension = X509V3_EXT_conf_nid(0, 0, nid, copy)))
    {
        X509_add_ext(cert, extension, -1);
        X509_EXTENSION_free(extension);
        
        free(copy);
        return 1;
    }
    
    free(copy);
    return 0;
}

int export_pk_to_pem(EVP_PKEY* priv_key, const char* file, int append)
{
    FILE* f;
    const char* mode;
    
    mode = append ? "a" : "w";
    
    if (!(f = fopen(file, mode)))
    {
        write_out(PRINT_ERROR, "Unable to open file to export private key: %s", file);
        return 0;
    }
    
    if (PEM_write_PrivateKey(f, priv_key, 0, 0, 0, 0, 0) != 1)
    {
        write_out(PRINT_ERROR, "Unable to write private key to file: %s", file);
        
        fclose(f);
        return 0;
    }
    
    fclose(f);
    return 1;
}

int export_cert_to_pem(X509* cert, const char* file, int append)
{
    FILE* f;
    const char* mode;
    
    mode = append ? "a" : "w";
    
    if (!(f = fopen(file, mode)))
    {
        write_out(PRINT_ERROR, "Unable to open file to export certificate: %s", file);
        return 0;
    }
    
    if (PEM_write_X509(f, cert) != 1)
    {
        write_out(PRINT_ERROR, "Unable to write cert to file: %s", file);
        
        fclose(f);
        return 0;
    }
    
    fclose(f);
    return 1;
}

int export_key_pair_to_pkcs12(X509* cert, EVP_PKEY* pk, const char* file, char* password, char* name)
{
    FILE* f;
    PKCS12* pkcs12;
    
    if (!(f = fopen(file, "wb")))
    {
        write_out(PRINT_ERROR, "Unable to open file to export PKCS12: %s", file);
        return 0;
    }
    
    if (!(pkcs12 = PKCS12_create(password, name, pk, cert, 0, 0, 0, 0, 0, 0)))
    {
        write_out(PRINT_ERROR, "Unable to create PKCS12 for export.");
        fclose(f);
        return 0;
    }
    
    i2d_PKCS12_fp(f, pkcs12);
    PKCS12_free(pkcs12);
    fclose(f);
    
    return 1;
}

X509* create_cert_v3(const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int sec_start, int sec_end)
{
    X509* cert = 0;
    X509_NAME* name = 0;
    
    cert = X509_new();
    if (!cert)
    {
        write_out(PRINT_ERROR, "Unable to create X509 object!");
        goto error_die;
    }
    
    if (!X509_set_version(cert, 2))
    {
        write_out(PRINT_ERROR, "Unable to set X509 to version 3.");
        goto error_die;
    }

    if (ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) != 1)
    {
        write_out(PRINT_ERROR, "Unable to set X509 serial number.");
        goto error_die;
    }
    
    X509_gmtime_adj(X509_get_notBefore(cert), sec_start);
    X509_gmtime_adj(X509_get_notAfter(cert), sec_end);
    
    name = X509_get_subject_name(cert);
    if (country)     X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)country, -1, -1, 0);
    if (common_name) X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)common_name, -1, -1, 0);
    if (org_name)    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)org_name, -1, -1, 0);
    if (org_unit)    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)org_unit, -1, -1, 0);
    
    return cert;
    
error_die:
    if (cert)
        X509_free(cert);
    
    return 0;
}

int create_rsa_cert_v3_ex(int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int sec_start, int sec_end, X509** out_cert, EVP_PKEY** out_private_key)
{
    X509* cert = 0;
    RSA* rsa = 0;
    EVP_PKEY* private_key = 0;
    BIGNUM* bn = 0;
    
    cert = create_cert_v3(country, org_name, org_unit, common_name, serial, sec_start, sec_end);
    if (!cert)
        goto error_die;
    
    rsa = RSA_generate_key(bits, RSA_F4, 0, 0);
    
    if (!(rsa = RSA_new()))
    {
        write_out(PRINT_ERROR, "Unable to create RSA object for certificate generation.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
    
    if (!(bn = BN_new()))
    {
        write_out(PRINT_ERROR, "Unable to create RSA e bignum.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
    
    if (!BN_set_word(bn, RSA_F4))
    {
        write_out(PRINT_ERROR, "Unable to set RSA e bignum.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
    
    if (!RSA_generate_key_ex(rsa, bits, bn, 0))
    {
        write_out(PRINT_ERROR, "Unable to generate RSA key pair.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
    
    BN_free(bn);
    bn = 0;
    
    if (!(private_key = EVP_PKEY_new()))
    {
        write_out(PRINT_ERROR, "Unable to allocate RSA private key storage.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
    
    if (!EVP_PKEY_assign_RSA(private_key, rsa))
    {
        write_out(PRINT_ERROR, "Unable to assign RSA private key to certificate.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
    
    rsa = 0; //private_key should clean up the RSA object
    
    if (!X509_set_pubkey(cert, private_key))
    {
        write_out(PRINT_ERROR, "Unable to assign RSA public key to certificate.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
        
    *out_cert = cert;
    *out_private_key = private_key;
    
    return 1;
    
error_die:
    if (cert)
        X509_free(cert);
    if (private_key)
        EVP_PKEY_free(private_key);
    if (rsa)
        RSA_free(rsa);
    if (bn)
        BN_free(bn);
    
    *out_cert = 0;
    *out_private_key = 0;

    return 0;
}

int create_rsa_cert_v3(int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int days_valid, X509** out_cert, EVP_PKEY** out_private_key)
{
    return create_rsa_cert_v3_ex(bits, country, org_name, org_unit, common_name, serial, 0, 60 * 60 * 24 * days_valid, out_cert, out_private_key);
}

int create_ecdsa_cert_v3_ex(const char* ecdh_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int sec_start, int sec_end, X509** out_cert, EVP_PKEY** out_private_key)
{
    X509* cert = 0;
    EVP_PKEY* private_key = 0;
    EC_KEY* ecdh = 0;
    int nid;
    
    cert = create_cert_v3(country, org_name, org_unit, common_name, serial, sec_start, sec_end);
    if (!cert)
        goto error_die;
    
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
    
    if (!EC_KEY_generate_key(ecdh))
    {
        write_out(PRINT_ERROR, "Unable to generate ECDSA keys.");
        goto error_die;
    }
    
    if (!EC_KEY_check_key(ecdh))
    {
        write_out(PRINT_ERROR, "Generated ECDSA keys did not successfully validate.");
        goto error_die;
    }
    
    EC_KEY_set_asn1_flag(ecdh, OPENSSL_EC_NAMED_CURVE);
    
    if (!(private_key = EVP_PKEY_new()))
    {
        write_out(PRINT_ERROR, "Unable to allocate ECDSA private key storage.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
    
    if (!EVP_PKEY_assign_EC_KEY(private_key, ecdh))
    {
        write_out(PRINT_ERROR, "Unable to assign ECDSA private key to certificate.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        goto error_die;
    }
    
    if (!X509_set_pubkey(cert, private_key))
    {
        write_out(PRINT_ERROR, "Unable to assign ECDSA public key to certificate.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        goto error_die;
    }
        
    *out_cert = cert;
    *out_private_key = private_key;
    
    return 1;
    
error_die:
    if (cert)
        X509_free(cert);
    if (private_key)
        EVP_PKEY_free(private_key);
    if (ecdh)
        EC_KEY_free(ecdh);
    
    return 0;
}

int create_ecdsa_cert_v3(const char* ecdh_curve, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int days_valid, X509** out_cert, EVP_PKEY** out_private_key)
{
    return create_ecdsa_cert_v3_ex(ecdh_curve, country, org_name, org_unit, common_name, serial, 0, 60 * 60 * 24 * days_valid, out_cert, out_private_key);
}

int sign_x509_cert(X509* issuer, EVP_PKEY* issuer_private_key, X509* cert, const EVP_MD* hash)
{
    X509_NAME* name = 0;
    
    name = X509_get_subject_name(issuer);
    X509_set_issuer_name(cert, name);
    
    if (!X509_sign(cert, issuer_private_key, hash))
    {
        write_out(PRINT_ERROR, "Unable to sign certificate.");
        write_raise_level();
        print_ssl_error_stack(PRINT_ERROR);
        write_lower_level();
        
        return 0;
    }
    
    return 1;
}

int generate_rsa_ca(int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int days_valid, X509** out_cert, EVP_PKEY** out_private_key, const EVP_MD* hash)
{
    if (!create_rsa_cert_v3(bits, country, org_name, org_unit, common_name, serial, days_valid, out_cert, out_private_key))
        return 0;
    
    if (!add_x509_extension(*out_cert, NID_basic_constraints, "critical,CA:TRUE"))
    {
        X509_free(*out_cert);
        *out_cert = 0;
        EVP_PKEY_free(*out_private_key);
        *out_private_key = 0;
        return 0;
    }
    
    if (!sign_x509_cert(*out_cert, *out_private_key, *out_cert, hash))
    {
        X509_free(*out_cert);
        *out_cert = 0;
        EVP_PKEY_free(*out_private_key);
        *out_private_key = 0;
        return 0;
    }
    
    return 1;
}

//ensure that cert_stack and pk_stack are allocated depth space space to prevent overflows
int build_rsa_x509_chain_ex(int depth, X509** cert_stack, EVP_PKEY** pk_stack, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid, int set_ca, int set_server_auth)
{
    X509* parent_cert;
    EVP_PKEY* parent_pk;
    X509* current_cert;
    EVP_PKEY* current_pk;
    char icountry[CERT_NAME_SIZE];
    char iorg_name[CERT_NAME_SIZE];
    char iorg_unit[CERT_NAME_SIZE];
    char icomm_name[CERT_NAME_SIZE];
    int i;
    
    parent_cert = root_cert;
    parent_pk = root_pk;
    
    for (i = 0; i < (depth - 1); ++i)
    {
        snprintf(icountry, CERT_NAME_SIZE, "%s%d", ICOUNTRY, i);
        snprintf(iorg_name, CERT_NAME_SIZE, "%s%d", IORG_NAME, i);
        snprintf(iorg_unit, CERT_NAME_SIZE, "%s%d", IORG_UNIT, i);
        snprintf(icomm_name, CERT_NAME_SIZE, "%s%d", ICOMM_NAME, i);
        
        if (!create_rsa_cert_v3(bits, icountry, iorg_name, iorg_unit, icomm_name, rand(), 1, &current_cert, &current_pk))
        {
            write_out(PRINT_ERROR, "Unable to generate intermediate RSA CA certificate.");
            return 0;
        }
        
        switch (set_ca)
        {
            case SET_CA_FALSE:
                if (!add_x509_extension(current_cert, NID_basic_constraints, "CA:FALSE"))
                    write_out(PRINT_WARNING, "Unable to set RSA CA extension to FALSE!");
                break;
            case SET_CA_TRUE:
                if (!add_x509_extension(current_cert, NID_basic_constraints, "CA:TRUE")) //critical,CA:TRUE
                    write_out(PRINT_WARNING, "Unable to set RSA CA extension to TRUE!");
                break;
            case SET_CA_NONE:
            default:
                ;
        }
        
        if (!sign_x509_cert(parent_cert, parent_pk, current_cert, EVP_sha256()))
        {
            write_out(PRINT_ERROR, "Unable to sign intermidate RSA CA certificate.");
            return 0;
        }
        
        cert_stack[i] = current_cert;
        pk_stack[i] = current_pk;
        
        parent_cert = current_cert;
        parent_pk = current_pk;
    }
    
    if (!create_rsa_cert_v3(bits, country, org_name, org_unit, common_name, rand(), 1, &current_cert, &current_pk))
    {
        write_out(PRINT_ERROR, "Unable to generate final RSA certificate.");
        return 0;
    }
    
    if (alt_name)
        if (!add_x509_extension(current_cert, NID_subject_alt_name, alt_name))
            write_out(PRINT_WARNING, "Unable to add alt extension to certificate!");
        
    if (set_server_auth)
        if (!add_x509_extension(current_cert, NID_ext_key_usage, "serverAuth"))
            write_out(PRINT_WARNING, "Unable to add alt extension to certificate!");
    
    if (!sign_x509_cert(parent_cert, parent_pk, current_cert, EVP_sha256()))
    {
        write_out(PRINT_ERROR, "Unable to sign final RSA certificate.");
        return 0;
    }
    
    cert_stack[depth - 1] = current_cert;
    pk_stack[depth - 1] = current_pk;
    
    return 1;
}

int build_rsa_x509_chain(int depth, X509** cert_stack, EVP_PKEY** pk_stack, X509* root_cert, EVP_PKEY* root_pk, int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, const char* alt_name, int serial, int days_valid)
{
    return build_rsa_x509_chain_ex(depth, cert_stack, pk_stack, root_cert, root_pk, bits, country, org_name, org_unit, common_name, alt_name, serial, days_valid, SET_CA_TRUE, 1);
}

int generate_rsa_client_cert(int bits, const char* country, const char* org_name, const char* org_unit, const char* common_name, int serial, int days_valid, X509* ca_cert, EVP_PKEY* ca_private_key, X509** out_cert, EVP_PKEY** out_private_key, const EVP_MD* hash)
{
    if (!create_rsa_cert_v3(bits, country, org_name, org_unit, common_name, serial, days_valid, out_cert, out_private_key))
        return 0;
    
    if (!add_x509_extension(*out_cert, NID_ext_key_usage, "clientAuth"))
    {
        X509_free(*out_cert);
        *out_cert = 0;
        EVP_PKEY_free(*out_private_key);
        *out_private_key = 0;
        return 0;
    }
    
    if (!sign_x509_cert(ca_cert, ca_private_key, *out_cert, hash))
    {
        X509_free(*out_cert);
        *out_cert = 0;
        EVP_PKEY_free(*out_private_key);
        *out_private_key = 0;
        return 0;
    }
    
    return 1;
}