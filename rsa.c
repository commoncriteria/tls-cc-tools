#include "rsa.h"

#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif


int make_root_ca()
{
    return -1;
}