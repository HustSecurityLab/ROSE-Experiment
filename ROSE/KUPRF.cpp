#include <iostream>
#include "KUPRF.h"
#include <gmpxx.h>

extern "C"
{
#include <relic/relic.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
}

using namespace std;

int KUPRF::key_gen(unsigned char *out)
{
    bn_t ord, bn1;

    bn_new(ord);
    bn_new(bn1);

    ep_curve_get_ord(ord);
    bn_rand_mod(bn1, ord);

    bn_write_bin(out, 32, bn1);

    bn_free(ord);
    bn_free(bn1);

    return 0;
}

int KUPRF::Eval(unsigned char *out, const unsigned char *key, const string &keyword, const int id, OpType op)
{
    unsigned char buf[256];
    unsigned int op_data;
    SHA512_CTX ctx;
    ep_t ele;
    bn_t bn1;

    ep_new(ele);
    bn_new(bn1);

    switch (op)
    {
        case op_add:
            op_data = 0x0000ffff;
            break;
        case op_del:
            op_data = 0xffff0000;
            break;
        case op_srh:
            op_data = 0xffffffff;
            break;
        default:
            op_data = 0;
    }

    SHA512_Init(&ctx);
    SHA512_Update(&ctx, keyword.c_str(), keyword.size());
    SHA512_Update(&ctx, &id, sizeof(id));
    SHA512_Update(&ctx, &op_data, sizeof(op_data));
    SHA512_Final(buf, &ctx);

    ep_map(ele, buf, 64);

    bn_read_bin(bn1, (const unsigned char *) key, 32);

    ep_mul(ele, ele, bn1);

    //size is 33
    ep_write_bin(out, 33, ele, 1);

    ep_free(ele);
    bn_free(bn1);

    return 0;
}

int KUPRF::update_token(unsigned char *out, const unsigned char *K1, const unsigned char *K2)
{
    bn_t bn_K1, bn_K2, bn_out, b, c, ord;
    unsigned char buf[256];

    bn_new(bn_K1);
    bn_new(bn_K2);
    bn_new(bn_out);
    bn_new(b);
    bn_new(c);
    bn_new(ord);

    ep_curve_get_ord(ord);

    bn_read_bin(bn_K1, (const unsigned char *) K1, 32);
    bn_read_bin(bn_K2, (const unsigned char *) K2, 32);

    bn_gcd_ext(b, bn_out, c, bn_K1, ord);
    //bn4 is the inverse of bn1 mod order
    bn_mod(bn_out, bn_out, ord);

    bn_mul(bn_out, bn_out, bn_K2);

    bn_mod(bn_out, bn_out, ord);

    bn_write_bin(out, 32, bn_out);

    bn_free(bn_K1);
    bn_free(bn_K2);
    bn_free(bn_out);
    bn_free(b);
    bn_free(c);
    bn_free(ord);

    return 0;
}

int KUPRF::update(unsigned char *out, const unsigned char *token, const unsigned char *data)
{
    bn_t bn1;
    ep_t ele;

    bn_new(bn1);
    ep_new(ele);

    bn_read_bin(bn1, (const unsigned char *) token, 32);
    ep_read_bin(ele, (const unsigned char *) data, 33);

    ep_mul(ele, ele, bn1);

    ep_write_bin(out, 33, ele, 1);

    bn_free(bn1);
    ep_new(ele);
    return 0;
}

int KUPRF::mul(unsigned char *out, const unsigned char *K1, const unsigned char *K2)
{
    bn_t bn_K1, bn_K2, ord;
    unsigned char buf[256];

    bn_new(bn_K1);
    bn_new(bn_K2);
    bn_new(ord);

    ep_curve_get_ord(ord);

    bn_read_bin(bn_K1, (const unsigned char *) K1, 32);
    bn_read_bin(bn_K2, (const unsigned char *) K2, 32);
    bn_mul(bn_K1, bn_K1, bn_K2);
    bn_mod(bn_K1, bn_K1, ord);

    bn_write_bin(out, 32, bn_K1);

    bn_free(bn_K1);
    bn_free(bn_K2);
    bn_free(ord);

    return 0;
}

void KUPRF::clean()
{
    //core_clean();
}

void KUPRF::init()
{
   core_init();
   ep_param_set(NIST_P256);
}
