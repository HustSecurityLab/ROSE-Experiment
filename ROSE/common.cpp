#include "common.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <gmpxx.h>

extern "C"
{
#include <relic/relic.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
};


using namespace std;

int PRF_F(unsigned char *out, const unsigned char *key, const string &keyword, const int id, OpType op)
{
    unsigned int out_len;
    unsigned int op_data;
    HMAC_CTX *ctx = HMAC_CTX_new();

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

    HMAC_Init_ex(ctx, key, 16, EVP_sha3_256(), nullptr);
    HMAC_Update(ctx, (const unsigned char *) keyword.c_str(), keyword.size());
    HMAC_Update(ctx, (const unsigned char *) &id, sizeof(id));
    HMAC_Update(ctx, (const unsigned char *) &op_data, sizeof(op_data));
    HMAC_Final(ctx, out, &out_len);
    HMAC_CTX_free(ctx);

    return 0;
}

int Hash_H(unsigned char *out, int out_len, const unsigned char *in1, const unsigned char *R)
{
    unsigned char tmp_buf[128];
    int hash_len = out_len;
    unsigned char sha_buf[64];
    int ret_len = 0;
    int dif;

    memcpy(tmp_buf, in1, 32);
    memcpy(tmp_buf + 32, R, 16);

    SHA512((const unsigned char *) tmp_buf, 32 + 16, sha_buf);

    while (ret_len < hash_len)
    {
        dif = hash_len - ret_len;
        if (dif >= 64)
        {
            memcpy(out + ret_len, sha_buf, 64);
            ret_len += 64;
        }
        else
        {
            memcpy(out + ret_len, sha_buf, dif);
            ret_len += dif;
        }
        memcpy(tmp_buf, sha_buf, 64);
        memcpy(tmp_buf + 64, R, 16);
        SHA512(tmp_buf, 64 + 16, sha_buf);
    }

    return 0;
}

int print_hex(unsigned char *data, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", data[i]);
    }
    printf("\n");
    return 0;
}

int Hash_G(unsigned char *out, const unsigned char *data, const unsigned char *R)
{
    unsigned char buf[256];
    unsigned int len;

    EVP_MD_CTX *evpCtx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(evpCtx, EVP_sha256(), NULL);
    EVP_DigestUpdate(evpCtx, data, 33);
    EVP_DigestUpdate(evpCtx, R, 16);
    EVP_DigestFinal_ex(evpCtx, buf, &len);

    EVP_MD_CTX_free(evpCtx);

    /*SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, 33);
    SHA256_Update(&ctx, R, 16);
    SHA256_Final(buf, &ctx);*/

    memcpy(out, buf, 32);

    return 0;
}


int Xor(int _bytes, const unsigned char *in1, const unsigned char *in2, unsigned char *out)
{
    int unit = sizeof(long long);
    int unit_num = _bytes / unit;
    const long long *_in1 = (const long long *) in1;
    const long long *_in2 = (const long long *) in2;
    long long *_out = (long long *) out;
    int start;

    if (_out == _in1)
    {
        for (int i = 0; i < unit_num; i++)
        {
            _out[i] ^= _in2[i];
        }

        start = unit_num * unit;
        for (int i = 0; i < _bytes - start; i++)
        {
            out[i + start] ^= in2[i + start];
        }
    }
    else if (_out == _in2)
    {
        for (int i = 0; i < unit_num; i++)
        {
            _out[i] ^= _in1[i];
        }

        start = unit_num * unit;
        for (int i = 0; i < _bytes - start; i++)
        {
            out[i + start] ^= in1[i + start];
        }
    }
    else
    {
        for (int i = 0; i < unit_num; i++)
        {
            _out[i] = _in1[i] ^ _in2[i];
        }

        start = unit_num * unit;

        for (int i = 0; i < _bytes - start; i++)
        {
            out[i + start] = in1[i + start] ^ in2[i + start];
        }
    }

    return 0;
}

void save_string(FILE *f_out, const string &str)
{
    size_t size = str.size();

    fwrite(&size, sizeof(size), 1, f_out);
    fwrite(str.c_str(), sizeof(char), size, f_out);
}

std::string load_string(FILE *f_in)
{
    char buf[512];
    string str;
    size_t size;

    fread(&size, sizeof(size), 1, f_in);
    fread(buf, sizeof(char), size, f_in);
    str.assign(buf, size);

    return str;
}