#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <gmp.h>

extern "C"
{
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
}

#include <experimental/filesystem>
#include "trapdoor_permutation.h"
#include "sophos.h"

using std::cout;
using std::endl;
using std::string;
using std::vector;

int SophosClient::Setup()
{
    TrapdoorPermutation tdp;

    RAND_bytes(this->Ks, 16);
    RAND_bytes(this->prf_key, 16);

    this->keyword_counters.clear();

    tdp.generate_key_pair(&(this->tdp_pk), &(this->tdp_sk));

    return 1;
}

int SophosClient::update(const std::string &keyword, unsigned char *label)
{
    unsigned char _data[288 + sizeof(size_t)], _st[256 + sizeof(size_t)];
    unsigned char *kw = _data, *st = _data + 32;
    unsigned int counter = -1;
    TrapdoorPermutation tdp;

    memset(_data, 0, 288 + sizeof(size_t));
    memset(_st, 0, 256 + sizeof(size_t));
    this->_prf(keyword, kw);

    if (this->keyword_counters.find(keyword) != this->keyword_counters.end())
        counter = keyword_counters[keyword];

    counter++;
    keyword_counters[keyword] = counter;

    this->_gen_initial_st(keyword, _st);

    tdp.permutate_private(&(this->tdp_sk), &(this->tdp_pk), _st, counter + 1, st);

    SHA256(_data, 288, label);

    return 1;
}

int SophosClient::_prf(const std::string &keyword, unsigned char *kw)
{
    unsigned int out_len;
    HMAC_CTX *ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, this->Ks, 16, EVP_sha256(), nullptr);
    HMAC_Update(ctx, (const unsigned char *) keyword.c_str(), keyword.size());
    HMAC_Final(ctx, kw, &out_len);

    HMAC_CTX_free(ctx);

    return 1;
}

int SophosClient::_gen_initial_st(const std::string &keyword, unsigned char *st)
{
    unsigned int len;
    HMAC_CTX *ctx;

    for (int i = 0; i < 4; i++)
    {
        ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, this->prf_key, 16, EVP_sha512(), nullptr);
        HMAC_Update(ctx, (const unsigned char *) keyword.c_str(), keyword.size());
        HMAC_Update(ctx, (const unsigned char *) &i, sizeof(i));
        HMAC_Final(ctx, st + i * 64, &len);
        HMAC_CTX_free(ctx);
    }

    *(size_t *) (st + 256) = 256;

    return 1;
}

int SophosClient::trapdoor(const std::string &keyword, unsigned char *kw, unsigned char *st, unsigned int &counter)
{
    unsigned char _st[256 + sizeof(size_t)];
    TrapdoorPermutation tdp;

    memset(_st, 0, 256 + sizeof(size_t));

    this->_prf(keyword, kw);
    counter = this->keyword_counters[keyword];

    this->_gen_initial_st(keyword, _st);

    tdp.permutate_private(&(this->tdp_sk), &(this->tdp_pk), _st, counter + 1, st);

    return 1;
}

int SophosClient::get_pk(TdpPK *pk)
{
    mpz_set(pk->e, this->tdp_pk.e);
    mpz_set(pk->n, this->tdp_pk.n);

    return 1;
}

void SophosClient::dump_data(FILE *f_out)
{
    char buf1[512];
    unsigned long counter_len;
    size_t countp;

    fwrite(this->Ks, sizeof(char), 16, f_out);
    fwrite(this->prf_key, sizeof(char), 16, f_out);

    counter_len = this->keyword_counters.size();
    fwrite(&counter_len, sizeof(char), sizeof(counter_len), f_out);

    for (auto &itr:this->keyword_counters)
    {
        auto str_len = itr.first.size();
        unsigned int counter = itr.second;

        fwrite(&str_len, sizeof(char), sizeof(str_len), f_out);
        fwrite(itr.first.c_str(), sizeof(char), str_len, f_out);

        fwrite(&counter, sizeof(char), sizeof(counter), f_out);
    }

    //dump pk
    mpz_export(buf1, &countp, 1, sizeof(char), 0, 0, this->tdp_pk.e);
    fwrite(&countp, sizeof(char), sizeof(size_t), f_out);
    fwrite(buf1, sizeof(char), countp, f_out);

    mpz_export(buf1, &countp, 1, sizeof(char), 0, 0, this->tdp_pk.n);
    fwrite(&countp, sizeof(char), sizeof(size_t), f_out);
    fwrite(buf1, sizeof(char), countp, f_out);

    //dump sk
    mpz_export(buf1, &countp, 1, sizeof(char), 0, 0, this->tdp_sk.d);
    fwrite(&countp, sizeof(char), sizeof(size_t), f_out);
    fwrite(buf1, sizeof(char), countp, f_out);
    mpz_export(buf1, &countp, 1, sizeof(char), 0, 0, this->tdp_sk.f);
    fwrite(&countp, sizeof(char), sizeof(size_t), f_out);
    fwrite(buf1, sizeof(char), countp, f_out);
    mpz_export(buf1, &countp, 1, sizeof(char), 0, 0, this->tdp_sk.p);
    fwrite(&countp, sizeof(char), sizeof(size_t), f_out);
    fwrite(buf1, sizeof(char), countp, f_out);
    mpz_export(buf1, &countp, 1, sizeof(char), 0, 0, this->tdp_sk.q);
    fwrite(&countp, sizeof(char), sizeof(size_t), f_out);
    fwrite(buf1, sizeof(char), countp, f_out);

    //gmp_printf("e:%Zd\nn:%Zd\nd:%Zd\nf:%Zd\np:%Zd\nq:%Zd\n\n\n",
    //           tdp_pk.e, tdp_pk.n, tdp_sk.d, tdp_sk.f, tdp_sk.p, tdp_sk.q);
}

void SophosClient::load_data(FILE *f_in)
{
    char buf1[512];
    unsigned long counter_len;
    unsigned long str_len;
    size_t countp;

    this->keyword_counters.clear();

    fread(this->Ks, sizeof(char), 16, f_in);
    fread(this->prf_key, sizeof(char), 16, f_in);

    fread(&counter_len, sizeof(char), sizeof(counter_len), f_in);

    for (unsigned long i = 0; i < counter_len; i++)
    {
        string keyword;
        unsigned int counter;

        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);
        buf1[str_len] = 0;
        keyword = buf1;

        fread(&counter, sizeof(char), sizeof(counter), f_in);

        this->keyword_counters[keyword] = counter;
    }

    fread(&countp, sizeof(char), sizeof(size_t), f_in);
    fread(buf1, sizeof(char), countp, f_in);
    mpz_import(this->tdp_pk.e, countp, 1, sizeof(char), 0, 0, buf1);

    fread(&countp, sizeof(char), sizeof(size_t), f_in);
    fread(buf1, sizeof(char), countp, f_in);
    mpz_import(this->tdp_pk.n, countp, 1, sizeof(char), 0, 0, buf1);

    fread(&countp, sizeof(char), sizeof(size_t), f_in);
    fread(buf1, sizeof(char), countp, f_in);
    mpz_import(this->tdp_sk.d, countp, 1, sizeof(char), 0, 0, buf1);

    fread(&countp, sizeof(char), sizeof(size_t), f_in);
    fread(buf1, sizeof(char), countp, f_in);
    mpz_import(this->tdp_sk.f, countp, 1, sizeof(char), 0, 0, buf1);

    fread(&countp, sizeof(char), sizeof(size_t), f_in);
    fread(buf1, sizeof(char), countp, f_in);
    mpz_import(this->tdp_sk.p, countp, 1, sizeof(char), 0, 0, buf1);

    fread(&countp, sizeof(char), sizeof(size_t), f_in);
    fread(buf1, sizeof(char), countp, f_in);
    mpz_import(this->tdp_sk.q, countp, 1, sizeof(char), 0, 0, buf1);

    //gmp_printf("e:%Zd\nn:%Zd\nd:%Zd\nf:%Zd\np:%Zd\nq:%Zd\n\n\n",
    //           tdp_pk.e, tdp_pk.n, tdp_sk.d, tdp_sk.f, tdp_sk.p, tdp_sk.q);
}


int SophosServer::Setup()
{
    this->cipher_db.clear();

    return 1;
}

int SophosServer::save(const unsigned char *label,  const unsigned char *ciphertext)
{
    string _label, _value;

    _label.assign((char *) label, 32);
    _value.assign((char *) ciphertext, 32);

    this->cipher_db[_label] = _value;

    return 1;
}

int SophosServer::search(TdpPK *pk, const unsigned char *kw, const unsigned char *st, unsigned int counter,
                         std::vector<std::string> &out)
{
    unsigned char buf1[288 + sizeof(size_t)], _st[256 + sizeof(size_t)], label[32];
    TrapdoorPermutation tdp;

    memset(buf1, 0, 288 + sizeof(size_t));
    memcpy(buf1, kw, 32);
    memcpy(_st, st, 256 + sizeof(size_t));

    for (unsigned int i = 0; i <= counter; i++)
    {
        string _l;

        memcpy(buf1 + 32, _st, 256 + sizeof(size_t));
        SHA256(buf1, 288, label);
        _l.assign((char *) label, 32);
        if (this->cipher_db.find(_l) != this->cipher_db.end())
        {
            out.emplace_back(this->cipher_db[_l]);
            this->cipher_db.erase(_l);
        }
        tdp.permutate_public(pk, buf1 + 32, _st);
    }

    return 1;
}

void SophosServer::dump_data(FILE *f_out)
{
    size_t db_len = this->cipher_db.size();
    char buf1[512];

    fwrite(&db_len, sizeof(size_t), 1, f_out);

    for (auto &itr:this->cipher_db)
    {
        unsigned long str_len = itr.first.size();

        fwrite(&str_len, sizeof(size_t), 1, f_out);
        fwrite(itr.first.c_str(), sizeof(char), str_len, f_out);

        str_len = itr.second.size();

        fwrite(&str_len, sizeof(size_t), 1, f_out);
        fwrite(itr.second.c_str(), sizeof(char), str_len, f_out);
    }
}

void SophosServer::load_data(FILE *f_in)
{
    unsigned long db_len;
    char buf1[512];
    size_t str_len;

    this->cipher_db.clear();

    fread(&db_len, sizeof(char), sizeof(db_len), f_in);

    for (unsigned long i = 0; i < db_len; i++)
    {
        string l, v;
        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);
        l.assign(buf1, str_len);

        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);
        v.assign(buf1, str_len);

        this->cipher_db[l] = v;
    }
}
