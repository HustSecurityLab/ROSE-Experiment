#ifndef SOPHOS_H
#define SOPHOS_H

#include <unordered_map>
#include <string>
#include <vector>
#include "trapdoor_permutation.h"

extern "C"
{
#include <cstdio>
};

class SophosClient
{
public:
    SophosClient() = default;

    ~SophosClient() = default;

    int Setup();

    int update(const std::string &keyword, unsigned char *label);

    int trapdoor(const std::string &keyword, unsigned char *kw, unsigned char *st, unsigned int &counter);

    int get_pk(TdpPK *pk);

    void dump_data(FILE *f_out);

    void load_data(FILE *f_in);


private:
    unsigned char Ks[16];
    unsigned char prf_key[16];
    std::unordered_map<std::string, unsigned int> keyword_counters;
    TdpPK tdp_pk;
    TdpSK tdp_sk;

    int _prf(const std::string &keyword, unsigned char *kw);

    int _gen_initial_st(const std::string &keyword, unsigned char *st);
};

class SophosServer
{
public:
    SophosServer() = default;

    ~SophosServer() = default;

    int Setup();

    int save(const unsigned char *label, const unsigned char *ciphertext);

    int search(TdpPK *pk, const unsigned char *kw, const unsigned char *st, unsigned int counter,
               std::vector<std::string> &out);

    void dump_data(FILE *f_out);

    void load_data(FILE *f_in);

private:
    std::unordered_map<std::string, std::string> cipher_db;
};

#endif
