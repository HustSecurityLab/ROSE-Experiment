#ifndef FIDES_H
#define FIDES_H

#include <string>
#include <vector>
#include <unordered_map>
#include "sophos.h"

class FidesClient;

enum FidesOp
{
    Fides_Add,
    Fides_Del
};

struct ParallelDATA
{
    FidesClient *_this;
    std::string *keyword;
    std::vector<std::string> *inds;
    int sno;
};

class FidesClient
{
public:
    FidesClient() = default;

    ~FidesClient() = default;

    int Setup();

    int update(std::string &label, std::string &cipher, const std::string &keyword, const int ind, FidesOp op);

    int search_stage1(std::string &kw, std::string &st, unsigned int &counter, const std::string &keyword);

    int
    search_stage2(std::vector<int> &out, const std::string &keyword, const std::vector<std::string> &enc_data);

    int get_pk(TdpPK *pk);

    int update_after_search(const std::string &keyword, const std::vector<int> &inds,
                            std::vector<std::string> &vec_label, std::vector<std::string> &vec_cipher);

    void dump_data(const std::string &filename = "fides_clnt_data");

    void load_data(const std::string &filename = "fides_clnt_data");

private:
    SophosClient sophos_clnt;
    std::unordered_map<std::string, unsigned int> Tw;
    unsigned char K_master[16];

    int _gen_kw(const std::string &keyword, unsigned char *Kw);
};

class FidesServer
{
public:
    FidesServer() = default;

    ~FidesServer() = default;

    int Setup();

    int save(const std::string &label, const std::string &value);

    int save(std::vector<std::string> &labels, std::vector<std::string> &ciphers);

    int search(std::vector<std::string> &out, TdpPK *pk, const std::string &kw, const std::string &st,
               unsigned int counter);

    void dump_data(const std::string &filename = "fides_srv_data");

    void load_data(const std::string &filename = "fides_srv_data");

private:
    SophosServer sophos_srv;
};
#endif
