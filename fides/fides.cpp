#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <set>
#include <string>
#include <list>
#include <iostream>
#include <experimental/filesystem>

extern "C"
{
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
}

#include "fides.h"

using std::string;
using std::vector;
using std::unordered_map;
using std::cout;
using std::endl;
using std::set;
using std::list;

int FidesClient::Setup()
{
    RAND_bytes(this->K_master, 16);

    this->sophos_clnt.Setup();
    this->Tw.clear();

    return 1;
}

int
FidesClient::update(std::string &label, std::string &cipher, const std::string &keyword, const int ind, FidesOp op)
{
    unsigned char Kw[32], _plain[16], _cipher[48], iv[16], _label[256];
    AES_KEY aes_key;
    string keyword_with_tw;
    char tw[16];

    this->_gen_kw(keyword, Kw);

    sprintf(tw, "%u", this->Tw[keyword]);

    keyword_with_tw = keyword + tw;

    this->sophos_clnt.update(keyword_with_tw, _label);
    label.assign((const char *) _label, 32);

    memset(_plain, 0, 16);
    memcpy((char *) _plain, (char *) &ind, sizeof(int));

    if (op == Fides_Add)
        _plain[15] = 1;
    else
        _plain[15] = 0;

    memset(_cipher, 0, 32);
    AES_set_encrypt_key(Kw, 128, &aes_key);
    RAND_bytes(iv, 16);
    memcpy(_cipher, iv, 16);

    AES_cbc_encrypt(_plain, _cipher + 16, 16, &aes_key, iv, AES_ENCRYPT);
    cipher.assign((const char *) _cipher, 32);

    return 1;
}

int FidesClient::_gen_kw(const std::string &keyword, unsigned char *Kw)
{
    unsigned char buf1[80];

    memcpy(buf1, this->K_master, 16);
    SHA256((unsigned char *) keyword.c_str(), keyword.size(), buf1 + 16);
    memset(buf1 + 48, 0, 16);
    if (this->Tw.find(keyword) == this->Tw.end())
        this->Tw[keyword] = 0;

    sprintf((char *) buf1 + 48, "%u", this->Tw[keyword]);

    SHA256(buf1, 64, Kw);

    return 1;
}

int FidesClient::search_stage1(std::string &kw, std::string &st, unsigned int &counter, const std::string &keyword)
{
    unsigned char Kw[32], _kw[256], _st[512];
    string keyword_with_tw;
    char tw[16];

    this->_gen_kw(keyword, Kw);

    sprintf(tw, "%u", this->Tw[keyword]);
    keyword_with_tw = keyword + tw;

    this->sophos_clnt.trapdoor(keyword_with_tw, _kw, _st, counter);
    kw.assign((const char *) _kw, 32);
    st.assign((const char *) _st, 256 + sizeof(size_t));

    return 1;
}

int FidesClient::search_stage2(std::vector<int> &out, const std::string &keyword,
                               const std::vector<std::string> &enc_data)
{
    unsigned char Kw[32], _plain[16], iv[16];
    set<int> _ind_to_del;
    vector<int> _temp_ret;
    AES_KEY aes_key;
    unsigned int count;
    string value;

    _temp_ret.reserve(300000);

    this->_gen_kw(keyword, Kw);
    AES_set_decrypt_key(Kw, 128, &aes_key);

    for (const auto &a:enc_data)
    {
        memcpy(iv, a.c_str(), 16);
        AES_cbc_encrypt((unsigned char *) a.c_str() + 16, _plain, 16, &aes_key, iv, AES_DECRYPT);

        if (_plain[15] == 0)
            _ind_to_del.emplace(*((int *) _plain));
        else
            _temp_ret.emplace_back(*((int *) _plain));
    }

    for (auto it = _temp_ret.begin(); it != _temp_ret.end(); it++)
    {
        if (_ind_to_del.find(*it) == _ind_to_del.end())
        {
            out.emplace_back(*it);
        }
    }

    this->Tw[keyword] = this->Tw[keyword] + 1;

    return 1;
}

int FidesClient::get_pk(TdpPK *pk)
{
    return this->sophos_clnt.get_pk(pk);
}

int FidesClient::update_after_search(const std::string &keyword, const std::vector<int> &inds,
                                     std::vector<std::string> &vec_label, std::vector<std::string> &vec_cipher)
{
    string label, cipher;
    for (auto &itr:inds)
    {
        this->update(label, cipher, keyword, itr, Fides_Add);
        vec_label.emplace_back(label);
        vec_cipher.emplace_back(cipher);
    }

    return 0;
}

void FidesClient::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");
    unsigned long Tw_len = this->Tw.size();

    fwrite(&Tw_len, sizeof(char), sizeof(Tw_len), f_out);

    for (auto &itr:this->Tw)
    {
        unsigned long str_len = itr.first.size();
        unsigned int tw = itr.second;

        fwrite(&str_len, sizeof(char), sizeof(str_len), f_out);
        fwrite(itr.first.c_str(), sizeof(char), str_len, f_out);

        fwrite(&tw, sizeof(char), sizeof(tw), f_out);
    }

    fwrite(this->K_master, sizeof(char), 16, f_out);

    this->sophos_clnt.dump_data(f_out);

    fclose(f_out);
}

void FidesClient::load_data(const string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");
    char buf1[512];
    unsigned long tw_len, str_len;
    unsigned int tw;

    this->Tw.clear();

    fread(&tw_len, sizeof(char), sizeof(tw_len), f_in);

    for (unsigned long i = 0; i < tw_len; i++)
    {
        string keyword;

        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);
        buf1[str_len] = 0;

        keyword = buf1;

        fread(&tw, sizeof(char), sizeof(tw), f_in);

        this->Tw[keyword] = tw;
    }

    fread(this->K_master, sizeof(char), 16, f_in);

    this->sophos_clnt.load_data(f_in);

    fclose(f_in);
}


int FidesServer::Setup()
{
    this->sophos_srv.Setup();
    return 1;
}

int FidesServer::save(const std::string &label, const std::string &value)
{
    this->sophos_srv.save((const unsigned char *) label.c_str(),
                          (const unsigned char *) value.c_str());
    return 1;
}

int FidesServer::search(std::vector<std::string> &out, TdpPK *pk, const std::string &kw, const std::string &st,
                        unsigned int counter)
{
    this->sophos_srv.search(pk, (const unsigned char *) kw.c_str(), (const unsigned char *) st.c_str(), counter, out);
    return 1;
}

int FidesServer::save(vector<std::string> &labels, vector<std::string> &ciphers)
{
    int count = labels.size();

    for (int i = 0; i < count; i++)
    {
        this->sophos_srv.save((unsigned char *) labels[i].c_str(), (unsigned char *) ciphers[i].c_str());
    }

    return 0;
}

void FidesServer::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");

    this->sophos_srv.dump_data(f_out);

    fclose(f_out);
}

void FidesServer::load_data(const string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");

    this->sophos_srv.load_data(f_in);

    fclose(f_in);
}
