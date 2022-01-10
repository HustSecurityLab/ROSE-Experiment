#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C"
{
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
}

#include <experimental/filesystem>
#include "rose_client.h"

using namespace std;

RoseClient::RoseClient()
{
    memset(this->Kse, 0, 16);
}

RoseClient::~RoseClient()
{
}


int RoseClient::setup(bool init)
{
    RAND_bytes(this->Kse, 16);

    return 0;
}

int RoseClient::encrypt(std::string &L_out, std::string &cip_R, std::string &cip_D, std::string &cip_C, OpType op,
                        const std::string &keyword, const int ind)
{
    unsigned char buf1[256], buf2[256], buf_D[256], buf_K1[256], buf_S1[256], buf_R[256];
    OpType op1;
    unsigned char op_ch;
    string s_K1, s_S1, s_R1, value;
    int id1;
    KUPRF kuprf;

    if (op == op_add)
        op_ch = 0x0f;
    else if (op == op_del)
        op_ch = 0xf0;
    else
        op_ch = 0xff;

    if (this->LastK.find(keyword) == this->LastK.end())
    {
        RAND_bytes(buf_S1, 16);
        kuprf.key_gen(buf_K1);
        s_S1.assign((char *) buf_S1, 16);
        s_K1.assign((char *) buf_K1, 32);
        this->LastK[keyword] = s_K1;
        this->LastS[keyword] = s_S1;
    }
    else
    {
        s_K1 = this->LastK[keyword];
        s_S1 = this->LastS[keyword];
        memcpy(buf_K1, (const unsigned char *) s_K1.c_str(), 32);
        memcpy(buf_S1, (const unsigned char *) s_S1.c_str(), 16);
    }

    RAND_bytes(buf_R, 16);
    cip_R.assign((const char *) buf_R, 16);

    kuprf.Eval(buf2, buf_K1, keyword, ind, op);
    Hash_G(buf1, buf2, buf_R);

    L_out.assign((const char *) buf1, 32);

    Enc_id(cip_C, ind);

    PRF_F(buf1, buf_S1, keyword, ind, op);
    Hash_H(buf_D, 1 + 32 * 2 + 33, buf1, buf_R);
    buf_D[0] = buf_D[0] ^ op_ch;

    if (this->LastOp.find(keyword) != this->LastOp.end())
    {
        id1 = this->LastId[keyword];
        op1 = this->LastOp[keyword];
        s_R1 = this->LastR[keyword];

        kuprf.Eval(buf1, buf_K1, keyword, id1, op1);
        Hash_G(buf2, buf1, (const unsigned char *) s_R1.c_str());
        Xor(32, buf_D + 1 + 33, buf2, buf_D + 1 + 33);

        PRF_F(buf1, buf_S1, keyword, id1, op1);
        Xor(32, buf_D + 1 + 33 + 32, buf1, buf_D + 1 + 33 + 32);

        if (op == op_del)
        {
            kuprf.Eval(buf1, buf_K1, keyword, ind, op_add);
            Xor(33, buf_D + 1, buf1, buf_D + 1);
        }
    }


    LastOp[keyword] = op;
    LastId[keyword] = ind;
    LastR[keyword] = cip_R;

    cip_D.assign((const char *) buf_D, 1 + 33 + 32 * 2);

    return 0;
}

int RoseClient::Enc_id(std::string &C_out, const int id)
{
    AES_KEY aes_key;
    unsigned char iv[16], iv1[16];
    unsigned char cipher_out[CIPHER_SIZE];
    unsigned char plain[CIPHER_SIZE - 16];

    RAND_bytes(iv, 16);
    memcpy(iv1, iv, 16);

    memset(plain, 0, CIPHER_SIZE - 16);
    strncpy((char *) plain, (char*)&id, 4);

    AES_set_encrypt_key(this->Kse, 128, &aes_key);
    AES_cbc_encrypt(plain, cipher_out, CIPHER_SIZE - 16, &aes_key, iv, AES_ENCRYPT);

    memcpy(cipher_out + CIPHER_SIZE - 16, iv1, 16);
    C_out.assign((char *) cipher_out, CIPHER_SIZE);
    return 0;
}

int
RoseClient::trapdoor(const string &keyword, string &tpd_L, string &tpd_T, string &cip_L, string &cip_R,
                     string &cip_D, string &cip_C)
{
    string s_R1, s_K1, s_S1,  s_K, s_S;
    int s_id1, ind_0;
    OpType op1;
    unsigned char buf1[256], buf2[256], buf_D[256], buf_R[256], buf_K1[256], buf_S1[256];
    unsigned char buf_K[256], buf_S[256];
    KUPRF kuprf;

    ind_0 = -1;

    s_id1 = this->LastId[keyword];
    op1 = this->LastOp[keyword];
    s_R1 = this->LastR[keyword];

    s_K1 = this->LastK[keyword];
    s_S1 = this->LastS[keyword];

    memcpy(buf_K1, (const unsigned char *) s_K1.c_str(), 32);
    memcpy(buf_S1, (const unsigned char *) s_S1.c_str(), 16);

    kuprf.Eval(buf1, buf_K1, keyword, s_id1, op1);
    Hash_G(buf2, buf1, (const unsigned char *) s_R1.c_str());

    memcpy(buf_D + 1 + 33, buf2, 32);
    tpd_L.assign((const char *) buf2, 32);

    PRF_F(buf1, buf_S1, keyword, s_id1, op1);
    memcpy(buf_D + 1 + 33 + 32, buf1, 32);
    tpd_T.assign((const char *) buf1, 32);

    kuprf.key_gen(buf_K);
    RAND_bytes(buf_S, 16);
    s_K.assign((const char *) buf_K, 32);
    s_S.assign((const char *) buf_S, 16);

    RAND_bytes(buf_R, 16);
    cip_R.assign((const char *) buf_R, 16);

    kuprf.update_token(buf_D + 1, buf_K, buf_K1);

    memset(buf1, 0, 64);
    kuprf.Eval(buf2, buf_K, keyword, ind_0, op_srh);
    Hash_G(buf1, buf2, buf_R);
    cip_L.assign((const char *) buf1, 32);

    PRF_F(buf1, buf_S, keyword, ind_0, op_srh);
    Hash_H(buf2, 1 + 32 * 2 + 33, buf1, buf_R);
    buf_D[0] = 0xff;
    Xor(1 + 32 * 2 + 33, buf_D, buf2, buf_D);

    Enc_id(cip_C, ind_0);

    LastOp[keyword] = op_srh;
    LastId[keyword] = ind_0;
    LastR[keyword] = cip_R;

    LastK[keyword] = s_K;
    LastS[keyword] = s_S;

    cip_D.assign((const char *) buf_D, 1 + 32 * 2 + 33);

    return 0;
}

int RoseClient::decrypt(vector<int> &out, const string &keyword, const std::vector<std::string> &in)
{
    if (in.empty())
    {
        this->LastOp.erase(keyword);
        this->LastK.erase(keyword);
        this->LastId.erase(keyword);
        this->LastR.erase(keyword);
        this->LastS.erase(keyword);
    }
    for (auto itr = in.begin(); itr != in.end(); itr++)
    {
        int id;
        Dec_id(id, *itr);
        out.emplace_back(id);
    }

    return 0;
}

int RoseClient::Dec_id(int &id_out, const string &C_in)
{
    AES_KEY aes_key;
    unsigned char iv[16];
    unsigned char plain_out[CIPHER_SIZE];

    memset(plain_out, 0, CIPHER_SIZE);
    memcpy(iv, C_in.c_str() + CIPHER_SIZE - 16, 16);

    AES_set_decrypt_key(this->Kse, 128, &aes_key);
    AES_cbc_encrypt((const unsigned char *) C_in.c_str(), plain_out, CIPHER_SIZE - 16, &aes_key, iv, AES_DECRYPT);

    memcpy(&id_out, plain_out, 4);

    return 0;
}

void RoseClient::save_data(const std::string &fname)
{
    FILE *f_out = fopen(fname.c_str(), "wb");

    size_t size;

    fwrite(this->Kse, sizeof(char), 16, f_out);

    size = this->LastK.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr :this->LastK)
    {
        save_string(f_out, itr.first);
        save_string(f_out, itr.second);
    }

    size = this->LastS.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr :this->LastS)
    {
        save_string(f_out, itr.first);
        save_string(f_out, itr.second);
    }

    size = this->LastR.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr :this->LastR)
    {
        save_string(f_out, itr.first);
        save_string(f_out, itr.second);
    }

    size = this->LastId.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr :this->LastId)
    {
        int id = itr.second;
        save_string(f_out, itr.first);
        fwrite(&id, sizeof(int), 1, f_out);
    }

    size = this->LastOp.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr :this->LastOp)
    {
        save_string(f_out, itr.first);
        fwrite(&(itr.second), sizeof(itr.second), 1, f_out);
    }

    fclose(f_out);
}

void RoseClient::load_data(const std::string &fname )
{
    FILE *f_in = fopen(fname.c_str(), "rb");

    size_t size;

    fread(this->Kse, sizeof(char), 16, f_in);

    fread(&size, sizeof(size), 1, f_in);
    this->LastK.clear();
    for (size_t i = 0; i < size; i++)
    {
        string str1, str2;
        str1 = load_string(f_in);
        str2 = load_string(f_in);
        this->LastK[str1] = str2;
    }

    fread(&size, sizeof(size), 1, f_in);
    this->LastS.clear();
    for (size_t i = 0; i < size; i++)
    {
        string str1, str2;
        str1 = load_string(f_in);
        str2 = load_string(f_in);
        this->LastS[str1] = str2;
    }

    fread(&size, sizeof(size), 1, f_in);
    this->LastR.clear();
    for (size_t i = 0; i < size; i++)
    {
        string str1, str2;
        str1 = load_string(f_in);
        str2 = load_string(f_in);
        this->LastR[str1] = str2;
    }

    fread(&size, sizeof(size), 1, f_in);
    this->LastId.clear();
    for (size_t i = 0; i < size; i++)
    {
        int id;
        string str1;
        str1 = load_string(f_in);
        fread(&id, sizeof(int), 1, f_in);
        this->LastId[str1] = id;
    }

    fread(&size, sizeof(size), 1, f_in);
    this->LastOp.clear();
    for (size_t i = 0; i < size; i++)
    {
        string str1 = load_string(f_in);
        OpType op;
        fread(&op, sizeof(op), 1, f_in);

        this->LastOp[str1] = op;
    }

    fclose(f_in);
}
