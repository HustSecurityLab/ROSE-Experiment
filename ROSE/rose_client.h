#ifndef SSE_CLIENT_H
#define SSE_CLIENT_H

#include <string>
#include <map>
#include <vector>
#include <array>
#include "common.h"
#include "KUPRF.h"

//Key Size of KUPRF: 32
//Result Size of KUPRF: 33
class RoseClient
{
public:
    RoseClient();

    ~RoseClient();

    int setup(bool init=false);

    int encrypt(std::string &L_out, std::string &cip_R, std::string &cip_D, std::string &cip_C, OpType op,
                const std::string &keyword, const int ind);

    int trapdoor(const std::string &keyword, std::string &tpd_L, std::string &tpd_T, std::string &cip_L,
                 std::string &cip_R, std::string &cip_D, std::string &cip_C);

    int decrypt(std::vector<int> &out, const std::string &keyword, const std::vector<std::string> &in);

    void save_data(const std::string &fname = "rose_client_data.dat");

    void load_data(const std::string &fname = "rose_client_data.dat");


private:
    unsigned char Kse[16];
    std::map<std::string,int>LastId;
    std::map<std::string, std::string> LastK, LastS, LastR;
    std::map<std::string, OpType> LastOp;

    int Enc_id(std::string &C_out, const int id);

    int Dec_id(int &id_out, const std::string &C_in);

};

#endif
