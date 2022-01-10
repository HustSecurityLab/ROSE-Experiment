#ifndef SSE_SERVER_H
#define SSE_SERVER_H

#include "common.h"
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <thread>
#include "KUPRF.h"

struct Cipher
{
    unsigned char R[16];
    unsigned char D[1 + 32 * 2 + 33];
    unsigned char C[CIPHER_SIZE];
};

class RoseServer
{
public:
    RoseServer();

    RoseServer(bool enable_thread);

    ~RoseServer();

    int setup();

    int save(const std::string &L, const std::string &R, const std::string &D, const std::string &C);

    int search(std::vector<std::string> &result, const std::string &tpd_L, const std::string &tpd_T,
               const std::string &cip_L, const std::string &cip_R, const std::string &cip_D, const std::string &cip_C);

    int search_with_parallel_del(std::vector<std::string> &result, const std::string &tpd_L, const std::string &tpd_T,
                                 const std::string &cip_L, const std::string &cip_R, const std::string &cip_D,
                                 const std::string &cip_C, int thread_num);

    void save_data(const std::string &fname = "rose_server_data.dat");

    void load_data(const std::string &fname = "rose_server_data.dat");

private:
    std::map<std::string, Cipher *> _store;

    void _create_thread();

    std::vector<std::thread *> threads;

};

#endif
