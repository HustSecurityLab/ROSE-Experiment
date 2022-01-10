#include "rose_server.h"
#include <set>
#include <cstring>
#include <cstdlib>
#include <experimental/filesystem>
#include <thread>
#include <mutex>
#include <iostream>
#include <array>
#include <condition_variable>

extern "C"
{
#include "unistd.h"
}

using namespace std;

static bool volatile if_thread_created = false;
static volatile int counter, num_finished;
static mutex mtx_counter, mtx_bool;
static mutex mtx_test_thread[32], mtx_update_thread[32];
static volatile int x = 0;
static volatile bool if_test_thread_quit[32], if_update_thread_quit[32];
static volatile bool if_test_thread_run[32], if_update_thread_run[32];
static vector<string> *thd_D;
static unsigned char thd_R[64];
static string thd_L;


struct ArgTestDel
{
    vector<string> *updated_D;
    int start_pos;
    int end_pos;
};

static volatile ArgTestDel _arg[64];

static void do_test_deletion(int _thread_num)
{
    int thread_num = _thread_num;
    unsigned char buf1[32];

    while (true)
    {
        mtx_test_thread[thread_num].lock();

        if (if_test_thread_quit[thread_num])
        {
            mtx_test_thread[thread_num].unlock();
            break;
        }

        if (if_test_thread_run[thread_num])
        {
            volatile ArgTestDel &arg = _arg[thread_num];

            if_test_thread_run[thread_num] = false;

            for (int i = arg.start_pos; i < arg.end_pos; i++)
            {
                if (counter == 0)
                    break;

                Hash_G(buf1, (const unsigned char *) (*thd_D)[i].c_str(), thd_R);

                if (memcmp(buf1, thd_L.c_str(), 32) == 0)
                {
                    counter = counter - 1;
                }
            }
            mtx_counter.lock();
            num_finished += 1;
            mtx_counter.unlock();
        }
        mtx_test_thread[thread_num].unlock();
        usleep(23);

    }
}

static bool test_deletion_in_multithread(vector<string> &D, const unsigned char *R, string &L,
                                         int thread_num)
{
    int avg = D.size() / thread_num;
    int remainder = D.size() % thread_num;
    int cur_pos = 0;

    for (int j = 0; j < 16; j++)
        thd_R[j] = R[j];
    thd_L = L;
    thd_D = &D;

    counter = 1;
    num_finished = 0;

    for (int i = 0; i < thread_num; i++)
    {
        volatile ArgTestDel &arg = _arg[i];

        arg.start_pos = cur_pos;
        cur_pos = arg.end_pos = cur_pos + avg;
        if (remainder > 0)
        {
            arg.end_pos = arg.end_pos + 1;
            remainder--;
            cur_pos++;
        }

        mtx_bool.lock();
        if_test_thread_run[i] = true;
        mtx_bool.unlock();
        mtx_test_thread[i].unlock();
    }
    do
    {
        usleep(10);

    }while(num_finished < thread_num);

    for (int i = 0; i < thread_num; i++)
        mtx_test_thread[i].lock();
    if (counter <= 0)
        return true;
    else
        return false;
}

static void do_update_X_in_multithread(int _thread_num)
{
    KUPRF kuprf;
    unsigned char buf1[48];
    string str1;

    int thread_num = _thread_num;

    KUPRF::init();

    while (true)
    {
        mtx_update_thread[thread_num].lock();

        if (if_update_thread_quit[thread_num])
        {
            mtx_update_thread[thread_num].unlock();
            break;
        }
        if (if_update_thread_run[thread_num])
        {
            if_update_thread_run[thread_num] = false;

            for (int i = _arg[thread_num].start_pos; i < _arg[thread_num].end_pos; i++)
            {
                kuprf.update(buf1, (unsigned char *) thd_R, (unsigned char *) (*thd_D)[i].c_str());
                str1.assign((const char *) buf1, 33);
                _arg[thread_num].updated_D->emplace_back(str1);
            }
            mtx_counter.lock();
            num_finished += 1;
            mtx_counter.unlock();
        }
        mtx_update_thread[thread_num].unlock();
        usleep(23);
    }

    KUPRF::clean();
}

static void update_X_in_multithread(vector<string> &D, unsigned char *update_token, int thread_num)
{
    int avg = D.size() / thread_num;
    int remainder = D.size() % thread_num;
    int cur_pos = 0;

    for (int j = 0; j < 32; j++)
        thd_R[j] = update_token[j];
    thd_D = &D;
    num_finished = 0;
    for (int i = 0; i < thread_num; i++)
    {
        volatile ArgTestDel &arg = _arg[i];

        arg.start_pos = cur_pos;
        cur_pos = arg.end_pos = cur_pos + avg;
        arg.updated_D = new vector<string>;
        if (remainder > 0)
        {
            arg.end_pos = arg.end_pos + 1;
            remainder--;
            cur_pos++;
        }

        if_update_thread_run[i] = true;
        mtx_update_thread[i].unlock();
    }
    do
    {
        usleep(10);
    }while(num_finished < thread_num);

    for (int i = 0; i < thread_num; i++)
        mtx_update_thread[i].lock();

    D.clear();
    for (int i = 0; i < thread_num; i++)
    {
        for (auto &itr1 : *(_arg[i].updated_D))
            D.emplace_back(itr1);

        delete _arg[i].updated_D;
    }
}

RoseServer::RoseServer()
{
    if_thread_created = false;
}

RoseServer::RoseServer(bool enable_thread)
{
    if (enable_thread)
    {
        if (!if_thread_created)
        {
            _create_thread();
            if_thread_created = true;
        }
    }
    else
        if_thread_created = false;
}

RoseServer::~RoseServer()
{
    for (auto itr:_store)
    {
        delete itr.second;
    }
    _store.clear();

    if (if_thread_created)
    {
        for (int i = 0; i < 32; i++)
        {
            if_test_thread_quit[i] = true;
            if_update_thread_quit[i] = true;

            mtx_test_thread[i].unlock();
            mtx_update_thread[i].unlock();
        }

        for (thread *t : this->threads)
            t->join();
    }
    if_thread_created = false;
}

int RoseServer::setup()
{
    for (auto itr:_store)
    {
        delete itr.second;
    }
    _store.clear();

    return 0;
}

int RoseServer::save(const string &L, const string &R, const string &D, const string &C)
{
    Cipher *cip = new Cipher;

    memcpy(cip->R, R.c_str(), 16);
    memcpy(cip->D, D.c_str(), 1 + 32 * 2 + 33);
    memcpy(cip->C, C.c_str(), CIPHER_SIZE);

    _store[L] = cip;

    return 0;
}

int RoseServer::search(vector<std::string> &result, const string &tpd_L, const string &tpd_T, const string &cip_L,
                       const string &cip_R, const string &cip_D, const string &cip_C)
{
    Cipher *cip = new Cipher;
    unsigned char buf1[256], buf2[256], buf3[256], buf_Dt[256], buf_Deltat[256];
    OpType opt;
    vector<string> D;
    bool is_delta_null = true;
    string s_Lt, s_L1t, s_L1, s_T1, s_T1t, s_tmp;
    set<string> L_cache;
    KUPRF kuprf;

    memcpy(cip->R, cip_R.c_str(), 16);
    memcpy(cip->D, cip_D.c_str(), 1 + 33 + 32 * 2);
    memcpy(cip->C, cip_D.c_str(), CIPHER_SIZE);

    _store[cip_L] = cip;

    s_Lt = cip_L;
    memcpy(buf_Dt, cip_D.c_str(), 1 + 33 + 32 * 2);
    opt = op_srh;
    is_delta_null = true;

    s_L1 = s_L1t = tpd_L;
    s_T1 = s_T1t = tpd_T;


    while (true)
    {
        L_cache.emplace(s_L1);
        cip = _store[s_L1];
        Hash_H(buf2, 1 + 32 * 2 + 33, (const unsigned char *) s_T1.c_str(), cip->R);

        Xor(1 + 33 + 32 * 2, cip->D, buf2, buf3);
        if (buf3[0] == 0xf0) // del
        {
            L_cache.erase(s_L1);
            _store.erase(s_L1);
            delete cip;

            s_tmp.assign((const char *) buf3 + 1, 33);
            D.emplace_back(s_tmp);

            Xor(32, (const unsigned char *) s_L1t.c_str(), (const unsigned char *) buf3 + 1 + 33, buf2);
            Xor(32, (const unsigned char *) s_T1t.c_str(), (const unsigned char *) buf3 + 1 + 33 + 32,
                buf2 + 32);
            Xor(64, buf_Dt + 1 + 33, buf2, buf_Dt + 1 + 33);

            cip = _store[s_Lt];
            memcpy(cip->D, buf_Dt, 1 + 32 * 2 + 33);

            s_L1t.assign((const char *) buf3 + 1 + 33, 32);
            s_T1t.assign((const char *) buf3 + 1 + 33 + 32, 32);
        }
        else if (buf3[0] == 0x0f) //add
        {
            for (auto itr = D.rbegin(); itr != D.rend(); itr++)
            {
                Hash_G(buf1, (const unsigned char *) itr->c_str(), cip->R);
                if (memcmp(buf1, s_L1.c_str(), 32) == 0)
                {
                    L_cache.erase(s_L1);
                    _store.erase(s_L1);
                    delete cip;

                    Xor(32, (const unsigned char *) s_L1t.c_str(), (const unsigned char *) buf3 + 1 + 33, buf2);
                    Xor(32, (const unsigned char *) s_T1t.c_str(), (const unsigned char *) buf3 + 1 + 33 + 32,
                        buf2 + 32);
                    Xor(64, buf_Dt + 1 + 33, buf2, buf_Dt + 1 + 33);

                    cip = _store[s_Lt];
                    memcpy(cip->D, buf_Dt, 1 + 32 * 2 + 33);
                    s_L1t.assign((const char *) buf3 + 1 + 33, 32);
                    s_T1t.assign((const char *) buf3 + 1 + 33 + 32, 32);
                    cip = nullptr;
                    break;
                }
            }
            if (cip != nullptr)
            {
                s_Lt = s_L1;
                memcpy(buf_Dt, cip->D, 1 + 32 * 2 + 33);
                s_L1t.assign((const char *) buf3 + 1 + 33, 32);
                s_T1t.assign((const char *) buf3 + 1 + 33 + 32, 32);
                opt = op_add;
                s_tmp.assign((const char *) cip->C, CIPHER_SIZE);
                result.emplace_back(s_tmp);
            }
        }
        else
        {
            if (opt == op_srh && (!is_delta_null))
            {
                L_cache.erase(s_L1);
                _store.erase(s_L1);
                delete cip;

                kuprf.mul(buf1, buf_Deltat, buf3 + 1);

                Xor(32, buf_Deltat, buf1, buf_Deltat);
                Xor(32, buf_Dt + 1, buf_Deltat, buf_Dt + 1);

                Xor(32, (const unsigned char *) s_L1t.c_str(), buf3 + 1 + 33, buf2);
                Xor(32, (const unsigned char *) s_T1t.c_str(), buf3 + 1 + 33 + 32, buf2 + 32);
                Xor(64, buf_Dt + 1 + 33, buf2, buf_Dt + 1 + 33);

                cip = _store[s_Lt];
                memcpy(cip->D, buf_Dt, 1 + 32 * 2 + 33);

                memcpy(buf_Deltat, buf1, 32);
                s_L1t.assign((const char *) buf3 + 1 + 33, 32);
                s_T1t.assign((const char *) buf3 + 1 + 33 + 32, 32);
            }
            else
            {
                s_Lt = s_L1;
                memcpy(buf_Dt, cip->D, 1 + 32 * 2 + 33);
                s_L1t.assign((const char *) buf3 + 1 + 33, 32);
                s_T1t.assign((const char *) buf3 + 1 + 33 + 32, 32);
                opt = op_srh;
                memcpy(buf_Deltat, buf3 + 1, 32);
                is_delta_null = false;
            }
            for (auto itr = D.begin(); itr != D.end(); itr++)
            {
                kuprf.update(buf1, buf3 + 1, (const unsigned char *) itr->c_str());
                itr->assign((const char *) buf1, 33);
            }
        }
        memset(buf2, 0, 64);
        if (memcmp(buf2, buf3 + 1 + 33, 64) == 0)
            break;
        s_L1.assign((const char *) buf3 + 1 + 33, 32);
        s_T1.assign((const char *) buf3 + 1 + 33 + 32, 32);
    }
    if (result.empty())
    {
        for (auto itr = L_cache.begin(); itr != L_cache.end(); itr++)
        {
            Cipher *cip = _store[*itr];
            delete cip;
            _store.erase(*itr);
        }
    }
    return 0;
}

int RoseServer::search_with_parallel_del(vector<std::string> &result, const string &tpd_L, const string &tpd_T,
                                         const string &cip_L, const string &cip_R, const string &cip_D,
                                         const string &cip_C, int thread_num)
{
    x = 0;
    Cipher *cip = new Cipher;
    unsigned char buf1[256], buf2[256], buf3[256], buf_Dt[256], buf_Deltat[256];
    OpType opt;
    vector<string> D;
    bool is_delta_null = true;
    string s_Lt, s_L1t, s_L1, s_T1, s_T1t, s_tmp;
    set<string> L_cache;
    KUPRF kuprf;

    memcpy(cip->R, cip_R.c_str(), 16);
    memcpy(cip->D, cip_D.c_str(), 1 + 33 + 32 * 2);
    memcpy(cip->C, cip_D.c_str(), CIPHER_SIZE);

    _store[cip_L] = cip;

    s_Lt = cip_L;
    memcpy(buf_Dt, cip_D.c_str(), 1 + 33 + 32 * 2);
    opt = op_srh;
    is_delta_null = true;

    s_L1 = s_L1t = tpd_L;
    s_T1 = s_T1t = tpd_T;


    while (true)
    {
        L_cache.emplace(s_L1);
        cip = _store[s_L1];
        Hash_H(buf2, 1 + 32 * 2 + 33, (const unsigned char *) s_T1.c_str(), cip->R);

        Xor(1 + 33 + 32 * 2, cip->D, buf2, buf3);
        if (buf3[0] == 0xf0) // del
        {
            L_cache.erase(s_L1);
            _store.erase(s_L1);
            delete cip;

            s_tmp.assign((const char *) buf3 + 1, 33);
            D.emplace_back(s_tmp);

            Xor(32, (const unsigned char *) s_L1t.c_str(), (const unsigned char *) buf3 + 1 + 33, buf2);
            Xor(32, (const unsigned char *) s_T1t.c_str(), (const unsigned char *) buf3 + 1 + 33 + 32,
                buf2 + 32);
            Xor(64, buf_Dt + 1 + 33, buf2, buf_Dt + 1 + 33);

            cip = _store[s_Lt];
            memcpy(cip->D, buf_Dt, 1 + 32 * 2 + 33);

            s_L1t.assign((const char *) buf3 + 1 + 33, 32);
            s_T1t.assign((const char *) buf3 + 1 + 33 + 32, 32);
        }
        else if (buf3[0] == 0x0f) //add
        {
            if (test_deletion_in_multithread(D, cip->R, s_L1, thread_num))
            {
                L_cache.erase(s_L1);
                _store.erase(s_L1);
                delete cip;

                Xor(32, (const unsigned char *) s_L1t.c_str(), (const unsigned char *) buf3 + 1 + 33, buf2);
                Xor(32, (const unsigned char *) s_T1t.c_str(), (const unsigned char *) buf3 + 1 + 33 + 32,
                    buf2 + 32);
                Xor(64, buf_Dt + 1 + 33, buf2, buf_Dt + 1 + 33);

                cip = _store[s_Lt];
                memcpy(cip->D, buf_Dt, 1 + 32 * 2 + 33);
                s_L1t.assign((const char *) buf3 + 1 + 33, 32);
                s_T1t.assign((const char *) buf3 + 1 + 33 + 32, 32);
                cip = nullptr;
            }

            if (cip != nullptr)
            {
                s_Lt = s_L1;
                memcpy(buf_Dt, cip->D, 1 + 32 * 2 + 33);
                s_L1t.assign((const char *) buf3 + 1 + 33, 32);
                s_T1t.assign((const char *) buf3 + 1 + 33 + 32, 32);
                opt = op_add;
                s_tmp.assign((const char *) cip->C, CIPHER_SIZE);
                result.emplace_back(s_tmp);
            }
        }
        else
        {
            if (opt == op_srh && (!is_delta_null))
            {
                L_cache.erase(s_L1);
                _store.erase(s_L1);
                delete cip;

                kuprf.mul(buf1, buf_Deltat, buf3 + 1);

                Xor(32, buf_Deltat, buf1, buf_Deltat);
                Xor(32, buf_Dt + 1, buf_Deltat, buf_Dt + 1);

                Xor(32, (const unsigned char *) s_L1t.c_str(), buf3 + 1 + 33, buf2);
                Xor(32, (const unsigned char *) s_T1t.c_str(), buf3 + 1 + 33 + 32, buf2 + 32);
                Xor(64, buf_Dt + 1 + 33, buf2, buf_Dt + 1 + 33);

                cip = _store[s_Lt];
                memcpy(cip->D, buf_Dt, 1 + 32 * 2 + 33);

                memcpy(buf_Deltat, buf1, 32);
                s_L1t.assign((const char *) buf3 + 1 + 33, 32);
                s_T1t.assign((const char *) buf3 + 1 + 33 + 32, 32);
            }
            else
            {
                s_Lt = s_L1;
                memcpy(buf_Dt, cip->D, 1 + 32 * 2 + 33);
                s_L1t.assign((const char *) buf3 + 1 + 33, 32);
                s_T1t.assign((const char *) buf3 + 1 + 33 + 32, 32);
                opt = op_srh;
                memcpy(buf_Deltat, buf3 + 1, 32);
                is_delta_null = false;
            }
            update_X_in_multithread(D, buf3 + 1, thread_num);
        }
        memset(buf2, 0, 64);
        if (memcmp(buf2, buf3 + 1 + 33, 64) == 0)
            break;
        s_L1.assign((const char *) buf3 + 1 + 33, 32);
        s_T1.assign((const char *) buf3 + 1 + 33 + 32, 32);
    }

    if (result.empty())
    {
        for (auto itr = L_cache.begin(); itr != L_cache.end(); itr++)
        {
            Cipher *cip = _store[*itr];
            delete cip;
            _store.erase(*itr);
        }
    }
    return 0;
}

void RoseServer::save_data(const std::string &fname)
{
    FILE *f_out = fopen(fname.c_str(), "wb");
    size_t size = this->_store.size();


    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr:this->_store)
    {
        save_string(f_out, itr.first);
        fwrite(itr.second->R, sizeof(char), 16, f_out);
        fwrite(itr.second->D, sizeof(char), 1 + 32 * 2 + 33, f_out);
        fwrite(itr.second->C, sizeof(char), CIPHER_SIZE, f_out);
    }

    fclose(f_out);
}

void RoseServer::load_data(const std::string &fname)
{
    FILE *f_in = fopen(fname.c_str(), "rb");
    size_t size;

    for (auto &itr:this->_store)
    {
        delete itr.second;
    }
    this->_store.clear();

    fread(&size, sizeof(size), 1, f_in);
    for (size_t i = 0; i < size; i++)
    {
        string str1 = load_string(f_in);
        auto cip = new Cipher;
        fread(cip->R, sizeof(char), 16, f_in);
        fread(cip->D, sizeof(char), 1 + 32 * 2 + 33, f_in);
        fread(cip->C, sizeof(char), CIPHER_SIZE, f_in);

        this->_store[str1] = cip;
    }
    fclose(f_in);
}

void RoseServer::_create_thread()
{
    for (int i = 0; i < 32; i++)
    {
        if_test_thread_quit[i] = false;
        if_update_thread_quit[i] = false;
        if_test_thread_run[i] = false;
        if_update_thread_run[i] = false;

        mtx_test_thread[i].lock();
        mtx_update_thread[i].lock();

        thread *t1 = new thread(do_test_deletion, i);
        thread *t2 = new thread(do_update_X_in_multithread, i);

        this->threads.emplace_back(t1);
        this->threads.emplace_back(t2);
    }
}
