#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <chrono>
#include <set>
#include <random>
#include "sse_benchmark.h"
#include "rose_client.h"
#include "rose_server.h"

extern "C"
{
#include <openssl/rand.h>
}

using namespace std;

int SSEBenchmark::Setup(const std::string &filename)
{
    string L, R, D, C;
    char word[512];
    int name;
    FILE *f_data = fopen(filename.c_str(), "r");
    RoseClient rose_clnt;
    RoseServer rose_srv;
    int counter = 0;
    FILE *fp_clnt = fopen("rose_client_data.dat", "rb");
    FILE *fp_srv = fopen("rose_server_data.dat", "rb");

    this->data_to_encrypt.clear();
    this->total_add_records = 0;

    fscanf(f_data, "%d\n", &this->keyword_number);
    for (int i = 0; i < this->keyword_number; i++)
    {
        fscanf(f_data, "%s\n", word);
        if (this->data_to_encrypt.find(word) == this->data_to_encrypt.end())
        {
            vector<int> _t;
            this->data_to_encrypt[word] = _t;
        }

        vector<int> &_v = this->data_to_encrypt[word];

        int file_numbers = 0;
        fscanf(f_data, "%d\n", &file_numbers);
        for (int j = 0; j < file_numbers; j++)
        {
            this->total_add_records += 1;
            fscanf(f_data, "%d\n", &name);
            _v.emplace_back(name);
        }
    }
    fclose(f_data);

    cout << "read " << this->total_add_records << " save records " << endl
         << endl;

    if (fp_clnt && fp_srv)
    {
        fclose(fp_clnt);
        fclose(fp_srv);
    }
    else
    {
        rose_clnt.setup();
        rose_srv.setup();
        for (const auto &a : data_to_encrypt)
        {
            for (const auto &f_name : a.second)
            {
                rose_clnt.encrypt(L, R, D, C, op_add, a.first, f_name);
                rose_srv.save(L, R, D, C);
            }
        }
        rose_clnt.save_data();
        rose_srv.save_data();
    }
    return 1;
}

int SSEBenchmark::benchmark_gen_add_cipher()
{
    RoseClient rose_clnt;
    RoseServer rose_srv;
    string L, R, D, C;
    int _add_number = 0;

    rose_clnt.setup();
    rose_srv.setup();

    auto start = chrono::steady_clock::now();
    for (const auto &a : data_to_encrypt)
    {
        for (const auto &f_name : a.second)
        {
            rose_clnt.encrypt(L, R, D, C, op_add, a.first, f_name);
            rose_srv.save(L, R, D, C);
            _add_number++;
        }
    }
    auto end = chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    cout << "encryption time cost: " << endl;
    cout << "\ttotally " << _add_number << " records, total " << elapsed.count() << " us" << endl;
    cout << "\taverage time " << elapsed.count() / _add_number << " us" << endl;
    cout << "length of a ciphertext is " << 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE << " bytes" << endl
         << endl;

    return 1;
}

int SSEBenchmark::benchmark_gen_del_cipher()
{
    RoseClient rose_clnt;
    RoseServer rose_srv;
    string L, R, D, C;
    int _del_number = 0;

    rose_clnt.setup();
    rose_srv.setup();
    rose_clnt.load_data();
    rose_srv.load_data();

    auto start = chrono::steady_clock::now();
    for (const auto &a : data_to_encrypt)
    {
        for (const auto &f_name : a.second)
        {
            rose_clnt.encrypt(L, R, D, C, op_del, a.first, f_name);
            rose_srv.save(L, R, D, C);
            _del_number++;
        }
    }
    auto end = chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;

    cout << "generating delete ciphertexts time cost: " << endl;
    cout << "\ttotal " << _del_number << ", time cost: " << elapsed.count() << " us" << endl;
    cout << "\taverage " << elapsed.count() / _del_number << " us" << endl
         << endl;
    cout << "length of a deleting ciphertext is " << 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE << " bytes" << endl
         << endl;

    return 1;
}

int SSEBenchmark::benchmark_search()
{
    RoseClient rose_clnt;
    RoseServer rose_srv;
    vector<string> cipher_out,labels;
    vector<int>  plain_out;
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;
    string tpd_L, tpd_T, L, R, D, C;
    unsigned int counter;

    //for every keywords, execute search
    for (auto &itr : this->data_to_encrypt)
    {
        //set up the client and the server and load data
        rose_clnt.setup();
        rose_srv.setup();

        rose_clnt.load_data();
        rose_srv.load_data();

        cipher_out.clear();
        plain_out.clear();
        labels.clear();

        cipher_out.reserve(300000);
        plain_out.reserve(300000);
        labels.reserve(300000);

        //search stage 1: generate trapdoor
        auto start = std::chrono::steady_clock::now();
        rose_clnt.trapdoor(itr.first, tpd_L, tpd_T, L, R, D, C);
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        clnt_time_cost_in_srch = elapsed.count();
        total_data_size = 32 + 32 + 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE;

        //search stage 2: find cipehrtexts
        start = std::chrono::steady_clock::now();
        rose_srv.search(cipher_out, tpd_L, tpd_T, L, R, D, C);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch = elapsed.count();
        total_data_size += cipher_out.size() * (CIPHER_SIZE);

        //search stage 3: decrypt and re-encrypt ciphertexts
        start = std::chrono::steady_clock::now();
        rose_clnt.decrypt(plain_out, itr.first, cipher_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        clnt_time_cost_in_srch += elapsed.count();
        for (auto &itr : plain_out)
            total_data_size += sizeof(int);

        total_time_in_srch = clnt_time_cost_in_srch + srv_time_cost_in_srch;

        cout << "Searching for keyword: " << itr.first << endl;
        cout << "\tTotally find " << plain_out.size() << " records and the last file ID is "
             << plain_out[plain_out.size() - 1] << endl;
        cout << "\tTime cost of client is " << std::fixed << clnt_time_cost_in_srch << " us, average is "
             << clnt_time_cost_in_srch / plain_out.size() << endl;
        cout << "\tTime cost of server is " << fixed << srv_time_cost_in_srch << " us, average is "
             << srv_time_cost_in_srch / plain_out.size() << endl;
        cout << "\tTime cost of the whole search phase is " << fixed << total_time_in_srch << " us" << endl;
        cout << "\tAverage time cost is " << fixed << total_time_in_srch / plain_out.size() << " us" << endl;
        cout << "\tTotal data exchanged are " << total_data_size << " Bytes, " << total_data_size / 1024 << " KB, "
             << total_data_size / 1024 / 1024 << " MB " << endl
             << endl;
    }

    return 0;
}

int SSEBenchmark::benchmark_deletions()
{
    RoseClient rose_clnt;
    RoseServer rose_srv;
    vector<string> cipher_out, labels;
    vector<int> plain_out;
    //vector<double> portion_to_del = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9};
    vector<double> portion_to_del = {0.0, 0.02, 0.04, 0.06, 0.08, 0.1, 0.12, 0.14, 0.16, 0.18, 0.2, 0.22, 0.24, 0.26, 0.28, 0.3, 0.32, 0.34, 0.36, 0.38, 0.4, 0.42, 0.44, 0.46, 0.48, 0.5};
    vector<int> srch_count = {0, 20, 50, 70, 100, 120, 150, 170, 200};
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;
    string keyword_to_delete = "40";
    string tpd_T, tpd_L, L, R, D, C;
    unsigned int counter;
    unordered_set<int> indices;

    //for every keywords, execute search
    cout << endl
         << endl
         << "Begin test deletions" << endl;
    for (int number_of_srch : srch_count)
    {
        for (double por : portion_to_del)
        {
            //set up the client and the server and load data
            rose_clnt.setup();
            rose_srv.setup();

            rose_clnt.load_data();
            rose_srv.load_data();

            vector<int> &fnames = data_to_encrypt[keyword_to_delete];

            cipher_out.clear();
            plain_out.clear();
            labels.clear();
            indices.clear();

            cipher_out.reserve(300000);
            plain_out.reserve(300000);
            labels.reserve(300000);
            indices.reserve(300000);

            for (int i = 0; i < number_of_srch; i++)
            {
                rose_clnt.trapdoor(keyword_to_delete, tpd_L, tpd_T, L, R, D, C);
                rose_srv.save(L, R, D, C);
            }

            //generate delete ciphertexts
            this->randomly_select_deletions(indices, keyword_to_delete, por);
            for (auto &itr : indices)
            {
                rose_clnt.encrypt(L, R, D, C, op_del, keyword_to_delete, fnames[itr]);
                rose_srv.save(L, R, D, C);
            }

            //search stage 1: generate trapdoor
            auto start = std::chrono::steady_clock::now();
            rose_clnt.trapdoor(keyword_to_delete, tpd_L, tpd_T, L, R, D, C);
            auto end = std::chrono::steady_clock::now();
            std::chrono::duration<double, std::micro> elapsed = end - start;
            clnt_time_cost_in_srch = elapsed.count();
            total_data_size = 32 + 32 + 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE;

            //search stage 2: find cipehrtexts
            start = std::chrono::steady_clock::now();
            rose_srv.search(cipher_out, tpd_L, tpd_T, L, R, D, C);
            end = std::chrono::steady_clock::now();
            elapsed = end - start;
            srv_time_cost_in_srch = elapsed.count();
            total_data_size += cipher_out.size() * (CIPHER_SIZE);

            //search stage 3: decrypt and re-encrypt ciphertexts
            start = std::chrono::steady_clock::now();
            rose_clnt.decrypt(plain_out, keyword_to_delete, cipher_out);
            end = std::chrono::steady_clock::now();
            elapsed = end - start;
            clnt_time_cost_in_srch += elapsed.count();
            for (auto &itr : plain_out)
                total_data_size += sizeof(int);

            total_time_in_srch = clnt_time_cost_in_srch + srv_time_cost_in_srch;

            cout << "Searching for keyword: " << keyword_to_delete << endl;
            cout << "Number of Search Queries: " << number_of_srch << endl;
            cout << "Deletion Portion: " << por << " and deleted entries is: " << int(por * fnames.size()) << endl;
            cout << "\tTotally find " << plain_out.size() << endl;
            cout << "\tTime cost of client is " << std::fixed << clnt_time_cost_in_srch << " us, average is "
                 << clnt_time_cost_in_srch / plain_out.size() << endl;
            cout << "\tTime cost of server is " << fixed << srv_time_cost_in_srch << " us, average is "
                 << srv_time_cost_in_srch / plain_out.size() << endl;
            cout << "\tTime cost of the whole search phase is " << fixed << total_time_in_srch << " us" << endl;
            cout << "\tAverage time cost is " << fixed << total_time_in_srch / plain_out.size() << " us" << endl;
            cout << "\tTotal data exchanged are " << total_data_size << " bytes" << endl
                 << endl;
        }
    }

    return 0;
}

void SSEBenchmark::randomly_select_deletions(std::unordered_set<int> &indices, std::string &keyword, double por)
{
    vector<int> &t = this->data_to_encrypt[keyword];
    int total_number_filenames = t.size();
    int required_number = int(por * total_number_filenames);
    int cur_number = 0;
    int index = 0;

    if (required_number >= total_number_filenames)
    {
        required_number = total_number_filenames;
        for (int i = 0; i < total_number_filenames; i++)
            indices.emplace(i);
    }
    else
    {
        while (cur_number < required_number)
        {
            RAND_bytes((unsigned char *)&index, sizeof(int));
            index = index % total_number_filenames;
            if (index < 0)
                index = -index;
            if (indices.find(index) == indices.end())
            {
                indices.emplace(index);
                cur_number++;
            }
        }
    }
}

int SSEBenchmark::benchamark_deletion_in_parallel()
{
    cout << endl
         << endl
         << "Begin test parallel deletions" << endl;

    RoseClient rose_clnt;
    RoseServer rose_srv(true);
    vector<string> cipher_out, labels;
    vector<int>  plain_out;
    //vector<double> portion_to_del = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9};
    vector<double> portion_to_del = {0.0, 0.02, 0.04, 0.06, 0.08, 0.1, 0.12, 0.14, 0.16, 0.18, 0.2, 0.22, 0.24, 0.26, 0.28, 0.3, 0.32, 0.34, 0.36, 0.38, 0.4, 0.42, 0.44, 0.46, 0.48, 0.5};
    vector<int> srch_count = {0, 20, 50, 70, 100, 120, 150, 170, 200};
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;
    string keyword_to_delete = "40";
    string tpd_T, tpd_L, L, R, D, C;
    unsigned int counter;
    unordered_set<int> indices;
    vector<int> &fnames = data_to_encrypt[keyword_to_delete];

    for (int sc : srch_count)
    {
        for (double por : portion_to_del)
        {
            rose_clnt.setup();
            rose_srv.setup();

            rose_clnt.load_data();
            rose_srv.load_data();

            indices.clear();
            indices.reserve(300000);

            //store data at first
            for (int i = 0; i < sc; i++)
            {
                rose_clnt.trapdoor(keyword_to_delete, tpd_L, tpd_T, L, R, D, C);
                rose_srv.save(L, R, D, C);
            }

            //generate delete ciphertexts
            this->randomly_select_deletions(indices, keyword_to_delete, por);
            for (auto &itr : indices)
            {
                rose_clnt.encrypt(L, R, D, C, op_del, keyword_to_delete, fnames[itr]);
                rose_srv.save(L, R, D, C);
            }

            rose_clnt.save_data("rose_clnt_paral_data.dat");
            rose_srv.save_data("rose_srv_paral_data.dat");

            for (int num_thread = 2; num_thread <= 16; num_thread += 2)
            {
                cerr << "search count: " << sc << ", portion: " << por << ", number of thread: " << num_thread << endl;

                rose_clnt.setup();
                rose_srv.setup();

                rose_clnt.load_data("rose_clnt_paral_data.dat");
                rose_srv.load_data("rose_srv_paral_data.dat");

                cipher_out.clear();
                plain_out.clear();
                labels.clear();

                cipher_out.reserve(300000);
                plain_out.reserve(300000);
                labels.reserve(300000);

                //search stage 1: generate trapdoor
                auto start = std::chrono::steady_clock::now();
                rose_clnt.trapdoor(keyword_to_delete, tpd_L, tpd_T, L, R, D, C);
                auto end = std::chrono::steady_clock::now();
                std::chrono::duration<double, std::micro> elapsed = end - start;
                clnt_time_cost_in_srch = elapsed.count();
                total_data_size = 32 + 32 + 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE;

                //search stage 2: find cipehrtexts
                if (num_thread == 1)
                {
                    start = std::chrono::steady_clock::now();
                    //rose_srv.search_with_parallel_del(cipher_out, tpd_L, tpd_T, L, R, D, C, num_thread);
                    rose_srv.search(cipher_out, tpd_L, tpd_T, L, R, D, C);
                    end = std::chrono::steady_clock::now();
                }
                else
                {
                    start = std::chrono::steady_clock::now();
                    rose_srv.search_with_parallel_del(cipher_out, tpd_L, tpd_T, L, R, D, C, num_thread);
                    end = std::chrono::steady_clock::now();
                }

                elapsed = end - start;
                srv_time_cost_in_srch = elapsed.count();
                total_data_size += cipher_out.size() * (CIPHER_SIZE);

                //search stage 3: decrypt and re-encrypt ciphertexts
                start = std::chrono::steady_clock::now();
                rose_clnt.decrypt(plain_out, keyword_to_delete, cipher_out);
                end = std::chrono::steady_clock::now();
                elapsed = end - start;
                clnt_time_cost_in_srch += elapsed.count();
                for (auto &itr : plain_out)
                    total_data_size += sizeof(int);

                total_time_in_srch = clnt_time_cost_in_srch + srv_time_cost_in_srch;

                cout << "Searching for keyword: " << keyword_to_delete << endl;
                cout << "Deletion Portion: " << por << " and deleted entries is: " << int(por * fnames.size()) << endl;
                cout << "Number of Search Queries: " << sc << endl;
                cout << "Number of thread: " << num_thread << endl;
                cout << "\tTotally find " << plain_out.size() << endl;
                cout << "\tTime cost of client is " << std::fixed << clnt_time_cost_in_srch << " us, average is "
                     << clnt_time_cost_in_srch / plain_out.size() << endl;
                cout << "\tTime cost of server is " << fixed << srv_time_cost_in_srch << " us, average is "
                     << srv_time_cost_in_srch / plain_out.size() << endl;
                cout << "\tTime cost of the whole search phase is " << fixed << total_time_in_srch << " us" << endl;
                cout << "\tAverage time cost is " << fixed << total_time_in_srch / plain_out.size() << " us" << endl;
                cout << "\tTotal data exchanged are " << total_data_size << " bytes" << endl
                     << endl;
            }
        }
    }

    return 0;
}

int SSEBenchmark::benchmark_opt_deletions()
{
    RoseClient rose_clnt;
    RoseServer rose_srv;
    vector<string> cipher_out,labels;
    vector<int>  plain_out;
    //vector<double> portion_to_del = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9};
    vector<double> portion_to_del = {0.0, 0.02, 0.04, 0.06, 0.08, 0.1, 0.12, 0.14, 0.16, 0.18, 0.2, 0.22, 0.24, 0.26, 0.28, 0.3, 0.32, 0.34, 0.36, 0.38, 0.4, 0.42, 0.44, 0.46, 0.48, 0.5};
    vector<int> srch_count = {0,};
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;
    string keyword_to_delete = "40";
    string tpd_T, tpd_L, L, R, D, C;
    unsigned int counter;
    unordered_set<int> indices;
    vector<int> &t = this->data_to_encrypt[keyword_to_delete];

    //for every keywords, execute search
    cout << endl
         << endl
         << "Begin test optimal deletions" << endl;
    for (int number_of_srch : srch_count)
    {
        for (double por : portion_to_del)
        {
            int num_encrypted = 0;
            int num_deleted = por * t.size();
            //set up the client and the server and load data
            rose_clnt.setup();
            rose_srv.setup();

            for (auto &ind : t)
            {
                rose_clnt.encrypt(L, R, D, C, op_add, keyword_to_delete, ind);
                rose_srv.save(L, R, D, C);
                if (num_encrypted < num_deleted)
                {
                    num_encrypted ++ ;
                    rose_clnt.encrypt(L, R, D, C, op_del, keyword_to_delete, ind);
                    rose_srv.save(L, R, D, C);
                }
            }

            vector<int> &fnames = data_to_encrypt[keyword_to_delete];

            cipher_out.clear();
            plain_out.clear();
            labels.clear();
            indices.clear();

            cipher_out.reserve(300000);
            plain_out.reserve(300000);
            labels.reserve(300000);
            indices.reserve(300000);

            //search stage 1: generate trapdoor
            auto start = std::chrono::steady_clock::now();
            rose_clnt.trapdoor(keyword_to_delete, tpd_L, tpd_T, L, R, D, C);
            auto end = std::chrono::steady_clock::now();
            std::chrono::duration<double, std::micro> elapsed = end - start;
            clnt_time_cost_in_srch = elapsed.count();
            total_data_size = 32 + 32 + 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE;

            //search stage 2: find cipehrtexts
            start = std::chrono::steady_clock::now();
            rose_srv.search(cipher_out, tpd_L, tpd_T, L, R, D, C);
            end = std::chrono::steady_clock::now();
            elapsed = end - start;
            srv_time_cost_in_srch = elapsed.count();
            total_data_size += cipher_out.size() * (CIPHER_SIZE);

            //search stage 3: decrypt and re-encrypt ciphertexts
            start = std::chrono::steady_clock::now();
            rose_clnt.decrypt(plain_out, keyword_to_delete, cipher_out);
            end = std::chrono::steady_clock::now();
            elapsed = end - start;
            clnt_time_cost_in_srch += elapsed.count();
            for (auto &itr : plain_out)
                total_data_size += sizeof(int);

            total_time_in_srch = clnt_time_cost_in_srch + srv_time_cost_in_srch;

            cout << "Searching for keyword: " << keyword_to_delete << endl;
            cout << "Deletion Portion: " << por << " and deleted entries is: " << int(por * fnames.size()) << endl;
            cout << "\tTotally find " << plain_out.size() << endl;
            cout << "\tTime cost of client is " << std::fixed << clnt_time_cost_in_srch << " us, average is "
                 << clnt_time_cost_in_srch / plain_out.size() << endl;
            cout << "\tTime cost of server is " << fixed << srv_time_cost_in_srch << " us, average is "
                 << srv_time_cost_in_srch / plain_out.size() << endl;
            cout << "\tTime cost of the whole search phase is " << fixed << total_time_in_srch << " us" << endl;
            cout << "\tAverage time cost is " << fixed << total_time_in_srch / plain_out.size() << " us" << endl;
            cout << "\tTotal data exchanged are " << total_data_size << " bytes" << endl
                 << endl;
        }
    }

    return 0;
}