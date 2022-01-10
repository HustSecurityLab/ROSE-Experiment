#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <chrono>
#include <set>
#include <random>
#include "sse_benchmark.h"
#include "fides.h"

extern "C"
{
#include <openssl/rand.h>
}

using namespace std;

int SSEBenchmark::Setup(const std::string &filename)
{
    string label, cipher;
    char  word[256];
    int ind;
    FILE *f_data = fopen(filename.c_str(), "r");
    FidesClient fides_clnt;
    FidesServer fides_srv;
    int counter = 0;
    FILE *fp_clnt = fopen("fides_clnt_data", "rb");
    FILE *fp_srv = fopen("fides_srv_data", "rb");

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
            fscanf(f_data, "%d\n", &ind);
            _v.emplace_back(ind);
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
        fides_clnt.Setup();
        fides_srv.Setup();
        for (const auto &a : data_to_encrypt)
        {
            for (const auto &f_name : a.second)
            {
                fides_clnt.update(label,  cipher, a.first, f_name, Fides_Add);
                fides_srv.save(label, cipher);
            }
        }
        fides_clnt.dump_data();
        fides_srv.dump_data();
    }
    return 1;
}

int SSEBenchmark::benchmark_gen_add_cipher()
{
    FidesClient fides_clnt;
    FidesServer fides_srv;
    string label, cipher, IV;
    int _add_number = 0;

    fides_clnt.Setup();
    fides_srv.Setup();

    auto start = chrono::steady_clock::now();
    for (const auto &a : data_to_encrypt)
    {
        for (const auto &f_name : a.second)
        {
            fides_clnt.update(label,  cipher, a.first, f_name, Fides_Add);
            fides_srv.save(label, cipher);
            _add_number++;
        }
    }
    auto end = chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    cout << "encryption time cost: " << endl;
    cout << "\ttotally " << _add_number << " records, total " << elapsed.count() << " us" << endl;
    cout << "\taverage time " << elapsed.count() / _add_number << " us" << endl;
    cout << "length of a ciphertext is " << 32 + 32 << " bytes" << endl
         << endl;

    return 1;
}

int SSEBenchmark::benchmark_gen_del_cipher()
{
    FidesClient fides_clnt;
    FidesServer fides_srv;
    string label, cipher, IV;
    int _del_number = 0;

    fides_clnt.Setup();
    fides_srv.Setup();
    fides_clnt.load_data();
    fides_srv.load_data();

    auto start = chrono::steady_clock::now();
    for (const auto &a : data_to_encrypt)
    {
        for (const auto &f_name : a.second)
        {
            fides_clnt.update(label, cipher, a.first, f_name, Fides_Del);
            fides_srv.save(label, cipher);
            _del_number++;
        }
    }
    auto end = chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;

    cout << "generating delete ciphertexts time cost: " << endl;
    cout << "\ttotal " << _del_number << ", time cost: " << elapsed.count() << " us" << endl;
    cout << "\taverage " << elapsed.count() / _del_number << " us" << endl
         << endl;
    cout << "length of a deleting ciphertext is " << 32 + 32 << " bytes" << endl
         << endl;

    return 1;
}

int SSEBenchmark::benchmark_search()
{
    FidesClient fides_clnt;
    FidesServer fides_srv;
    vector<string> cipher_out, labels, ciphers;
    vector<int> plain_out;
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;
    string label, cipher, st, kw, IV;
    unsigned int counter;
    TdpPK pk;

    //for every keywords, execute search
    for (auto &itr : this->data_to_encrypt)
    {
        //set up the client and the server and load data
        fides_clnt.Setup();
        fides_srv.Setup();

        fides_clnt.load_data();
        fides_srv.load_data();

        cipher_out.clear();
        plain_out.clear();
        labels.clear();
        ciphers.clear();

        cipher_out.reserve(300000);
        plain_out.reserve(300000);
        labels.reserve(300000);
        ciphers.reserve(300000);

        //search stage 1: generate trapdoor
        auto start = std::chrono::steady_clock::now();
        fides_clnt.search_stage1(kw, st, counter, itr.first);
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        clnt_time_cost_in_srch = elapsed.count();
        total_data_size = 32 + 256 + sizeof(counter);

        fides_clnt.get_pk(&pk);

        //search stage 2: find cipehrtexts
        start = std::chrono::steady_clock::now();
        fides_srv.search(cipher_out, &pk, kw, st, counter);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch = elapsed.count();
        total_data_size += cipher_out.size() * (32);

        //search stage 3: decrypt and re-encrypt ciphertexts
        start = std::chrono::steady_clock::now();
        fides_clnt.search_stage2(plain_out, itr.first, cipher_out);
        fides_clnt.update_after_search(itr.first, plain_out, labels, ciphers);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        clnt_time_cost_in_srch += elapsed.count();
        for (auto &itr : plain_out)
            total_data_size += sizeof(int);
        total_data_size +=
            32 * labels.size() + (16 + 16) * ciphers.size(); //returned file identifiers

        //search stage 4: save re-encrypted cipehrtexts
        start = std::chrono::steady_clock::now();
        fides_srv.save(labels, ciphers);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch += elapsed.count();

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
    FidesClient fides_clnt;
    FidesServer fides_srv;
    vector<string> cipher_out, labels, ciphers;
    vector<int>  plain_out;
    vector<double> portion_to_del = {0.2, 0.4, 0.6,0.8};
    //vector<double> portion_to_del = {0.0, 0.02, 0.04, 0.06, 0.08, 0.1, 0.12, 0.14, 0.16, 0.18, 0.2, 0.22, 0.24, 0.26, 0.28, 0.3, 0.32, 0.34, 0.36, 0.38, 0.4, 0.42, 0.44, 0.46, 0.48, 0.5};
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;
    string keyword_to_delete = "40";
    string label, cipher, st, kw, IV;
    unsigned int counter;
    TdpPK pk;
    unordered_set<int> indices;

    //for every keywords, execute search
    cout << endl
         << endl
         << "Begin test deletions" << endl;
    for (double por : portion_to_del)
    {
        //set up the client and the server and load data
        fides_clnt.Setup();
        fides_srv.Setup();

        vector<int> &fnames = data_to_encrypt[keyword_to_delete];

        fides_clnt.load_data();
        fides_srv.load_data();

        cipher_out.clear();
        plain_out.clear();
        labels.clear();
        ciphers.clear();
        indices.clear();

        cipher_out.reserve(300000);
        plain_out.reserve(300000);
        labels.reserve(300000);
        ciphers.reserve(300000);
        indices.reserve(300000);

        //generate delete ciphertexts
        this->randomly_select_deletions(indices, keyword_to_delete, por);
        for (auto &itr : indices)
        {
            fides_clnt.update(label, cipher, keyword_to_delete, fnames[itr], Fides_Del);
            fides_srv.save(label, cipher);
        }

        //search stage 1: generate trapdoor
        auto start = std::chrono::steady_clock::now();
        fides_clnt.search_stage1(kw, st, counter, keyword_to_delete);
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        clnt_time_cost_in_srch = elapsed.count();
        total_data_size = 32 + 256 + sizeof(counter);

        fides_clnt.get_pk(&pk);

        //search stage 2: find cipehrtexts
        start = std::chrono::steady_clock::now();
        fides_srv.search(cipher_out, &pk, kw, st, counter);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch = elapsed.count();
        total_data_size += cipher_out.size() * (16 + 16);

        //search stage 3: decrypt and re-encrypt ciphertexts
        start = std::chrono::steady_clock::now();
        fides_clnt.search_stage2(plain_out, keyword_to_delete, cipher_out);
        fides_clnt.update_after_search(keyword_to_delete, plain_out, labels, ciphers);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        clnt_time_cost_in_srch += elapsed.count();
        for (auto &itr : plain_out)
            total_data_size += sizeof(int);
        total_data_size += 32 * labels.size() + (16 + 16) * ciphers.size(); //returned file identifiers

        //search stage 4: save re-encrypted cipehrtexts
        start = std::chrono::steady_clock::now();
        fides_srv.save(labels, ciphers);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch += elapsed.count();

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
