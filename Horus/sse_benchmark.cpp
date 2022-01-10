#include "sse_benchmark.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <chrono>
#include <set>
#include <random>
#include "sse_benchmark.h"
#include "Horus.h"

extern "C"
{
#include <openssl/rand.h>
}

size_t total_bandwidth = 0;

using namespace std;

int SSEBenchmark::Setup(const std::string &filename)
{
    cout << "Beginning setup bencmark..." << endl;
    FILE *f_data = fopen(filename.c_str(), "r");
    Horus horus(false, 180000);
    int counter = 0;
    char word[64], name[64];
    FILE *f_horus = fopen("Horus-data.dat", "rb");

    this->data_to_encrypt.clear();
    this->total_add_records = 0;
    total_bandwidth = 0;
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
            int ind;
            this->total_add_records += 1;
            fscanf(f_data, "%d\n", &ind);
            _v.emplace_back(ind);
        }
    }
    fclose(f_data);

    cout << "read " << this->total_add_records << " save records " << endl
         << endl;

    if (f_horus)
    {
        fclose(f_horus);
    }
    else
    {
        int _add_number = 0;
        auto start = chrono::steady_clock::now();
        for (const auto &a : data_to_encrypt)
        {
            for (const auto &f_name : a.second)
            {
                horus.insert(a.first, f_name);
                _add_number += 1;
            }
        }
        auto end = chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        cout << "encryption time cost: " << endl;
        cout << "\ttotally " << _add_number << " records, total " << elapsed.count() << " us" << endl;
        cout << "\tclient time " << elapsed.count() << " us" << endl;
        cout << "\taverage time " << elapsed.count() / _add_number << " us" << endl;
        cout << "average length of a ciphertext is " << total_bandwidth / _add_number << " bytes" << endl
             << endl;

        horus.DumpData();
    }

    return 1;
}

int SSEBenchmark::benchmark_gen_del_cipher()
{
    cout << "Beginning gen_del benchmark..." << endl;
    Horus horus(false, 180000);
    int _add_number = 0;

    horus.LoadData();
    total_bandwidth = 0;
    auto start = chrono::steady_clock::now();
    for (const auto &a : data_to_encrypt)
    {
        for (const auto &f_name : a.second)
        {
            horus.remove(a.first, f_name);
            _add_number++;
        }
    }
    auto end = chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    cout << "deletion time cost: " << endl;
    cout << "\ttotally " << _add_number << " records, total " << elapsed.count() << " us" << endl;
    cout << "\taverage time " << elapsed.count() / _add_number << " us" << endl;
    cout << "average length of a ciphertext is " << total_bandwidth / _add_number << " bytes" << endl
         << endl;

    return 1;
}

int SSEBenchmark::benchmark_search()
{
    cout << "Beginning search benchmark..." << endl;

    Horus horus(false, 180000);

    vector<int> plain_out;
    int64_t total_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;

    //for every keywords, execute search
    for (auto &itr : this->data_to_encrypt)
    {
        //set up the client and the server and load data
        horus.LoadData();

        plain_out.clear();

        plain_out.reserve(300000);
        total_bandwidth = 0;
        //search
        auto start = std::chrono::steady_clock::now();
        plain_out = horus.search(itr.first);
        auto end = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        total_time_cost_in_srch = elapsed.count();
        total_data_size = total_bandwidth;

        cout << "Searching for keyword: " << itr.first << endl;
        cout << "\tTotally find " << plain_out.size() << " records and the last file ID is "
             << plain_out[plain_out.size() - 1] << endl;
        cout << "\tTotal time cost is " << std::fixed << total_time_cost_in_srch << " us, average is "
             << total_time_cost_in_srch / plain_out.size() << endl;
        cout << "\tTime cost of the whole search phase is " << fixed << elapsed.count() << " us" << endl;
        cout << "\tAverage time cost is " << fixed << elapsed.count() / plain_out.size() << " us" << endl;
        cout << "\tTotal data exchanged are " << total_data_size << " Bytes, " << total_data_size / 1024 << " KB, "
             << total_data_size / 1024 / 1024 << " MB " << endl
             << endl;
    }

    return 0;
}

int SSEBenchmark::benchmark_deletions()
{
    cout << "Beginning deleting and search benchmark..." << endl;

    Horus horus(false, 180000);
    vector<int> plain_out;
    vector<double> portion_to_del = {0.0, 0.02, 0.04, 0.06, 0.08, 0.1, 0.12, 0.14, 0.16, 0.18, 0.2, 0.22, 0.24, 0.26, 0.28, 0.3, 0.32, 0.34, 0.36, 0.38, 0.4, 0.42, 0.44, 0.46, 0.48, 0.5};
    int64_t total_time_cost_in_srch = 0;
    int64_t del_time_cost = 0;
    unsigned int total_data_size = 0;
    string keyword_to_delete = "40";
    size_t del_bandwidth_cost = 0;
    unordered_set<int> indices;
    int divisor = 1;

    //for every keywords, execute search
    cout << endl
         << endl
         << "Begin test deletions" << endl;
    for(int __i=0; __i<10; __i++)
    {
        for (double por : portion_to_del)
        {
            //set up the client and the server and load data
            horus.LoadData();

            total_bandwidth = 0;

            vector<int> &fnames = data_to_encrypt[keyword_to_delete];

            indices.clear();
            plain_out.clear();

            indices.reserve(300000);
            plain_out.reserve(300000);
            //generate delete ciphertexts
            this->randomly_select_deletions(indices, keyword_to_delete, por);

            //search stage 1: generate trapdoor
            auto start = std::chrono::steady_clock::now();
            for (auto &itr : indices)
            {
                horus.remove(keyword_to_delete, fnames[itr]);
            }
            auto end = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            del_time_cost = elapsed.count();
            del_bandwidth_cost = total_bandwidth;
            total_bandwidth = 0;

            start = std::chrono::steady_clock::now();
            plain_out = horus.search(keyword_to_delete);
            end = std::chrono::steady_clock::now();
            elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

            total_time_cost_in_srch = del_time_cost + elapsed.count();
            total_data_size = total_bandwidth;

            cout << "Performing Deleting When Searching for keyword: " << keyword_to_delete << endl;
            cout << "Deletion Portion: " << por << " and deleted entries is: " << int(por * fnames.size()) << endl;
            cout << "\tTotally found " << plain_out.size() << endl;
            divisor = int(por * fnames.size());
            if(divisor > 0)
                cout << "\tDeletion time cost is " << del_time_cost << " us, average is "
                << del_time_cost / divisor << endl;
            cout << "\tDeletion data exchanged are " << del_bandwidth_cost << " bytes, " << del_bandwidth_cost / 1024
            << " KB, " << del_bandwidth_cost / 1024 / 1024 << " MB" << endl;
            cout << "\tSearch time cost is " << elapsed.count() << " us, average is " << elapsed.count() / plain_out.size()
            << endl;
            cout << "\tSearch data exchanged are " << total_data_size << " bytes, " << total_data_size / 1024 << " KB, "
            << total_data_size / 1024 / 1024 << " MB" << endl;
            cout << "\tTotal time cost is " << std::fixed << total_time_cost_in_srch << " us, average is "
            << total_time_cost_in_srch / plain_out.size() << endl;
            cout << "\tTotal data exchanged are " << total_data_size + del_bandwidth_cost << " bytes" << endl
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
