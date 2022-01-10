#include "sse_benchmark.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <chrono>
#include <set>
#include <random>
#include "sse_benchmark.h"
#include "IM-DSSE-Server.h"
#include "IM-DSSE-Client.h"

extern "C"
{
#include <openssl/rand.h>
}

using namespace std;

int SSEBenchmark::Setup(const std::string &filename)
{
    FILE *f_data = fopen(filename.c_str(), "r");
    int counter = 0;
    char word[64], name[64];

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
            int ind;
            this->total_add_records += 1;
            fscanf(f_data, "%d\n", &ind);
            _v.emplace_back(ind);
        }
    }
    fclose(f_data);
    return 1;
}

int SSEBenchmark::benchmark_gen_add_cipher()
{
    IMDSSEClient imdsse_clnt;
    IMDSSEServer imdsse_srv;
    MatrixType **I;
    MatrixType *I_data1;
    TYPE_INDEX idx;
    double time_to_add = 0;
    long long total_bandwidth = 0;

    imdsse_clnt.genMaster_key();
    imdsse_clnt.setupData_structure(&I);
    imdsse_srv.Setup(I);

    chrono::_V2::steady_clock::time_point start, end;
    chrono::duration<double, std::micro> elapsed;

    cout << "Beginning gen_add benchmark..." << endl;

    for (const auto &a : data_to_encrypt)
        for (const auto &f_name : a.second)
        {
            start = chrono::steady_clock::now();
            imdsse_clnt.addToken_step1(idx, f_name);
            end = chrono::steady_clock::now();
            elapsed = end - start;
            time_to_add += elapsed.count();

            total_bandwidth += sizeof(idx);

            imdsse_srv.readUpdateDataBlock(idx, &I_data1);

            total_bandwidth += ((MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE) / BYTE_SIZE);

            start = chrono::steady_clock::now();
            imdsse_clnt.addToken_step2(I_data1, idx, f_name, a.first);
            end = chrono::steady_clock::now();
            elapsed = end - start;
            time_to_add += elapsed.count();

            total_bandwidth += sizeof(idx) + ((MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE) / BYTE_SIZE);

            imdsse_srv.writeUpdateDataBlock(idx, I_data1);
            delete[] I_data1;
        }

    cout << "add time cost: " << endl;
    cout << "\ttotally " << total_add_records << " records, total " << time_to_add << " us" << endl;
    cout << "\t average time " << time_to_add / total_add_records << " us" << endl;
    cout << "average bandwdith cost is " << total_bandwidth / total_add_records << " bytes" << endl
         << endl;
    return 1;
}

int SSEBenchmark::benchmark_gen_del_cipher()
{
    IMDSSEClient imdsse_clnt;
    IMDSSEServer imdsse_srv;
    MatrixType **I;
    MatrixType *I_data1;
    TYPE_INDEX idx;
    double time_to_add = 0;
    long long total_bandwidth = 0;

    imdsse_clnt.genMaster_key();
    imdsse_clnt.setupData_structure(&I);
    imdsse_srv.Setup(I);

    chrono::_V2::steady_clock::time_point start, end;
    chrono::duration<double, std::micro> elapsed;

    cout << "Beginning gen_del benchmark..." << endl;

    for (const auto &a : data_to_encrypt)
        for (const auto &f_name : a.second)
        {
            imdsse_clnt.addToken_step1(idx, f_name);
            imdsse_srv.readUpdateDataBlock(idx, &I_data1);
            imdsse_clnt.addToken_step2(I_data1, idx, f_name, a.first);
            imdsse_srv.writeUpdateDataBlock(idx, I_data1);
            delete[] I_data1;
        }

    for (const auto &a : data_to_encrypt)
        for (const auto &f_name : a.second)
        {
            start = chrono::steady_clock::now();
            imdsse_clnt.delToken_step1(idx, f_name);
            end = chrono::steady_clock::now();
            elapsed = end - start;
            time_to_add += elapsed.count();

            total_bandwidth += sizeof(idx);

            imdsse_srv.readUpdateDataBlock(idx, &I_data1);

            total_bandwidth += ((MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE) / BYTE_SIZE);

            start = chrono::steady_clock::now();
            imdsse_clnt.delToken_step2(I_data1, idx, f_name, a.first);
            end = chrono::steady_clock::now();
            elapsed = end - start;
            time_to_add += elapsed.count();

            total_bandwidth += sizeof(idx) + ((MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE) / BYTE_SIZE);

            imdsse_srv.writeUpdateDataBlock(idx, I_data1);
            delete[] I_data1;
        }

    cout << "del time cost: " << endl;
    cout << "\ttotally " << total_add_records << " records, total " << time_to_add << " us" << endl;
    cout << "\t average time " << time_to_add / total_add_records << " us" << endl;
    cout << "average bandwdith cost is " << total_bandwidth / total_add_records << " bytes" << endl
         << endl;
    return 1;
}

int SSEBenchmark::benchmark_search()
{
    cout << "Beginning search benchmark..." << endl;

    IMDSSEClient imdsse_clnt;
    IMDSSEServer imdsse_srv;
    MatrixType **I;
    MatrixType *I_data1;
    TYPE_INDEX idx;
    double time_cost_clnt = 0;
    double time_cost_srv = 0;
    long long total_bandwidth = 0;
    vector<int> plain_out;

    imdsse_clnt.genMaster_key();
    imdsse_clnt.setupData_structure(&I);
    imdsse_srv.Setup(I);

    chrono::_V2::steady_clock::time_point start, end;
    chrono::duration<double, std::micro> elapsed;

    for (const auto &a : data_to_encrypt)
        for (const auto &f_name : a.second)
        {
            imdsse_clnt.addToken_step1(idx, f_name);
            imdsse_srv.readUpdateDataBlock(idx, &I_data1);
            imdsse_clnt.addToken_step2(I_data1, idx, f_name, a.first);
            imdsse_srv.writeUpdateDataBlock(idx, I_data1);
            delete[] I_data1;
        }

    //for every keywords, execute search
    for (auto &itr : this->data_to_encrypt)
    {
        time_cost_clnt = 0;
        time_cost_srv = 0;
        total_bandwidth = 0;

        plain_out.clear();

        plain_out.reserve(300000);
        total_bandwidth = 0;
        //search
        start = std::chrono::steady_clock::now();
        imdsse_clnt.searchToken(idx, itr.first);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        time_cost_clnt += elapsed.count();
        total_bandwidth += sizeof(idx);

        start = std::chrono::steady_clock::now();
        imdsse_srv.readSearchDataBlock(idx, &I_data1);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        time_cost_srv += elapsed.count();
        total_bandwidth += MATRIX_COL_SIZE;

        start = std::chrono::steady_clock::now();
        imdsse_clnt.decrypt(plain_out, I_data1, idx, itr.first);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        time_cost_clnt += elapsed.count();

        cout << "Searching for keyword: " << itr.first << endl;
        cout << "\tTotally find " << plain_out.size() << " records and the last file ID is "
             << plain_out[plain_out.size() - 1] << endl;
        cout << "\tTotal time cost is " << std::fixed << time_cost_clnt + time_cost_srv << " us, average is "
             << (time_cost_clnt + time_cost_srv) / plain_out.size() << endl;
        cout << "\tClient time cost is " << time_cost_clnt << " us, average is " << time_cost_clnt / plain_out.size() << endl;
        cout << "\tTotal data exchanged are " << total_bandwidth << " Bytes, " << total_bandwidth / 1024 << " KB, "
             << total_bandwidth / 1024 / 1024 << " MB " << endl
             << endl;

        delete[] I_data1;
    }

    return 0;
}

int SSEBenchmark::benchmark_deletions()
{
    cout << "Beginning deleting and search benchmark..." << endl;

    vector<int> plain_out;
    vector<double> portion_to_del = {0.0, 0.02, 0.04, 0.06, 0.08, 0.1, 0.12, 0.14, 0.16, 0.18, 0.2, 0.22, 0.24, 0.26, 0.28, 0.3, 0.32, 0.34, 0.36, 0.38, 0.4, 0.42, 0.44, 0.46, 0.48, 0.5};
    string keyword_to_delete = "40";

    //for every keywords, execute search
    cout << endl
         << endl
         << "Begin test deletions" << endl;
    for (int __i = 0; __i < 2; __i++)
    {
        for (double por : portion_to_del)
        {
            IMDSSEClient imdsse_clnt;
            IMDSSEServer imdsse_srv;
            MatrixType **I;
            MatrixType *I_data1;
            TYPE_INDEX idx;
            double time_cost_clnt = 0;
            double time_cost_srv = 0;
            long long total_bandwidth = 0;
            vector<int> plain_out;
            unordered_set<int> indices;

            imdsse_clnt.genMaster_key();
            imdsse_clnt.setupData_structure(&I);
            imdsse_srv.Setup(I);

            chrono::_V2::steady_clock::time_point start, end;
            chrono::duration<double, std::micro> elapsed;

            for (const auto &a : data_to_encrypt)
                for (const auto &f_name : a.second)
                {
                    imdsse_clnt.addToken_step1(idx, f_name);
                    imdsse_srv.readUpdateDataBlock(idx, &I_data1);
                    imdsse_clnt.addToken_step2(I_data1, idx, f_name, a.first);
                    imdsse_srv.writeUpdateDataBlock(idx, I_data1);
                    delete[] I_data1;
                }

            vector<int> &fnames = data_to_encrypt[keyword_to_delete];

            indices.clear();
            plain_out.clear();

            indices.reserve(300000);
            plain_out.reserve(300000);
            //generate delete ciphertexts
            this->randomly_select_deletions(indices, keyword_to_delete, por);

            for (auto &itr : indices)
            {
                imdsse_clnt.delToken_step1(idx, itr);
                imdsse_srv.readUpdateDataBlock(idx, &I_data1);
                imdsse_clnt.delToken_step2(I_data1, idx, itr, keyword_to_delete);
                imdsse_srv.writeUpdateDataBlock(idx, I_data1);
                delete[] I_data1;
            }

            start = std::chrono::steady_clock::now();
            imdsse_clnt.searchToken(idx, keyword_to_delete);
            end = std::chrono::steady_clock::now();
            elapsed = end - start;
            time_cost_clnt += elapsed.count();
            total_bandwidth += sizeof(idx);

            start = std::chrono::steady_clock::now();
            imdsse_srv.readSearchDataBlock(idx, &I_data1);
            end = std::chrono::steady_clock::now();
            elapsed = end - start;
            time_cost_srv += elapsed.count();
            total_bandwidth += MATRIX_COL_SIZE;

            start = std::chrono::steady_clock::now();
            imdsse_clnt.decrypt(plain_out, I_data1, idx, keyword_to_delete);
            end = std::chrono::steady_clock::now();
            elapsed = end - start;
            time_cost_clnt += elapsed.count();

            cout << "Performing Deleting When Searching for keyword: " << keyword_to_delete << endl;
            cout << "Deletion Portion: " << por << " and deleted entries is: " << int(por * fnames.size()) << endl;
            cout << "\tTotally found " << plain_out.size() << endl;
            cout << "\tSearch time cost is " << (time_cost_clnt + time_cost_srv) << " us, average is " << (time_cost_clnt + time_cost_srv) / plain_out.size()
                 << " us" << endl;
            cout << "\tSearch data exchanged are " << total_bandwidth << " bytes, " << total_bandwidth / 1024 << " KB, "
                 << total_bandwidth / 1024 / 1024 << " MB" << endl
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
