#include <chrono>
#include <vector>
#include <iostream>
#include <string>
#include "IM-DSSE-Client.h"
#include "IM-DSSE-Server.h"
#include "sse_benchmark.h"

using namespace std;

void test_IM_DSSE()
{

    cout << "MATRIX_ROW_SIZE: " << MATRIX_ROW_SIZE << endl;
    cout << "MATRIX_COL_SIZE: " << MATRIX_COL_SIZE << endl;
    cout << "MATRIX_PIECE_COL_SIZE: " << MATRIX_PIECE_COL_SIZE << endl;
    cout << "ENCRYPT_BLOCK_SIZE: " << ENCRYPT_BLOCK_SIZE << endl;
    cout << "BYTE_SIZE: " << BYTE_SIZE << endl;
    IMDSSEClient imdsse_clnt;
    IMDSSEServer imdsse_srv;
    TYPE_INDEX idx;
    MatrixType *I_data1;
    MatrixType **I;
    vector<int> rslt;

    imdsse_clnt.genMaster_key();
    imdsse_clnt.setupData_structure(&I);
    imdsse_srv.Setup(I);

    for (int i = 0; i < 20; i++)
    {
        imdsse_clnt.addToken_step1(idx, i);
        imdsse_srv.readUpdateDataBlock(idx, &I_data1);
        imdsse_clnt.addToken_step2(I_data1, idx, i, "abc");
        imdsse_srv.writeUpdateDataBlock(idx, I_data1);
        delete[] I_data1;
    }

    for (int i = 10; i < 20; i++)
    {
        imdsse_clnt.addToken_step1(idx, i);
        imdsse_srv.readUpdateDataBlock(idx, &I_data1);
        imdsse_clnt.addToken_step2(I_data1, idx, i, "def");
        imdsse_srv.writeUpdateDataBlock(idx, I_data1);
        delete[] I_data1;
    }

    for (int i = 15; i < 20; i++)
    {
        imdsse_clnt.delToken_step1(idx, i);
        imdsse_srv.readUpdateDataBlock(idx, &I_data1);
        imdsse_clnt.delToken_step2(I_data1, idx, i, "def");
        imdsse_srv.writeUpdateDataBlock(idx, I_data1);
        delete[] I_data1;
    }

    imdsse_clnt.searchToken(idx, "def");
    imdsse_srv.readSearchDataBlock(idx, &I_data1);
    imdsse_clnt.decrypt(rslt, I_data1, idx, "def");

    for (auto itr : rslt)
        cout << itr << endl;

    cout << rslt.size() << endl;
    cout << "----------------" << endl;
    rslt.clear();

    imdsse_clnt.searchToken(idx, "abc");
    imdsse_srv.readSearchDataBlock(idx, &I_data1);
    imdsse_clnt.decrypt(rslt, I_data1, idx, "abc");

    for (auto itr : rslt)
        cout << itr << endl;

    cout << rslt.size() << endl;

}

void benchmark()
{
    SSEBenchmark benchmark;

    benchmark.Setup("sse_data_test");
    benchmark.benchmark_gen_add_cipher();
    benchmark.benchmark_gen_del_cipher();
    benchmark.benchmark_search();
    benchmark.benchmark_deletions();
}


int main(int argc, char *argv[])
{
    benchmark();
    //test_IM_DSSE();
}