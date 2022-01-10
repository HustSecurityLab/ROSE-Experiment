#include <iostream>
#include <string>
#include <vector>
#include "KUPRF.h"
#include "rose_client.h"
#include "rose_server.h"
#include "sse_benchmark.h"

using namespace std;

int test_sse()
{
    RoseClient rose_client;
    RoseServer rose_server(true);
    vector<int>  result_plain;
    vector<string> result_cip;
    string L, R, D, C, tpd_L, tpd_T;

    rose_client.setup();
    rose_server.setup();

    for(int i=0; i<200;i++)
    {
        rose_client.encrypt(L, R, D, C,op_add, "abc", i);
        rose_server.save(L, R, D, C);
    }
    for(int i=20; i<300;i++)
    {
        rose_client.encrypt(L, R, D, C,op_add, "abc", i);
        rose_server.save(L, R, D, C);
    }

    for(int i=30; i<400;i++)
    {
        rose_client.encrypt(L, R, D, C,op_add, "abc", i);
        rose_server.save(L, R, D, C);
    }

    for(int i=40; i<500;i++)
    {
        rose_client.encrypt(L, R, D, C,op_add, "abc", i);
        rose_server.save(L, R, D, C);
    }
    rose_client.trapdoor("abc", tpd_L, tpd_T, L, R, D, C);
    rose_server.save(L,R,D,C);
    rose_client.trapdoor("abc", tpd_L, tpd_T, L, R, D, C);
    rose_server.save(L,R,D,C);
    rose_client.trapdoor("abc", tpd_L, tpd_T, L, R, D, C);
    rose_server.save(L,R,D,C);
    rose_client.trapdoor("abc", tpd_L, tpd_T, L, R, D, C);
    rose_server.save(L,R,D,C);

    for(int i=0;i<400;i++)
    {
        rose_client.encrypt(L, R, D, C,op_del, "abc", i);
        rose_server.save(L, R, D, C);
    }

    rose_client.save_data();
    rose_client.load_data();
    rose_server.save_data();
    rose_server.load_data();

    rose_client.trapdoor("abc", tpd_L, tpd_T, L, R, D, C);
    result_cip.clear();
    result_plain.clear();
    //rose_server.search(result_cip, tpd_L, tpd_T, L, R, D, C);
    rose_server.search_with_parallel_del(result_cip, tpd_L, tpd_T, L, R, D, C, 6);
    rose_client.decrypt(result_plain, "abc", result_cip);

    for (auto itr:result_plain)
    {
        cout << itr << endl;
    }

    cout << "----------------------------------------\nTotally found " << result_plain.size() << " records" << endl;

    return 0;
}

void benchmark()
{
    SSEBenchmark benchmark;

    benchmark.Setup("sse_data_test");
    //benchmark.benchmark_gen_add_cipher();
    //benchmark.benchmark_gen_del_cipher();
    benchmark.benchmark_search();
    benchmark.benchmark_deletions();
    benchmark.benchamark_deletion_in_parallel();
    benchmark.benchmark_opt_deletions();
}

int main()
{
    KUPRF::init();

    benchmark();
    //test_sse();

    KUPRF::clean();

    return 0;
}
