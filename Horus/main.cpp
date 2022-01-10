#include "Horus.h"
#include "sse_benchmark.h"

using namespace std;

void run_benchmark()
{
    SSEBenchmark benchmark;

    benchmark.Setup("sse_data_test");
    benchmark.benchmark_gen_del_cipher();
    benchmark.benchmark_search();
    benchmark.benchmark_deletions();
}

void test_crash()
{
    Horus horus(false, 3000);


    for (int i = 0; i < 3000; i++)
    {
        cout << "Encrypting " <<  i << " ..." << endl;
        horus.insert("abc", i);
    }

    auto result = horus.search("abc");

    cout << result.size() << endl;

}


int main(int, char **)
{
    run_benchmark();
    //test_crash();
    return 0;
}

