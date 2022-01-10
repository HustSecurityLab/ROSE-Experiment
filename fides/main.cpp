#include <iostream>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include "trapdoor_permutation.h"
#include "sophos.h"
#include "fides.h"
#include "sse_benchmark.h"

using std::cout;
using std::endl;
using std::vector;
using std::string;

int test_fides_correctness()
{
    FidesClient fides_clnt;
    FidesServer fides_srv;
    char buf1[64];
    string label, cipher, st, kw, IV;
    unsigned int counter;
    TdpPK pk;
    vector<string> cipher_out;
    vector<int> plain_out;
    vector<string> labels, ciphers;

    fides_clnt.Setup();
    fides_srv.Setup();

    for (int i = 0; i < 200; i++)
    {
        fides_clnt.update(label,cipher, "abc", i, Fides_Add);
        fides_srv.save(label,  cipher);
    }

    for (int i = 10; i < 70; i++)
    {
        fides_clnt.update(label, cipher, "abc",i, Fides_Del);
        fides_srv.save(label,  cipher);
    }

    fides_clnt.search_stage1(kw, st, counter, "abc");
    fides_clnt.get_pk(&pk);
    fides_srv.search(cipher_out, &pk, kw, st, counter);
    fides_clnt.search_stage2(plain_out, "abc", cipher_out);
    fides_clnt.update_after_search("abc", plain_out, labels, ciphers);
    fides_srv.save(labels, ciphers);

    fides_clnt.dump_data();
    fides_clnt.load_data();
    fides_srv.dump_data();
    fides_srv.load_data();

    plain_out.clear();
    cipher_out.clear();
    labels.clear();
    ciphers.clear();

    fides_clnt.search_stage1(kw, st, counter, "abc");
    fides_clnt.get_pk(&pk);
    fides_srv.search(cipher_out, &pk, kw, st, counter);
    fides_clnt.search_stage2(plain_out, "abc", cipher_out);
    fides_clnt.update_after_search("abc", plain_out, labels, ciphers);
    fides_srv.save(labels, ciphers);

    for (const auto &a:plain_out)
        cout << a << endl;

    cout << "Totally find " << plain_out.size() << " ids." << endl;

    cout << "----------------------------" << endl;

    FidesClient _fides_clnt;
    FidesServer _fides_srv;

    _fides_clnt.Setup();
    _fides_srv.Setup();

    _fides_clnt.load_data();
    _fides_srv.load_data();
    cipher_out.clear();
    plain_out.clear();
    labels.clear();
    ciphers.clear();
    _fides_clnt.search_stage1(kw, st, counter, "abc");
    _fides_clnt.get_pk(&pk);
    _fides_srv.search(cipher_out, &pk, kw, st, counter);
    _fides_clnt.search_stage2(plain_out, "abc", cipher_out);

    _fides_clnt.update_after_search("abc", plain_out, labels, ciphers);
    _fides_srv.save(labels, ciphers);

    cout << "Totally find " << plain_out.size() << " ids." << endl;

    return 1;
}

int run_sse_benchmark(const string filename)
{
    SSEBenchmark bench;
    bench.Setup(filename);
    //bench.benchmark_gen_add_cipher();
    //bench.benchmark_gen_del_cipher();
    //bench.benchmark_search();
    bench.benchmark_deletions();

    return 0;
}

int main()
{
   run_sse_benchmark("sse_data_test");
   //test_fides_correctness();

    return 0;
}
