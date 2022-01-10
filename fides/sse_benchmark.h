#ifndef SSE_BENCHMARK_H
#define SSE_BENCHMARK_H

#include <vector>
#include <unordered_map>
#include <string>

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>

class SSEBenchmark
{
public:
    SSEBenchmark() = default;

    ~SSEBenchmark() = default;

    //read data and generate ciphertexts and local state
    int Setup(const std::string &filename);

    //time cost of generating save ciphertext
    int benchmark_gen_add_cipher();

    //time cost of generating delete ciphertext
    int benchmark_gen_del_cipher();

    //time cost of search with deletions
    int benchmark_deletions();

    //time cost of search without deletions
    int benchmark_search();

private:
    std::unordered_map<std::string, std::vector<int>> data_to_encrypt;
    void randomly_select_deletions(std::unordered_set<int> &indices, std::string &keyword, double por);
    int total_add_records = 0;
    int keyword_number = 0;

};


#endif
