#include "struct_thread_precompute_aeskey.h"

THREAD_PRECOMPUTE_AESKEY::THREAD_PRECOMPUTE_AESKEY()
{
}


THREAD_PRECOMPUTE_AESKEY::THREAD_PRECOMPUTE_AESKEY(unsigned char* aes_keys, TYPE_INDEX idx, int dim, bool isIncremental, TYPE_COUNTER* block_counter_arr,unsigned char* row_keys, MasterKey* masterKey)
{
    this->idx = idx;
    this->dim = dim;
    this->block_counter_arr = block_counter_arr;
    this->row_keys = row_keys;
    this->masterKey = masterKey;
    this->aes_keys = aes_keys;
    this->isIncremental = isIncremental;
}



THREAD_PRECOMPUTE_AESKEY::~THREAD_PRECOMPUTE_AESKEY()
{
}
