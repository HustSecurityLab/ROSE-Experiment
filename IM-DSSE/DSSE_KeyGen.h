#ifndef DSSE_KEYGEN_H
#define DSSE_KEYGEN_H

#include "MasterKey.h"
#include "struct_MatrixType.h"
#include "config.h"
class DSSE_KeyGen
{
public:
    DSSE_KeyGen();
    ~DSSE_KeyGen();

    int genMaster_key(MasterKey *pKey, prng_state *prng);

    int genRow_key(unsigned char *pOutData, int out_len, unsigned char *pInData, int in_len, MasterKey *pKey);

    int pregenerateRow_keys(TYPE_COUNTER *row_counter_arr,
                            unsigned char output[MATRIX_ROW_SIZE * BLOCK_CIPHER_SIZE],
                            MasterKey *pKey);

    int precomputeAES_CTR_keys(unsigned char *key,
                               TYPE_INDEX idx, int dim, bool isIncremental,
                               TYPE_COUNTER *col_counter_arr,
                               unsigned char *pregenRow_keys,
                               MasterKey *pKey);

    int enc_dec_preAESKey(MatrixType *output,
                          MatrixType *input,
                          unsigned char preKey[],
                          TYPE_INDEX len);
};

#endif // DSSE_KEYGEN_H