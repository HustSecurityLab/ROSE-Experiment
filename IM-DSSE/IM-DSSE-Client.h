#ifndef IM_DSSE_CLIENT_H
#define IM_DSSE_CLIENT_H

#include <string>
#include <vector>
#include <map>
#include "struct_MatrixType.h"
#include "MasterKey.h"

using std::string;
using std::vector;
using std::map;

enum UpdateBlockOp
{
    OpAdd = 0,
    OpDel
};

class IMDSSEClient
{
public:
    IMDSSEClient();
    ~IMDSSEClient();

    int genMaster_key();

    int setupData_structure(MatrixType *** I_out);

    int addToken_step1(TYPE_INDEX &block_index, int filename);

    int addToken_step2(MatrixType *I_prime, TYPE_INDEX &block_index, int filename,const vector<string>& keywords);

    int addToken_step2(MatrixType *I_prime, TYPE_INDEX &block_index, int filename,const string& keyword);

    int delToken_step1(TYPE_INDEX &block_index, int filename);

    int delToken_step2(MatrixType *I_prime, TYPE_INDEX &block_index, int filename,const vector<string>& keywords);

    int delToken_step2(MatrixType *I_prime, TYPE_INDEX &block_index, int filename,const string& keyword);

    int searchToken(TYPE_INDEX &row_index, const string &keyword);

    int decrypt(vector<int> &rslt, MatrixType *search_data, TYPE_INDEX row_index, const string &keyword);

private:
    MasterKey* masterKey;

    prng_state prng;
    MatrixType* I_prime;

    unsigned char* row_keys;
    unsigned char* decrypt_key;
    unsigned char* reencrypt_key;

    map<TYPE_INDEX, int> idx_F;
    TYPE_GOOGLE_DENSE_HASH_MAP rT_W, rT_F;

    TYPE_COUNTER keyword_counter_arr[MAX_NUM_KEYWORDS], block_counter_arr[NUM_BLOCKS];
    MatrixType** block_state_mat;
    vector<TYPE_INDEX> lstFree_column_idx;
    vector<TYPE_INDEX> lstFree_row_idx;

    int createEncrypted_matrix(MatrixType *** I_out);

    int requestBlock_index(int adding_filename_with_pad,
                            TYPE_INDEX &block_index,
                            TYPE_GOOGLE_DENSE_HASH_MAP &r_TF,
                            vector<TYPE_INDEX> &lstFree_column_idx,
                            MasterKey *pKey);
    int pickRandom_element(TYPE_INDEX &randomIdx,vector<TYPE_INDEX> &setIdx,prng_state* prng);
    int updateBlock(    MatrixType* updating_block,
                        MatrixType* input_block,
                        TYPE_INDEX update_idx,
                        UpdateBlockOp op=OpAdd);


    int getBlock( TYPE_INDEX index,
                        int dim,
                        MatrixType** I,
                        MatrixType* I_prime);

    static void* thread_precomputeAesKey_func(void* param);
};

#endif