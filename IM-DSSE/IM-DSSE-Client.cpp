#include "IM-DSSE-Client.h"

#include <tomcrypt.h>
#include "config.h"
#include "DSSE_KeyGen.h"
#include "DSSE_Crypto.h"
#include "DSSE_Trapdoor.h"
#include "struct_thread_precompute_aeskey.h"

IMDSSEClient::IMDSSEClient()
{
    int err;
    if ((err = register_prng(&fortuna_desc)) != CRYPT_OK)
    {
        printf("Error registering Fortuna PRNG : %s\n", error_to_string(err));
    }

    if ((err = find_prng("fortuna")) != CRYPT_OK)
    {
        printf("Invalid PRNG : %s\n", error_to_string(err));
    }

    /* start it */
    if ((err = fortuna_start(&prng)) != CRYPT_OK)
    {
        printf("Start error: %s\n", error_to_string(err));
    }

    if ((err = fortuna_add_entropy((unsigned char *)seed.c_str(), seed.size(), &prng)) != CRYPT_OK)
    {
        printf("Add_entropy error: %s\n", error_to_string(err));
    }
    if ((err = fortuna_ready(&prng)) != CRYPT_OK)
    {
        printf("Ready error: %s\n", error_to_string(err));
    }

    /* Allocate memory for I' & block state array */
    I_prime = new MatrixType[MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE];
    memset(I_prime, 0, MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE);

    decrypt_key = new unsigned char[MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE];
    reencrypt_key = new unsigned char[MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE];
    memset(decrypt_key, 0, MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE);
    memset(reencrypt_key, 0, MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE);
}

IMDSSEClient::~IMDSSEClient()
{
}

int IMDSSEClient::genMaster_key()
{
    DSSE_KeyGen *dsse_key = new DSSE_KeyGen();
    this->masterKey = new MasterKey();
    dsse_key->genMaster_key(this->masterKey, &prng);

    delete dsse_key;
    return 0;
}

int IMDSSEClient::createEncrypted_matrix(MatrixType ***I_out)
{
    int n;
    TYPE_INDEX curIdx;
    TYPE_INDEX size_row;
    TYPE_INDEX col, row, row_idx;
    TYPE_INDEX vector_idx = 0;
    TYPE_INDEX ii, jj;
    int bit_number;
    n = MATRIX_COL_SIZE / MATRIX_PIECE_COL_SIZE;

    unsigned char U[BLOCK_CIPHER_SIZE];
    unsigned char V[BLOCK_CIPHER_SIZE];
    unsigned char uchar_counter[BLOCK_CIPHER_SIZE];
    TYPE_INDEX block_idx;
    unsigned char row_key[BLOCK_CIPHER_SIZE];
    unsigned char row_key_input[BLOCK_CIPHER_SIZE];
    DSSE_KeyGen *dsse_keygen = new DSSE_KeyGen();

    MatrixType **I = new MatrixType *[MATRIX_ROW_SIZE];
    for (TYPE_INDEX m = 0; m < MATRIX_ROW_SIZE; m++)
    {
        I[m] = new MatrixType[MATRIX_PIECE_COL_SIZE];
        memset(I[m], 0, MATRIX_PIECE_COL_SIZE);
    }

    block_idx = 0;

    for (int i = 0; i < n; i++)
    {
        for (TYPE_INDEX m = 0; m < MATRIX_ROW_SIZE; m++)
        {
            memset(I[m], 0, MATRIX_PIECE_COL_SIZE);
        }

        // encrypt block by block, there are two options:
        if (ENCRYPT_BLOCK_SIZE < BYTE_SIZE) // block size < byte size
        {
            for (row = 0; row < MATRIX_ROW_SIZE; row++)
            {
                memcpy(row_key_input, &row, sizeof(row));
                memcpy(&row_key_input[BLOCK_CIPHER_SIZE / 2], &keyword_counter_arr[row], sizeof(keyword_counter_arr[row]));

                dsse_keygen->genRow_key(row_key, BLOCK_CIPHER_SIZE, row_key_input, BLOCK_CIPHER_SIZE, masterKey);

                block_idx = (MATRIX_PIECE_COL_SIZE * BYTE_SIZE / ENCRYPT_BLOCK_SIZE) * i;
                for (jj = 0; jj < MATRIX_PIECE_COL_SIZE * BYTE_SIZE; jj += ENCRYPT_BLOCK_SIZE, block_idx++)
                {
                    col = jj / BYTE_SIZE;
                    for (ii = 0, bit_number = jj % BYTE_SIZE; ii < ENCRYPT_BLOCK_SIZE; ii++, bit_number++)
                    {
                        if (BIT_CHECK(&I[row][col].byte_data, bit_number))
                            BIT_SET(&U[0], ii);
                        else
                            BIT_CLEAR(&U[0], ii);
                    }
                    memset(uchar_counter, 0, BLOCK_CIPHER_SIZE);
                    memcpy(&uchar_counter[BLOCK_CIPHER_SIZE / 2], &block_counter_arr[block_idx], sizeof(TYPE_COUNTER));
                    memcpy(&uchar_counter, &block_idx, sizeof(TYPE_INDEX));
                    // Encrypting the  matrix I using AES CTR 128 function
                    aes128_ctr_encdec(U, V, row_key, uchar_counter, ONE_VALUE);
                    // Write the encryped row back to matrix I
                    for (ii = 0, bit_number = jj % BYTE_SIZE; ii < ENCRYPT_BLOCK_SIZE; ii++, bit_number++)
                    {

                        if (BIT_CHECK(&V[0], ii))
                            BIT_SET(&I[row][col].byte_data, bit_number);
                        else
                            BIT_CLEAR(&I[row][col].byte_data, bit_number);
                    }
                }
            }
        }
        else // encrypt block size > byte_size
        {
            if (ENCRYPT_BLOCK_SIZE % BYTE_SIZE != 0)
            {
                printf("Invalid block size, it should be divisible by 8 and not larger than 128");
                exit(1);
            }

            for (row = 0; row < MATRIX_ROW_SIZE; row++)
            {
                memcpy(row_key_input, &row, sizeof(row));
                memcpy(&row_key_input[BLOCK_CIPHER_SIZE / 2], &keyword_counter_arr[row], sizeof(keyword_counter_arr[row]));

                dsse_keygen->genRow_key(row_key, BLOCK_CIPHER_SIZE, row_key_input, BLOCK_CIPHER_SIZE, masterKey);

                block_idx = (MATRIX_PIECE_COL_SIZE * BYTE_SIZE / ENCRYPT_BLOCK_SIZE) * i;
                for (col = 0; col < MATRIX_PIECE_COL_SIZE; col += (ENCRYPT_BLOCK_SIZE / BYTE_SIZE), block_idx++)
                {
                    for (jj = col, ii = 0; ii < ENCRYPT_BLOCK_SIZE / BYTE_SIZE; jj++, ii++)
                    {
                        U[ii] = I[row][jj].byte_data;
                    }
                    memset(uchar_counter, 0, BLOCK_CIPHER_SIZE);
                    memcpy(&uchar_counter[BLOCK_CIPHER_SIZE / 2], &block_counter_arr[block_idx], sizeof(TYPE_COUNTER));
                    memcpy(&uchar_counter, &block_idx, sizeof(TYPE_INDEX));
                    // Encrypting the  matrix I using AES CTR 128 function
                    aes128_ctr_encdec(U, V, row_key, uchar_counter, ONE_VALUE);
                    for (jj = col, ii = 0; ii < ENCRYPT_BLOCK_SIZE / BYTE_SIZE; jj++, ii++)
                    {
                        I[row][jj].byte_data = V[ii];
                    }
                }
            }
        }
    }

    *I_out = I;

    return 0;
}

int IMDSSEClient::setupData_structure(MatrixType ***I_out)
{
    set<string>::iterator iter;

    unsigned char empty_label[6] = "EMPTY";
    unsigned char delete_label[7] = "DELETE";
    hashmap_key_class empty_key = hashmap_key_class(empty_label, 6);
    hashmap_key_class delete_key = hashmap_key_class(delete_label, 7);

    rT_W = TYPE_GOOGLE_DENSE_HASH_MAP(MAX_NUM_KEYWORDS * KEYWORD_LOADING_FACTOR);
    rT_W.max_load_factor(KEYWORD_LOADING_FACTOR);
    rT_W.min_load_factor(0.0);
    rT_W.set_empty_key(empty_key);
    rT_W.set_deleted_key(delete_key);

    rT_F = TYPE_GOOGLE_DENSE_HASH_MAP(MAX_NUM_OF_FILES * KEYWORD_LOADING_FACTOR);
    rT_F.max_load_factor(FILE_LOADING_FACTOR);
    rT_F.min_load_factor(0.0);
    rT_F.set_empty_key(empty_key);
    rT_F.set_deleted_key(delete_key);

    lstFree_column_idx.reserve(MAX_NUM_OF_FILES);
    lstFree_column_idx.clear();
    lstFree_row_idx.reserve(MAX_NUM_KEYWORDS);
    lstFree_row_idx.clear();

    for (TYPE_INDEX j = 0; j < MAX_NUM_KEYWORDS; j++)
        lstFree_row_idx.push_back(j);
    for (TYPE_INDEX j = 0; j < MAX_NUM_OF_FILES; j++)
        lstFree_column_idx.push_back(j);
    for (TYPE_INDEX i = 0; i < MAX_NUM_KEYWORDS; i++)
        keyword_counter_arr[i] = 1;
    for (TYPE_INDEX i = 0; i < MAX_NUM_OF_FILES / ENCRYPT_BLOCK_SIZE; i++)
        block_counter_arr[i] = 1;

    this->row_keys = new unsigned char[BLOCK_CIPHER_SIZE * MATRIX_ROW_SIZE];
    memset(this->row_keys, 0, BLOCK_CIPHER_SIZE * MATRIX_ROW_SIZE);
    DSSE_KeyGen *dsse_keygen = new DSSE_KeyGen();
    dsse_keygen->pregenerateRow_keys(this->keyword_counter_arr, row_keys, this->masterKey);

    createEncrypted_matrix(I_out);

    delete dsse_keygen;

    return 0;
}

int IMDSSEClient::requestBlock_index(int adding_filename_with_pad,
                                     TYPE_INDEX &block_index,
                                     TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
                                     vector<TYPE_INDEX> &lstFree_column_idx,
                                     MasterKey *pKey)
{
    unsigned char file_trapdoor[TRAPDOOR_SIZE];
    TYPE_INDEX file_index;
    DSSE_Trapdoor *dsse_trapdoor = new DSSE_Trapdoor();
    TYPE_INDEX selectedIdx;

    dsse_trapdoor->generateTrapdoor_single_input(file_trapdoor, TRAPDOOR_SIZE,
                                                 (unsigned char *)&adding_filename_with_pad,
                                                 sizeof(adding_filename_with_pad), pKey);
    hashmap_key_class hmap_file_trapdoor(file_trapdoor, TRAPDOOR_SIZE);
    if (rT_F.find(hmap_file_trapdoor) == rT_F.end())
    {
        this->pickRandom_element(selectedIdx, lstFree_column_idx, &prng);
        rT_F[hmap_file_trapdoor] = selectedIdx;
        idx_F[selectedIdx] = adding_filename_with_pad;
    }
    // Get the file index from the hashmap
    file_index = rT_F[hmap_file_trapdoor];
    block_index = file_index / ENCRYPT_BLOCK_SIZE;
    if (block_index > NUM_BLOCKS)
    {
        printf("Error!!\n");
        exit(1);
    }

    delete dsse_trapdoor;
    return 0;
}

int IMDSSEClient::pickRandom_element(TYPE_INDEX &random_element, vector<TYPE_INDEX> &setIdx, prng_state *prng)
{
    TYPE_INDEX random_idx;
    unsigned char pseudo_random_number[BLOCK_CIPHER_SIZE];
    int seed_len = BLOCK_CIPHER_SIZE;
    int error = 0;

    TYPE_INDEX tmp;

    memset(pseudo_random_number, 0, BLOCK_CIPHER_SIZE);

    // Generate random number
    fortuna_read(pseudo_random_number, BLOCK_CIPHER_SIZE, prng);

    memcpy(&tmp, &pseudo_random_number[7], sizeof(tmp)); // TAKE A HALF OF PSEUDO RANDOM NUMBER VARIABLE
    random_idx = tmp % setIdx.size();

    random_element = setIdx[random_idx];
    setIdx.erase(setIdx.begin() + random_idx);

    memset(pseudo_random_number, 0, BLOCK_CIPHER_SIZE);
    return 0;
}

int IMDSSEClient::addToken_step1(TYPE_INDEX &block_index, int filename)
{
    this->requestBlock_index(filename, block_index, this->rT_F, this->lstFree_column_idx, this->masterKey);

    return 0;
}

int IMDSSEClient::addToken_step2(MatrixType *I_prime, TYPE_INDEX &block_index, int filename, const vector<string> &keywords)
{
    DSSE_Trapdoor *dsse_trapdoor = new DSSE_Trapdoor();
    DSSE_KeyGen *dsse_keygen = new DSSE_KeyGen();
    int bit_position;
    TYPE_INDEX keyword_index, file_index;
    TYPE_INDEX row;
    unsigned char file_trapdoor[TRAPDOOR_SIZE];
    unsigned char keyword_trapdoor[TRAPDOOR_SIZE];

    TYPE_INDEX selectedIdx;
    MatrixType *I_bar;
    MatrixType *decrypted_block;

    THREAD_PRECOMPUTE_AESKEY aes_key_decrypt_param(decrypt_key, block_index, COL, false, this->block_counter_arr, this->row_keys, this->masterKey);
    THREAD_PRECOMPUTE_AESKEY aes_key_reencrypt_param(reencrypt_key, block_index, COL, true, this->block_counter_arr, this->row_keys, this->masterKey);

    thread_precomputeAesKey_func(&aes_key_decrypt_param);
    thread_precomputeAesKey_func(&aes_key_reencrypt_param);

    decrypted_block = new MatrixType[MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE];

    I_bar = new MatrixType[MATRIX_ROW_SIZE / BYTE_SIZE];
    memset(I_bar, 0, MATRIX_ROW_SIZE / BYTE_SIZE);

    dsse_trapdoor->generateTrapdoor_single_input(file_trapdoor, TRAPDOOR_SIZE,
                                                 (unsigned char *)&filename,
                                                 sizeof(filename), masterKey);

    hashmap_key_class hmap_file_trapdoor(file_trapdoor, TRAPDOOR_SIZE);
    if (rT_F.find(hmap_file_trapdoor) == rT_F.end())
    {
        this->pickRandom_element(selectedIdx, lstFree_column_idx, &prng);
        rT_F[hmap_file_trapdoor] = selectedIdx;
        idx_F[selectedIdx] = filename;
    }

    for (auto iter = keywords.begin(); iter != keywords.end(); iter++)
    {
        string word = *iter;
        int keyword_len = word.size();

        if (keyword_len > 0)
        {
            dsse_trapdoor->generateTrapdoor_single_input(keyword_trapdoor, TRAPDOOR_SIZE,
                                                         (unsigned char *)word.c_str(), keyword_len, masterKey);
        }
        hashmap_key_class hmap_keyword_trapdoor(keyword_trapdoor, TRAPDOOR_SIZE);
        if (rT_W.find(hmap_keyword_trapdoor) == rT_W.end())
        {
            this->pickRandom_element(selectedIdx, lstFree_row_idx, &prng);
            rT_W[hmap_keyword_trapdoor] = selectedIdx;
        }
        keyword_index = rT_W[hmap_keyword_trapdoor];
        row = keyword_index / BYTE_SIZE;
        bit_position = keyword_index % BYTE_SIZE;

        BIT_SET(&I_bar[row].byte_data, bit_position);

        word.clear();
    }
    file_index = rT_F[hmap_file_trapdoor];

    //decrypt the input block first
    memset(decrypted_block, 0, MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE);
    dsse_keygen->enc_dec_preAESKey(decrypted_block, I_prime, decrypt_key, MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE);

    //update the decrypted block with newly adding file block
    this->updateBlock(I_bar, decrypted_block, file_index);

    //reencrypt the updated blocks with reenncryption key
    dsse_keygen->enc_dec_preAESKey(I_prime, decrypted_block, reencrypt_key, MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE);

    this->block_counter_arr[block_index] += 1;

    // free memory
    delete dsse_trapdoor;
    delete dsse_keygen;
    delete[] decrypted_block;
    delete[] I_bar;

    return 0;
}

/**
 * Function Name: updateBlock
 *
 * Description:
 * Update the input block with a new column data
 *
 * @param updating_block: (input) the new data which will be used to update a column data in the input block
 * @param input_block: (input) block going to be updated
 * @param update_idx: (input) the index of columns which will be updated in the input block
 * @return	0 if successful
 */

int IMDSSEClient::updateBlock(MatrixType *updating_block,
                              MatrixType *input_block,
                              TYPE_INDEX update_idx,
                              UpdateBlockOp op)
{
    int bit_position;
    TYPE_INDEX row, col;
    TYPE_INDEX idx, ii, size;
    TYPE_INDEX I_bar_idx, I_bar_row, I_bar_bit_position;

    if (op == OpAdd)
    {
        for (I_bar_idx = 0, idx = 0, size = MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE; idx < size; idx += ENCRYPT_BLOCK_SIZE, I_bar_idx++)
        {
            col = idx / BYTE_SIZE;
            row = idx / ENCRYPT_BLOCK_SIZE;
            I_bar_row = I_bar_idx / BYTE_SIZE;
            I_bar_bit_position = I_bar_idx % BYTE_SIZE;

            if (ENCRYPT_BLOCK_SIZE < BYTE_SIZE)
            {
                bit_position = (idx % BYTE_SIZE) + (update_idx % ENCRYPT_BLOCK_SIZE);

                if (BIT_CHECK(&updating_block[I_bar_row].byte_data, I_bar_bit_position))
                    BIT_SET(&input_block[col].byte_data, bit_position);
            }
            else
            {
                //Update decrypted I_prime (V) by I_bar
                ii = (update_idx % ENCRYPT_BLOCK_SIZE) / BYTE_SIZE;
                bit_position = update_idx % BYTE_SIZE;

                if (BIT_CHECK(&updating_block[I_bar_row].byte_data, I_bar_bit_position))
                    BIT_SET(&input_block[row * (ENCRYPT_BLOCK_SIZE / BYTE_SIZE) + ii].byte_data, bit_position);
            }
        }
    }
    else
    {
        for (I_bar_idx = 0, idx = 0, size = MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE; idx < size; idx += ENCRYPT_BLOCK_SIZE, I_bar_idx++)
        {
            col = idx / BYTE_SIZE;
            row = idx / ENCRYPT_BLOCK_SIZE;
            I_bar_row = I_bar_idx / BYTE_SIZE;
            I_bar_bit_position = I_bar_idx % BYTE_SIZE;

            if (ENCRYPT_BLOCK_SIZE < BYTE_SIZE)
            {
                bit_position = (idx % BYTE_SIZE) + (update_idx % ENCRYPT_BLOCK_SIZE);

                if (BIT_CHECK(&updating_block[I_bar_row].byte_data, I_bar_bit_position))
                    BIT_CLEAR(&input_block[col].byte_data, bit_position);
            }
            else
            {
                //Update decrypted I_prime (V) by I_bar
                ii = (update_idx % ENCRYPT_BLOCK_SIZE) / BYTE_SIZE;
                bit_position = update_idx % BYTE_SIZE;

                if (BIT_CHECK(&updating_block[I_bar_row].byte_data, I_bar_bit_position))
                    BIT_CLEAR(&input_block[row * (ENCRYPT_BLOCK_SIZE / BYTE_SIZE) + ii].byte_data, bit_position);
            }
        }
    }
    return 0;
}

/**
 * Function Name: getBlock
 *
 * Description:
 * get the block data from the encrypted data structure, given a block index and the dimension
 *
 * @param block_index: (input) block index
 * @param dim: dimension (ROW or COL)
 * @param I_prime: (output) block data
 * @param I: (input) DSSE encrypted data structure
 * @return	0 if successful
 */
int IMDSSEClient::getBlock(TYPE_INDEX index,
                           int dim,
                           MatrixType **I,
                           MatrixType *I_prime)
{
    TYPE_INDEX row, col;
    TYPE_INDEX I_prime_col;
    try
    {
        if (dim == COL)
        {
            TYPE_INDEX I_prime_idx = 0;
            TYPE_INDEX begin;
            TYPE_INDEX end;
            if (ENCRYPT_BLOCK_SIZE >= BYTE_SIZE)
            {
                begin = index * (ENCRYPT_BLOCK_SIZE / BYTE_SIZE);
                end = begin + (ENCRYPT_BLOCK_SIZE / BYTE_SIZE);

                for (row = 0; row < MATRIX_ROW_SIZE; row++)
                {
                    for (col = begin; col < end; col++, I_prime_idx++)
                    {
                        I_prime[I_prime_idx].byte_data = I[row][col].byte_data;
                    }
                }
            }
            else
            {
                TYPE_INDEX I_bit_idx, I_prime_bit_idx;
                col = (index * ENCRYPT_BLOCK_SIZE) / BYTE_SIZE;
                begin = (index * ENCRYPT_BLOCK_SIZE) % BYTE_SIZE;
                end = begin + ENCRYPT_BLOCK_SIZE;
                for (row = 0; row < MATRIX_ROW_SIZE; row++)
                {
                    for (I_bit_idx = begin; I_bit_idx < end; I_bit_idx++, I_prime_idx++)
                    {
                        I_prime_col = I_prime_idx / BYTE_SIZE;
                        I_prime_bit_idx = I_prime_idx % BYTE_SIZE;

                        if (BIT_CHECK(&I[row][col].byte_data, I_bit_idx))
                            BIT_SET(&I_prime[I_prime_col].byte_data, I_prime_bit_idx);
                        else
                            BIT_CLEAR(&I_prime[I_prime_col].byte_data, I_prime_bit_idx);
                    }
                }
            }
        }
        else
        {
            memcpy(I_prime, I[index], MATRIX_COL_SIZE);
        }
    }
    catch (exception &e)
    {
        printf("Error!!\n");
        exit(1);
    }

    return 0;
}

void *IMDSSEClient::thread_precomputeAesKey_func(void *param)
{
    THREAD_PRECOMPUTE_AESKEY *opt = (THREAD_PRECOMPUTE_AESKEY *)param;
    DSSE_KeyGen *dsse_keygen = new DSSE_KeyGen();
    dsse_keygen->precomputeAES_CTR_keys(opt->aes_keys, opt->idx, opt->dim, opt->isIncremental, opt->block_counter_arr, opt->row_keys, opt->masterKey);
    delete dsse_keygen;

    return 0;
}

int IMDSSEClient::delToken_step1(TYPE_INDEX &block_index, int filename)
{
    this->requestBlock_index(filename, block_index, this->rT_F, this->lstFree_column_idx, this->masterKey);

    return 0;
}

int IMDSSEClient::delToken_step2(MatrixType *I_prime, TYPE_INDEX &block_index, int filename, const vector<string> &keywords)
{
    DSSE_Trapdoor *dsse_trapdoor = new DSSE_Trapdoor();
    DSSE_KeyGen *dsse_keygen = new DSSE_KeyGen();
    int bit_position;
    TYPE_INDEX keyword_index, file_index;
    TYPE_INDEX row;
    unsigned char file_trapdoor[TRAPDOOR_SIZE];
    unsigned char keyword_trapdoor[TRAPDOOR_SIZE];

    TYPE_INDEX selectedIdx;
    MatrixType *I_bar;
    MatrixType *decrypted_block;

    THREAD_PRECOMPUTE_AESKEY aes_key_decrypt_param(decrypt_key, block_index, COL, false, this->block_counter_arr, this->row_keys, this->masterKey);
    THREAD_PRECOMPUTE_AESKEY aes_key_reencrypt_param(reencrypt_key, block_index, COL, true, this->block_counter_arr, this->row_keys, this->masterKey);

    thread_precomputeAesKey_func(&aes_key_decrypt_param);
    thread_precomputeAesKey_func(&aes_key_reencrypt_param);

    decrypted_block = new MatrixType[MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE];

    I_bar = new MatrixType[MATRIX_ROW_SIZE / BYTE_SIZE];
    memset(I_bar, 0, MATRIX_ROW_SIZE / BYTE_SIZE);

    dsse_trapdoor->generateTrapdoor_single_input(file_trapdoor, TRAPDOOR_SIZE,
                                                 (unsigned char *)&filename,
                                                 sizeof(filename), masterKey);

    hashmap_key_class hmap_file_trapdoor(file_trapdoor, TRAPDOOR_SIZE);
    if (rT_F.find(hmap_file_trapdoor) == rT_F.end())
    {
        this->pickRandom_element(selectedIdx, lstFree_column_idx, &prng);
        rT_F[hmap_file_trapdoor] = selectedIdx;
        idx_F[selectedIdx] = filename;
    }

    for (auto iter = keywords.begin(); iter != keywords.end(); iter++)
    {
        string word = *iter;
        int keyword_len = word.size();

        if (keyword_len > 0)
        {
            dsse_trapdoor->generateTrapdoor_single_input(keyword_trapdoor, TRAPDOOR_SIZE,
                                                         (unsigned char *)word.c_str(), keyword_len, masterKey);
        }
        hashmap_key_class hmap_keyword_trapdoor(keyword_trapdoor, TRAPDOOR_SIZE);
        if (rT_W.find(hmap_keyword_trapdoor) == rT_W.end())
        {
            this->pickRandom_element(selectedIdx, lstFree_row_idx, &prng);
            rT_W[hmap_keyword_trapdoor] = selectedIdx;
        }
        keyword_index = rT_W[hmap_keyword_trapdoor];
        row = keyword_index / BYTE_SIZE;
        bit_position = keyword_index % BYTE_SIZE;

        BIT_SET(&I_bar[row].byte_data, bit_position);

        word.clear();
    }
    file_index = rT_F[hmap_file_trapdoor];

    //decrypt the input block first
    memset(decrypted_block, 0, MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE);
    dsse_keygen->enc_dec_preAESKey(decrypted_block, I_prime, decrypt_key, MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE);

    //update the decrypted block with newly adding file block
    this->updateBlock(I_bar, decrypted_block, file_index, OpDel);

    //reencrypt the updated blocks with reenncryption key
    dsse_keygen->enc_dec_preAESKey(I_prime, decrypted_block, reencrypt_key, MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE / BYTE_SIZE);

    this->block_counter_arr[block_index] += 1;

    // free memory
    delete dsse_trapdoor;
    delete dsse_keygen;
    delete[] decrypted_block;
    delete[] I_bar;

    return 0;
}

int IMDSSEClient::searchToken(TYPE_INDEX &row_index, const string &keyword)
{
    unsigned char keyword_trapdoor[TRAPDOOR_SIZE] = {'\0'};
    DSSE_Trapdoor *dsse_trapdoor = new DSSE_Trapdoor();

    int keyword_length = strlen(keyword.c_str());

    dsse_trapdoor->generateTrapdoor_single_input(keyword_trapdoor, TRAPDOOR_SIZE, (unsigned char *)keyword.c_str(), keyword_length, masterKey);

    hashmap_key_class hmap_keyword_trapdoor(keyword_trapdoor, TRAPDOOR_SIZE);
    if (rT_W.find(hmap_keyword_trapdoor) != rT_W.end())
        row_index = rT_W[hmap_keyword_trapdoor];
    else
        row_index = KEYWORD_NOT_EXIST;

    delete dsse_trapdoor;

    return 0;
}

int IMDSSEClient::decrypt(vector<int> &rslt, MatrixType *search_data, TYPE_INDEX row_index, const string &keyword)
{
    DSSE_KeyGen *dsse_keygen = new DSSE_KeyGen();
    unsigned char *aes_keys = new unsigned char[MATRIX_COL_SIZE];
    MatrixType *search_res = new MatrixType[MATRIX_COL_SIZE];

    memset(aes_keys, 0, MATRIX_COL_SIZE);
    memset(search_res, 0, MATRIX_COL_SIZE);
    THREAD_PRECOMPUTE_AESKEY aes_key_decrypt_param(aes_keys, row_index, ROW, false, this->block_counter_arr, this->row_keys, this->masterKey);

    thread_precomputeAesKey_func(&aes_key_decrypt_param);

    dsse_keygen->enc_dec_preAESKey(search_res, search_data, aes_keys, MATRIX_COL_SIZE);

    for (TYPE_INDEX ii = 0; ii < MATRIX_COL_SIZE; ii++)
    {
        for (int bit_number = 0; bit_number < BYTE_SIZE; bit_number++)
            if (BIT_CHECK(&search_res[ii].byte_data, bit_number))
                rslt.push_back(idx_F[ii * BYTE_SIZE + bit_number]);
    }

    delete dsse_keygen;

    return 0;
}

int IMDSSEClient::addToken_step2(MatrixType *I_prime, TYPE_INDEX &block_index, int filename,const string& keyword)
{
    vector<string> keywords;

    keywords.emplace_back(keyword);

    this->addToken_step2(I_prime, block_index, filename, keywords);

    return 0;
}

int IMDSSEClient::delToken_step2(MatrixType *I_prime, TYPE_INDEX &block_index, int filename,const string& keyword)
{
    vector<string> keywords;

    keywords.emplace_back(keyword);

    this->delToken_step2(I_prime, block_index, filename, keywords);

    return 0;
}