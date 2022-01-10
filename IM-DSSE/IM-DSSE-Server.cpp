#include "IM-DSSE-Server.h"
#include "config.h"

IMDSSEServer::IMDSSEServer()
{
    this->I = new MatrixType *[MATRIX_ROW_SIZE];
    for (TYPE_INDEX i = 0; i < MATRIX_ROW_SIZE; i++)
    {
        this->I[i] = new MatrixType[MATRIX_COL_SIZE];
    }
}

IMDSSEServer::~IMDSSEServer()
{
}

int IMDSSEServer::Setup(MatrixType **I_in)
{
    for(TYPE_INDEX i=0; i <MATRIX_ROW_SIZE; i++)
    {
        for(TYPE_INDEX j=0; j<MATRIX_PIECE_COL_SIZE; j++)
            this->I[i][j] = I_in[i][j];
    }

    return 0;
}

int IMDSSEServer::writeUpdateDataBlock(TYPE_INDEX block_idx, MatrixType *I_prime)
{
    TYPE_INDEX row, col;
    TYPE_INDEX idx;
    TYPE_INDEX begin, end;
    TYPE_INDEX I_prime_bit_idx, I_prime_col_idx;
    TYPE_INDEX bit_position;
    TYPE_INDEX bit_number;

    if (ENCRYPT_BLOCK_SIZE > 1)
    {
        if (ENCRYPT_BLOCK_SIZE > BYTE_SIZE)
        {
            begin = block_idx * ENCRYPT_BLOCK_SIZE / BYTE_SIZE;
            end = block_idx * ENCRYPT_BLOCK_SIZE / BYTE_SIZE + ENCRYPT_BLOCK_SIZE / BYTE_SIZE;
            idx = 0;
            for (row = 0; row < MATRIX_ROW_SIZE; row++)
            {
                for (col = begin; col < end; col++, idx++)
                {
                    I[row][col].byte_data = I_prime[idx].byte_data;
                }
            }
        }
        else
        {
            col = block_idx * ENCRYPT_BLOCK_SIZE / BYTE_SIZE;
            bit_position = (block_idx * ENCRYPT_BLOCK_SIZE) % BYTE_SIZE;
            idx = 0;
            for (row = 0; row < MATRIX_ROW_SIZE; row++)
            {
                for (bit_number = bit_position; bit_number < bit_position + ENCRYPT_BLOCK_SIZE; bit_number++, idx++)
                {
                    I_prime_col_idx = idx / BYTE_SIZE;
                    I_prime_bit_idx = idx % BYTE_SIZE;
                    if (BIT_CHECK(&I_prime[I_prime_col_idx].byte_data, I_prime_bit_idx))
                        BIT_SET(&I[row][col].byte_data, bit_number);
                    else
                        BIT_CLEAR(&I[row][col].byte_data, bit_number);
                }
            }
        }
    }
    else
    {
        col = block_idx / (BYTE_SIZE);
        bit_position = block_idx % BYTE_SIZE;
        for (row = 0, idx = 0; row < MATRIX_ROW_SIZE; row++, idx++)
        {
            I_prime_bit_idx = idx % BYTE_SIZE;
            I_prime_col_idx = idx / BYTE_SIZE;
            if (BIT_CHECK(&I_prime[I_prime_col_idx].byte_data, I_prime_bit_idx))
                BIT_SET(&I[row][col].byte_data, bit_position);
            else
                BIT_CLEAR(&I[row][col].byte_data, bit_position);
        }
    }

    return 0;
}

int IMDSSEServer::readUpdateDataBlock(TYPE_INDEX block_idx, MatrixType **I_prime)
{
    TYPE_INDEX row, col;
    TYPE_INDEX I_prime_col;
    TYPE_INDEX I_prime_idx = 0;
    TYPE_INDEX begin;
    TYPE_INDEX end;

    *I_prime = new MatrixType[(MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE) / BYTE_SIZE];
    memset(*I_prime, 0, (MATRIX_ROW_SIZE * ENCRYPT_BLOCK_SIZE) / BYTE_SIZE);

    if (ENCRYPT_BLOCK_SIZE >= BYTE_SIZE)
    {
        begin = block_idx * (ENCRYPT_BLOCK_SIZE / BYTE_SIZE);
        end = begin + (ENCRYPT_BLOCK_SIZE / BYTE_SIZE);

        for (row = 0; row < MATRIX_ROW_SIZE; row++)
        {
            for (col = begin; col < end; col++, I_prime_idx++)
            {
                (*I_prime)[I_prime_idx].byte_data = I[row][col].byte_data;
            }
        }
    }
    else
    {
        TYPE_INDEX I_bit_idx, I_prime_bit_idx;
        col = (block_idx * ENCRYPT_BLOCK_SIZE) / BYTE_SIZE;
        begin = (block_idx * ENCRYPT_BLOCK_SIZE) % BYTE_SIZE;
        end = begin + ENCRYPT_BLOCK_SIZE;
        for (row = 0; row < MATRIX_ROW_SIZE; row++)
        {
            for (I_bit_idx = begin; I_bit_idx < end; I_bit_idx++, I_prime_idx++)
            {
                I_prime_col = I_prime_idx / BYTE_SIZE;
                I_prime_bit_idx = I_prime_idx % BYTE_SIZE;

                if (BIT_CHECK(&I[row][col].byte_data, I_bit_idx))
                    BIT_SET(&(*I_prime)[I_prime_col].byte_data, I_prime_bit_idx);
                else
                    BIT_CLEAR(&(*I_prime)[I_prime_col].byte_data, I_prime_bit_idx);
            }
        }
    }

    return 0;
}

int IMDSSEServer::readSearchDataBlock(TYPE_INDEX block_idx, MatrixType **I_prime)
{
    TYPE_INDEX row, col;
    TYPE_INDEX I_prime_col;

    *I_prime = new MatrixType[MATRIX_COL_SIZE];
    memset(*I_prime, 0, MATRIX_COL_SIZE);

    memcpy(*I_prime,I[block_idx],MATRIX_COL_SIZE);

    return 0;
}