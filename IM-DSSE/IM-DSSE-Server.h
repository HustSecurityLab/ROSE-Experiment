#ifndef IM_DSSE_SERVER_H
#define IM_DSSE_SERVER_H

#include "struct_MatrixType.h"
#include "config.h"

class IMDSSEServer
{
public:
    IMDSSEServer();
    ~IMDSSEServer();

    int Setup(MatrixType **I_in);

    int writeUpdateDataBlock(TYPE_INDEX block_idx, MatrixType *data);

    int readUpdateDataBlock(TYPE_INDEX block_idx, MatrixType **data);

    int readSearchDataBlock(TYPE_INDEX block_idx, MatrixType **data);

private:

    MatrixType ** I;
};

#endif