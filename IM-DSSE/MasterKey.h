#ifndef MASTERKEY_H
#define MASTERKEY_H

#include "config.h"


struct MasterKey
{
    unsigned char key1[BLOCK_CIPHER_SIZE];
	unsigned char key2[BLOCK_CIPHER_SIZE];
	unsigned char key3[BLOCK_CIPHER_SIZE];

public:
    MasterKey();
    ~MasterKey();

    bool isNULL();

};

#endif // MASTERKEY_H