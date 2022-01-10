#include "MasterKey.h"

MasterKey::MasterKey()
{
}

MasterKey::~MasterKey()
{
}

/**
 * Function Name: isNULL
 *
 * Description:
 * Check if the keys are generated or not
 *
 * @return	0 if keys are not null, 1 otherwise
 */
bool MasterKey::isNULL()
{
    if(this->key1 ==NULL || this->key2 == NULL || this->key3 == NULL)
        return 1;
    return 0;
}