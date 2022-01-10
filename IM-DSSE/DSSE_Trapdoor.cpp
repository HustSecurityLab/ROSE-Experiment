#include "DSSE_Trapdoor.h"
#include "DSSE_Crypto.h"
DSSE_Trapdoor::DSSE_Trapdoor()
{
}

DSSE_Trapdoor::~DSSE_Trapdoor()
{

}


/**
 * Function Name: generateTrapdoor_single_input
 *
 * Description:
 * Generate hash value of a string
 *
 * @param pOutData: (output) hash value
 * @param out_len: (output) length of hash value
 * @param pInData: (input) input string
 * @param in_len: (input) length of input string
 * @param pKey: (input) symmetric key
 * @return	0 if successful
 */
int DSSE_Trapdoor::generateTrapdoor_single_input(unsigned char *pOutData,
		int out_len,
		unsigned char *pInData,
		int in_len,
		MasterKey *pKey)
{
	// NULL checks
	if(pOutData == NULL || pInData == NULL || pKey->isNULL())
    {
        return -1;
    }

	if(out_len>0 && in_len>0)
		omac_aes128(pOutData, out_len, pInData, in_len, pKey->key2);
	//	hmac_sha256_intel(pKey->key2, pKey->skey2_3_pad_len, pInData, in_len, pOutData, out_len);
	else
		cout << "Either length of input or output to data_trapdoor is <= 0" << endl;
	return 0;
}
