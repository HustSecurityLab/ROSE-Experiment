#include "config.h"
#include "Krawczyk128_KDF.h"

#include <iostream>
#include "DSSE_Crypto.h"
using namespace std;

Krawczyk128_KDF::Krawczyk128_KDF()
{

}
Krawczyk128_KDF::~Krawczyk128_KDF()
{

}


int Krawczyk128_KDF::generate_128_PRK(unsigned char *pPRK,
                     int PRK_len,
                     unsigned char *pXTS,
                     int XTS_len,
                     unsigned char *pSKM,
                     int SKM_len)
{
	int error = 0;

    if ( pPRK == NULL || pXTS == NULL || pSKM == NULL)
    {
        return -1;
    }

	if(XTS_len>0 && PRK_len>0 && pSKM>0)
    {
		//cout << "Generating Pseudo Random Key..." << endl;
		if ((error = omac_aes128(pPRK, BLOCK_CIPHER_SIZE, pXTS, XTS_len, pSKM)) != CRYPT_OK) {
			printf("Error calling omac_aes128_intel: %d\n", error/*error_to_string(error)*/);
			return -1;
		}
	}
    else
    {
		cout << "Either length of Pseudo Random Key or Extractor salt or Source Key Material is <= 0" << endl;
	}
	return 0;
}

int Krawczyk128_KDF::generate_krawczyk_128_KDF(unsigned char *pKM,
                     int KM_len,
                     unsigned char *pCTXinfo,
                     int CTXinfo_len,
                     unsigned char *pPRK,
                     int PRK_len)
{

	int error = 0;
	unsigned char *pKeyMaterial;

	// NULL checks
	if(pKM == NULL || pCTXinfo == NULL || pPRK==NULL)
    {
        return -1;
    }

	pKeyMaterial = new unsigned char[BLOCK_CIPHER_SIZE];

	if(KM_len>0 && CTXinfo_len &&  PRK_len)
    {
		//cout << "Generating Random & Uniform Key \"" << pCTXinfo << "\" using Krawczyk Key Derivation Function..." << endl;
		if ((error = omac_aes128(pKeyMaterial, BLOCK_CIPHER_SIZE, pCTXinfo, CTXinfo_len, pPRK)) != CRYPT_OK) {
			printf("Error calling omac_aes128_intel: %d\n", error/*error_to_string(error)*/);
			return -1;
		}

		memcpy(pKM,pKeyMaterial,KM_len);

		delete[] pKeyMaterial;
		pKeyMaterial = NULL;
	}
    else
    {
		cout << "Either length of Key Material or Label of Key Material or Pseudo Random Key is <= 0" << endl;
	}
	return 0;
}
