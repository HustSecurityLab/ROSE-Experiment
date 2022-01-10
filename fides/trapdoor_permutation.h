#ifndef TRAPDOOR_PERMUTATION_H
#define TRAPDOOR_PERMUTATION_H

#include <gmp.h>
#include <string>

struct TdpPK
{
    TdpPK();
    ~TdpPK();
    mpz_t n;
    mpz_t e;

    std::string export_to_string();
    void import_as_string(std::string value);
};

struct TdpSK
{
    TdpSK();
    ~TdpSK();
    mpz_t p;
    mpz_t q;
    mpz_t d;
    mpz_t f;

    std::string export_to_string();
    void import_as_string(std::string value);
};

class TrapdoorPermutation
{
public:
    TrapdoorPermutation() = default;
    ~TrapdoorPermutation() = default;
    int generate_key_pair(TdpPK *pk, TdpSK *sk);
    int permutate_private(const TdpSK *sk, const TdpPK *pk, const unsigned char *in, unsigned int times, unsigned char *out);
    int permutate_public(const TdpPK *pk, const unsigned char *in, unsigned char *out);

};

#endif
