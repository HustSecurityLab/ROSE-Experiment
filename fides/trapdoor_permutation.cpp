#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gmp.h>
#include "trapdoor_permutation.h"

using std::endl;
using std::cout;

TdpPK::TdpPK()
{
    mpz_init(this->n);
    mpz_init(this->e);
}

TdpPK::~TdpPK()
{
    mpz_clear(this->n);
    mpz_clear(this->e);
}

std::string TdpPK::export_to_string()
{
    unsigned char buf[1024];
    std::string ret, a;
    size_t len;

    mpz_export(buf + sizeof(size_t), &len, 1, 1, 1, 0, this->n);
    memcpy(buf, &len, sizeof(size_t));
    ret.assign((const char *) buf, len + sizeof(size_t));

    mpz_export(buf + sizeof(size_t), &len, 1, 1, 1, 0, this->e);
    memcpy(buf, &len, sizeof(size_t));
    a.assign((const char *) buf, len + sizeof(size_t));

    ret = ret + a;

    return ret;
}

void TdpPK::import_as_string(std::string value)
{
    size_t len;

    len = *((size_t *) value.c_str());
    mpz_import(this->n, len, 1, 1, 1, 0, value.c_str() + sizeof(size_t));
    mpz_import(this->e, *((size_t *) (value.c_str() + len + sizeof(size_t))), 1, 1, 1, 0,
               value.c_str() + len + 2 * sizeof(size_t));
}

TdpSK::TdpSK()
{
    mpz_init(this->p);
    mpz_init(this->q);
    mpz_init(this->d);
    mpz_init(this->f);
}

TdpSK::~TdpSK()
{
    mpz_clear(this->p);
    mpz_clear(this->q);
    mpz_clear(this->d);
    mpz_clear(this->f);
}

std::string TdpSK::export_to_string()
{
    unsigned char buf[1024];
    std::string ret, a;
    size_t len;

    mpz_export(buf + sizeof(size_t), &len, 1, 1, 1, 0, this->p);
    memcpy(buf, &len, sizeof(size_t));
    ret.assign((const char *) buf, len + sizeof(size_t));

    mpz_export(buf + sizeof(size_t), &len, 1, 1, 1, 0, this->q);
    memcpy(buf, &len, sizeof(size_t));
    a.assign((const char *) buf, len + sizeof(size_t));
    ret = ret + a;

    mpz_export(buf + sizeof(size_t), &len, 1, 1, 1, 0, this->d);
    memcpy(buf, &len, sizeof(size_t));
    a.assign((const char *) buf, len + sizeof(size_t));
    ret = ret + a;

    mpz_export(buf + sizeof(size_t), &len, 1, 1, 1, 0, this->f);
    memcpy(buf, &len, sizeof(size_t));
    a.assign((const char *) buf, len + sizeof(size_t));
    ret = ret + a;

    return ret;
}

void TdpSK::import_as_string(std::string value)
{
    size_t len, len_sum;

    len = *((size_t *) value.c_str());
    mpz_import(this->p, len, 1, 1, 1, 0, value.c_str() + sizeof(size_t));
    len_sum = len + sizeof(size_t);

    len = *((size_t*)(value.c_str() + len_sum));
    mpz_import(this->q, len, 1, 1, 1, 0,
               value.c_str() + len_sum + sizeof(size_t));
    len_sum = len_sum + len + sizeof(size_t);

    len = *((size_t*)(value.c_str() + len_sum));
    mpz_import(this->d, len, 1, 1, 1, 0,
               value.c_str() + len_sum + sizeof(size_t));
    len_sum = len_sum + len + sizeof(size_t);

    len = *((size_t*)(value.c_str() + len_sum));
    mpz_import(this->f, len, 1, 1, 1, 0,
               value.c_str() + len_sum + sizeof(size_t));

}

int TrapdoorPermutation::generate_key_pair(TdpPK *pk, TdpSK *sk)
{
    FILE *f_rand = fopen("/dev/urandom", "rb");
    unsigned char buf1[144];
    gmp_randstate_t r_stat;
    mpz_t p_1, q_1;
    mpz_t a;
    mp_bitcnt_t m2exp = 512;

    //init random generator
    mpz_init(a);
    fread(buf1, sizeof(unsigned char), 144, f_rand);
    mpz_import(a, 128, 1, sizeof(unsigned char), 0, 0, buf1);
    gmp_randinit_lc_2exp(r_stat, a, *((unsigned long *) (buf1 + 128)), m2exp);

    fread(buf1, sizeof(unsigned char), 128, f_rand);
    mpz_import(a, 128, 1, sizeof(unsigned char), 0, 0, buf1);
    gmp_randseed(r_stat, a);
    fclose(f_rand);

    //fix e
    mpz_set_ui(pk->e, 3);

    //initialize sk
    mpz_init(p_1);
    mpz_init(q_1);

    //because we fix e to 3, thus the Euler number of p and q can't
    //be divided by 3. Otherwise there is no d.
    do
    {
        mpz_urandomb(sk->p, r_stat, 1024);
        mpz_nextprime(sk->p, sk->p);
        mpz_sub_ui(p_1, sk->p, 1u);
    } while (mpz_divisible_ui_p(p_1, 3u));

    do
    {
        mpz_urandomb(sk->q, r_stat, 1024);
        mpz_nextprime(sk->q, sk->q);
        mpz_sub_ui(q_1, sk->q, 1u);
    } while (mpz_divisible_ui_p(q_1, 3u));

    mpz_mul(pk->n, sk->p, sk->q);

    //calculate d
    mpz_mul(sk->f, p_1, q_1);
    mpz_invert(sk->d, pk->e, sk->f);

    mpz_clears(p_1, q_1, a, nullptr);
    gmp_randclear(r_stat);

    return 1;
}

int
TrapdoorPermutation::permutate_private(const TdpSK *sk, const TdpPK *pk, const unsigned char *in, unsigned int times,
                                       unsigned char *out)
{
    mpz_t r, m, ind;

    mpz_init(m);
    mpz_import(m, *(size_t *) (in + 256), 1, sizeof(unsigned char), 0, 0, in);

    mpz_init(ind);
    mpz_init(r);
    mpz_powm_ui(ind, sk->d, times, sk->f);
    mpz_powm(r, m, ind, pk->n);

    memset(out, 0, 256);

    mpz_export(out, (size_t *) (out + 256), 1, sizeof(unsigned char), 0, 0, r);


    mpz_clears(r, m, ind, nullptr);

    return 1;
}

int TrapdoorPermutation::permutate_public(const TdpPK *pk, const unsigned char *in, unsigned char *out)
{
    mpz_t enc;

    mpz_init(enc);
    mpz_import(enc, *(size_t *) (in + 256), 1, sizeof(unsigned char), 0, 0, in);
    mpz_powm(enc, enc, pk->e, pk->n);

    memset(out, 0, 256);
    mpz_export(out, (size_t *) (out + 256), 1, sizeof(unsigned char), 0, 0, enc);

    mpz_clear(enc);
    return 1;
}
