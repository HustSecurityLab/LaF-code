#include "LaFCommon.h"

#include <string>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include "NewHope512cpa/api.h"
#include "NewHope512cpa/cpapke.h"
#include "NewHope512cpa/rng.h"
#include "NewHope512cpa/poly.h"
#include "NewHope512cpa/fips202.h"

extern "C"
{
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/socket.h>
}

using namespace std;

bool recv_data(int sock, unsigned char *buf, int len)
{
    int recv_len = 0;
    int tmp;
    while (recv_len < len)
    {
        tmp = recv(sock, buf + recv_len, len - recv_len > 512 ? 512 : len - recv_len, 0);
        if(tmp == -1)
        {
            //cout << "recv_data failed " << endl;
            return false;
        }
        else
        {
            recv_len += tmp;
        }
    }
    if(len > 480)
        send(sock, &tmp, sizeof(tmp), 0);
    return true;
}

bool send_data(int sock, unsigned char *buf, int len)
{
    int sent = 0;
    int tmp;
    do
    {
        tmp = send(sock, buf + sent, len - sent > 512 ? 512 : len - sent, 0);
        if(tmp == -1)
        {
            //cout << "send_data failed " << endl;
            return false;
        }
        else
        {
            sent += tmp;
        }
    } while (sent < len);
    if(len > 480)
        recv(sock, &tmp, sizeof(tmp), 0);
    return true;
}

bool recv_bytes(int sock, std::string &str_out)
{
    int buf_len, recved = 0;
    unsigned char buf[528];
    string tmp;

    str_out = "";

    if(!recv_data(sock, (unsigned char *) &buf_len, sizeof(int)))
        return false;

    while (recved < buf_len)
    {
        if (512 <= (buf_len - recved))
        {
            if(!recv_data(sock, buf, 512))
                return false;
            tmp.assign((const char *) buf, 512);
            str_out += tmp;
            recved += 512;
        }
        else
        {
            if(!recv_data(sock, buf, buf_len - recved))
                return false;
            tmp.assign((const char *) buf, buf_len - recved);
            str_out += tmp;
            recved = buf_len;
        }
    }
    return true;
}

bool send_bytes(int sock, const std::string &str_in)
{
    int len, sent = 0, tmp;

    len = str_in.size();
    if(!send_data(sock, (unsigned char*)&len, sizeof(int)))
        return false;
    while(sent < str_in.length())
    {
        if(512 <= (str_in.length() - sent))
        {
            if(!send_data(sock, (unsigned char*)str_in.c_str() + sent, 512))
                return false;
            sent += 512;
        }
        else
        {
            if(!send_data(sock, (unsigned char*)str_in.c_str() + sent, str_in.length() - sent))
                return false;
            sent = str_in.length();
        }
    }
    return true;
}

void print_hex(const void *data, int len)
{
    unsigned char *p = (unsigned char *) data;
    for (int i = 0; i < len; i++)
    {
        printf("%02X ", p[i]);
    }
    printf("\n");
}

/*************************************************
* Name:        encode_pk
*
* Description: Serialize the public key as concatenation of the
*              serialization of the polynomial pk and the public seed
*              used to generete the polynomial a.
*
* Arguments:   unsigned char *r:          pointer to the output serialized public key
*              const poly *pk:            pointer to the input public-key polynomial
*              const unsigned char *seed: pointer to the input public seed
**************************************************/
static void encode_pk(unsigned char *r, const poly *pk, const unsigned char *seed)
{
    int i;
    poly_tobytes(r, pk);
    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        r[NEWHOPE_POLYBYTES + i] = seed[i];
}

/*************************************************
* Name:        decode_pk
*
* Description: De-serialize the public key; inverse of encode_pk
*
* Arguments:   poly *pk:               pointer to output public-key polynomial
*              unsigned char *seed:    pointer to output public seed
*              const unsigned char *r: pointer to input byte array
**************************************************/
static void decode_pk(poly *pk, unsigned char *seed, const unsigned char *r)
{
    int i;
    poly_frombytes(pk, r);
    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        seed[i] = r[NEWHOPE_POLYBYTES + i];
}

/*************************************************
* Name:        encode_c
*
* Description: Serialize the ciphertext as concatenation of the
*              serialization of the polynomial b and serialization
*              of the compressed polynomial v
*
* Arguments:   - unsigned char *r: pointer to the output serialized ciphertext
*              - const poly *b:    pointer to the input polynomial b
*              - const poly *v:    pointer to the input polynomial v
**************************************************/
static void encode_c(unsigned char *r, const poly *b, const poly *v)
{
    poly_tobytes(r, b);
    poly_compress(r + NEWHOPE_POLYBYTES, v);
}

/*************************************************
* Name:        decode_c
*
* Description: de-serialize the ciphertext; inverse of encode_c
*
* Arguments:   - poly *b:                pointer to output polynomial b
*              - poly *v:                pointer to output polynomial v
*              - const unsigned char *r: pointer to input byte array
**************************************************/
static void decode_c(poly *b, poly *v, const unsigned char *r)
{
    poly_frombytes(b, r);
    poly_decompress(v, r + NEWHOPE_POLYBYTES);
}

/*************************************************
* Name:        gen_a
*
* Description: Deterministically generate public polynomial a from seed
*
* Arguments:   - poly *a:                   pointer to output polynomial a
*              - const unsigned char *seed: pointer to input seed
**************************************************/
static void gen_a(poly *a, const unsigned char *seed)
{
    poly_uniform(a, seed);
}

void LaF_cpapke_keypair(unsigned char *pk,
                        unsigned char *sk,
                        unsigned char *e,
                        unsigned char *coin,
                        bool use_coin)
{
    poly ahat, ehat, ahat_shat, bhat, shat;
    unsigned char z[2 * NEWHOPE_SYMBYTES];
    unsigned char *publicseed = z;
    unsigned char *noiseseed = z + NEWHOPE_SYMBYTES;
    unsigned char buf[512];

    if (!use_coin)
    {
        RAND_bytes(buf, 16);
        if (coin != nullptr)
            memcpy(coin, buf, 16);
    }
    else
        memcpy(buf, coin, 16);
    for (int i = 0; i < 3; i++)
        SHA256(buf, 16 + i * 32, buf + 16 + i * 32);

    randombytes_init(buf, buf + 48, 128);

    randombytes(z, NEWHOPE_SYMBYTES);
    shake256(z, 2 * NEWHOPE_SYMBYTES, z, NEWHOPE_SYMBYTES);

    gen_a(&ahat, publicseed);

    poly_sample(&shat, noiseseed, 0);
    poly_ntt(&shat);

    poly_sample(&ehat, noiseseed, 1);
    poly_ntt(&ehat);

    poly_mul_pointwise(&ahat_shat, &shat, &ahat);
    poly_add(&bhat, &ehat, &ahat_shat);

    //poly_invntt(&shat);
    //poly_invntt(&ehat);
    poly_tobytes(sk, &shat);
    poly_tobytes(e, &ehat);
    encode_pk(pk, &bhat, publicseed);
}

/*************************************************
* Name:        cpapke_enc
*
* Description: Encryption function of
*              the CPA public-key encryption scheme underlying
*              the NewHope KEMs
*
* Arguments:   - unsigned char *c:          pointer to output ciphertext
*              - const unsigned char *m:    pointer to input message (of length NEWHOPE_SYMBYTES bytes)
*              - const unsigned char *pk:   pointer to input public key
*              - const unsigned char *coin: pointer to input random coins used as seed
*                                           to deterministically generate all randomness
**************************************************/
void LaF_cpapke_enc(unsigned char *c,
                    const unsigned char *m,
                    const unsigned char *pk,
                    const unsigned char *sk,
                    const unsigned char *e)
{
    poly sprime, eprime, vprime, ahat, bhat, eprimeprime, uhat, v;
    unsigned char publicseed[NEWHOPE_SYMBYTES];
    unsigned char coin[NEWHOPE_SYMBYTES];

    RAND_bytes(coin, 32);

    poly_frommsg(&v, m);

    decode_pk(&bhat, publicseed, pk);
    gen_a(&ahat, publicseed);

    poly_frombytes(&sprime, sk);
    poly_frombytes(&eprime, e);
    //poly_sample(&sprime, coin, 0);
    //poly_sample(&eprime, coin, 1);
    poly_sample(&eprimeprime, coin, 2);

    //poly_ntt(&sprime);
    //poly_ntt(&eprime);

    poly_mul_pointwise(&uhat, &ahat, &sprime);
    poly_add(&uhat, &uhat, &eprime);

    poly_mul_pointwise(&vprime, &bhat, &sprime);
    poly_invntt(&vprime);

    poly_add(&vprime, &vprime, &eprimeprime);
    poly_add(&vprime, &vprime, &v); // add message

    encode_c(c, &uhat, &vprime);
}


/*************************************************
* Name:        cpapke_dec
*
* Description: Decryption function of
*              the CPA public-key encryption scheme underlying
*              the NewHope KEMs
*
* Arguments:   - unsigned char *m:        pointer to output decrypted message
*              - const unsigned char *c:  pointer to input ciphertext
*              - const unsigned char *sk: pointer to input secret key
**************************************************/
void LaF_cpapke_dec(unsigned char *m,
                    const unsigned char *c,
                    const unsigned char *sk)
{
    poly vprime, uhat, tmp, shat;

    poly_frombytes(&shat, sk);

    decode_c(&uhat, &vprime, c);
    poly_mul_pointwise(&tmp, &shat, &uhat);
    poly_invntt(&tmp);

    poly_sub(&tmp, &tmp, &vprime);

    poly_tomsg(m, &tmp);
}

void LaF_cpapke_rec(unsigned char *m,
                    const unsigned char *c,
                    const unsigned char *pk,
                    const unsigned char *sk,
                    const unsigned char *e)
{
    poly sprime, eprime, vprime, ahat, bhat, eprimeprime, uhat, v;
    unsigned char publicseed[NEWHOPE_SYMBYTES];
    unsigned char coin[NEWHOPE_SYMBYTES];

    RAND_bytes(coin, 32);

    decode_pk(&bhat, publicseed, pk);
    gen_a(&ahat, publicseed);

    poly_frombytes(&sprime, sk);
    poly_frombytes(&eprime, e);
    //poly_sample(&sprime, coin, 0);
    //poly_sample(&eprime, coin, 1);
    poly_sample(&eprimeprime, coin, 2);

    //poly_ntt(&sprime);
    //poly_ntt(&eprime);

    poly_mul_pointwise(&uhat, &ahat, &sprime);
    poly_add(&uhat, &uhat, &eprime);

    poly_mul_pointwise(&vprime, &bhat, &sprime);
    poly_invntt(&vprime);

    poly_add(&vprime, &vprime, &eprimeprime);
    decode_c(&uhat, &v, c);
    poly_sub(&v, &v, &vprime);

    poly_tomsg(m, &v);
}

void PRG(vec_RR &out, const vec_ZZ_p &b, int m, bool neg)
{
    string str_tmp;
    unsigned char buf[64];

    vec_zz_p_to_string(str_tmp, b);
    SHA256((const unsigned char *) str_tmp.c_str(), str_tmp.length(), buf);
    str_tmp.assign((const char *) buf, 32);
    PRG(out, str_tmp, m, neg);
}

void PRG(vec_RR &out, const string &ss, int m, bool neg)
{
    unsigned char hash[128];
    RR tmp;
    vec_RR _t;

    clear(out);
    out = _t;
    memcpy(hash, ss.c_str(), 32);

    for (int i = 0; i < 3; i++)
        SHA256(hash, (i + 1) * 32, hash + (i + 1) * 32);

    randombytes_init(hash, hash + 64, 128);

    for (int i = 0; i < m; i++)
    {
        int counter = 0, p = 0;
        stringstream sstream;

        if (neg)
            sstream << '-';
        sstream << "1.";
        randombytes(hash, 64);
        while (counter <= RR::precision() / 4)
        {
            sstream << '0' + (hash[p] % 10);
            p++, counter++;
            if (p == 64)
            {
                randombytes(hash, 64);
                p = 0;
            }
        }
        sstream >> tmp;
        out.append(tmp);
    }
}

void vec_zz_p_from_string(vec_ZZ_p &vec, const string &str)
{
    std::stringstream sstream;
    vec_ZZ_p tmp;

    sstream.str(str);
    sstream >> tmp;
    vec = tmp;
}

void mat_zz_p_from_string(mat_ZZ_p &mat, const string &str)
{
    std::stringstream sstream;
    mat_ZZ_p tmp;

    sstream.str(str);
    sstream >> tmp;
    mat = tmp;
}

void vec_zz_p_to_string(std::string &str, const vec_ZZ_p &vec)
{
    std::stringstream sstream;

    sstream << vec;
    str = sstream.str();
}

void mat_zz_p_to_string(std::string &str, const mat_ZZ_p &mat)
{
    std::stringstream sstream;

    sstream << mat;
    str = sstream.str();
}

void vec_RR_to_string(std::string &str, const vec_RR &vec)
{
    std::stringstream sstream;

    sstream << vec;
    str = sstream.str();
}

void vec_RR_from_string(vec_RR &vec, const std::string &str)
{
    std::stringstream sstream;
    vec_RR tmp;

    sstream.str(str);
    sstream >> tmp;
    vec = tmp;
}