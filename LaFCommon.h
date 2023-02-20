#ifndef LAF_LAFCOMMON_H
#define LAF_LAFCOMMON_H

#include <string>
#include "MuS.h"

//#define MODULUS_R "334173832591553103871865662602621542401"


enum NetOp
{
    NetOp_KeyExchange_init_send_pk,
    NetOp_KeyExchange_init_recv_pk_and_gen_ss,
    NetOp_KeyExchange_init_recv_cip_and_gen_ss,
    NetOp_ShareTwoMasks_init,
    NetOp_MaskInputs,
    NetOp_Recover_init,
    NetOp_KeyExchange_cons_send_pk,
    NetOp_KeyExchange_cons_recv_pk_and_gen_ss,
    NetOp_KeyExchange_cons_recv_cip_and_gen_ss,
    NetOp_Recover_cons
};

bool recv_data(int sock, unsigned char *buf, int length);
bool send_data(int sock, unsigned char *buf, int len);
bool recv_bytes(int sock, std::string &str_out);
bool send_bytes(int sock, const std::string &str_in);

void print_hex(const void *data, int len);

void LaF_cpapke_keypair(unsigned char *pk,
                        unsigned char *sk,
                        unsigned char *e,
                        unsigned char *coin= nullptr,
                        bool use_coin=false);

void LaF_cpapke_enc(unsigned char *c,
                    const unsigned char *m,
                    const unsigned char *pk,
                    const unsigned char *sk,
                    const unsigned char *e);

void LaF_cpapke_dec(unsigned char *m,
                    const unsigned char *c,
                    const unsigned char *sk);

void LaF_cpapke_rec(unsigned char *m,
                const unsigned char *c,
                const unsigned char *pk,
                const unsigned char *sk,
                const unsigned char *e);

void PRG(vec_RR &out, const std::string &ss, int m, bool neg=false);
void PRG(vec_RR &out, const vec_ZZ_p &b, int m, bool neg=false);
void vec_zz_p_from_string(vec_ZZ_p &vec, const std::string &str);
void mat_zz_p_from_string(mat_ZZ_p &mat, const std::string &str);
void vec_zz_p_to_string(std::string &str, const vec_ZZ_p &vec);
void mat_zz_p_to_string(std::string &str, const mat_ZZ_p &mat);
void vec_RR_to_string(std::string &str, const vec_RR &vec);
void vec_RR_from_string(vec_RR &vec, const std::string &str);

#endif
