#include "LaFParticipant.h"
#include "LaFCommon.h"
#include "MuS.h"
#include <cstring>
#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include <set>
#include <algorithm>
#include "NewHope512cpa/api.h"
#include "NewHope512cpa/rng.h"

extern "C"
{
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
}

using namespace std;

LaFParticipant::LaFParticipant(const string &ip, int port)
{
    unsigned char buf[512];
    RR::SetPrecision(96);
    RR::SetOutputPrecision(96);

    this->server_ip = ip;
    this->server_port = port;

    RAND_bytes(buf, 512);
    randombytes_init(buf, buf + 256, 128);
    if_init_round = true;
    this->epoch = 0;
}

// In the initial phase,
// the identity of this client is assigned by the server
void LaFParticipant::KeyExchange_init()
{
    KeyExchange_init_gen_pk();
    KeyExchange_init_recv_pk_gen_ss();
    KeyExchange_init_recv_cip_gen_ss();
}

int LaFParticipant::ConnectToServer_()
{
    struct sockaddr_in srv_addr;
    int sock;
    int buf_size = 1024 * 1024 * 10;
    int flag;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char *) &buf_size, sizeof(int));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *) &buf_size, sizeof(int));
    flag = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (const char *) &flag, sizeof(int));
#ifndef __APPLE__
    flag = 3;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (const char *) &flag, sizeof(int));
#endif
    flag = 20;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (const char *) &flag, sizeof(int));
    flag = 3;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (const char *) &flag, sizeof(int));

    memset(&srv_addr, 0, sizeof(srv_addr));

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(server_port);
    srv_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());

    int ret = connect(sock, (struct sockaddr *) &srv_addr, sizeof(srv_addr));
    if (ret != 0)
        std::cerr << "Connect to the server failed!" << std::endl;
    return sock;
}

void LaFParticipant::KeyExchange_init_gen_pk()
{
    int sock;
    int op;
    string tmp;
    unsigned char _pk[CRYPTO_PUBLICKEYBYTES], _sk[CRYPTO_SECRETKEYBYTES];
    unsigned char _e[CRYPTO_SECRETKEYBYTES], seed[96];

    do
    {
        op = static_cast<int>(NetOp_KeyExchange_init_send_pk);
        sock = ConnectToServer_();
        send_data(sock, (unsigned char *) &op, sizeof(op));
    } while (!recv_data(sock, (unsigned char *) &(this->identity), sizeof(this->identity)));

    LaF_cpapke_keypair(_pk, _sk, _e);
    this->pk_c.assign((const char *) _pk, CRYPTO_PUBLICKEYBYTES);
    this->sk_c.assign((const char *) _sk, CRYPTO_SECRETKEYBYTES);
    this->e_c.assign((const char *) _e, CRYPTO_SECRETKEYBYTES);

    LaF_cpapke_keypair(_pk, _sk, _e, seed);
    this->pk_s.assign((const char *) _pk, CRYPTO_PUBLICKEYBYTES);
    this->sk_s.assign((const char *) _sk, CRYPTO_SECRETKEYBYTES);
    this->e_s.assign((const char *) _e, CRYPTO_SECRETKEYBYTES);
    this->seed_s.assign((const char *) seed, 16);

    cout << "Client id: " << this->identity << endl;

    send_bytes(sock, pk_c);
    recv_data(sock, (unsigned char *) &op, sizeof(int));
    send_bytes(sock, pk_s);
    recv_data(sock, (unsigned char *) &op, sizeof(int));
    close(sock);
}

void LaFParticipant::KeyExchange_init_recv_pk_gen_ss()
{
    int sock;
    int op;
    string tmp, tmp_pk;
    unsigned char _ct[CRYPTO_CIPHERTEXTBYTES], _ss[CRYPTO_BYTES];

    do
    {
        sock = ConnectToServer_();
        op = static_cast<int>(NetOp_KeyExchange_init_recv_pk_and_gen_ss);
        send_data(sock, (unsigned char *) &op, sizeof(op));
        send_data(sock, (unsigned char *) &(this->identity), sizeof(this->identity));
    } while (!recv_data(sock, (unsigned char *) &op, sizeof(op)));

    for (int i = 1; i < this->identity; i++)
    {
        recv_bytes(sock, tmp_pk);
        RAND_bytes(_ss, CRYPTO_BYTES);
        LaF_cpapke_enc(_ct, _ss, (const unsigned char *) tmp_pk.c_str(),
                       (const unsigned char *) sk_c.c_str(), (const unsigned char *) e_c.c_str());
        tmp.assign((const char *) _ss, CRYPTO_BYTES);
        this->arr_ss_c[i] = tmp;
        tmp.assign((const char *) _ct, CRYPTO_CIPHERTEXTBYTES);
        send_bytes(sock, tmp);
        recv_data(sock, (unsigned char *) &op, sizeof(op));

        recv_bytes(sock, tmp_pk);
        RAND_bytes(_ss, CRYPTO_BYTES);
        LaF_cpapke_enc(_ct, _ss, (const unsigned char *) tmp_pk.c_str(),
                       (const unsigned char *) sk_s.c_str(), (const unsigned char *) e_s.c_str());
        tmp.assign((const char *) _ss, CRYPTO_BYTES);
        this->arr_ss_s[i] = tmp;
        tmp.assign((const char *) _ct, CRYPTO_CIPHERTEXTBYTES);
        send_bytes(sock, tmp);
        recv_data(sock, (unsigned char *) &op, sizeof(op));
    }
    close(sock);
}

void LaFParticipant::KeyExchange_init_recv_cip_gen_ss()
{
    int sock;
    int op;
    string tmp;
    unsigned char _ct[CRYPTO_CIPHERTEXTBYTES], _ss[CRYPTO_BYTES];

    do
    {
        sock = ConnectToServer_();
        op = static_cast<int>(NetOp_KeyExchange_init_recv_cip_and_gen_ss);
        send_data(sock, (unsigned char *) &op, sizeof(op));
        send_data(sock, (unsigned char *) &(this->identity), sizeof(this->identity));
    } while (!recv_data(sock, (unsigned char *) &op, sizeof(op)));

    op = 0;
    for (int i = this->identity + 1; i <= MSSS_N; i++)
    {
        recv_bytes(sock, tmp);
        LaF_cpapke_dec(_ss, (const unsigned char *) tmp.c_str(), (const unsigned char *) sk_c.c_str());
        tmp.assign((const char *) _ss, CRYPTO_BYTES);
        this->arr_ss_c[i] = tmp;
        tmp.assign((const char *) _ct, CRYPTO_CIPHERTEXTBYTES);
        send_data(sock, (unsigned char *) &op, sizeof(op));

        recv_bytes(sock, tmp);
        LaF_cpapke_dec(_ss, (const unsigned char *) tmp.c_str(), (const unsigned char *) sk_s.c_str());
        tmp.assign((const char *) _ss, CRYPTO_BYTES);
        this->arr_ss_s[i] = tmp;
        tmp.assign((const char *) _ct, CRYPTO_CIPHERTEXTBYTES);
        send_data(sock, (unsigned char *) &op, sizeof(op));

        //cout << "ss_c of " << i << "@" << identity << ":" << endl;
        //print_hex(this->arr_ss_c[i].c_str(), this->arr_ss_c[i].length());
        //cout << "ss_s of " << i << "@" << identity << ":" << endl;
        //print_hex(this->arr_ss_s[i].c_str(), this->arr_ss_s[i].length());
        //cout << "----------------------------------------" << endl;
    }
    close(sock);
}

void LaFParticipant::ShareTwoMasks()
{
    MuS mus;
    vec_ZZ_p sec_seed, b;
    vec_ZZ_p v_seed, v_b;
    mat_ZZ_p Lambda_seed, A_seed, Lambda_b, A_b;
    std::vector<vec_ZZ_p> sp_seed, kp_seed, sp_b, kp_b;
    std::vector<int> p;
    int sock, op, ctr;
    std::string tmp;
    stringstream sstream;

    do
    {
        sock = ConnectToServer_();
        op = static_cast<int>(NetOp_ShareTwoMasks_init);
        send_data(sock, (unsigned char *) &op, sizeof(op));
        send_data(sock, (unsigned char *) &(this->identity), sizeof(this->identity));
    } while (!recv_data(sock, (unsigned char *) &op, sizeof(op)));

    TransToZq(sec_seed, (const unsigned char *) this->seed_s.c_str(),
              this->seed_s.length());
    random(b, MSSS_T);

    for (int i = 1; i <= MSSS_N; i++)
        p.emplace_back(i);

    mus.Share(v_seed, Lambda_seed, A_seed, sp_seed, kp_seed,
              sec_seed, p, MSSS_T, MSSS_N);
    sp_to_others_seed = sp_seed;
    kp_to_others_seed = kp_seed;

    mus.Share(v_b, Lambda_b, A_b, sp_b, kp_b,
              b, p, MSSS_T, MSSS_N);
    sp_to_others_b = sp_b;
    kp_to_others_b = kp_b;

    this->bi = b;

    for (int i = 1; i <= MSSS_N; i++)
    {
        if (i == this->identity)
            continue;
        Encrypt_shares(tmp, this->identity, i, sp_seed[i - 1], kp_seed[i - 1], sp_b[i - 1], kp_b[i - 1]);
        send_data(sock, (unsigned char *) &i, sizeof(i));
        send_bytes(sock, tmp);
        recv_data(sock, (unsigned char *) &op, sizeof(op));
    }
    vec_zz_p_to_string(tmp, v_seed);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &ctr, sizeof(ctr));

    mat_zz_p_to_string(tmp, Lambda_seed);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &ctr, sizeof(ctr));

    mat_zz_p_to_string(tmp, A_seed);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &ctr, sizeof(ctr));

    vec_zz_p_to_string(tmp, v_b);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &ctr, sizeof(ctr));

    mat_zz_p_to_string(tmp, Lambda_b);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &ctr, sizeof(ctr));

    mat_zz_p_to_string(tmp, A_b);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &ctr, sizeof(ctr));

    recv_data(sock, (unsigned char *) &ctr, sizeof(ctr));

    for (int i = 0; i < ctr; i++)
    {
        recv_data(sock, (unsigned char *) &op, sizeof(op));
        recv_bytes(sock, tmp);
        send_data(sock, (unsigned char *) &op, sizeof(op));
        this->e[op] = tmp;
    }
    close(sock);
}

void
LaFParticipant::Encrypt_shares(string &out, int id_i, int id_j, vec_ZZ_p &sp_seed, vec_ZZ_p &kp_seed, vec_ZZ_p &sp_b,
                               vec_ZZ_p &kp_b)
{
    stringstream sstream;
    string tmp1, tmp2, tmp3;
    vec_ZZ_p *(vec_arr[4]) = {&sp_seed, &kp_seed, &sp_b, &kp_b};
    unsigned char buf[32], IV[16], *cip;
    int len, cipher_len;
    EVP_CIPHER_CTX *ctx;

    RAND_bytes(IV, 16);

    memcpy(buf, &id_i, sizeof(id_i));
    memcpy(buf + sizeof(id_i), &id_j, sizeof(id_j));
    tmp1.assign((const char *) buf, sizeof(id_i) + sizeof(id_j));

    for (int i = 0; i < 4; i++)
    {
        vec_zz_p_to_string(tmp2, *vec_arr[i]);
        len = tmp2.length();
        tmp3.assign((const char *) &len, sizeof(len));
        tmp1 += tmp3;
        tmp1 += tmp2;
    }

    tmp3.assign((const char *) IV, 16);

    cip = (unsigned char *) calloc((tmp1.length() / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, sizeof(char));

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, (const unsigned char *) this->arr_ss_c[id_j].c_str(), IV);
    EVP_EncryptUpdate(ctx, cip, &cipher_len, (const unsigned char *) tmp1.c_str(), tmp1.length());
    EVP_EncryptFinal_ex(ctx, cip + cipher_len, &len);
    EVP_CIPHER_CTX_free(ctx);
    out.assign((const char *) cip, cipher_len + len);
    out = out + tmp3;
    free(cip);
}

void LaFParticipant::Decrypt_shares(vec_ZZ_p &sp_seed, vec_ZZ_p &kp_seed, vec_ZZ_p &sp_b,
                                    vec_ZZ_p &kp_b, const string &in, int id_i, int id_j)
{
    stringstream sstream;
    string tmp1;
    vec_ZZ_p *(vec_arr[4]) = {&sp_seed, &kp_seed, &sp_b, &kp_b};
    unsigned char IV[16], *plain;
    int len, p, plain_len;
    AES_KEY aes_key;
    EVP_CIPHER_CTX *ctx;

    memcpy(IV, in.c_str() + in.length() - 16, 16);
    plain = (unsigned char *) calloc(in.length(), sizeof(char));

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) this->arr_ss_c[id_j].c_str(), IV);
    EVP_DecryptUpdate(ctx, plain, &len, (const unsigned char *) in.c_str(), in.length() - 16);
    EVP_DecryptFinal_ex(ctx, plain + len, &plain_len);

    memcpy(&len, plain, sizeof(len));
    if (len != id_j && len != id_i)
        cout << "decrypted sender mismatch " << endl;

    memcpy(&len, plain + sizeof(len), sizeof(len));
    if (len != id_j && len != id_i)
        cout << "decrypted sender mismatch " << endl;

    p = sizeof(len) * 2;

    for (int i = 0; i < 4; i++)
    {
        memcpy(&len, plain + p, sizeof(len));
        tmp1.assign((const char *) plain + p + 4, len);
        vec_zz_p_from_string(*vec_arr[i], tmp1);
        p += 4 + len;
    }

    free(plain);
    EVP_CIPHER_CTX_free(ctx);
}

int LaFParticipant::MaskInputs(const vector<string> &data)
{
    std::stringstream sstream;
    vec_RR xi, msk;
    string str_tmp;
    unsigned char buf[32];
    int sock, op;

    do
    {
        sock = ConnectToServer_();
        op = static_cast<int>(NetOp_MaskInputs);
        send_data(sock, (unsigned char *) &op, sizeof(op));
        send_data(sock, (unsigned char *) &(this->identity), sizeof(this->identity));
    } while (!recv_data(sock, (unsigned char *) &op, sizeof(op)));

    for (int i = 0; i < data.size(); i++)
    {
        RR tmp;

        sstream.clear();
        sstream.str("");
        sstream << data[i];
        sstream >> tmp;

        xi.append(tmp);
    }
    for (int i = 1; i <= MSSS_N; i++)
    {
        if (i == this->identity)
            continue;
        if (i < this->identity)
            PRG(msk, this->arr_ss_s[i], data.size(), false);
        else
            PRG(msk, this->arr_ss_s[i], data.size(), true);
        add(xi, xi, msk);
    }
    PRG(msk, this->bi, data.size(), false);

    add(xi, xi, msk);
    vec_RR_to_string(str_tmp, xi);

    send_bytes(sock, str_tmp);

    for (int i = 0; i < MSSS_N; i++)
    {
        recv_data(sock, (unsigned char *) &op, sizeof(op));
        if (op == -1)
            break;
        Pprime.emplace_back(op);
    }

    send_data(sock, (unsigned char *) &op, sizeof(op));
    close(sock);

    return 1;
}

int LaFParticipant::Recover()
{
    int sock, op;
    vec_ZZ_p sp_seed, kp_seed, sp_b, kp_b;
    string _tmp_str;

    if (std::find(Pprime.begin(), Pprime.end(), identity) == Pprime.end())
        return 0;

    do
    {
        sock = ConnectToServer_();
        op = static_cast<int>(NetOp_Recover_init);
        send_data(sock, (unsigned char *) &op, sizeof(op));
        send_data(sock, (unsigned char *) &(this->identity), sizeof(this->identity));
    } while (!recv_data(sock, (unsigned char *) &op, sizeof(op)));

    //cout << this->identity << " start recover" << endl;
    for (int i = 1; i <= MSSS_N; i++)
    {
        stringstream sstream;
        string tmp;

        if (i == this->identity)
            continue;
        if (if_init_round)
        {
            Decrypt_shares(sp_seed, kp_seed, sp_b, kp_b, this->e[i], this->identity, i);

            this->sp_from_others_seed[i] = sp_seed;
            this->sp_from_others_b[i] = sp_b;
            this->kp_from_others_b[i] = kp_b;
            this->kp_from_others_seed[i] = kp_seed;
        }
        else
        {
            sp_seed = this->sp_from_others_seed[i];
            sp_b = this->sp_from_others_b[i];
        }

        if (std::find(Pprime.begin(), Pprime.end(), i) == Pprime.end())
            sstream << sp_seed;
        else
            sstream << sp_b;
        tmp = sstream.str();
        send_bytes(sock, tmp);
        recv_data(sock, (unsigned char *) &op, sizeof(op));
    }
    //cout << this->identity << " waiting for gradient" << endl;
    recv_bytes(sock, _tmp_str);
    send_data(sock, (unsigned char *) &op, sizeof(op));
    cout << "The size of global gradient is: " << _tmp_str.size() << endl;

    close(sock);
    Pprime.clear();
    if_init_round = false;
    this->epoch++;
    return 0;
}

void LaFParticipant::KeyExchange_Cons()
{
    KeyExchange_cons_gen_pk();
    KeyExchange_cons_recv_pk_gen_ss();
    KeyExchange_cons_recv_cip_gen_ss();
}

void LaFParticipant::KeyExchange_cons_gen_pk()
{
    int sock;
    int op;
    string tmp;
    unsigned char _pk[CRYPTO_PUBLICKEYBYTES], _sk[CRYPTO_SECRETKEYBYTES], _e[CRYPTO_SECRETKEYBYTES], seed[96];

    do
    {
        op = static_cast<int>(NetOp_KeyExchange_cons_send_pk);
        sock = ConnectToServer_();
        send_data(sock, (unsigned char *) &op, sizeof(op));
    } while (!recv_data(sock, (unsigned char *) &op, sizeof(op)));

    LaF_cpapke_keypair(_pk, _sk, _e, seed);
    this->pk_s.assign((const char *) _pk, CRYPTO_PUBLICKEYBYTES);
    this->sk_s.assign((const char *) _sk, CRYPTO_SECRETKEYBYTES);
    this->e_s.assign((const char *) _e, CRYPTO_SECRETKEYBYTES);
    this->seed_s.assign((const char *) seed, 16);

    send_data(sock, (unsigned char *) &(this->identity), sizeof(this->identity));
    send_data(sock, (unsigned char *) &(this->epoch), sizeof(this->epoch));
    send_bytes(sock, pk_s);
    recv_data(sock, (unsigned char *) &op, sizeof(int));
    close(sock);
}

void LaFParticipant::KeyExchange_cons_recv_pk_gen_ss()
{
    MuS mus;
    int sock;
    int op;
    string tmp, tmp_pk;
    unsigned char _ct[CRYPTO_CIPHERTEXTBYTES], _ss[CRYPTO_BYTES];
    vec_ZZ_p sec_seed, b;
    vec_ZZ_p v_seed, v_b;
    mat_ZZ_p Lambda_seed, A_seed, Lambda_b, A_b;
    std::vector<vec_ZZ_p> sp_seed, sp_b;
    stringstream sstream;

    do
    {
        sock = ConnectToServer_();
        op = static_cast<int>(NetOp_KeyExchange_cons_recv_pk_and_gen_ss);
        send_data(sock, (unsigned char *) &op, sizeof(op));
    } while (!recv_data(sock, (unsigned char *) &op, sizeof(op)));
    send_data(sock, (unsigned char *) &(this->identity), sizeof(this->identity));

    for (int i = 1; i < this->identity; i++)
    {
        recv_bytes(sock, tmp_pk);
        RAND_bytes(_ss, CRYPTO_BYTES);
        LaF_cpapke_enc(_ct, _ss, (const unsigned char *) tmp_pk.c_str(),
                       (const unsigned char *) sk_s.c_str(), (const unsigned char *) e_s.c_str());
        tmp.assign((const char *) _ss, CRYPTO_BYTES);
        this->arr_ss_s[i] = tmp;
        tmp.assign((const char *) _ct, CRYPTO_CIPHERTEXTBYTES);
        send_bytes(sock, tmp);
        recv_data(sock, (unsigned char *) &op, sizeof(op));
    }

    TransToZq(sec_seed, (const unsigned char *) this->seed_s.c_str(), this->seed_s.length());
    random(b, MSSS_T);

    this->bi = b;

    //cout << b << endl;

    mus.UpdateParam(v_seed, Lambda_seed, A_seed, sp_seed, sec_seed, sp_to_others_seed, kp_to_others_seed, MSSS_T,
                    MSSS_N);
    this->sp_to_others_seed = sp_seed;

    mus.UpdateParam(v_b, Lambda_b, A_b, sp_b, b, sp_to_others_b, kp_to_others_b, MSSS_T, MSSS_N);
    this->sp_to_others_b = sp_b;

    for (auto &itr: this->sp_from_others_seed)
    {
        vec_ZZ_p tmp;
        mus.UpdateShare(tmp, sp_from_others_seed[itr.first], kp_from_others_seed[itr.first]);
        itr.second = tmp;
    }
    for (auto &itr: this->sp_from_others_b)
    {
        vec_ZZ_p tmp;
        mus.UpdateShare(tmp, sp_from_others_b[itr.first], kp_from_others_b[itr.first]);
        itr.second = tmp;
    }

    vec_zz_p_to_string(tmp, v_seed);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &op, sizeof(op));

    mat_zz_p_to_string(tmp, Lambda_seed);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &op, sizeof(op));

    mat_zz_p_to_string(tmp, A_seed);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &op, sizeof(op));

    vec_zz_p_to_string(tmp, v_b);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &op, sizeof(op));

    mat_zz_p_to_string(tmp, Lambda_b);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &op, sizeof(op));

    mat_zz_p_to_string(tmp, A_b);
    send_bytes(sock, tmp);
    recv_data(sock, (unsigned char *) &op, sizeof(op));

    close(sock);
}

void LaFParticipant::KeyExchange_cons_recv_cip_gen_ss()
{
    int sock;
    int op;
    string tmp;
    unsigned char _ss[CRYPTO_BYTES];

    do
    {
        sock = ConnectToServer_();
        op = static_cast<int>(NetOp_KeyExchange_cons_recv_cip_and_gen_ss);
        send_data(sock, (unsigned char *) &op, sizeof(op));
    } while (!recv_data(sock, (unsigned char *) &op, sizeof(op)));
    send_data(sock, (unsigned char *) &(this->identity), sizeof(this->identity));

    op = 0;
    for (int i = this->identity + 1; i <= MSSS_N; i++)
    {
        recv_bytes(sock, tmp);
        LaF_cpapke_dec(_ss, (const unsigned char *) tmp.c_str(), (const unsigned char *) sk_s.c_str());
        tmp.assign((const char *) _ss, CRYPTO_BYTES);
        this->arr_ss_s[i] = tmp;
        send_data(sock, (unsigned char *) &op, sizeof(op));
    }
    close(sock);
}
