#ifndef LAF_LAFPARTICIPANT_H
#define LAF_LAFPARTICIPANT_H

#include <string>
#include <vector>
#include <map>
#include "MuS.h"

using std::string;
using std::vector;
using std::map;

class LaFParticipant
{
public:
    LaFParticipant(const string &ip, int port);

    void KeyExchange_init();

    void ShareTwoMasks();

    int MaskInputs(const vector<string> &data);

    int Recover();

    void KeyExchange_Cons();

    int get_id()
    {
        return identity;
    }

    int get_epoch()
    {
        return epoch;
    }

private:
    string server_ip;
    int server_port;
    int identity;
    string ss_c, ss_s;
    string pk_c, sk_c, e_c, pk_s, sk_s, e_s, seed_s;
    map<int, string> arr_ss_c, arr_ss_s, e;
    vector<int> Pprime;
    vec_ZZ_p bi;
    vector<vec_ZZ_p> sp_to_others_seed, kp_to_others_seed, sp_to_others_b, kp_to_others_b;
    map<int, vec_ZZ_p> sp_from_others_seed, kp_from_others_seed, sp_from_others_b, kp_from_others_b;
    bool if_init_round = true;
    int epoch;

    int ConnectToServer_();

    void KeyExchange_init_gen_pk();
    void KeyExchange_init_recv_pk_gen_ss();
    void KeyExchange_init_recv_cip_gen_ss();

    void KeyExchange_cons_gen_pk();
    void KeyExchange_cons_recv_pk_gen_ss();
    void KeyExchange_cons_recv_cip_gen_ss();

    void Encrypt_shares(string &out, int id_i, int id_j, vec_ZZ_p &sp_seed, vec_ZZ_p &kp_seed, vec_ZZ_p &sp_b, vec_ZZ_p &kp_b);
    void Decrypt_shares(vec_ZZ_p &sp_seed, vec_ZZ_p &kp_seed, vec_ZZ_p &sp_b, vec_ZZ_p &kp_b, const string &in,int id_i, int id_j);
};


#endif //LAF_LAFPARTICIPANT_H
