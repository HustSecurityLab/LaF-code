#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <sstream>
#include <set>
#include <algorithm>
#include "LaFCommon.h"
#include "MuS.h"
#include <NTL/RR.h>
#include <NTL/vec_RR.h>
#include "NewHope512cpa/api.h"
#include "NewHope512cpa/rng.h"
#include "NewHope512cpa/ntt.h"
#include "NewHope512cpa/poly.h"
#include "NewHope512cpa/fips202.h"

extern "C"
{
#include "openssl/rand.h"
}

using std::cout;
using std::endl;
using std::vector;

void test_key_exchange()
{
    unsigned char pk1[CRYPTO_PUBLICKEYBYTES], pk2[CRYPTO_PUBLICKEYBYTES], sk1[NEWHOPE_POLYBYTES], sk2[CRYPTO_SECRETKEYBYTES], e1[CRYPTO_SECRETKEYBYTES], e2[CRYPTO_SECRETKEYBYTES];
    unsigned char c[CRYPTO_CIPHERTEXTBYTES], m[32], m1[32];

    for(int i=0;i<31;i++)
        m[i] = 'a';
    m[31] = 0;
    cout << (char *)m << endl;
    LaF_cpapke_keypair(pk1, sk1, e1);
    LaF_cpapke_keypair(pk2, sk2, e2);

    LaF_cpapke_enc(c, m, pk1, sk2, e2);
    memset(m1, 0, 32);
    LaF_cpapke_dec(m1, c, sk1);
    cout << (char*)m1 << endl;
    memset(m1, 0, 32);
    LaF_cpapke_rec(m1, c, pk1, sk2, e2);
    cout << (char*)m1 << endl;
}

void test_trans()
{
    MuS mus;

    vec_ZZ_p vec;
    unsigned char buf1[32], buf2[32];

    for(int i=0;i<25;i++)
        buf1[i] = 'A' + i;
    buf1[25] = 0;

    memset(buf2, 'c', 32);
    cout << (char *)buf1 << endl;
    TransToZq(vec, buf1, 26);
    TransToBit(buf2, vec);
    cout << (char *)buf2 << endl;
}

void test_ZZ_IO()
{
    ZZ p;
    std::stringstream sstream;
    sstream << "1235097861549018734650148601847515151";
    sstream >> p;
    ZZ_p::init(p);
    ZZ_p x;

    cout << p << endl;

    sstream.clear();
    sstream.str("");
    sstream << "98467581956127985612229875613498576329";
    sstream << "8571359182375";
    sstream << "6138561154";
    sstream >> x;

    cout << x << endl;
}

void test_MuS()
{
    MuS mus;
    vec_ZZ_p v, secrets, secrets_rec;
    mat_ZZ_p Lambda, A;
    std::vector<vec_ZZ_p> sp, kp, _sp;
    std::vector<int> p, _p;
    vec_ZZ_p sp_new;
    int t = 12, n = 20;
    std::vector<int> _p_set;

    for (int i = 1; i <= t; i++)
        secrets.append(random_ZZ_p());

    for (int i = 1; i <= t; i++)
        p.emplace_back(i);

    //cout << "Begin share" << endl;
    mus.Share(v, Lambda, A, sp, kp, secrets, p, t, n);

    for (int i = 1; i <= t; i++)
    {
        ZZ_p tmp = random_ZZ_p();
        secrets(i) = tmp;
    }

    //cout << "Secrets: " << endl << secrets << endl;
    //cout << "Begin updates" << endl;
    mus.UpdateParam(v, Lambda, A, sp, secrets, sp, kp, t, n);

    while(_p_set.size()<t)
    {
        int x;
        RAND_bytes((unsigned char*)&x, sizeof(x));
        if(x<0)
            x = -x;
        x = (x % n) + 1;
        if(std::find(_p_set.begin(), _p_set.end(), x) == _p_set.end())
        {
            _p_set.emplace_back(x);
        }
    }
    std::sort(_p_set.begin(), _p_set.end());
    for(int i:_p_set)
    {
        _p.emplace_back(i);
        _sp.emplace_back(sp[i-1]);
    }

    mus.Recover(secrets_rec, _p, _sp, v, Lambda, A, t, n);
    //cout << "Recovered Secrets: " << endl << secrets_rec << endl;
}

int main(int argc, char *argv[])
{
    RR::SetPrecision(128);
    RR::SetOutputPrecision(64);
    std::stringstream sstream;
    RR R1,R2;

    sstream << "-213425.2354235";
    sstream >> R1;
    cout << R1 << endl;
    sstream.clear();
    sstream << "-0.2354235034513452362435762623452456";
    sstream >> R1;
    cout << R1 << endl;
    sstream.clear();
    sstream << "0.2354235034513452362435762623452456";
    sstream >> R1;
    cout << R1 << endl;
    sstream.clear();
    sstream << "2354235034513452362435762623452456";
    sstream >> R1;
    cout << R1 << endl;

    sstream.clear();


    return 0;
}