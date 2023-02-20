#include "MuS.h"
#include <cmath>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

extern "C"
{
#include<openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
}

using std::cout;
using std::endl;

MuS::MuS()
{
    ZZ p;
    std::stringstream sstream;
    sstream << MSSS_q;
    sstream >> p;

    ZZ_p::init(p);
}

int MuS::calc_r(int t, int n)
{
    double x = t * log2(t);

    if ((256 > x) && (256 > n))
        return 256;

    if (x > n)
        return (int) (x + 1);
    else
        return n;
}

void MuS::Share(vec_ZZ_p &v, mat_ZZ_p &Lambda, mat_ZZ_p &A, std::vector<vec_ZZ_p> &sp, std::vector<vec_ZZ_p> &kp,
                const vec_ZZ_p &secrets, const std::vector<int> &p, int t, int n)
{
    mat_ZZ_p S;
    int r = calc_r(t, n), int_tmp;
    ZZ_p tmp;
    vec_ZZ_p tmp_v;
    mat_ZZ_p tmp_Lambda, tmp_A;
    std::vector<vec_ZZ_p> tmp_sp, tmp_kp;

    generating_S(S, t, n);
    for (int j = 1; j <= n; j++)
    {
        vec_ZZ_p _tmp_vec;
        for (int i = 1; i <= r; i++)
        {
            tmp = S(i, j);
            _tmp_vec.append(tmp);
        }
        tmp_sp.emplace_back(_tmp_vec);
    }
    for (int i = 1; i <= n; i++)
    {
        vec_ZZ_p _tmp_vec;
        for (int j = 1; j <= r; j++)
        {
            RAND_bytes((unsigned char *) &int_tmp, sizeof(int_tmp));
            int_tmp = int_tmp % 2;
            tmp = int_tmp;
            _tmp_vec.append(tmp);
        }
        tmp_kp.emplace_back(_tmp_vec);
    }
    CalcParam(tmp_v, tmp_Lambda, tmp_A, secrets, S, t, n);

    v = tmp_v;
    Lambda = tmp_Lambda;
    A = tmp_A;
    sp = tmp_sp;
    kp = tmp_kp;
}

void MuS::generating_S(mat_ZZ_p &S, int t, int n)
{
    mat_ZZ_p S1, S2;
    ZZ tmp_p;
    ZZ_p tmp;
    unsigned int int_tmp;
    int r = calc_r(t, n);
    std::stringstream sstream;

    tmp_p = 2;
    ZZ_p::init(tmp_p);

    S1.SetDims(n, n);
    S2.SetDims(r - n, n);

    do
    {
        random(S1, n, n);
        //cout << S1 << endl;
    } while (IsZero(determinant(S1)));


    random(S2, r - n, n);

    S.SetDims(r, n);
    for (int i = 1; i <= n; i++)
        for (int j = 1; j <= n; j++)
            S(i, j) = S1(i, j);
    for (int i = n + 1; i <= r; i++)
        for (int j = 1; j <= n; j++)
            S(i, j) = S2(i - n, j);

    sstream << MSSS_q;
    sstream >> tmp_p;
    ZZ_p::init(tmp_p);

}

void
MuS::CalcParam(vec_ZZ_p &v, mat_ZZ_p &Lambda, mat_ZZ_p &A, const vec_ZZ_p &secrets, const mat_ZZ_p &S, int t, int n)
{
    vec_ZZ_p v1, vec_tmp;
    ZZ_p tmp;
    unsigned int int_tmp;
    mat_ZZ_p B1, B;
    // 1. calculate v
    for (int i = 0; i < t - 1; i++)
    {
        RAND_bytes((unsigned char *) &int_tmp, sizeof(int_tmp));
        int_tmp = int_tmp % 2;
        tmp = int_tmp;
        v1.append(tmp);
    }
    v = v1;
    tmp = 1;
    v.append(tmp);
    // 2. Choose B1
    random(B1, t, t - 1);
    while (!isColumnIndependent(B1))
        random(B1, t, t - 1);
    // 3. calculate matrix B
    B.SetDims(t, t);
    mul(vec_tmp, B1, v1);
    for (int i = 1; i <= t; i++)
    {
        tmp = secrets(i) - vec_tmp(i);
        for (int j = 1; j <= t - 1; j++)
            B(i, j) = B1(i, j);
        B(i, t) = tmp;
    }
    // 4. generate Lambda
    generating_Lambda(Lambda, t, n);
    // 5. generate A
    generating_A(A, B, Lambda, S, t, n);
}

bool MuS::isColumnIndependent(const mat_ZZ_p &m)
{
    mat_ZZ_p _m = m;

    if (gauss(_m) == m.NumCols())
        return true;
    else
        return false;
}

void MuS::generating_Lambda(mat_ZZ_p &Lambda, int t, int n)
{
    mat_ZZ_p mat_tmp, mat_vand;

    mat_tmp.SetDims(t, t);

    do
    {
        random(mat_tmp, t, t);
    } while (IsZero(determinant(mat_tmp)));

    mat_vand.SetDims(t, n);

    for (int i = 1; i <= t; i++)
    {
        mat_vand(i, 1) = 1;
        mat_vand(i, 2) = random_ZZ_p();
        for (int j = 3; j <= n; j++)
        {
            mat_vand(i, j) = power(mat_vand(i, 2), j - 1);
        }
    }
    mul(Lambda, mat_tmp, mat_vand);
}

void MuS::generating_A(mat_ZZ_p &A, const mat_ZZ_p &B, const mat_ZZ_p &Lambda, const mat_ZZ_p &S, int t, int n)
{
    mat_ZZ_p A1, A2, S1, S2, S1_inv;
    int r = calc_r(t, n);

    random(A2, t, r - n);
    S1.SetDims(n, n);
    S2.SetDims(r - n, n);
    clear(A);
    A.SetDims(t, r);

    for (int i = 1; i <= n; i++)
    {
        for (int j = 1; j <= n; j++)
            S1(i, j) = S(i, j);
    }
    for (int i = n + 1; i <= r; i++)
        for (int j = 1; j <= n; j++)
            S2(i - n, j) = S(i, j);
    S1_inv = inv(S1);
    mul(S1, B, Lambda);
    mul(S2, A2, S2);
    sub(S1, S1, S2);
    mul(A1, S1, S1_inv);

    for (int i = 1; i <= t; i++)
    {
        for (int j = 1; j <= n; j++)
            A(i, j) = A1(i, j);
        for (int j = 1; j <= r - n; j++)
            A(i, j + n) = A2(i, j);
    }
}

void MuS::UpdateShare(vec_ZZ_p &spi_new, const vec_ZZ_p &spi, const vec_ZZ_p &kpi)
{
    int n = spi.length();
    int counter = 0;
    unsigned char mask = 1;
    unsigned char buf[256], hash[128], hash1[128];
    std::stringstream sstream;
    std::string data;
    ZZ_p tmp;
    vec_ZZ_p tmp_spi_new;

    sstream << spi << "-@-@-" << kpi;
    data = sstream.str();
    SHA256((const unsigned char *) data.c_str(), data.length(), hash);

    while (counter < n)
    {
        memcpy(hash1, hash, 32);
        for (int i = 4; i < 8; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                tmp = hash[i] & mask;
                tmp_spi_new.append(tmp);
                hash[i] = hash[i] >> 1;
                counter++;
                if (counter >= n)
                    break;
            }
            if (counter >= n)
                break;
        }
        if (counter < n)
        {
            int len = 200 < data.length() ? 200 : data.length();
            memset(buf, 0, 256);
            memcpy(buf, hash1, 32);
            memcpy(buf + 32, data.c_str(), len);
            SHA256(buf, len + 32, hash);
        }
    }

    spi_new = tmp_spi_new;
}

void MuS::UpdateParam(vec_ZZ_p &v, mat_ZZ_p &Lambda, mat_ZZ_p &A, std::vector<vec_ZZ_p> &sp, const vec_ZZ_p &secrets,
                      const std::vector<vec_ZZ_p> &sp_old, const std::vector<vec_ZZ_p> &kp, int t, int n)
{
    vec_ZZ_p spi;
    mat_ZZ_p S;
    vec_ZZ_p tmp_v;
    mat_ZZ_p tmp_A, tmp_Lambda;
    std::vector<vec_ZZ_p> tmp_sp;

    S.SetDims(sp_old[0].length(), sp_old.size());

    for (int i = 0; i < sp_old.size(); i++)
    {
        UpdateShare(spi, sp_old[i], kp[i]);
        tmp_sp.emplace_back(spi);
    }

    for (int i = 1; i <= tmp_sp.size(); i++)
    {
        for (int j = 1; j <= tmp_sp[i - 1].length(); j++)
        {
            S(j, i) = tmp_sp[i - 1](j);
        }
    }
    CalcParam(tmp_v, tmp_Lambda, tmp_A, secrets, S, t, n);
    v = tmp_v;
    Lambda = tmp_Lambda;
    A = tmp_A;
    sp = tmp_sp;
}

void
MuS::Recover(vec_ZZ_p &S, const std::vector<int> &p, const std::vector<vec_ZZ_p> &sp, vec_ZZ_p &v, mat_ZZ_p &Lambda,
             mat_ZZ_p &A, int t, int n)
{
    mat_ZZ_p Sp, Ap, B;
    int r, col;

    if (sp.size() < t)
    {
        cout << "Not enough shares!" << endl;
        return;
    }
    r = calc_r(t, n);
    Sp.SetDims(r, t);
    Ap.SetDims(Lambda.NumRows(), t);
    col = 1;
    for (int _p: p)
    {
        for (int i = 1; i <= Lambda.NumRows(); i++)
            Ap(i, col) = Lambda(i, _p);
        col++;
        if (col > t)
            break;
    }
    col = 1;
    for (int j=0; j<sp.size();j++)
    {
        for (int i = 1; i <= sp[0].length(); i++)
            Sp(i, col) = sp[j](i);
        col++;
        if (col > t)
            break;
    }
    mul(B, A, Sp);
    inv(Ap, Ap);
    mul(B, B, Ap);
    mul(S, B, v);
}

void TransToZq(vec_ZZ_p &out, const unsigned char *in, int len)
{
    int tmp_int, ctr = 0;
    ZZ_p tmp_zzp;

    clear(out);

    if ((len / 3 + 2) > MSSS_T)
    {
        cout << "Cannot transform " << len << "-byte data to " << MSSS_T << " dimension ZZ_q vector" << endl;
        return;
    }

    tmp_zzp = len;
    out.append(tmp_zzp);

    while (ctr < len)
    {
        tmp_int = 0;

        for (int i = ctr; (i < ctr + 3) && (i < len); i++)
        {
            tmp_int = tmp_int * 256 + in[i];
        }
        tmp_zzp = tmp_int;
        out.append(tmp_zzp);
        ctr += 3;
    }
    while(out.length() < MSSS_T)
        out.append(random_ZZ_p());
}

void TransToBit(unsigned char *out, const vec_ZZ_p &in)
{
    int tmp_int, len, ctr = 0, step, index;

    conv(len, in(1));

    for (int i = 2; i <= in.length(); i++)
    {
        conv(tmp_int, in(i));
        step = len - ctr >= 3 ? 3 : len - ctr;
        for (int j = 0; (j < step) && (ctr < len); j++)
        {
            index = ctr + (step - 1) - j;
            out[index] = tmp_int % 256;
            tmp_int = tmp_int >> 8;
        }
        ctr += step;
    }
}