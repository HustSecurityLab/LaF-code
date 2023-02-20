#ifndef MUS_MUS_H
#define MUS_MUS_H

#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vector.h>
#include <NTL/RR.h>
#include <NTL/vec_RR.h>
#include <vector>
#include <string>

using namespace NTL;

#define MSSS_q  "4721940989"
#define MSSS_N (50)
#define MSSS_T (21)

class MuS
{
public:
    MuS();

    void Share(vec_ZZ_p &v, mat_ZZ_p &Lambda, mat_ZZ_p &A, std::vector<vec_ZZ_p> &sp, std::vector<vec_ZZ_p> &kp,
               const vec_ZZ_p &secrets, const std::vector<int> &p, int t, int n);

    void UpdateShare(vec_ZZ_p &spi_new, const vec_ZZ_p &spi, const vec_ZZ_p &kpi);

    void UpdateParam(vec_ZZ_p &v, mat_ZZ_p &Lambda, mat_ZZ_p &A, std::vector<vec_ZZ_p> &sp, const vec_ZZ_p &secrets,
                     const std::vector<vec_ZZ_p> &sp_old, const std::vector<vec_ZZ_p> &kp, int t, int n);

    void Recover(vec_ZZ_p &S, const std::vector<int> &p, const std::vector<vec_ZZ_p> &sp, vec_ZZ_p &v, mat_ZZ_p &Lambda,
                 mat_ZZ_p &A, int t, int n);

private:
    int calc_r(int t, int n);

    void generating_S(mat_ZZ_p &S, int t, int n);

    void
    CalcParam(vec_ZZ_p &v, mat_ZZ_p &Lambda, mat_ZZ_p &A, const vec_ZZ_p &secrets, const mat_ZZ_p &S, int t, int n);

    bool isColumnIndependent(const mat_ZZ_p &m);

    void generating_Lambda(mat_ZZ_p &Lambda, int t, int n);

    void generating_A(mat_ZZ_p &A, const mat_ZZ_p &B, const mat_ZZ_p &Lambda, const mat_ZZ_p &S, int t, int n);
};

void TransToZq(vec_ZZ_p &out, const unsigned char *in, int len);

void TransToBit(unsigned char *out, const vec_ZZ_p &in);

#endif
