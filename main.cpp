#include <iostream>
#include "MuS.h"

using std::cout;
using std::endl;

int main()
{
    MuS mus;
    vec_ZZ_p v, secrets, secrets_rec;
    mat_ZZ_p Lambda, A;
    std::vector<vec_ZZ_p> sp, kp;
    std::vector<int> p;
    vec_ZZ_p sp_new;
    int t = 40, n = 200;

    for (int i = 1; i <= t; i++)
        secrets.append(random_ZZ_p());

    for (int i = 1; i <= t; i++)
        p.emplace_back(i);

    cout << "Begin share" << endl;
    mus.Share(v, Lambda, A, sp, kp, secrets, p, t, n);

    for (int i = 1; i <= t; i++)
        secrets[i] = random_ZZ_p();

    cout << "Secrets: " << endl << secrets << endl;
    cout << "Begin updates" << endl;
    mus.UpdateParam(v, Lambda, A, sp, secrets, sp, kp, t, n);
    mus.Recover(secrets_rec, p, sp, v, Lambda, A, t, n);
    cout << "Recovered Secrets: " << endl << secrets_rec << endl;


    return 0;
}
