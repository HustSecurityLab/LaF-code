#ifndef LAF_LAFSERVER_H
#define LAF_LAFSERVER_H

#include <string>
#include <map>
#include <vector>

using std::string;
using std::vector;
using std::map;

class LaFServer
{
public:
    LaFServer(const string &server_ip, int port);
    void Run();

private:
    string server_ip;
    int port;

    int ServerSockInit_();
    void Init_KeyExchange_SavePk_(int sock);
    void Init_KeyExchange_DistPk_(int sock);
    void Init_KeyExchange_DistCip_(int sock);
    void Init_ShareTwoMasks_(int sock);
    void MaskInputs_(int sock);
    void Recover_Init_(int sock);
    void Cons_KeyExchange_SavePk_(int sock);
    void Cons_KeyExchange_DistPk_(int sock);
    void Cons_KeyExchange_DistCip_(int sock);
};


#endif //LAF_LAFSERVER_H
