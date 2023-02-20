#include "LaFParticipant.h"
#include <iostream>
#include <fstream>

extern "C"
{
#include "unistd.h"
}

using std::cout;
using std::endl;

void print_data(LaFParticipant &laf_prt, const vector<string> &data)
{
    cout << "Data of client #" << laf_prt.get_id() << " in epoch " << laf_prt.get_epoch() << ":" << endl;
    cout << '[' << endl;
    for (const auto &itr: data)
        cout << itr << " ";
    cout << ']' << endl;
}

vector<string> split(const string& str, const string& delim) {
    vector<string> res;
    if("" == str) return res;
    //先将要切割的字符串从string类型转换为char*类型
    char * strs = new char[str.length() + 1] ; //不要忘了
    strcpy(strs, str.c_str());

    char * d = new char[delim.length() + 1];
    strcpy(d, delim.c_str());

    char *p = strtok(strs, d);
    while(p) {
        string s = p; //分割得到的字符串转换为string类型
        res.push_back(s); //存入结果数组
        p = strtok(NULL, d);
    }

    return res;
}

vector<string> load_model(string filename) {
    std::ifstream t(filename);
    std::string weights((std::istreambuf_iterator<char>(t)),
                        std::istreambuf_iterator<char>());
    return split(weights, ",");
}

void test_load(){
    vector<string> data = load_model("LeNet-model-0");
    cout << data.size() << endl;
}

int main(int argc, char *argv[])
{
    int num_clients = 50;
    int total_rounds = 3;
    //vector<string> data = load_model("LeNet-model-0");
    for(int i = 0; i < num_clients; i++)
    {
        if(fork() == 0)
        {
            LaFParticipant laf_prt("127.0.0.1", 54322);
            vector<string> data;

            for (int i = 1; i <= 15; i++)
                data.emplace_back(std::to_string(i));
            //cout << "Key Exchange " << endl;
            laf_prt.KeyExchange_init();
//            print_data(laf_prt, data);
            //cout << "ShareTwoMasks" << endl;
            laf_prt.ShareTwoMasks();
            //cout << "MaskInputs" << endl;
            laf_prt.MaskInputs(data);
            //cout << "Recover" << endl;
            laf_prt.Recover();

            for (int i = 0; i < total_rounds; i++)
            {
                data.clear();
                for (int j = 1; j <= 15; j++)
                    data.emplace_back("0." + std::to_string(j * 231) +
                                      std::to_string(laf_prt.get_id() * 62291 + laf_prt.get_epoch() * 812343));
//                print_data(laf_prt, data);

                laf_prt.KeyExchange_Cons();
                laf_prt.MaskInputs(data);
                laf_prt.Recover();
            }
            break;
        }
    }

    return 0;
}