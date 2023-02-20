#include "LaFServer.h"

int main(int argc, char *argv[])
{
    LaFServer laf_srv("127.0.0.1", 54322);

    laf_srv.Run();
    return 0;
}