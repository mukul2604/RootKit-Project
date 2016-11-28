#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define ADD_BACKDOOR    -31337
int main()
{
    close(ADD_BACKDOOR);
    return 0;
}
