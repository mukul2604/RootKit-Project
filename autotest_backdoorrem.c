#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define REMOVE_BACKDOOR -841841
int main()
{
    close(REMOVE_BACKDOOR);
    return 0;
}
