#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define HIDE_FILES   -7111963
int main()
{
    close(HIDE_FILES);
    return 0;
}
