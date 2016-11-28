#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define SHOW_FILES   -294365563
int main()
{
    close(SHOW_FILES);
    return 0;
}
