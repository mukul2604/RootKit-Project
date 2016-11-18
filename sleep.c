#include <unistd.h>

int main (int argc, const char *argv[])
{
    close(-19091992);
    sleep(5);
    close(-2051967);
    sleep(5);
    return 0;
}
