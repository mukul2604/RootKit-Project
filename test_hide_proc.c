#include <stdio.h>
#include <unistd.h>

#define HIDE_PROC -19091992
#define SHOW_PROC -2051967

#define DELAY 15

int main (int argc, const char *argv[])
{
    close(HIDE_PROC);

    printf("If you do ps -e | grep test_hide_proc\n");

    printf("You should NOT be able to see this process right now\n");
    printf("Sleeping for %d seconds\n", DELAY);
    sleep(DELAY);

    close(SHOW_PROC);
    printf("\nYou SHOULD be able to see this process right now\n");
    printf("Sleeping for %d seconds\n", DELAY);
    sleep(DELAY);

    return 0;
}
