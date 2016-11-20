#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define BUFSIZE 4096
#define ELEVATE_UID -23121990

void try_something_rooty();

int main(int argc, const char *argv[])
{

    printf("Normal program; uid: %d\n", getuid());
    try_something_rooty();

    printf("\nElevate privileges\n");
    close(ELEVATE_UID);
    printf("Elevated uid: %d\n", getuid());

    try_something_rooty();

    return 0;
}

void try_something_rooty()
{
    int fd;

    const char *path = "/testing";

    printf("Trying to create %s\n", path);
    fd = open(path, O_RDONLY | O_CREAT, 0755);
    if (fd < 0) {
        printf("Can't create %s\n", path);
    }
    else {
        printf("%s created\n", path);
    }
}
