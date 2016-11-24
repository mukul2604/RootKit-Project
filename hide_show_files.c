#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define HIDE_FILES   -7111963
#define SHOW_FILES   -294365563
int main()
{
    int ch = 0;
    printf("\t1. Hide files");
    printf("\n\t2. Unhide files\n");
    scanf("%d", &ch);
    switch (ch) {
        case 1:
            printf("\n\nHiding files\n");
            close(HIDE_FILES);
            break;
        case 2:
            printf("\n\nUnhiding files\n");
            close(SHOW_FILES);
            break;
        default:
            printf("\n\nThat's a bad choice!\n");
    }
    return 0;
}
