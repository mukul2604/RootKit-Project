#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define ADD_BACKDOOR    -31337
#define REMOVE_BACKDOOR -841841
int main()
{
    int ch = 0;
    printf("\t1. Add backdoor");
    printf("\n\t2. Remove backdoor\n");
    scanf("%d", &ch);
    switch (ch) {
        case 1:
            printf("\n\nAdding a backdoor\n");
            close(ADD_BACKDOOR);
            break;
        case 2:
            printf("\n\nRemoving backdoor\n");
            close(REMOVE_BACKDOOR);
            break;
        default:
            printf("\n\nThat's a bad choice!\n");
    }
    return 0;
}
