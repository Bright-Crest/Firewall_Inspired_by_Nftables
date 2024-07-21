#include <stdio.h>

int main() {
    char name[] = "abc";
    char *p = NULL;
    if (typeof(name) == typeof(p))
        printf("equal\n");

    return 0;
}