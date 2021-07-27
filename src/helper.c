#include <stdio.h>

void hprint(char *ch, unsigned len)
{
	for(int i = 0; i < len; i++) {
            printf("0x%x ", *(ch) & 0xff);
            ch++;
        }
        printf("\n");
}