#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

static uint32_t table_key = 0x19ab75cd;

void *x(void *, int);
void handle_escape_char(char* buf, char* old, char* new);

int main(int argc, char **args)
{
    void *data;
    int len, i, byte_length;
    unsigned char* byte_string = NULL;
    char *pos;

    if (argc != 3)
    {
        printf("Usage: %s <string | ip | uint32 | uint16 | uint8 | bool | byte-strings> <data>\n", args[0]);
        return 0;
    }

    if (strcmp(args[1], "byte-strings") == 0)
    {
        data = args[2];
        len = strlen(data);
        byte_length = len / 4;
        byte_string = malloc(len / 4);
        
        for (int i = 0; i < len; i += 4) {
            sscanf(data + i, "\\x%2hhx", &byte_string[i / 4]);
        }

        data = byte_string;
        len = byte_length;
    }
    else if (strcmp(args[1], "string") == 0)
    {
        data = args[2];
        handle_escape_char(data, "\\r", "\r");
        handle_escape_char(data, "\\n", "\n");
        len = strlen(data) + 1;
    }
    else if (strcmp(args[1], "ip") == 0)
    {
        data = calloc(1, sizeof (uint32_t));
        *((uint32_t *)data) = inet_addr(args[2]);
        len = sizeof (uint32_t);
    }
    else if (strcmp(args[1], "uint32") == 0)
    {
        data = calloc(1, sizeof (uint32_t));
        *((uint32_t *)data) = htonl((uint32_t)atoi(args[2]));
        len = sizeof (uint32_t);
    }
    else if (strcmp(args[1], "uint16") == 0)
    {
        data = calloc(1, sizeof (uint16_t));
        *((uint16_t *)data) = htons((uint16_t)atoi(args[2]));
        len = sizeof (uint16_t);
    }
    else if (strcmp(args[1], "uint8") == 0)
    {
        data = calloc(1, sizeof (uint8_t));
        *((uint8_t *)data) = atoi(args[2]);
        len = sizeof (uint8_t);
    }
    else if (strcmp(args[1], "bool") == 0)
    {
        data = calloc(1, sizeof (char));
        if (strcmp(args[2], "false") == 0)
            ((char *)data)[0] = 0;
        else if (strcmp(args[2], "true") == 0)
            ((char *)data)[0] = 1;
        else
        {
            printf("Unknown value `%s` for datatype bool!\n", args[2]);
            return -1;
        }
        len = sizeof (char);
    }
    else
    {
        printf("Unknown data type `%s`!\n", args[1]);
        return -1;
    }

    // Yes we are leaking memory, but the program is so
    // short lived that it doesn't really matter...
    printf("XOR'ing %d bytes of data...\n", len);
    data = x(data, len);
    for (i = 0; i < len; i++)
        printf("\\x%02X", ((unsigned char *)data)[i]);
    printf("\n");

    printf("\n");
    printf("For decryption: \n");

    printf("(char*)util_decrypt(\"");
    for (i = 0; i < len; i++)
        printf("\\x%02X", ((unsigned char *)data)[i]);
    printf("\", %d)\r\n", len);
}

void *x(void *_buf, int len)
{
    unsigned char *buf = (char *)_buf, *out = malloc(len);
    int i;
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for (i = 0; i < len; i++)
    {
        char tmp = buf[i] ^ k1;

        tmp ^= k2;
        tmp ^= k3;
        tmp ^= k4;

        out[i] = tmp;
    }

    return out;
}

void handle_escape_char(char* buf, char* old_char, char* new_char)
{
    char* pos = buf;
    while ((pos = strstr(pos, old_char)) != NULL) 
    {
        *pos = *(new_char);
        memmove(pos + 1, pos + 2, strlen(pos + 2) + 1);
        pos++;
    }
}