#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct info
{
    char magic[0x320 /* 800 */];
    char ip[0x40 /* 64 */];
    uint32_t junk1[1];
    char flags[0x41];
    char str1[0x103];
    uint32_t junk2[1];
    char str2[0x10 + 448];
    uint32_t junk3[5];
    char str3[0x30];
};

int is_buffer_all_zero(const char* buffer, const size_t size)
{
    for (size_t i = 0; i < size; ++i)
    {
        if (buffer[i] != 0x0)
        {
            return 0;
        }
    }
    return 1;
}

void my_print(FILE* stream, const char* name, const char* str, const size_t len)
{
    const size_t l = strlen(str);
    const int ret = is_buffer_all_zero(str + l, len - l);
    assert(ret == 1);
    fprintf(stream, "%s: [%s]\n", name, str);
}

void my_print_u32(FILE* stream, const uint32_t* d, size_t len)
{
    const size_t n = len / sizeof(uint32_t);
    for (int i = 0; i < n; ++i)
    {
        if (i)
            fprintf(stream, " ");
        fprintf(stream, "%x", d[i]);
    }
    fprintf(stream, "\n");
}

static void process_canon(FILE* stream, const char* data, size_t size)
{
    const size_t SIZE = 18748; // 4687 * 4
    struct info* pinfo = malloc(sizeof(struct info));
    if (!pinfo)
    {
        perror("Failed to allocate struct info");
        // Handle error as needed
    }
    memcpy(pinfo, data, sizeof(struct info));

    my_print(stream, "magic", pinfo->magic, sizeof(pinfo->magic));
    my_print(stream, "ip", pinfo->ip, sizeof(pinfo->ip));
    my_print_u32(stream, pinfo->junk1, sizeof(pinfo->junk1));
    my_print(stream, "hostname", pinfo->flags, sizeof(pinfo->flags));
    my_print(stream, "flags", pinfo->str1, sizeof(pinfo->str1));
    my_print_u32(stream, pinfo->junk2, sizeof(pinfo->junk2));
    assert(pinfo->junk2[0] == 0x2);
    const int ret = is_buffer_all_zero(pinfo->str2, sizeof(pinfo->str2));
    assert(ret==1);
    my_print_u32(stream, pinfo->junk3, sizeof(pinfo->junk3));
    my_print(stream, "str3", pinfo->str3, sizeof(pinfo->str3));
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        (void)fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    const char* filename = argv[1];
    FILE* file = fopen(filename, "rb");
    if (!file)
    {
        perror("Failed to open file");
        return 1;
    }

    // Determine file size
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    rewind(file);

    // Allocate buffer
    char* buffer = malloc(filesize + 1);
    if (!buffer)
    {
        perror("Failed to allocate buffer");
        (void)fclose(file);
        return 1;
    }

    // Read file into buffer
    size_t read_size = fread(buffer, 1, filesize, file);
    buffer[read_size] = '\0'; // Null-terminate the buffer

    // Use buffer as needed...
    process_canon(stdout, buffer, filesize);

    free(buffer);
    (void)fclose(file);
    return 0;
}
