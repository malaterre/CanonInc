#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    char str3[0x30 + 209];
    char str4[257];
    char str5[0x0a94 - 0x0892];
    char str6[0x0c96 - 0x0a94];
    char str7[0x0d97 - 0x0c96];
    char str8[0x0e98 - 0x0d97];
    char str9[0x0f99 - 0x0e98];
    char str10[0x109a - 0x0f99];
    char str11[0x119b - 0x109a];
    char str12[0x129c - 0x119b];
    char str13[0x169d - 0x129c];
    char str14[0x1a9e - 0x169d];
    char str15[0x1e9f - 0x1a9e];
    char str16[0x22a0 - 0x1e9f];
    char str17[0x2aaa - 0x22a0];
    char fixme1[0x2BEA - 0x2aaa - 0];
    char str18[0x2df0 - 0x2bea - 4];
    uint32_t junk4[1];
    char str19[0x2ff4 - 0x2df0 - 4];
    uint32_t junk5[1];
    char str20[0x3034 - 0x2ff4];
    uint32_t junk6[11 - 2];
    char zeros2[0x34A4 - 0x3058];
    char str21[0x35BC - 0x34A4];
    uint32_t junk7[12];
    char str22[0x3630 - 0x35EC];
    char str23[0x3674 - 0x3630];
};

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
    int ret = is_buffer_all_zero(pinfo->str2, sizeof(pinfo->str2));
    assert(ret==1);
    my_print_u32(stream, pinfo->junk3, sizeof(pinfo->junk3));
    my_print(stream, "str3", pinfo->str3, sizeof(pinfo->str3));
    my_print(stream, "str4", pinfo->str4, sizeof(pinfo->str4));
    my_print(stream, "str5", pinfo->str5, sizeof(pinfo->str5));
    my_print(stream, "str6", pinfo->str6, sizeof(pinfo->str6));
    my_print(stream, "str7", pinfo->str7, sizeof(pinfo->str7));
    my_print(stream, "str8", pinfo->str8, sizeof(pinfo->str8));
    my_print(stream, "str9", pinfo->str9, sizeof(pinfo->str9));
    my_print(stream, "str10", pinfo->str10, sizeof(pinfo->str10));
    my_print(stream, "str11", pinfo->str11, sizeof(pinfo->str11));
    my_print(stream, "str12", pinfo->str12, sizeof(pinfo->str12));
    my_print(stream, "str13", pinfo->str13, sizeof(pinfo->str13));
    my_print(stream, "str14", pinfo->str14, sizeof(pinfo->str14));
    my_print(stream, "str15", pinfo->str15, sizeof(pinfo->str15));
    my_print(stream, "str16", pinfo->str16, sizeof(pinfo->str16));
    my_print(stream, "str17", pinfo->str17, sizeof(pinfo->str17));
    // fixme1 ??
    my_print(stream, "str18", pinfo->str18, sizeof(pinfo->str18));
    my_print_u32(stream, pinfo->junk4, sizeof(pinfo->junk4));
    my_print(stream, "str19", pinfo->str19, sizeof(pinfo->str19));
    my_print(stream, "str20", pinfo->str20, sizeof(pinfo->str20));
    my_print_u32(stream, pinfo->junk6, sizeof(pinfo->junk6));
    ret = is_buffer_all_zero(pinfo->zeros2, sizeof(pinfo->zeros2));
    assert(ret==1);
    my_print(stream, "str21", pinfo->str21, sizeof(pinfo->str21));
    my_print_u32(stream, pinfo->junk7, sizeof(pinfo->junk7));
    my_print(stream, "str22", pinfo->str22, sizeof(pinfo->str22));
    my_print(stream, "str23", pinfo->str23, sizeof(pinfo->str23));
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
