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
    char magic[0x8D - 0x00];
    char str31[0x320 - 0x8D];
    char ip4[0x40 /* 64 */];
    uint32_t junk1[1];
    char hostname1[0x41];
    char str1[0x103];
    uint32_t junk2[1];
    char str2[0x10 + 448];
    uint32_t junk3[5];
    char caltype[0x30 + 209];
    char cdc[257];
    char cc[0x0a94 - 0x0892];
    char am[0x0c96 - 0x0a94];
    char pos1[0x0d97 - 0x0c96];
    char pos2[0x0e98 - 0x0d97];
    char pos3[0x0f99 - 0x0e98];
    char pos4[0x109a - 0x0f99];
    char pos5[0x119b - 0x109a];
    char pos6[0x129c - 0x119b];
    char ope_button[0x169d - 0x129c];
    char study_dt[0x1a9e - 0x169d];
    char ltrlty1[0x1e9f - 0x1a9e];
    char ltrlty2[0x22a0 - 0x1e9f];
    char pid[0x26A1 - 0x22a0];
    char str36[0x2aaa - 0x26A1];
    char fixme1[0x2BEA - 0x2aaa - 0];
    char str18[0x2df0 - 0x2bea - 4];
    uint32_t junk4[1];
    char str19[0x2ff4 - 0x2df0 - 4];
    uint32_t junk5[1];
    char str20[0x3034 - 0x2ff4];
    uint32_t junk6[9];
    char zeros2[1];
    char str32[0x309C - 0x3059];
    char str33[0X30E0 - 0x309C];
    char str34[0X31E4 - 0X30E0];
    uint32_t j[10];
    char p[1];
    char str26[0x3250 - 0x320D];
    char str27[0x3294 - 0x3250];
    char str28[0x339C - 0x3294];
    char str29[0x34A4 - 0x339C]; // fixme
    char hostname2[0x34E8 - 0x34A4];
    char str37[0x352C - 0x34E8];
    char str35[0x3570 - 0x352C];
    char str30[0x35B8 - 0x3570];
    uint32_t junk10[1];
    uint32_t junk7[12];
    char str22[0x3630 - 0x35EC];
    char str23[0x3674 - 0x3630];
    uint32_t junk8[19];
    char str24[0x3AD0 - 0x36C0 - 8];
    uint32_t junk9[5 + 2];
    char gender[0x493B - 0x3AE4];
};

static void process_canon(FILE* stream, const char* data, size_t size)
{
    const size_t SIZE = 18748; // 4687 * 4
    const size_t s = sizeof(struct info);
    assert(s==SIZE);
    struct info* pinfo = malloc(sizeof(struct info));
    if (!pinfo)
    {
        perror("Failed to allocate struct info");
        // Handle error as needed
    }
    memcpy(pinfo, data, sizeof(struct info));

    my_print(stream, "magic", pinfo->magic, sizeof(pinfo->magic));
    my_print(stream, "str31", pinfo->str31, sizeof(pinfo->str31));
    my_print(stream, "ip4", pinfo->ip4, sizeof(pinfo->ip4));
    my_print_u32(stream, pinfo->junk1, sizeof(pinfo->junk1));
    my_print(stream, "hostname1", pinfo->hostname1, sizeof(pinfo->hostname1));
    my_print(stream, "flags", pinfo->str1, sizeof(pinfo->str1));
    my_print_u32(stream, pinfo->junk2, sizeof(pinfo->junk2));
    my_print(stream, "str2", pinfo->str2, sizeof(pinfo->str2));
    my_print_u32(stream, pinfo->junk3, sizeof(pinfo->junk3));
    my_print(stream, "caltype", pinfo->caltype, sizeof(pinfo->caltype));
    my_print(stream, "cdc", pinfo->cdc, sizeof(pinfo->cdc));
    my_print(stream, "cc", pinfo->cc, sizeof(pinfo->cc));
    my_print(stream, "am", pinfo->am, sizeof(pinfo->am));
    my_print(stream, "pos1", pinfo->pos1, sizeof(pinfo->pos1));
    my_print(stream, "pos2", pinfo->pos2, sizeof(pinfo->pos2));
    my_print(stream, "pos3", pinfo->pos3, sizeof(pinfo->pos3));
    my_print(stream, "pos4", pinfo->pos4, sizeof(pinfo->pos4));
    my_print(stream, "pos5", pinfo->pos5, sizeof(pinfo->pos5));
    my_print(stream, "pos6", pinfo->pos6, sizeof(pinfo->pos6));
    my_print(stream, "ope button", pinfo->ope_button, sizeof(pinfo->ope_button));
    my_print(stream, "study_dt", pinfo->study_dt, sizeof(pinfo->study_dt));
    my_print(stream, "laterality1", pinfo->ltrlty1, sizeof(pinfo->ltrlty1));
    my_print(stream, "laterality2", pinfo->ltrlty2, sizeof(pinfo->ltrlty2));
    my_print(stream, "pid", pinfo->pid, sizeof(pinfo->pid));
    // fixme1 ??
    my_print(stream, "str18", pinfo->str18, sizeof(pinfo->str18));
    my_print_u32(stream, pinfo->junk4, sizeof(pinfo->junk4));
    my_print(stream, "str19", pinfo->str19, sizeof(pinfo->str19));
    my_print(stream, "str20", pinfo->str20, sizeof(pinfo->str20));
    my_print_u32(stream, pinfo->junk6, sizeof(pinfo->junk6));
    int ret = is_buffer_all_zero(pinfo->zeros2, sizeof(pinfo->zeros2));
    assert(ret==1);
    my_print(stream, "hostname2", pinfo->hostname2, sizeof(pinfo->hostname2));
    my_print_u32(stream, pinfo->junk7, sizeof(pinfo->junk7));
    my_print(stream, "str22", pinfo->str22, sizeof(pinfo->str22));
    my_print(stream, "str23", pinfo->str23, sizeof(pinfo->str23));
    my_print_u32(stream, pinfo->junk8, sizeof(pinfo->junk8));
    my_print(stream, "str24", pinfo->str24, sizeof(pinfo->str24));
    my_print_u32(stream, pinfo->junk9, sizeof(pinfo->junk9));
    my_print(stream, "gender", pinfo->gender, sizeof(pinfo->gender));
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
