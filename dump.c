#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h> /* offsetof */

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

void my_print(FILE* stream, const char* name, const char* str, const size_t len, const size_t offset)
{
    const size_t l = strlen(str);
    const int ret = is_buffer_all_zero(str + l, len - l);
    // digital trash
    assert(len < 512u*4);
    char buffer[512 * 4];
    memcpy(buffer, str, len);
    buffer[len] = '\0';
    if (*buffer == 0)
    {
        assert(l==0);
        buffer[0] = ' ';
    }
    const size_t l2 = strlen(buffer);
    const int ret2 = is_buffer_all_zero(buffer + l2, len - l2);
    const size_t alignement = offset % 4u;
    if (ret == 1 || ret2 == 1)
        fprintf(stream, "%04zx %zu %s %zu: [%s]\n", offset, alignement, name, len, str);
    else
        fprintf(stream, "DT %04zx %zu %s %zu: [%s]\n", offset, alignement, name, len, str);
}

void my_print2(FILE* stream, const char* name, const uint32_t* d, const size_t len, const size_t offset)
{
    const size_t alignement = offset % 4u;
    assert(alignement==0);
    fprintf(stream, "%04zx %s %zu: ", offset, name, len);
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
    char flags1[0x190 - 0x8D];
    uint32_t two_states1[1]; // O or 2
    char zeros1[0x320 - 0x194];
    char local_ip[0x40 /* 64 */];
    uint32_t junk2[1];
    char hostname1[0x41];
    char flags2[0x103];
    uint32_t two_states2[1]; // 0 or 2
    char ip4_2[0x4EC - 0x4ac];
    uint32_t junk4[1];
    char aetitle2[0x531 - 0x4F0];
    char flags3[0x634 - 0x531];
    uint32_t junk5[23];
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
    char format0[0x2aaa - 0x26A1];
    // not aligned:
    char fixme1[0x2BEA - 0x2aaa];
    char study_id[0x2df0 - 0x2bea - 4];
    uint32_t small_number[1];
    char study_desc[0x2ff0 - 0x2df0];
    uint32_t junk7[1];
    char versions[0x3034 - 0x2ff4];
    uint32_t junk8[9];
    char zeros2[1];
    char ip4[0x309C - 0x3059];
    char hostname3[0X30E0 - 0x309C];
    char flags4[0X31E4 - 0X30E0];
    uint32_t junk9[10];
    char zeros3[1];
    char ip4_dt[0x3250 - 0x320D]; // digital trash ?
    char dry2[0x3294 - 0x3250];
    char flags5[0x3398 - 0x3294];
    char str29[0x34A4 - 0x3398]; // fixme
    char hostname2[0x34E8 - 0x34A4];
    char aetitle[0x352C - 0x34E8];
    char app_name[0x3570 - 0x352C];
    char dry[0x35B8 - 0x3570];
    uint32_t junk10[12 + 1];
    char orientation1[0x3630 - 0x35EC];
    char orientation2[0x3674 - 0x3630];
    uint32_t junk11[19];
    char dicom_ds[0x3AD0 - 0x36C0 - 8 - 8];
    uint32_t junk12[5 + 2 + 2];
    char gender[0x3CC4 - 0x3AE4];
    char mode[0x42DC - 0x3CC4];
    char left_right[0x48F4 - 0x42DC];
    char position[0x493B - 0x48F4];
};

#define MY_PRINT(stream, struct_ptr, member) \
    my_print((stream), #member, (struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))
#define MY_PRINT2(stream, struct_ptr, member) \
my_print2((stream), #member, (struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))

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

    MY_PRINT(stream, pinfo, magic);
    MY_PRINT(stream, pinfo, flags1);
    MY_PRINT2(stream, pinfo, two_states1);
    int ret = is_buffer_all_zero(pinfo->zeros1, sizeof(pinfo->zeros1));
    assert(ret==1);
    MY_PRINT(stream, pinfo, zeros1);
    MY_PRINT(stream, pinfo, local_ip);
    MY_PRINT2(stream, pinfo, junk2);
    MY_PRINT(stream, pinfo, hostname1);
    MY_PRINT(stream, pinfo, flags2);
    MY_PRINT2(stream, pinfo, two_states2);
    MY_PRINT(stream, pinfo, ip4_2);
    MY_PRINT2(stream, pinfo, junk4);
    MY_PRINT(stream, pinfo, aetitle2);
    MY_PRINT(stream, pinfo, flags3);
    MY_PRINT2(stream, pinfo, junk5);
    MY_PRINT(stream, pinfo, caltype);
    MY_PRINT(stream, pinfo, cdc);
    MY_PRINT(stream, pinfo, cc);
    MY_PRINT(stream, pinfo, am);
    MY_PRINT(stream, pinfo, pos1);
    MY_PRINT(stream, pinfo, pos2);
    MY_PRINT(stream, pinfo, pos3);
    MY_PRINT(stream, pinfo, pos4);
    MY_PRINT(stream, pinfo, pos5);
    MY_PRINT(stream, pinfo, pos6);
    MY_PRINT(stream, pinfo, ope_button);
    MY_PRINT(stream, pinfo, study_dt);
    MY_PRINT(stream, pinfo, ltrlty1);
    MY_PRINT(stream, pinfo, ltrlty2);
    MY_PRINT(stream, pinfo, pid);
    MY_PRINT(stream, pinfo, format0);
    MY_PRINT(stream, pinfo, fixme1);
    //ret = is_buffer_all_zero(pinfo->fixme1, sizeof(pinfo->fixme1));
    //assert(ret==1);
    MY_PRINT(stream, pinfo, study_id);
    MY_PRINT2(stream, pinfo, small_number);
    MY_PRINT(stream, pinfo, study_desc);
    MY_PRINT2(stream, pinfo, junk7);
    MY_PRINT(stream, pinfo, versions);
    MY_PRINT2(stream, pinfo, junk8);
    ret = is_buffer_all_zero(pinfo->zeros2, sizeof(pinfo->zeros2));
    assert(ret==1);
    MY_PRINT(stream, pinfo, ip4);
    MY_PRINT(stream, pinfo, hostname3);
    MY_PRINT(stream, pinfo, flags4);
    MY_PRINT2(stream, pinfo, junk9);
    ret = is_buffer_all_zero(pinfo->zeros3, sizeof(pinfo->zeros3));
    assert(ret==1);
    MY_PRINT(stream, pinfo, ip4_dt);
    MY_PRINT(stream, pinfo, dry2);
    MY_PRINT(stream, pinfo, flags5);
    MY_PRINT(stream, pinfo, str29);
    MY_PRINT(stream, pinfo, hostname2);
    MY_PRINT(stream, pinfo, aetitle);
    MY_PRINT(stream, pinfo, app_name);
    MY_PRINT(stream, pinfo, dry);
    MY_PRINT2(stream, pinfo, junk10);
    MY_PRINT(stream, pinfo, orientation1);
    MY_PRINT(stream, pinfo, orientation2);
    MY_PRINT2(stream, pinfo, junk11);
    MY_PRINT(stream, pinfo, dicom_ds);
    MY_PRINT2(stream, pinfo, junk12);
    MY_PRINT(stream, pinfo, gender);
    MY_PRINT(stream, pinfo, mode);
    MY_PRINT(stream, pinfo, left_right);
    MY_PRINT(stream, pinfo, position);
    free(pinfo);
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
