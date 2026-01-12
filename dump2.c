#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h> /* offsetof */

#ifdef _WIN32
#define bswap_32 _byteswap_ulong
#else
#include <byteswap.h>
// uint32_t swapped = bswap_32(value);
#endif

int is_buffer_all_zero(const char* buffer, const size_t size)
{
    assert(buffer);
    for (size_t i = 0; i < size; ++i)
    {
        if (buffer[i] != 0x0)
        {
            return 0;
        }
    }
    return 1;
}

int is_phi(const char* str, const size_t len)
{
    assert(str);
    assert(len > 2);
    if (str[0] == 0x0 && str[1] != 0x0)
    {
        char buffer[512 * 4];
        assert(len < sizeof(buffer));
        memcpy(buffer, str, len);
        buffer[len] = '\0';
        buffer[0] = ' ';
        const size_t l2 = strlen(buffer);
        assert(l2>2);
        const int ret2 = is_buffer_all_zero(buffer + l2, len - l2);
        assert(ret2);
        return 1;
    }
    return 0;
}

int is_value(const char* str, const size_t len)
{
    assert(str);
    assert(len > 2);
    int r = is_buffer_all_zero(str, len);
    if (r == 1) return 0;
    r = is_phi(str, len);
    if (r == 1) return 0;
    char buffer[512 * 4];
    assert(len < sizeof(buffer));
    memcpy(buffer, str, len);
    buffer[len] = '\0';
    const size_t l = strlen(buffer);
    const int ret = is_buffer_all_zero(str + l, len - l);
    assert(ret == 1);
    return 1;
}


#define STR_IS_ZERO(str) \
is_buffer_all_zero((str), sizeof(str))

#define STR_IS_VALUE(str) \
is_value((str), sizeof(str))

#define STR_IS_PHI(str) \
is_phi((str), sizeof(str))

void my_print(FILE* stream, const char* name, const char* str, const size_t len, const size_t offset)
{
    // digital trash
    char buffer[512 * 4];
    assert(len < sizeof(buffer));
    memcpy(buffer, str, len);
    buffer[len] = '\0';
    // end
    const size_t l = strlen(buffer);
    const int ret = is_buffer_all_zero(str + l, len - l);
    if (*buffer == 0)
    {
        assert(l==0);
        buffer[0] = ' ';
    }
    const size_t l2 = strlen(buffer);
    const int ret2 = is_buffer_all_zero(buffer + l2, len - l2);
    const size_t alignment = offset % 4u;
    if (ret == 1)
        fprintf(stream, "%04zx %zu %s %zu: [%s]\n", offset, alignment, name, len, str);
    else if (ret2 == 1)
        // quick PHI logic ? vendor is only blanking the first char
        fprintf(stream, "%04zx %zu %s %zu: [%s] PHI\n", offset, alignment, name, len, buffer);
    else
        fprintf(stream, "%04zx %zu %s %zu: [%s] TRASH\n", offset, alignment, name, len, str);
}

void my_print2(FILE* stream, const char* name, const uint32_t* d, const size_t len, const size_t offset)
{
    const size_t alignment = offset % 4u;
    assert(alignment==0);
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

void my_print3(FILE* stream, const char* name, const float* d, const size_t len, const size_t offset)
{
    const size_t alignment = offset % 4u;
    assert(alignment==0);
    fprintf(stream, "%04zx %s %zu: ", offset, name, len);
    const size_t n = len / sizeof(float);
    for (int i = 0; i < n; ++i)
    {
        if (i)
            fprintf(stream, " ");
        fprintf(stream, "%f", d[i]);
    }
    fprintf(stream, "\n");
}

enum STATUS
{
    EMPTY = 0,
    INITIALIZED = 2
};

struct magic
{
    uint32_t v[2];
    char magic[0x8C - 8];
    char padding;
    char flags[0x190 - 0x8D];
    uint32_t status; // O or 2
};

void print_magic(FILE* stream, const char* name, struct magic* m, const size_t len, const size_t offset)
{
    const size_t alignment = offset % 4u;
    char buffer[512 * 4];
    assert(len < sizeof(buffer));
    assert(m->padding==0);
    sprintf(buffer, "%.*s:%.*s:%u", (int)sizeof(m->magic), m->magic,
            (int)sizeof(m->flags), m->flags,
            m->status);
    assert(m->status == EMPTY || m->status == INITIALIZED);
    fprintf(stream, "%04zx %zu %s %zu: [%s]\n", offset, alignment, name, len, buffer);
}

struct endpoint
{
    char ip[0x40 /* 64 */];
    uint16_t port_numbers[2];
    char hostname[0x40];
    char padding1;
    char options[0x102];
    char padding2;
    uint32_t status; // 0 or 2
};

enum PORTS
{
    PORT_INDEX = 1
};

void my_print4(FILE* stream, const char* name, struct endpoint* e, const size_t len, const size_t offset)
{
    const size_t alignment = offset % 4u;
    assert(alignment==0);
    char buffer[512 * 4];
    assert(len < sizeof(buffer));
    assert(e->port_numbers[0] == 0);
    assert(e->padding1==0);
    assert(e->padding2==0);
    sprintf(buffer, "%.*s:%d:%.*s:%.*s:%u", (int)sizeof(e->ip), e->ip, e->port_numbers[PORT_INDEX],
            (int)sizeof(e->hostname), e->hostname,
            (int)sizeof(e->options), e->options,
            e->status);
    assert(e->status == EMPTY || e->status == INITIALIZED);
    fprintf(stream, "%04zx %zu %s %zu: [%s]\n", offset, alignment, name, len, buffer);
    if (e->status == EMPTY)
    {
        assert(STR_IS_ZERO(e->ip) == 1);
        assert(e->port_numbers[PORT_INDEX] == 0);
        assert(STR_IS_ZERO(e->hostname) == 1);
        assert(STR_IS_ZERO(e->options) == 1);
    }
    else
    {
        assert(STR_IS_VALUE(e->ip) == 1 || STR_IS_PHI(e->ip) == 1);
        assert(e->port_numbers[PORT_INDEX] != 0);
        assert(STR_IS_VALUE(e->hostname) == 1 || STR_IS_PHI(e->hostname) == 1);
        assert(STR_IS_VALUE(e->options) == 1|| STR_IS_PHI(e->options) == 1
            || STR_IS_ZERO(e->options) == 1);
    }
}

struct junk5
{
    uint32_t zeros[17];
    uint32_t values[5]; // patient_id/study_id followed by series_number x 2 ?
};

void my_print6(FILE* stream, const char* name, struct junk5* j, const size_t len, const size_t offset)
{
    const size_t alignment = offset % 4u;
    assert(alignment==0);
    char buffer[512 * 4];
    assert(len < sizeof(buffer));
    for (int i = 0; i < 17; ++i)
        assert(j->zeros[i] == 0);
    assert(j->values[2] == 1);
    assert(j->values[3] == 1);
    sprintf(buffer, "%u,%u,%u", j->values[0],
            j->values[1],
            j->values[4]
    );
    assert(j->values[1] == j->values[4]);
    fprintf(stream, "%04zx %zu %s %zu: [%s]\n", offset, alignment, name, len, buffer);
}

typedef char string257[256 + 1];

struct info
{
#if 0
    char magic[0x8D - 0x00];
    char flags1[0x190 - 0x8D];
    uint32_t two_states1[1]; // O or 2
#else
    struct magic magic;
#endif
    char zeros1[0x320 - 0x194];
    /* start endpoint */
    struct endpoint endpoint1;
    /* end endpoint */
    /* start endpoint */
    struct endpoint endpoint2;
    /* end endpoint */
#if 0
    uint32_t junk5[23 - 1];
#else
    struct junk5 junk5;
#endif
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
    char format1[0x169d - 0x129c];
    char format2[0x1a9e - 0x169d];
    char format3[0x1e9f - 0x1a9e];
    char format4[0x22a0 - 0x1e9f];
    char format5[0x26A1 - 0x22a0];
    char format6[0x2aaa - 0x26A1 - 8];
    // not aligned:
    char fixme1[0x2BEA - 0x2aaa + 8];
    char hardware_id[0x2df0 - 0x2bea - 4];
    uint32_t small_number[1];
    char study_desc[0x2ff0 - 0x2df0];
    uint32_t junk7[1];
    char versions[0x3034 - 0x2ff4];
    uint32_t junk8[9];
    /* start endpoint */
#if 1
    char ip4_2[0x309C - 0x3059 + 1 - 4];
    uint32_t port_number[1];
    char hostname3[0X30E0 - 0x309C];
    char flags4[0X31E4 - 0X30E0];
    uint32_t value1[1];
#else
    struct endpoint endpoint3;
#endif
    uint32_t two_states4[1]; // 0 or 2
    /* end endpoint */
    uint32_t two_states5[1]; // 0 or 2
    uint32_t junk9[10 - 3];
    /* start endpoint */
    char ip4_3[0x3250 - 0x320D + 1];
    char service_name1[0x3294 - 0x3250];
    char flags5[0x3398 - 0x3294 + 4];
    uint32_t two_states6[1]; // 0 or 2
    /* end endpoint */
    uint32_t two_states7[1]; // 0 or 2
    uint32_t junk10[48 - 3];
    char service_name2[0x34A4 - 0x3458];
    char aetitle1[0x34E8 - 0x34A4];
    char aetitle3[0x352C - 0x34E8];
    char app_name[0x3570 - 0x352C];
    char service_name3[0x35B8 - 0x3570];
    uint32_t service_name3_status[1];
    uint32_t junk11[12];
    char orientation1[0x3630 - 0x35EC];
    char orientation2[0x3674 - 0x3630];
    uint32_t junk12[19];
    char dicom_ds[0x3AD0 - 0x36C0 - 8 - 8];
#if 0
    uint32_t junk13[9];
#else
    float junk13[9];
#endif
    char gender[0x3B2C - 0x3AE4];
    char padding[0x3CC4 - 0x3B2C];
    char mode[0x42DC - 0x3CC4];
    char left_right[0x48F4 - 0x42DC];
    char series_name[0x493B - 0x48F4];
};


#define MY_PRINT(stream, struct_ptr, member) \
    my_print((stream), #member, (struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))

#define MY_PRINT2(stream, struct_ptr, member) \
    my_print2((stream), #member, (struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))

#define MY_PRINT3(stream, struct_ptr, member) \
  my_print3((stream), #member, (struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))

#define MY_PRINT4(stream, struct_ptr, member) \
  my_print4((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))
#define PRINT_MAGIC(stream, struct_ptr, member) \
print_magic((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))
#define MY_PRINT6(stream, struct_ptr, member) \
my_print6((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))


static void process_canon(FILE* stream, const char* data, const size_t size)
{
    const size_t SIZE1 = 15148;
    const size_t off1 = offsetof(struct info, padding);
    assert(off1==SIZE1);
    const size_t SIZE2 = 18748; // 4687 * 4
    const size_t s2 = sizeof(struct info);
    assert(s2==SIZE2);
    assert(size == SIZE1 || size == SIZE2);
    struct info* pinfo;
    pinfo = malloc(sizeof(struct info));
    if (!pinfo)
    {
        perror("Failed to allocate struct info");
        return;
    }
    memcpy(pinfo, data, size);

    PRINT_MAGIC(stream, pinfo, magic);
    int ret = is_buffer_all_zero(pinfo->zeros1, sizeof(pinfo->zeros1));
    assert(ret==1);
    MY_PRINT(stream, pinfo, zeros1);
    MY_PRINT4(stream, pinfo, endpoint1);
    MY_PRINT4(stream, pinfo, endpoint2);
    MY_PRINT6(stream, pinfo, junk5);
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
    MY_PRINT(stream, pinfo, format1);
    MY_PRINT(stream, pinfo, format2);
    MY_PRINT(stream, pinfo, format3);
    MY_PRINT(stream, pinfo, format4);
    MY_PRINT(stream, pinfo, format5);
    MY_PRINT(stream, pinfo, format6);
    MY_PRINT(stream, pinfo, fixme1);
    MY_PRINT(stream, pinfo, hardware_id);
    MY_PRINT2(stream, pinfo, small_number);
    MY_PRINT(stream, pinfo, study_desc);
    MY_PRINT2(stream, pinfo, junk7);
    MY_PRINT(stream, pinfo, versions);
    MY_PRINT2(stream, pinfo, junk8);
#if 1
    MY_PRINT(stream, pinfo, ip4_2);
    MY_PRINT(stream, pinfo, hostname3);
    MY_PRINT(stream, pinfo, flags4);
    MY_PRINT2(stream, pinfo, value1);
#else
    MY_PRINT4(stream, pinfo, endpoint3);
#endif
    MY_PRINT2(stream, pinfo, two_states4);
    MY_PRINT2(stream, pinfo, two_states5);
    MY_PRINT2(stream, pinfo, junk9);
    //    ret = is_buffer_all_zero(pinfo->zeros3, sizeof(pinfo->zeros3));
    //    assert(ret==1);
    MY_PRINT(stream, pinfo, ip4_3);
    MY_PRINT(stream, pinfo, service_name1);
    MY_PRINT(stream, pinfo, flags5);
    MY_PRINT2(stream, pinfo, two_states6);
    MY_PRINT2(stream, pinfo, two_states7);
    MY_PRINT2(stream, pinfo, junk10);
    MY_PRINT(stream, pinfo, service_name2);
    MY_PRINT(stream, pinfo, aetitle1);
    MY_PRINT(stream, pinfo, aetitle3);
    MY_PRINT(stream, pinfo, app_name);
    MY_PRINT(stream, pinfo, service_name3);
    MY_PRINT2(stream, pinfo, service_name3_status);
    MY_PRINT2(stream, pinfo, junk11);
    MY_PRINT(stream, pinfo, orientation1);
    MY_PRINT(stream, pinfo, orientation2);
    MY_PRINT2(stream, pinfo, junk12);
    MY_PRINT(stream, pinfo, dicom_ds);
    //MY_PRINT2(stream, pinfo, junk13);
    MY_PRINT3(stream, pinfo, junk13);
    MY_PRINT(stream, pinfo, gender);
    if (size == SIZE2)
    {
        MY_PRINT(stream, pinfo, padding);
        MY_PRINT(stream, pinfo, mode);
        MY_PRINT(stream, pinfo, left_right);
        MY_PRINT(stream, pinfo, series_name);
    }
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
    char* buffer = malloc(filesize + 0);
    if (!buffer)
    {
        perror("Failed to allocate buffer");
        (void)fclose(file);
        return 1;
    }

    // Read file into buffer
    const size_t read_size = fread(buffer, 1, filesize, file);

    // Use buffer as needed...
    process_canon(stdout, buffer, filesize);

    free(buffer);
    (void)fclose(file);
    return 0;
}
