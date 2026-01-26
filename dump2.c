#include <assert.h>
#include <stdbool.h>
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
        assert(l2>=2);
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
    return ret;
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
    STATUS_EMPTY = 0,
    STATUS_INITIALIZED = 2
};

enum TRI_STATE
{
    TRI_STATE_ZERO = 0,
    TRI_STATE_ONE = 1,
    TRI_STATE_TWO = 2
};

enum FOUR_STATE
{
    FOUR_STATE_ZERO = 0,
    FOUR_STATE_ONE = 1,
    // FOUR_STATE_TWO = 2,
    FOUR_STATE_THREE = 3
};

size_t make_str(char* out, const size_t out_len, const char* in, const size_t in_len)
{
    assert(out_len > 0);
    assert(in_len > 0);
    assert(out != NULL);
    assert(in != NULL);
    assert(out_len > in_len);
    memcpy(out, in, in_len);
    out[in_len] = '\0';
    assert(in_len >= 2);
    if (out[0] == 0)
    {
        if (out[1] == 0)
        {
            // ZERO
            assert(is_buffer_all_zero(out, in_len) == 1);
            return 0;
        }
        // PHI
        out[0] = 0x7F; // DEL
        out[0] = '?';
        out[0] = ' ';
        const size_t ret = strlen(out);
        assert(ret <= in_len);
        assert(is_buffer_all_zero(out + ret, in_len - ret) == 1);
        return ret;
    }
    // VALUE case
    const size_t ret = strlen(out);
    assert(ret <= in_len);
    if (is_buffer_all_zero(out + ret, in_len - ret) == 1)
        return ret;
    return -1;
}

#define MAKE_STR(out, in) \
make_str(out, sizeof(out), (in), sizeof(in))

struct config
{
    char zeros[0x84 /* 132 */ + 1];
    char options[0x102 /* 258 */ + 1];
    uint32_t status; /* O or 2 */
};

void print_config(FILE* stream, const char* name, struct config* m, const size_t len, const size_t offset)
{
    assert(sizeof(struct config) == len);
    const size_t alignment = offset % 4u;
    char options[512];
    MAKE_STR(options, m->options);
    char buffer[512 * 4];
    assert(len < sizeof(buffer));
    assert(is_buffer_all_zero(m->zeros, sizeof(m->zeros)) == 1);
    assert(m->status == STATUS_EMPTY || m->status == STATUS_INITIALIZED);
    if (m->status == 0)
        assert(STR_IS_ZERO(m->options) == 1);
    else
        assert(STR_IS_VALUE(m->options) == 1);
    sprintf(buffer, "%.*s:%s:%u", (int)sizeof(m->zeros), m->zeros,
            options,
            m->status);
    fprintf(stream, "%04zx %zu %s %zu: [%s]\n", offset, alignment, name, len, buffer);
}

struct endpoint /* 396 */
{
    char ip[0x40 /* 64 */];
    uint16_t port_numbers[2];
    char hostname[0x40 /* 64 */ + 1];
    char options[0x102 /* 258 */ + 1];
    uint32_t tri_state; /* 0, 1 or 2 */
};

struct endpoint_alt /* 404 */
{
    char ip[0x44 /* 68 */];
    char hostname[0x44 /* 68 */];
    char options[0x104 /* 260 */];
    uint32_t value32;
    uint32_t status; /* 0 or 2 */
    uint32_t tri_state; /* 0, 1 or 2 */
};

enum PORTS
{
    PORT_INDEX = 1
};

enum MAGIC
{
    MAGIC_VALUE0 = 0x41414141, // ASCII 'AAAA'
    MAGIC_VALUE1 = 0x1
};


void print_endpoint(FILE* stream, const char* name, struct endpoint* e, const size_t len, const size_t offset)
{
    assert(sizeof(struct endpoint) == len);
    const size_t alignment = offset % 4u;
    assert(alignment==0);
    char buffer[512 * 4];
    assert(len < sizeof(buffer));
    assert(e->port_numbers[0] == 0);
    char ip[512];
    char hostname[512];
    char options[512];
    size_t ret;
    MAKE_STR(ip, e->ip);
    bool trash = false;
    ret = MAKE_STR(hostname, e->hostname);
    if (ret == (size_t)-1)
    {
        trash = true;
    }
    MAKE_STR(options, e->options);
    sprintf(buffer, "%s:%d:%s:%s:%u [%s]", ip, e->port_numbers[PORT_INDEX],
            hostname,
            options,
            e->tri_state, trash ? " TRASH" : "");
    assert(e->tri_state == TRI_STATE_ONE || e->tri_state == TRI_STATE_TWO
        || e->tri_state == TRI_STATE_ZERO);
    fprintf(stream, "%04zx %zu %s %zu: [%s]\n", offset, alignment, name, len, buffer);
    if (e->tri_state == TRI_STATE_ZERO)
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
        //assert(STR_IS_VALUE(e->hostname) == 1 /*|| STR_IS_PHI(e->hostname) == 1*/);
        assert(STR_IS_VALUE(e->options) == 1
            || STR_IS_ZERO(e->options) == 1);
    }
}

int value32_valid(const uint32_t value32)
{
    if (value32 == 0x0
        || value32 == 0x1
        || value32 == 0x100
        || value32 == 0x200
        || value32 == 0x201
        || value32 == 0x300
        || value32 == 0x400
        || value32 == 0x500
        || value32 == 0x10000
        || value32 == 0x10001
        || value32 == 0x10100
        || value32 == 0x10200
        || value32 == 0x10300
        || value32 == 0x10400
        || value32 == 0x1000000
        || value32 == 0x1000001
        || value32 == 0x1010000
    )
        return 1;
    return 0;
}

void print_endpoint_alt(FILE* stream, const char* name, struct endpoint_alt* e, const size_t len, const size_t offset)
{
    assert(sizeof(struct endpoint_alt) == len);
    const size_t alignment = offset % 4u;
    assert(alignment==0);
    char buffer[512 * 4];
    assert(len < sizeof(buffer));
    char ip[512];
    char hostname[512];
    char options[512];
    MAKE_STR(ip, e->ip);
    MAKE_STR(hostname, e->hostname);
    MAKE_STR(options, e->options);
    sprintf(buffer, "%s:%s:%s:0x%08x:%u:%u", ip,
            hostname,
            options,
            e->value32,
            e->status,
            e->tri_state);
    assert(e->status == STATUS_EMPTY || e->status == STATUS_INITIALIZED);
    assert(e->tri_state == TRI_STATE_ZERO || e->tri_state == TRI_STATE_TWO || e->tri_state == TRI_STATE_ONE);
    fprintf(stream, "%04zx %zu %s %zu: [%s]\n", offset, alignment, name, len, buffer);
    assert(value32_valid(e->value32) == 1);
    if (e->status == STATUS_EMPTY)
    {
        assert(STR_IS_ZERO(e->ip) == 1);
        assert(STR_IS_ZERO(e->hostname) == 1|| STR_IS_PHI(e->hostname) == 1);
        assert(STR_IS_ZERO(e->options) == 1|| STR_IS_PHI(e->options) == 1);
    }
    else
    {
        assert(STR_IS_VALUE(e->ip) == 1 || STR_IS_PHI(e->ip) == 1 || STR_IS_ZERO(e->ip) == 1);
        //assert(e->port_number != 0);
        assert(STR_IS_VALUE(e->hostname) == 1 /*|| STR_IS_PHI(e->hostname) == 1*/);
        // assert(STR_IS_VALUE(e->options) == 1|| STR_IS_PHI(e->options) == 1 || STR_IS_ZERO(e->options) == 1);
        assert(STR_IS_VALUE(e->options) == 1);
    }
}

struct junk5 /* 88 */
{
    uint32_t zeros[17];
    uint32_t values[5]; // patient_id/study_id followed by series_number x 2 ?
};

void my_print6(FILE* stream, const char* name, struct junk5* j, const size_t len, const size_t offset)
{
    assert(sizeof(struct junk5) == len);
    const size_t alignment = offset % 4u;
    assert(alignment==0);
    char buffer[512 * 4];
    assert(len < sizeof(buffer));
    for (int i = 0; i < 17; ++i)
        assert(j->zeros[i] == 0);
    assert(j->values[2] == 1);
    assert(j->values[3] == 1);
    assert(j->values[1] == j->values[4]);
    sprintf(buffer, "%u,%u", j->values[0], j->values[1]);
    fprintf(stream, "%04zx %zu %s %zu: [%s]\n", offset, alignment, name, len, buffer);
}

typedef char string256[0x100 /*256*/ + 1];
typedef char string512[0x200 /*512*/ + 2];

struct str3_1 /* 1028 */
{
    string256 caltype;
    string256 cdc;
    string512 cc;
};

void my_print7(FILE* stream, const char* name, struct str3_1* s, const size_t len, const size_t offset)
{
    assert(sizeof(struct str3_1) == len);
    const size_t alignment = offset % 4u;
    assert(alignment==0);
    char buffer[512 * 4];
    assert(len < sizeof(buffer));
    assert(STR_IS_VALUE(s->caltype));
    assert(STR_IS_VALUE(s->cdc)|| STR_IS_ZERO(s->cdc));
    const size_t cc_len1 = strlen(s->cc);
    const char* cc2 = s->cc + cc_len1 + 1;
    const size_t cc_len2 = strlen(cc2);
    const int ret = is_buffer_all_zero(cc2, len - cc_len1 - 1);
    if (ret == 0)
    {
        // FIXME: this *really* looks like digital trash:
        //assert(is_value(cc2, sizeof(s->cc) - cc_len1 - 1) == 1);
    }
    else
    {
        assert(STR_IS_VALUE(s->cc)||STR_IS_ZERO(s->cc));
    }
    fprintf(stream, "%04zx %zu %s %zu: [\n\t%03zu: %s\n\t%03zu: %s\n\t%03zu: %s\n\t]\n", offset, alignment, name,
            len,
            strlen(s->caltype), s->caltype,
            strlen(s->cdc), s->cdc,
            strlen(s->cc), s->cc);
}

struct tmp
{
    uint16_t junk1;
    uint16_t junk2;
    //
    uint16_t value1;
    uint16_t value2;
    char uid[0X2C33 - 0X2BF2];
    char str1[0X2C44 - 0X2C33];
    char str2[510 - 86];
};

struct hardware
{
    uint16_t junk0;

    union
    {
        char hardware_id[0x2df0 - 0x2bea - 4];
        struct tmp tmp;
    };
};


void print_hardware(FILE* stream, const char* name, struct hardware* h, const size_t len, const size_t offset)
{
    assert(sizeof(struct hardware) == len);
    assert(h->junk0 == 0);
    uint32_t magic;
    memcpy(&magic, h->hardware_id, sizeof(magic));
    // '0x4d574d' 5068621
    if (magic == 0x4d574d) // ASCII 'MWM'
    {
        const size_t ll = sizeof(struct tmp);
        assert(ll == len - 2);
        const size_t alignment = offset % 4u;
        struct tmp* tmp = &h->tmp;
        assert(tmp->junk1 == 0x574D);
        assert(tmp->junk2 == 0x4D);
        assert(STR_IS_VALUE(tmp->uid));
        assert(STR_IS_VALUE(tmp->str1)||STR_IS_ZERO(tmp->str1));
        assert(STR_IS_VALUE(tmp->str2)||STR_IS_ZERO(tmp->str2));
        assert(tmp->value2==0|| tmp->value2==1);
        fprintf(stream, "%04zx %zu %s %zu: [%u,%u: %s:%s:%s]\n", offset, alignment, name, len, tmp->value1,
                tmp->value2, tmp->uid, tmp->str1, tmp->str2);
    }
    else
    {
        const char* str = h->hardware_id;
        my_print(stream, name, str, len - 2, offset);
    }
}

struct service_name
{
    char service_name[0x35B8 - 0x3570 - 4];
    uint32_t status; /* 0 or 2 */
    uint32_t four_state; /* 0, 1 or 3 */
};

void print_service_name(FILE* stream, const char* name, struct service_name* j, const size_t len, const size_t offset)
{
    assert(sizeof(struct service_name) == len);
    const size_t alignment = offset % 4u;
    if (j->four_state != 0)
        assert(STR_IS_VALUE(j->service_name) == 1);
    if (j->four_state == 0)
        assert(STR_IS_ZERO(j->service_name) == 1);
    assert(j->status == STATUS_EMPTY || j->status == STATUS_INITIALIZED);
    assert(j->four_state == FOUR_STATE_ZERO || j->four_state == FOUR_STATE_ONE || j->four_state == FOUR_STATE_THREE);
    fprintf(stream, "%04zx %zu %s %zu: [%s:%u:%u]\n", offset, alignment, name, len, j->service_name, j->status,
            j->four_state);
}

struct junk11
{
    uint32_t u32;
    uint32_t hexs[2];
    uint32_t zeros1;
    uint32_t tri_states[2]; /* 0, 1 or 2 */
    uint32_t u[2];
    uint32_t small_value1; // four states with only 0 & 3 ?
    uint32_t v;
    uint32_t zeros2;
    uint32_t w;
};

void print_junk11(FILE* stream, const char* name, struct junk11* j, const size_t len, const size_t offset)
{
    assert(sizeof(struct junk11) == len);
    const size_t alignment = offset % 4u;
    fprintf(stream, "%04zx %zu %s %zu: [%08u:%x:%x:%u:%u:%x:%x:%u:%u]\n", offset, alignment, name, len, j->u32,
            j->hexs[0], j->hexs[1],
            j->tri_states[0], j->tri_states[1],
            j->u[0], j->u[1],
            j->v, j->w
    );
    assert(j->u[0] == 0x0
        || j->u[0] == 0x32
        || j->u[0] == 0x52
        || j->u[0] == 0x63
        || j->u[0] == 0x280000
        || j->u[0] == 0x3f0000
        || j->u[0] == 0x440000
        || j->u[0] == 0x4e0000
        || j->u[0] == 0x520000
    );
    assert(j->v == 0x0
        || j->v == 0x3c /* 60 */
    );
    assert(j->w == 0x0
        || j->w == 0x3c /* 60 */
    );
    assert(j->u[1] == 0x0
        || j->u[1] == 0x1
        || j->u[1] == 0x100
        || j->u[1] == 0x101
        || j->u[1] == 0x10000
        || j->u[1] == 0x10001
        || j->u[1] == 0x10101
        || j->u[1] == 0x20100
        || j->u[1] == 0x30101
        || j->u[1] == 0x40101
        || j->u[1] == 0x50000
        || j->u[1] == 0x50101
        || j->u[1] == 0x60000
        || j->u[1] == 0x60001
        || j->u[1] == 0x60100
        || j->u[1] == 0x60101
        || j->u[1] == 0x70000
        || j->u[1] == 0x70001
        || j->u[1] == 0x70100
        || j->u[1] == 0x70101
        || j->u[1] == 0x130001
        || j->u[1] == 0xffff0000
        || j->u[1] == 0xffff0001
        || j->u[1] == 0xffff0100
        || j->u[1] == 0xffff0101
    );
    assert(j->zeros1 == 0);
    assert(j->small_value1 == 0 || j->small_value1 == 3);
    assert(j->zeros2 == 0);
    for (int i = 0; i < 2; ++i)
    {
        assert(j->tri_states[i] == TRI_STATE_ZERO
            || j->tri_states[i] == TRI_STATE_ONE
            || j->tri_states[i] == TRI_STATE_TWO);
    }
#if 0
    assert(j->hexs[0] == 0 || j->hexs[0] == 0x8000
        || j->hexs[0] == 0x4910fe
        || j->hexs[0] == 0x4a10fe
        || j->hexs[0] == 0x4b10fe
        || j->hexs[0] == 0x4c10fe
        || j->hexs[0] == 0x4d10fe
        || j->hexs[0] == 0x7410fc
        || j->hexs[0] == 0x7e10fc
        || j->hexs[0] == 0x8810fc
        || j->hexs[0] == 0x3708000
        || j->hexs[0] == 0x3c88000
    );
#endif
    assert(j->hexs[1] == 0
        || j->hexs[1] == 0x8000
        || j->hexs[1] == 0x8026
        || j->hexs[1] == 0x8032
        || j->hexs[1] == 0x8039
        || j->hexs[1] == 0x8067
        || j->hexs[1] == 0x40008000
        || j->hexs[1] == 0x40058000
        || j->hexs[1] == 0x40078000
        || j->hexs[1] == 0x4e008000
        || j->hexs[1] == 0x4e018000
        || j->hexs[1] == 0x4e028000
        || j->hexs[1] == 0x4e048000
        || j->hexs[1] == 0x4e068000
        || j->hexs[1] == 0x4e078000
        || j->hexs[1] == 0x50000000
        || j->hexs[1] == 0x50008000
        || j->hexs[1] == 0x50018000
        || j->hexs[1] == 0x50078000
        || j->hexs[1] == 0x60008000
        || j->hexs[1] == 0xffff8000
        || j->hexs[1] == 0xffff0000
    );
    // FIXME j->u[1] / j->hexs[1] seem correlated
}

struct junk13
{
    union
    {
        uint32_t hex;
        uint8_t hexs[4];
    };

    uint32_t v1;
    float f1;
    uint32_t v2;
    float f2;
    uint32_t v3;
    float f3;
};

void print_junk13(FILE* stream, const char* name, const struct junk13* j, const size_t len, const size_t offset)
{
    assert(sizeof(struct junk13) == len);
    const size_t alignment = offset % 4u;
    for (int i = 0; i < 4; ++i)
    {
        assert(j->hexs[i] == 0x0 || j->hexs[i] == 0x1);
    }
    fprintf(stream, "%04zx %zu %s %zu: [%08x:%u:%g:%u:%g:%u:%g]\n", offset, alignment, name, len, j->hex,
            j->v1, j->f1,
            j->v2, j->f2,
            j->v3, j->f3);
}

struct info
{
    uint32_t magic[2];
    struct config config1;
    struct config config2;
    struct endpoint endpoint1;
    struct endpoint endpoint2;
    struct junk5 junk5;
    struct str3_1 str3_1;
    char am[0x0c96 - 0x0a94];
    // 'Swiss721 BT' is an actual font name:
    char font1[0x0d97 - 0x0c96];
    char font2[0x0e98 - 0x0d97];
    char font3[0x0f99 - 0x0e98];
    char font4[0x109a - 0x0f99];
    char font5[0x119b - 0x109a];
    char font6[0x129c - 0x119b];
    char format1[0x169d - 0x129c];
    char format2[0x1a9e - 0x169d];
    char format3[0x1e9f - 0x1a9e];
    char format4[0x22a0 - 0x1e9f];
    char format5[0x26A1 - 0x22a0];
    char format6[0x2aaa - 0x26A1 - 8];
    // not aligned:
    uint16_t junk6[1];
    char fixme1[0x2B68 - 0x2aa4];
    char str1[0x2BA9 - 0x2b68];
    char str2[0x2BE8 - 0x2bA9];
    struct hardware hardware;
    uint32_t small_number[1];
    char study_desc[0x2ff0 - 0x2df0];
    uint32_t junk7[1];
    char versions[0x3034 - 0x2ff4];
    uint32_t junk8[9];
    /* start endpoint */
    struct endpoint_alt endpoint_alt1;
    /* end endpoint */
    uint32_t junk9[7];
    /* start endpoint */
    struct endpoint_alt endpoint_alt2;
    /* end endpoint */
    uint32_t junk10[11];
    char datetime1[68];
    char datetime2[136 - 68];
    char service_name1[0x34A4 - 0x3458];
    char aetitle1[0x34E8 - 0x34A4];
    char aetitle2[0x352C - 0x34E8];
    char aetitle3[0x3570 - 0x352C];
    struct service_name service_name2;
    struct junk11 junk11;
    char orientation1[0x3630 - 0x35EC];
    char orientation2[0x3674 - 0x3630];
    uint32_t junk12[2];
    char study_id[60 + 4 * 2];
    char dicom_ds1[0x38C4 - 0x36C0];
    char dicom_ds2[0x3AC0 - 0X38C4 + 8];
    struct junk13 junk13;
    char gender[0x3B2C - 0x3AE4];
    char padding[0x3B70 - 0x3B2C];
    char weight1[0x3CC4 - 0x3B70];
    char mode1[0x3DC8 - 0x3CC4];
    char mode2[0x3ECC - 0x3DC8];
    char mode3[0x3FD0 - 0x3ECC];
    char mode4[0x40D4 - 0x3FD0];
    char mode5[0x41D8 - 0x40D4];
    char mode6[0x42DC - 0x41D8];
    char left_right[0x43E0 - 0x42DC];
    char site_name1[0x44E4 - 0x43E0];
    char site_name2[0x45E8 - 0x44E4];
    char anon1[0x46EC - 0x45E8];
    char anon2[0x47F0 - 0x46EC];
    char anon3[0x48F4 - 0x47F0];
    char series_name[0x493A - 0x48F4 + 2];
};


#define MY_PRINT(stream, struct_ptr, member) \
    my_print((stream), #member, (struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))

#define MY_PRINT2(stream, struct_ptr, member) \
    my_print2((stream), #member, (struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))

#define MY_PRINT3(stream, struct_ptr, member) \
  my_print3((stream), #member, (struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))

#define PRINT_ENDPOINT(stream, struct_ptr, member) \
  print_endpoint((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))

#define PRINT_CONFIG(stream, struct_ptr, member) \
  print_config((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))

#define MY_PRINT6(stream, struct_ptr, member) \
  my_print6((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))

#define MY_PRINT7(stream, struct_ptr, member) \
my_print7((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))
#define PRINT_ENDPOINT_ALT(stream, struct_ptr, member) \
print_endpoint_alt((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))
#define PRINT_HARDWARE(stream, struct_ptr, member) \
print_hardware((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))
#define PRINT_SERVICE_NAME(stream, struct_ptr, member) \
print_service_name((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))
#define PRINT_JUNK11(stream, struct_ptr, member) \
print_junk11((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))
#define PRINT_JUNK13(stream, struct_ptr, member) \
print_junk13((stream), #member, &(struct_ptr)->member, sizeof((struct_ptr)->member), offsetof(struct info,member))

static void process_canon(FILE* stream, const char* data, const size_t size, const char* fn)
{
    const size_t SIZE0 = 15076;
    const size_t off0 = offsetof(struct info, gender);
    assert(off0==SIZE0);
    const size_t SIZE1 = 15148;
    const size_t off1 = offsetof(struct info, padding);
    assert(off1==SIZE1);
    const size_t SIZE2 = 18748; // 4687 * 4
    const size_t s2 = sizeof(struct info);
    assert(s2==SIZE2);
    assert(size == SIZE0
        || size == SIZE1
        || size == SIZE2);
    struct info* pinfo = malloc(sizeof(struct info));
    if (!pinfo)
    {
        perror("Failed to allocate struct info");
        return;
    }
    memcpy(pinfo, data, size);

    assert(pinfo->magic[0] == MAGIC_VALUE0);
    assert(pinfo->magic[1] == MAGIC_VALUE1);
    PRINT_CONFIG(stream, pinfo, config1);
    PRINT_CONFIG(stream, pinfo, config2);
    PRINT_ENDPOINT(stream, pinfo, endpoint1);
    PRINT_ENDPOINT(stream, pinfo, endpoint2);
    MY_PRINT6(stream, pinfo, junk5);
    MY_PRINT7(stream, pinfo, str3_1);
    MY_PRINT(stream, pinfo, am);
    MY_PRINT(stream, pinfo, font1);
    MY_PRINT(stream, pinfo, font2);
    MY_PRINT(stream, pinfo, font3);
    MY_PRINT(stream, pinfo, font4);
    MY_PRINT(stream, pinfo, font5);
    MY_PRINT(stream, pinfo, font6);
    MY_PRINT(stream, pinfo, format1);
    MY_PRINT(stream, pinfo, format2);
    MY_PRINT(stream, pinfo, format3);
    MY_PRINT(stream, pinfo, format4);
    MY_PRINT(stream, pinfo, format5);
    MY_PRINT(stream, pinfo, format6);
    assert(pinfo-> junk6 [0]== 0);
    //MY_PRINT2(stream, pinfo, junk6);
    MY_PRINT(stream, pinfo, fixme1);
    MY_PRINT(stream, pinfo, str1);
    MY_PRINT(stream, pinfo, str2);
    PRINT_HARDWARE(stream, pinfo, hardware);
    MY_PRINT2(stream, pinfo, small_number);
    assert(pinfo->small_number[0]!=0);
    MY_PRINT(stream, pinfo, study_desc);
    MY_PRINT2(stream, pinfo, junk7);
    MY_PRINT(stream, pinfo, versions);
    MY_PRINT2(stream, pinfo, junk8);
    PRINT_ENDPOINT_ALT(stream, pinfo, endpoint_alt1);
    MY_PRINT2(stream, pinfo, junk9);
    PRINT_ENDPOINT_ALT(stream, pinfo, endpoint_alt2);
    MY_PRINT2(stream, pinfo, junk10);
    MY_PRINT(stream, pinfo, datetime1);
    MY_PRINT(stream, pinfo, datetime2);
    MY_PRINT(stream, pinfo, service_name1);
    MY_PRINT(stream, pinfo, aetitle1);
    MY_PRINT(stream, pinfo, aetitle2);
    MY_PRINT(stream, pinfo, aetitle3);
    PRINT_SERVICE_NAME(stream, pinfo, service_name2);
    PRINT_JUNK11(stream, pinfo, junk11);
    MY_PRINT(stream, pinfo, orientation1);
    MY_PRINT(stream, pinfo, orientation2);
    MY_PRINT2(stream, pinfo, junk12);
    MY_PRINT(stream, pinfo, study_id);
    MY_PRINT(stream, pinfo, dicom_ds1);
    MY_PRINT(stream, pinfo, dicom_ds2);
    //MY_PRINT2(stream, pinfo, junk13);
    PRINT_JUNK13(stream, pinfo, junk13);
    if (size >= SIZE1)
        MY_PRINT(stream, pinfo, gender);
    if (size >= SIZE2)
    {
        MY_PRINT(stream, pinfo, padding);
        MY_PRINT(stream, pinfo, weight1);
        MY_PRINT(stream, pinfo, mode1);
        MY_PRINT(stream, pinfo, mode2);
        MY_PRINT(stream, pinfo, mode3);
        MY_PRINT(stream, pinfo, mode4);
        MY_PRINT(stream, pinfo, mode5);
        MY_PRINT(stream, pinfo, mode6);
        MY_PRINT(stream, pinfo, left_right);
        MY_PRINT(stream, pinfo, site_name1);
        MY_PRINT(stream, pinfo, site_name2);
        MY_PRINT(stream, pinfo, anon1);
        MY_PRINT(stream, pinfo, anon2);
        MY_PRINT(stream, pinfo, anon3);
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
    process_canon(stdout, buffer, filesize, filename);

    free(buffer);
    (void)fclose(file);
    return 0;
}
