//
// library for Lab 1
// Allows to determine whether the passed byte is the most frequent in the file
//
// gcc -shared -fPIC -o lib1mabN3248.so lib1mabN3248.c -ldl
//
//  (c) Mikhail Bakhov, 2021

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "plugin_api.h"

static char *g_plugin_name = "libmabN3248.so";
static char *g_plugin_purpose = "Search for files in which the specified byte is the most frequent.";
static char *g_plugin_author = "Bakhov Mikhail";

#define LAB1DEBUG_ENV_STR "LAB1DEBUG"
#define OPT_FREQ_BYTE_STR "two-freq-byte"

#define HEX_FORMAT_BYTE_MAX_LENGTH 4
#define BIN_FORMAT_BYTE_MAX_LENGTH 10

static struct plugin_option g_plugin_options_arr[] =
    {
        {
            .opt.name = OPT_FREQ_BYTE_STR,
            .opt.has_arg = required_argument,
            .opt.flag = 0,
            .opt.val = 0,
            .opt_descr = "Target byte",
        }};

static size_t g_plugin_options_arr_len = sizeof(g_plugin_options_arr) / sizeof(g_plugin_options_arr[0]);

static int is_byte_most_frequent(unsigned char *p, unsigned char byte);

int plugin_get_info(struct plugin_info *ppi)
{
    if (!ppi)
    {
        fprintf(stderr, "[ERROR] Invalid argument\n");
        return -1;
    }

    ppi->plugin_author = g_plugin_author;
    ppi->plugin_purpose = g_plugin_purpose;
    ppi->sup_opts_len = g_plugin_options_arr_len;
    ppi->sup_opts = g_plugin_options_arr;

    return 0;
}

/*
    Returns:
       1    - passed byte is the most frequent
       0    - otherwise
       -1   - error (errno is set)
*/
int plugin_process_file(const char *fname, struct option in_opts[], size_t in_opts_len)
{
    char *DEBUG = getenv(LAB1DEBUG_ENV_STR);

    int ret = -1;
    unsigned char *map_ptr = NULL;

    if (!(fname && in_opts && in_opts_len))
    {
        errno = EINVAL;
        return ret;
    }

    int errno_saved = 0;
    int fd = open(fname, O_RDONLY);

    if (fd < 0)
    {
        if (DEBUG)
            fprintf(stderr, "[DEBUG]\t[ERROR]\t[%s]\tCan't open file %s\n", g_plugin_name, fname);
        return ret;
    }

    struct stat st;
    if (fstat(fd, &st) < 0)
    {
        errno_saved = errno;
        goto END;
    }
    if (!st.st_size)
    {
        if (DEBUG)
            fprintf(stderr, "[DEBUG]\t[ERROR]\t[%s]\tFile size should be > 0: %s\n", g_plugin_name, fname);
        errno_saved = ERANGE;
        goto END;
    }

    map_ptr = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_ptr == MAP_FAILED)
    {

        errno_saved = errno;
        goto END;
    }

    /**
     * Pass all incoming options flags(optargs) into g_plugin_options_arr flags
     */
    for (size_t i = 0; i < in_opts_len; ++i)
    {
        for (size_t j = 0; j < g_plugin_options_arr_len; ++j)
        {
            if (!strcmp(in_opts[i].name, g_plugin_options_arr[j].opt.name))
            {
                g_plugin_options_arr[j].opt.flag = in_opts[i].flag;
            }
        }
    }
    char *byte_to_check = NULL;
    for (size_t i = 0; i < g_plugin_options_arr_len; ++i)
    {
        if (!strcmp(g_plugin_options_arr[i].opt.name, OPT_FREQ_BYTE_STR))
            byte_to_check = (char *)g_plugin_options_arr[i].opt.flag;
    }

    char *endptr;
    char byte = strtol(byte_to_check, &endptr, 10);
    if (!byte && byte_to_check[0] == '0' && byte_to_check[1] == 'x' && strlen(byte_to_check) <= HEX_FORMAT_BYTE_MAX_LENGTH)
        byte = strtol(byte_to_check, &endptr, 16);
    else if (!byte && byte_to_check[0] == '0' && byte_to_check[1] == 'b' && strlen(byte_to_check) <= BIN_FORMAT_BYTE_MAX_LENGTH)
        byte = strtol(++endptr, &endptr, 2);
    if (byte && !strlen(endptr))
        ret = is_byte_most_frequent(map_ptr, byte);
    else
    {
        if (DEBUG)
            fprintf(stderr, "[DEBUG]\t[ERROR]\t[%s]\tInvalid argument '%s' for option '%s'!\n", g_plugin_name, byte_to_check, OPT_FREQ_BYTE_STR);
        errno_saved = EINVAL;
        ret = -1;
        goto END;
    }

    if (DEBUG)
        switch (ret)
        {
        case 0:
            fprintf(stderr, "[DEBUG]\t[INFO]\t[%s]\tByte 0x%hhx IS NOT the most frequent in %s.\n", g_plugin_name, byte, fname);
            break;
        case 1:
            fprintf(stderr, "[DEBUG]\t[INFO]\t[%s]\tByte 0x%hhx IS the most frequent in %s.\n", g_plugin_name, byte, fname);
            break;
        default:
            break;
        }
END:
    if (fd)
        close(fd);
    if (map_ptr != MAP_FAILED && map_ptr != NULL)
        munmap(map_ptr, st.st_size);

    errno = errno_saved;
    return ret;
}

/*
    Returns:
       1 - passed byte is the most frequent
       0 - otherwise
*/
int is_byte_most_frequent(unsigned char *p, unsigned char byte)
{
    int *byteRating = (int *)calloc(UCHAR_MAX + 1, UCHAR_MAX * sizeof(int));

    while (*p)
    {
        byteRating[*p++]++;
    }

    int max = 0;
    char is_exclusive = 1;
    unsigned char frequent_byte = 0;
    for (size_t i = 0; i < UCHAR_MAX; i++)
    {
        if (byteRating[i] == max)
        {
            is_exclusive = 0;
            continue;
        }
        if (byteRating[i] > max)
        {
            max = byteRating[i];
            frequent_byte = i;
            is_exclusive = 1;
        }
    }

    free(byteRating);
    return is_exclusive && frequent_byte == byte;
}