#define _GNU_SOURCE
#define _XOPEN_SOURCE 500

#include <dlfcn.h>
#include <errno.h>
#include <ftw.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

#include "plugin_api.h"
#define PLUGIN_GET_INFO_STR "plugin_get_info"
#define PLUGIN_PROCESS_FILE_STR "plugin_process_file"

#define LAB1DEBUG_ENV_STR "LAB1DEBUG"
static char *DEBUG = NULL;

#define CURRENT_DIR_PATH "."

#define NFTW_MAX_DIRS_OPENED 20
#define NFTW_FLAGS 0

#define SUPPORTED_SHORT_OPRIONS "-P:AONvh"
static char SHORT_OPTS_BITMASK = 0;
#define P_OPTION_FLAG 1 << 0
#define A_OPTION_FLAG 1 << 1
#define O_OPTION_FLAG 1 << 2
#define N_OPTION_FLAG 1 << 3
#define v_OPTION_FLAG 1 << 4
#define h_OPTION_FLAG 1 << 5
static enum {
    EA_A_AND_B_AND,
    EA_A_OR_B_OR,
    EA_NA_AND_NB_AND_N,
    EA_NA_OR_NB_OR_N
} g_algebra;

typedef int (*plugin_get_info_handle)(struct plugin_info *);
typedef int (*plugin_process_file_handle)(const char *, struct option[], size_t);

typedef struct
{
    plugin_get_info_handle get_info;
    plugin_process_file_handle process_file;
    struct option *process_file_opts;
    size_t process_file_opts_len;
} PluginAPI;

typedef struct
{
    char *name;
    char *fpath;
    char is_required;
    PluginAPI *plugin_api;
} SupportedPlugin;

static SupportedPlugin *g_supported_plugins = NULL;
static size_t g_supported_plugins_amount = 0;

static void **g_dl_handles = NULL;
static size_t g_dl_handles_amount = 0;

static int is_plugin_name(const char *fpath, int base);
static int obtain_plugin(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);
/*
    Updates g_supported_plugins variable

    Returns:
       Number of plugins obtained
*/
static int obtain_plugin_apis(const char *dirpath);
/*
    Uses g_supported_plugins to process a file
*/

static int are_new_options_intersected();

static int process_file(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);

static void print_usage();
static void print_info();

static void set_algebra(const char short_opts_bitmask);

int main(int argc, char *argv[])
{
    if (argc == 1)
    {
        print_usage();
        return 0;
    }

    DEBUG = getenv(LAB1DEBUG_ENV_STR);

    char *supported_short_opts = NULL;
    struct option *supported_long_opts = NULL;
    size_t supported_long_opts_amount = 0;
    struct plugin_info *plugins_info = NULL;
    /**
     * Parse all options without check of unexpected options.
     * There are may be options that are supported within plugins which are not linked yet.
     */
    opterr = 0;
    int option_value = 0;
    char *plugin_dirpath = strdup(CURRENT_DIR_PATH);
    supported_short_opts = strdup(SUPPORTED_SHORT_OPRIONS);
    while (1)
    {
        if ((option_value = getopt_long_only(argc, argv, supported_short_opts, NULL, NULL)) == -1)
            break;
        switch (option_value)
        {
        case 'P':
            SHORT_OPTS_BITMASK |= P_OPTION_FLAG;
            if (DEBUG)
            {
                fprintf(stderr, "[DEBUG]\t[INFO]\t[%s]\t\tGot option P", program_invocation_short_name);
                if (optarg)
                    fprintf(stderr, " with arg %s\n", optarg);
                else
                    fprintf(stderr, "\n");
            }
            free(plugin_dirpath);
            plugin_dirpath = strdup(optarg);
            break;

        case 'A':
            SHORT_OPTS_BITMASK |= A_OPTION_FLAG;
            break;

        case 'O':
            SHORT_OPTS_BITMASK |= O_OPTION_FLAG;
            break;

        case 'N':
            SHORT_OPTS_BITMASK |= N_OPTION_FLAG;
            break;

        case 'v':
            SHORT_OPTS_BITMASK |= v_OPTION_FLAG;
            break;

        case 'h':
            SHORT_OPTS_BITMASK |= h_OPTION_FLAG;
            break;
        case '?':
        default:
            break;
        }
    }
    if (DEBUG)
        fprintf(stderr, "[DEBUG]\t[INFO]\t[%s]\t\tDirectory to search plugins in: %s\n",
                program_invocation_short_name, plugin_dirpath);
    opterr = 1;
    if (SHORT_OPTS_BITMASK & h_OPTION_FLAG)
    {
        print_usage();
        goto END;
    }
    if (SHORT_OPTS_BITMASK & v_OPTION_FLAG)
    {
        print_info();
        goto END;
    }
    set_algebra(SHORT_OPTS_BITMASK);
    /**
     * Obtain all available plugins from plugin_dirpath (default: ".")
     */
    if (obtain_plugin_apis(plugin_dirpath) == -1)
        goto END;

    if (are_new_options_intersected())
    {
        fprintf(stderr, "%s: There are intersections of options among obtained plugins. Try to use '%s' env to examine\n\n",
                program_invocation_short_name, LAB1DEBUG_ENV_STR);
        goto END;
    };
    /**
     * Prepare supported long options array for further parsing
     */
    plugins_info = (struct plugin_info *)calloc(g_supported_plugins_amount, sizeof(struct plugin_info));

    for (size_t i = 0; i < g_supported_plugins_amount; ++i)
    {

        g_supported_plugins[i].plugin_api->get_info(&plugins_info[i]);
        supported_long_opts_amount += plugins_info[i].sup_opts_len;
    }
    supported_long_opts = (struct option *)calloc(supported_long_opts_amount + 1, sizeof(struct option)); // +1 for "zero option"
    char previous_plugins_opts_amount = 0;
    for (size_t i = 0; i < g_supported_plugins_amount; ++i)
    {
        for (size_t j = 0; j < plugins_info[i].sup_opts_len; ++j)
        {
            supported_long_opts[previous_plugins_opts_amount + j] = plugins_info[i].sup_opts[j].opt;
        }
        previous_plugins_opts_amount += plugins_info[i].sup_opts_len;
    }
    supported_long_opts[supported_long_opts_amount] = (struct option){0, 0, 0, 0}; // "zero option"

    /**
     * Parse all options with check of unexpected options (from now all possible options are known)
     */
    optind = 0; // REINITIALIZE OF GETOPT
    supported_short_opts[0] = '+';
    while (1)
    {
        int long_option_index = 0;
        if ((option_value = getopt_long_only(argc, argv, supported_short_opts, supported_long_opts, &long_option_index)) == -1)
            break;

        switch (option_value)
        {
        case 0:
            if (DEBUG)
            {
                fprintf(stderr, "[DEBUG]\t[INFO]\t[%s]\t\tGot option %s",
                        program_invocation_short_name, supported_long_opts[long_option_index].name);
                if (optarg)
                    fprintf(stderr, " with arg %s\n", optarg);
                else
                    fprintf(stderr, "\n");
            }
            for (size_t i = 0; i < g_supported_plugins_amount; ++i)
            {
                struct plugin_info pi;
                g_supported_plugins[i].plugin_api->get_info(&pi);
                for (size_t j = 0; j < pi.sup_opts_len; ++j)
                {
                    if (!strcmp(pi.sup_opts[j].opt.name, supported_long_opts[long_option_index].name))
                    {
                        if (supported_long_opts[long_option_index].flag)
                        {
                            fprintf(stderr, "[DEBUG]\t[CRIT]\t[%s]\t\tMore than one argument was provided for option '%s'\n",
                                    program_invocation_short_name, supported_long_opts[long_option_index].name);
                            goto END;
                        }
                        /* Dynamically fill options array for each required plugin with every its supported option */
                        g_supported_plugins[i].is_required = 1;
                        g_supported_plugins[i].plugin_api->process_file_opts_len++;
                        supported_long_opts[long_option_index].flag = (int *)strdup(optarg);
                        struct option *options = (struct option *)realloc(
                            g_supported_plugins[i].plugin_api->process_file_opts,
                            g_supported_plugins[i].plugin_api->process_file_opts_len * sizeof(struct option));
                        if (options)
                        {
                            g_supported_plugins[i].plugin_api->process_file_opts = options; // Point to a new memory
                            g_supported_plugins[i].plugin_api->process_file_opts
                                [g_supported_plugins[i].plugin_api->process_file_opts_len - 1] =
                                supported_long_opts[long_option_index];
                        }
                        else
                        {
                            fprintf(stderr, "Memory allocation error!\n");
                            goto END;
                        }
                    }
                }
            }
            break;
        case '?':
            fprintf(stderr, "\t\tTry '%s -h' for more information\n", program_invocation_short_name);
            goto END;
        default:
            if (DEBUG && option_value != 'P')
            {
                fprintf(stderr, "[DEBUG]\t[INFO]\t[%s]\t\tGot option %c", program_invocation_short_name, option_value);
                if (optarg)
                    fprintf(stderr, " with argument %s\n", optarg);
                else
                    fprintf(stderr, "\n");
            }
            break;
        }
    }

    /**
     * Start processing files
     */
    if (optind < argc - 1)
    {
        fprintf(stderr, "%s: More arguments were passed than needed, or they were passed in the wrong order\n",
                program_invocation_short_name);
        fprintf(stderr, "\t\tTry '%s -h' for more information\n", program_invocation_short_name);
        goto END;
    }
    char *search_directory = (optind == argc ? CURRENT_DIR_PATH : argv[optind]);
    if (DEBUG)
        fprintf(stderr, "[DEBUG]\t[INFO]\t[%s]\t\tDirectory to search files in %s\n", program_invocation_short_name, search_directory);
    if (nftw(search_directory, process_file, NFTW_MAX_DIRS_OPENED, NFTW_FLAGS) == -1)
    {
        if (errno == ENOENT)
            fprintf(stderr, "%s: No such directory '%s' to search files in\n", program_invocation_short_name, search_directory);

        else if (errno == EINVAL)
            fprintf(stderr, "%s: Invalid option for one of plugins provided. Try to use '%s' env to examine\n",
                    program_invocation_short_name,
                    LAB1DEBUG_ENV_STR);
        else
            perror("nftw");
    }

END:
    free(plugin_dirpath);
    free(plugins_info);
    for (size_t i = 0; i < g_dl_handles_amount; ++i)
        if (g_dl_handles[i])
            dlclose(g_dl_handles[i]);
    free(g_dl_handles);
    for (size_t i = 0; i < g_supported_plugins_amount; ++i)
    {
        if (g_supported_plugins[i].plugin_api)
            free(g_supported_plugins[i].plugin_api->process_file_opts);
        free(g_supported_plugins[i].plugin_api);
        free(g_supported_plugins[i].name);
        free(g_supported_plugins[i].fpath);
    }
    free(g_supported_plugins);
    free(supported_short_opts);
    for (size_t i = 0; i < supported_long_opts_amount; ++i)
        free(supported_long_opts[i].flag);
    free(supported_long_opts);
    return 0;
}

int is_plugin_name(const char *fpath, int base)
{
    const char *fname = fpath + base;
    for (size_t i = 0; i < g_supported_plugins_amount; ++i)
    {
        if (!strcmp(fname, g_supported_plugins[i].name))
        {
            if (DEBUG)
                fprintf(stderr, "[DEBUG]\t[ERROR]\t[%s]\t\tThere is a duplicated plugin of %s .  %s : %s\n",
                        program_invocation_short_name, g_supported_plugins[i].name,
                        g_supported_plugins[i].fpath, fpath);
            return 0;
        }
    }
    char *substring = NULL;
    if (strstr(fname, "lib") && (substring = strstr(fname, ".so")) &&
        strlen(fname) > strlen(substring) &&
        (strlen(substring) > 3 ? (substring[3] == '.') : 1))
    {
        return 1;
    }
    return 0;
}

int obtain_plugin(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if (typeflag != FTW_F || !is_plugin_name(fpath, ftwbuf->base))
        return 0;
    g_supported_plugins_amount++;

    SupportedPlugin *new_mem = (SupportedPlugin *)realloc(g_supported_plugins, g_supported_plugins_amount * sizeof(SupportedPlugin));
    new_mem[g_supported_plugins_amount - 1].is_required = 0;
    new_mem[g_supported_plugins_amount - 1].fpath = NULL;
    new_mem[g_supported_plugins_amount - 1].name = NULL;
    new_mem[g_supported_plugins_amount - 1].plugin_api = NULL;

    if (new_mem)
        g_supported_plugins = new_mem;
    else
    {
        fprintf(stderr, "Memory allocation error!\n");
        return -1;
    }
    g_supported_plugins[g_supported_plugins_amount - 1].name = strdup(fpath + ftwbuf->base);
    g_supported_plugins[g_supported_plugins_amount - 1].fpath = strdup(fpath);
    if (DEBUG)
    {
        fprintf(stderr, "[DEBUG]\t[INFO]\t[%s]\t\tObtained plugin: %s(%ld)\n", // For sake of usage (-Werror)
                program_invocation_short_name, g_supported_plugins[g_supported_plugins_amount - 1].name, sb->st_size);
    }

    return 0;
}

int obtain_plugin_apis(const char *dirpath)
{
    if (nftw(dirpath, obtain_plugin, NFTW_MAX_DIRS_OPENED, NFTW_FLAGS) == -1)
    {
        if (errno == ENOENT)
            fprintf(stderr, "%s: No such directory '%s' to search plugins in!\n", program_invocation_short_name, dirpath);
        else if (errno = ENOMEM)
            fprintf(stderr, "%s: Out of memory...\n", program_invocation_short_name);
        else
            perror("nftw");
        return -1;
    }

    g_dl_handles = (void **)calloc(g_supported_plugins_amount, sizeof(void *));

    if (DEBUG && g_supported_plugins_amount)
        fprintf(stderr, "[DEBUG]\t[INFO]\t[%s]\t\tAdditional available options:\n", program_invocation_short_name);
    for (size_t i = 0; i < g_supported_plugins_amount; ++i)
    {
        g_supported_plugins[i].plugin_api = (PluginAPI *)calloc(g_supported_plugins_amount, sizeof(PluginAPI));

        /**
         * Obtain API
         */

        if (!(g_dl_handles[g_dl_handles_amount] = dlopen(g_supported_plugins[i].fpath, RTLD_LAZY)))
        {
            fprintf(stderr, "%s: Can't open obtained plugin: %s\n",
                    program_invocation_short_name, dlerror());
            return -1;
        }

        if (!(g_supported_plugins[i].plugin_api->get_info =
                  (plugin_get_info_handle)dlsym(g_dl_handles[g_dl_handles_amount], PLUGIN_GET_INFO_STR)) ||
            !(g_supported_plugins[i].plugin_api->process_file =
                  (plugin_process_file_handle)dlsym(g_dl_handles[g_dl_handles_amount], PLUGIN_PROCESS_FILE_STR)))
        {
            fprintf(stderr, "%s: Not a valid plugin has been found '%s': %s\n",
                    program_invocation_short_name, g_supported_plugins[i].name, dlerror());
            return -1;
        }
        if (DEBUG)
        {
            struct plugin_info pi;
            g_supported_plugins[i].plugin_api->get_info(&pi);
            for (size_t j = 0; j < pi.sup_opts_len; ++j)
                fprintf(stderr, "[DEBUG]\t[INFO]\t[%s]\t\t\t%s\n", program_invocation_short_name, pi.sup_opts[j].opt.name);
        }
        g_dl_handles_amount++;
    }
    return g_supported_plugins_amount;
}

int are_new_options_intersected()
{
    for (size_t i = 0; i < g_supported_plugins_amount - 1; ++i)
        for (size_t j = i + 1; j < g_supported_plugins_amount; ++j)
        {
            struct plugin_info pi1;
            struct plugin_info pi2;
            g_supported_plugins[i].plugin_api->get_info(&pi1);
            g_supported_plugins[j].plugin_api->get_info(&pi2);
            for (size_t v = 0; v < pi1.sup_opts_len; ++v)
                for (size_t w = 0; w < pi2.sup_opts_len; w++)
                    if (!strcmp(pi1.sup_opts[v].opt.name, pi2.sup_opts[w].opt.name))
                        return 1;
        }
    return 0;
}

void print_usage()
{
    printf("Usage: %s [OPTIONS]... [FILE]\n\
Search files in FILE using shared libraries(plugins).\n\
Located in P_DIRECTORY plugins extend supported search options list.\n",
           program_invocation_short_name);
    printf("\t -P [P_DIRECTORY]\tdirectory with plugins\n");
    printf("\t -A \t\t\tcombine plugins options using the AND operation\n");
    printf("\t -O \t\t\tcombine plugin options using the OR operation\n");
    printf("\t -N \t\t\tinvert the search term (after combining options plugins with -A or -O)\n");
    printf("\t -v \t\t\tdisplay the version of the program and information about the program and exit\n");
    printf("\t -h \t\t\tdisplay this help and exit\n");
}

void print_info()
{
    printf("Version: 1.0.0\n");
    printf("Author: Bakhov Mikhail Alexandrovich\n");
    printf("Group: N3248\n");
    printf("Variant: 4\n");
}

int process_file(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if (DEBUG)
        fprintf(stderr, "[DEBUG]\t[INFO]\t[%s]\t\tProcessing file %s(%ld)\n", // For sake of usage (-Werror)
                program_invocation_short_name, fpath + ftwbuf->base, sb->st_size);
    if (typeflag == FTW_F)
    {
        int *results = NULL;
        size_t results_len = 0;
        for (size_t i = 0; i < g_supported_plugins_amount; ++i)
            if (g_supported_plugins[i].is_required)
                results_len++;

        results = (int *)calloc(results_len, sizeof(int));
        char should_print = 1;
        for (size_t i = 0; i < results_len; ++i)
        {
            if (g_supported_plugins[i].is_required)
            {
                results[i] = g_supported_plugins[i].plugin_api->process_file(
                    fpath,
                    g_supported_plugins[i].plugin_api->process_file_opts,
                    g_supported_plugins[i].plugin_api->process_file_opts_len);

                if (results[i] == -1)
                {
                    if (errno == EINVAL)
                    {
                        if (DEBUG)
                            fprintf(stderr, "[DEBUG]\t[CRIT]\t[%s]\t\tUnhandled error happend in '%s': %s\n",
                                    program_invocation_short_name, g_supported_plugins[i].name, strerror(errno));
                        free(results);
                        return -1;
                    }
                    results[i] = 0;
                    if (DEBUG)
                        fprintf(stderr, "[DEBUG]\t[ERROR]\t[%s]\t\tHandled error happend in '%s': %s\n",
                                program_invocation_short_name, g_supported_plugins[i].name, strerror(errno));
                }
            }
        }
        if (results_len)
        {
            char should_not = 1;
            switch (g_algebra)
            {
            case EA_A_AND_B_AND:
                for (size_t i = 0; i < results_len; ++i)
                    if (results[i] == 0)
                    {
                        should_print = 0;
                        break;
                    }
                break;
            case EA_A_OR_B_OR:
                for (size_t i = 0; i < results_len; ++i)
                    if (results[i] == 1)
                    {
                        should_not = 0;
                        break;
                    }
                should_print -= should_not;
                break;
            case EA_NA_AND_NB_AND_N:
                for (size_t i = 0; i < results_len; ++i)
                    if (results[i] == 1)
                    {
                        should_print = 0;
                        break;
                    }
                break;
            case EA_NA_OR_NB_OR_N:
                for (size_t i = 0; i < results_len; ++i)
                    if (results[i] == 0)
                    {
                        should_not = 0;
                        break;
                    }
                should_print -= should_not;
                break;
            default:
                break;
            }
        }
        else
            should_print = (SHORT_OPTS_BITMASK & N_OPTION_FLAG) ? 0 : 1;
        if (should_print)
            printf("%s\n", fpath);

        free(results);
    }
    return 0;
}

void set_algebra(const char short_opts_bitmask)
{
    char algebra_mask = short_opts_bitmask & (A_OPTION_FLAG | O_OPTION_FLAG);
    char is_inverted = short_opts_bitmask & N_OPTION_FLAG;
    /**
     * A AND B AND
     *      None algebra options have been passed
     *      [-A] algebra option has been passed
     */
    if (!(algebra_mask) || (algebra_mask & A_OPTION_FLAG))
    {
        g_algebra = EA_A_AND_B_AND;
    }

    /**
     * A OR B OR
     *      [-O] algebra option has been passed but not [-A]
     */
    if (algebra_mask & O_OPTION_FLAG && !(algebra_mask & A_OPTION_FLAG))
    {
        g_algebra = EA_A_OR_B_OR;
    }

    if (is_inverted)
    {
        switch (g_algebra)
        {
        case EA_A_AND_B_AND:
            g_algebra = EA_NA_OR_NB_OR_N;
            break;
        case EA_A_OR_B_OR:
            g_algebra = EA_NA_AND_NB_AND_N;
            break;
        case EA_NA_OR_NB_OR_N:
            g_algebra = EA_A_AND_B_AND;
            break;
        case EA_NA_AND_NB_AND_N:
            g_algebra = EA_A_OR_B_OR;
            break;
        default:
            break;
        }
    }
}