#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <limits.h>

#include "path.h"
#include "mem.h"

#ifdef OS_WIN32
#define DIRECTORY_SEPARATOR '\\'
#else
#define DIRECTORY_SEPARATOR '/'
#endif

int SCDefaultMkDir(const char *path) {
    return mkdir(path, 0755);
}

int SCCreateDirectoryTree(const char *path, const bool final) {
    char pathbuf[PATH_MAX];
    char *p;
    size_t len = strlen(path);

    if (len >= PATH_MAX) {
        return -1;
    }

    strncpy(pathbuf, path, PATH_MAX);
    pathbuf[PATH_MAX - 1] = '\0';  // ensure null-terminated

    for (p = pathbuf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (SCDefaultMkDir(pathbuf) != 0 && errno != EEXIST) {
#ifdef DEBUG
                perror("mkdir failed");
#endif
                return -1;
            }
            *p = '/';
        }
    }

    if (final && SCDefaultMkDir(pathbuf) != 0 && errno != EEXIST) {
#ifdef DEBUG
        perror("mkdir final failed");
#endif
        return -1;
    }

    return 0;
}

int PathMerge(char *out_buf, size_t buf_size, const char *dir, const char *fname)
{
    if (dir == NULL || strlen(dir) == 0 || fname == NULL)
        return -1;

    size_t dir_len = strlen(dir);
    int need_sep = (dir[dir_len - 1] != DIRECTORY_SEPARATOR);

    size_t total_len = dir_len + (need_sep ? 1 : 0) + strlen(fname) + 1;
    if (total_len > buf_size)
        return -1;

    strcpy(out_buf, dir);
    if (need_sep) {
        strcat(out_buf, "/");
    }
    strcat(out_buf, fname);

    return 0;
}

char *PathMergeAlloc(const char *dir, const char *fname)
{
    char temp[PATH_MAX];
    if (PathMerge(temp, sizeof(temp), dir, fname) != 0)
        return NULL;

    char *ret = SCStrdup(temp);
    return ret;
}

bool SCPathExists(const char *path)
{
    struct stat sb;
    return stat(path, &sb) == 0;
}

const char *SCBasename(const char *path)
{
    if (!path || strlen(path) == 0)
        return NULL;

    const char *final = strrchr(path, DIRECTORY_SEPARATOR);
    return (final && *(final + 1) != '\0') ? final + 1 : NULL;
}

bool SCPathContainsTraversal(const char *path)
{
#ifdef OS_WIN32
    const char *pattern = "..\\";
#else
    const char *pattern = "../";
#endif
    return strstr(path, pattern) != NULL;
}

