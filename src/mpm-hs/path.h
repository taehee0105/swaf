/* 파일/디렉토리 경로 생성, 병합, 존재 여부 확인 등을 위한 헤더 */

#ifndef STANDALONE_UTIL_PATH_H
#define STANDALONE_UTIL_PATH_H

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int SCDefaultMkDir(const char *path);
int SCCreateDirectoryTree(const char *path, const bool final);
bool SCPathExists(const char *path); /* 구현은 path.c */

int PathMerge(char *out_buf, size_t buf_size, const char *dir, const char *fname);
char *PathMergeAlloc(const char *dir, const char *fname);
const char *SCBasename(const char *path);
bool SCPathContainsTraversal(const char *path);

#endif /* STANDALONE_UTIL_PATH_H */
