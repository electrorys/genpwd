#define MKPWD_INPUT_MAX 1024
#define MKPWD_OUTPUT_MAX 180
#define MKPWD_ROUNDS_MAX 100000

extern int rounds, offset, passlen, dechex;
char *mkpwd(const void *salt, size_t slen, const char **data);
void *mkpwbuf(const void *salt, size_t slen, const char **data);
