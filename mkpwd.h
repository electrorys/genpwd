#define MKPWD_INPUT_MAX 1024
#define MKPWD_OUTPUT_MAX 180
#define MKPWD_ROUNDS_MAX 100000

extern int mkpwd_passes_number, mkpwd_string_offset, mkpwd_password_length, mkpwd_output_format;
char *mkpwd(const void *salt, size_t slen, const char **data);
void *mkpwbuf(const void *salt, size_t slen, const char **data);
char *mkpwd_hint(const char *pw, size_t n);
