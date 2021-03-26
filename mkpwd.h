#ifndef _MKPWD_H
#define _MKPWD_H

#define MKPWD_NO	0
#define MKPWD_YES	1

#define MKPWD_FMT_B64	0
#define MKPWD_FMT_UNIV	1
#define MKPWD_FMT_CPWD	2

#define MKPWD_ALPHA_STRING "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define MKPWD_DIGIT_STRING "0123456789"

struct mkpwd_args {
	size_t pwdmax;

	const char *pwd;
	size_t szpwd;
	const char *id;
	size_t szid;
	const void *salt;
	size_t szsalt;

	short format;
	char *charset;
	size_t turns;
	size_t offset;
	size_t length;

	void *result;
	size_t szresult;
};

int mkpwd(struct mkpwd_args *mkpwa);
int mkpwd_key(struct mkpwd_args *mkpwa);
int mkpwd_hint(struct mkpwd_args *mkpwa);

#endif
