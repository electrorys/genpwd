/*
 * MIT License
 *
 * Copyright (c) 2021 Andrey Rys
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

#include "genpwd.h"
#include "genpwd_defs.h"

static char *masterpw;
static char *identifier;
static gpwd_yesno no_newline;
static char *fkeyname;
static int kfd = 1;
static gpwd_yesno do_random_pw = NO;

char *progname;

static char *stoi;

static struct mkpwd_args *mkpwa;
static struct getpasswd_state *getps;

static void usage(void)
{
	if (optopt == 'V') {
		char *shash = genpwd_malloc(64);
		genpwd_say("genpwd passwords keeper, version %s.", _GENPWD_VERSION);
		genpwd_hash_defaults(shash, 64);
		genpwd_say("Defaults hash: %s", shash);
		genpwd_free(shash);
		genpwd_exit(0);
	}

	genpwd_say("usage: %s [opts] [--]", progname);
	genpwd_say("\n");
	genpwd_say("genpwd: generate passwords that could be recalled later.");
	genpwd_say("\n");
	genpwd_say("  -L <file>: load genpwd defaults from file.");
	genpwd_say("  -B: make password from base64 substring");
	genpwd_say("  -C: like normal password, but with more digits");
	genpwd_say("  -U charset: generate password characters from the given charset");
	genpwd_say("  -U " GENPWD_ALNUM_STRING_NAME ": generate password characters from [a-zA-Z0-9] charset");
	genpwd_say("  -U " GENPWD_ALPHA_STRING_NAME ": generate password characters from [a-zA-Z] charset");
	genpwd_say("  -U " GENPWD_DIGIT_STRING_NAME ": generate password characters from [0-9] charset");
	genpwd_say("  -U " GENPWD_XDIGIT_STRING_NAME ": generate password characters from [0-9a-f] charset");
	genpwd_say("  -U " GENPWD_UXDIGIT_STRING_NAME ": generate password characters from [0-9A-F] charset");
	genpwd_say("  -U " GENPWD_LOWER_STRING_NAME ": generate password characters from [a-z] charset");
	genpwd_say("  -U " GENPWD_UPPER_STRING_NAME ": generate password characters from [A-Z] charset");
	genpwd_say("  -U " GENPWD_ASCII_STRING_NAME ": generate password characters from all ASCII characters");
	genpwd_say("  -j: omit newline when printing password");
	genpwd_say("  -R: do not ask for anything, and just generate random password of specified quality.");
	genpwd_say("  -l pwlen: set result password length");
	genpwd_say("  -w outkey: write key or password to this file");
	genpwd_say("\n");
	genpwd_exit(1);
}

static int getps_filter(struct getpasswd_state *getps, char chr, size_t pos)
{
	if (chr == '\x03') { /* ^C */
		getps->retn = ((size_t)-2);
		return 6;
	}
	return 1;
}

static inline int isctrlchr(int c)
{
	if (c == 9) return 0;
	if (c >= 0 && c <= 31) return 1;
	if (c == 127) return 1;
	return 0;
}

static int getps_plain_filter(struct getpasswd_state *getps, char chr, size_t pos)
{
	int x;

	x = getps_filter(getps, chr, pos);
	if (x != 1) return x;

	if (pos < getps->pwlen && !isctrlchr(chr))
		write(getps->efd, &chr, sizeof(char));
	return 1;
}

int main(int argc, char **argv)
{
	int c;
	char *s, *d;
	size_t x;

	install_signals();

	progname = genpwd_strdup(basename(*argv));
	mkpwa = genpwd_malloc(sizeof(struct mkpwd_args));
	getps = genpwd_malloc(sizeof(struct getpasswd_state));
	masterpw = genpwd_malloc(GENPWD_PWD_MAX);
	identifier = genpwd_malloc(GENPWD_PWD_MAX);

	s = genpwd_malloc(PATH_MAX);
	d = getenv("HOME");
	if (!d) d = "";
	if (xstrlcpy(s, d, PATH_MAX) >= PATH_MAX) goto _baddfname;
	if (xstrlcat(s, "/.genpwd.defs", PATH_MAX) >= PATH_MAX) goto _baddfname;
	genpwd_read_defaults(s, YES);
_baddfname:
	genpwd_free(s);

	opterr = 0;
	while ((c = getopt(argc, argv, "L:l:U:BCiI:jM:NRk:")) != -1) {
		switch (c) {
			case 'L':
				genpwd_read_defaults(optarg, NO);
				break;
			case 'l':
				default_password_length = strtoul(optarg, &stoi, 10);
				if (!fkeyname
				&& (!str_empty(stoi) || default_password_length == 0))
					xexit("%s: invalid password length number", optarg);
				break;
			case 'B':
				default_password_format = MKPWD_FMT_B64;
				break;
			case 'C':
				default_password_format = MKPWD_FMT_CPWD;
				break;
			case 'U':
				default_password_format = MKPWD_FMT_UNIV;
				genpwd_free(default_password_charset);
				default_password_charset = genpwd_strdup(pwl_charset_string(optarg));
				break;
			case 'j':
				no_newline = YES;
				break;
			case 'N':
			case 'M':
			case 'i':
			case 'I':
				xexit("unimplemented");
				break;
			case 'R':
				do_random_pw = YES;
				break;
			case 'k':
				if (fkeyname) genpwd_free(fkeyname);
				fkeyname = genpwd_strdup(optarg);
				break;
			default:
				usage();
				break;
		}
	}

	for (x = 1; x < argc; x++) {
		memset(argv[x], 0, strlen(argv[x]));
		argv[x] = NULL;
	}
	argc = 1;

	mkpwd_adjust(mkpwa);

	mkpwa->pwd = masterpw;
	mkpwa->id = identifier;

	if (do_random_pw == YES) {
		genpwd_getrandom(masterpw, genpwd_szalloc(masterpw));
		genpwd_getrandom(identifier, genpwd_szalloc(identifier));
		mkpwa->szpwd = genpwd_szalloc(masterpw);
		mkpwa->szid = genpwd_szalloc(identifier);
		goto _do_random;
	}

	getps->fd = getps->efd = -1;
	getps->passwd = masterpw;
	getps->pwlen = genpwd_szalloc(masterpw)-1;
	getps->echo = "Enter master: ";
	getps->charfilter = getps_filter;
	getps->maskchar = 'x';
	x = xgetpasswd(getps);
	if (x == NOSIZE) xerror("getting password");
	if (x == ((size_t)-2)) genpwd_exit(1);

	if (mkpwd_hint(mkpwa) == MKPWD_NO) xexit("error generating password hint");
	genpwd_esay("Password hint: %s", mkpwa->result);
	genpwd_free(mkpwa->result);

	getps->fd = getps->efd = -1;
	getps->passwd = identifier;
	getps->pwlen = genpwd_szalloc(identifier)-1;
	getps->echo = "Enter name: ";
	getps->charfilter = getps_plain_filter;
	getps->maskchar = 0;
	x = xgetpasswd(getps);
	if (x == NOSIZE) xerror("getting name");
	if (x == ((size_t)-2)) genpwd_exit(1);

_do_random:
	if (fkeyname) {
		if (!(!strcmp(fkeyname, "-")))
			kfd = creat(fkeyname, S_IRUSR | S_IWUSR);
		if (kfd == -1) xerror("%s", fkeyname);
		if (kfd != 1) no_newline = YES;
	}

	if (!fkeyname) {
		if (mkpwd(mkpwa) == MKPWD_NO) xexit("error generating password");
		write(kfd, mkpwa->result, mkpwa->szresult);
		if (!no_newline) write(kfd, "\n", 1);
	}
	else {
		if (mkpwd_key(mkpwa) == MKPWD_NO) xexit("error generating keyfile");
		write(kfd, mkpwa->result, mkpwa->szresult);
	}

	genpwd_free(mkpwa->result);
	if (kfd != 1) close(kfd);
	genpwd_exit(0);

	return 0;
}
