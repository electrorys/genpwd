#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>

#include "genpwd.h"
#include "getpasswd.h"
#include "defs.h"

static char master[256] = {0}, name[256] = {0};
static const char *d[] = {master, name, NULL, NULL};
static char *pwdout = NULL;
static int format_option = 0;
static int no_newline = 0;
static char keyfile[1024] = {0};
static char data[128] = {0};

char *progname = NULL;

static char *stoi;

size_t _slen = sizeof(salt);

static struct getpasswd_state getps;

static void usage(void)
{
	if (optopt == 'V') {
		printf("genpwd passwords keeper, version %s.\n", _GENPWD_VERSION);
		exit(0);
	}

	printf("usage: %s [-rODX8946mdULNi] [-n PASSES] [-o OFFSET] [-l PASSLEN]"
		" [-s/k filename/-]\n\n", progname);
	printf("  -O: output only numeric octal password\n");
	printf("  -D: output only numeric password (useful for pin numeric codes)\n");
	printf("  -X: output hexadecimal password\n");
	printf("  -8: output base85 password\n");
	printf("  -9: output base95 password\n");
	printf("  -4: output an ipv4 address\n");
	printf("  -6: output an ipv6 address\n");
	printf("  -m: output a mac address\n");
	printf("  -d data: provide optional data for -46m options\n");
	printf("  -U: output a UUID\n");
	printf("  -L: omit newline when printing password\n");
	printf("  -N: do not save ID data typed in Name field\n");
	printf("  -i: list identifiers from .genpwd.ids\n");
	printf("  -n PASSES: set number of PASSES of skein1024 function\n");
	printf("  -o OFFSET: offset from beginning of 'big-passwd' string\n");
	printf("  -l PASSLEN: with offset, sets the region of passwd substring from"
	       	" 'big-passwd' string\n");
	printf("  -s filename: load alternative binary salt from filename"
	       	" or stdin (if '-')\n");
	printf("  -k filename: generate a keyfile instead of password\n\n");
	exit(1);
}

static int getps_filter(struct getpasswd_state *getps, int chr, size_t pos)
{
	if (chr == '\x03') { /* ^C */
		getps->retn = (size_t)-1;
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

static int getps_plain_filter(struct getpasswd_state *getps, int chr, size_t pos)
{
	if (pos < getps->pwlen && !isctrlchr(chr))
		write(getps->efd, &chr, sizeof(char));
	return 1;
}

int main(int argc, char **argv)
{
	int c;

	progname = basename(argv[0]);

	if (!selftest())
		xerror(0, 1, "Self test failed. Program probably broken.");

	opterr = 0;
	while ((c = getopt(argc, argv, "n:o:l:ODX89is:LNk:46md:U")) != -1) {
		switch (c) {
			case 'n':
				default_passes_number = strtol(optarg, &stoi, 10);
				if (*stoi || default_passes_number < 0 || default_passes_number > MKPWD_ROUNDS_MAX)
					xerror(0, 1, "%s: rounds number must be between 0 and %u", optarg, MKPWD_ROUNDS_MAX);
				break;
			case 'o':
				default_string_offset = strtol(optarg, &stoi, 10);
				if (*stoi || default_string_offset < 0 || default_string_offset > MKPWD_OUTPUT_MAX)
					xerror(0, 1, "%s: offset must be between 0 and %u", optarg, MKPWD_OUTPUT_MAX);
				break;
			case 'l':
				default_password_length = strtol(optarg, &stoi, 10);
				if (!keyfile[0]
				&& (*stoi || !default_password_length || default_password_length < 0 || default_password_length > MKPWD_OUTPUT_MAX))
					xerror(0, 1, "%s: password length must be between 1 and %u", optarg, MKPWD_OUTPUT_MAX);
				break;
			case 'O':
				format_option = 3;
				break;
			case 'D':
				format_option = 1;
				break;
			case 'X':
				format_option = 2;
				break;
			case '8':
				format_option = 4;
				break;
			case '9':
				format_option = 5;
				break;
			case 's':
				loadsalt(optarg, &_salt, &_slen);
				break;
			case 'L':
				no_newline = 1;
				break;
			case 'N':
				to_saveids(-1);
				break;
			case 'i':
				listids();
				break;
			case 'k':
				strncpy(keyfile, optarg, sizeof(keyfile)-1);
				break;
			case '4':
				format_option = 0x1004;
				strcpy(data, "0.0.0.0/0");
				break;
			case '6':
				format_option = 0x1006;
				strcpy(data, "::/0");
				break;
			case 'm':
				format_option = 0x1001;
				strcpy(data, "0:0:0:0:0:0.0");
				break;
			case 'd':
				memset(data, 0, sizeof(data));
				strncpy(data, optarg, sizeof(data)-1);
				break;
			case 'U':
				format_option = 0xff;
				break;
			default:
				usage();
				break;
		}
	}

	int i; for (i = 1; i < argc; i++) { memset(argv[i], 0, strlen(argv[i])); argv[i] = NULL; }
	argc = 1;

	memset(&getps, 0, sizeof(struct getpasswd_state));
	getps.fd = getps.efd = -1;
	getps.passwd = master;
	getps.pwlen = sizeof(master)-1;
	getps.echo = "Enter master: ";
	getps.charfilter = getps_filter;
	getps.maskchar = 'x';
	if (xgetpasswd(&getps) == (size_t)-1) return 1;
	memset(&getps, 0, sizeof(struct getpasswd_state));

	pwdout = mkpwd_hint(_salt, _slen, master);
	fprintf(stderr, "Password hint: %s\n", pwdout);
	memset(pwdout, 0, 4);

	getps.fd = getps.efd = -1;
	getps.passwd = name;
	getps.pwlen = sizeof(name)-1;
	getps.echo = "Enter name: ";
	getps.charfilter = getps_plain_filter;
	getps.maskchar = 0;
	if (xgetpasswd(&getps) == (size_t)-1) return 1;
	memset(&getps, 0, sizeof(struct getpasswd_state));

	loadids(NULL);
	if (!is_dupid(name)) {
		addid(name);
		to_saveids(1);
	}

	mkpwd_adjust();

	mkpwd_output_format = format_option;
	if (!keyfile[0]) {
		if (format_option >= 0x1001 && format_option <= 0x1006) d[2] = data;
		pwdout = mkpwd(_salt, _slen, d);
		memset(master, 0, sizeof(master));
		memset(name, 0, sizeof(name));
		if (!pwdout[0] && pwdout[1]) xerror(0, 1, pwdout+1);
	
		no_newline ? printf("%s", pwdout) : printf("%s\n", pwdout);
		fflush(stdout);
		memset(pwdout, 0, MKPWD_OUTPUT_MAX); pwdout = NULL;
	}
	else {
		FILE *f;

		if (!strcmp(keyfile, "-")) f = stdout;
		else {
			f = fopen(keyfile, "wb");
			if (!f) xerror(0, 0, keyfile);
			if (fchmod(fileno(f), S_IRUSR | S_IWUSR) != 0)
				xerror(0, 0, keyfile);
		}

		pwdout = mkpwbuf(_salt, _slen, d);
		memset(master, 0, sizeof(master));
		memset(name, 0, sizeof(name));
		if (!pwdout[0] && pwdout[1]) xerror(0, 1, pwdout+1);

		fwrite(pwdout, default_password_length, 1, f);
		fclose(f);
		memset(pwdout, 0, default_password_length);
		genpwd_free(pwdout);
	}

	saveids();

	return 0;
}
